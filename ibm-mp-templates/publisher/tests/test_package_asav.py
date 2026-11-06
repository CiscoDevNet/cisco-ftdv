"""Publisher archive safety checks; no cloud calls or Terraform dependency."""
import importlib.util
import io
import json
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timezone, timedelta
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / 'package_asav.py'
spec = importlib.util.spec_from_file_location('package_asav', SCRIPT)
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class PackageChecks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='asav-package-test-')
        self.work = Path(self.tmp.name)
        self.source = self.work / 'source'
        shutil.copytree(SCRIPT.parent.parent / 'solutions/asav-ibm-tf', self.source)
        self.fixed_time = datetime(2026, 11, 5, 6, 30, 45, tzinfo=timezone.utc)
        (self.source / 'changelog.txt').write_text('2026-Nov-05\nversion 1.0.0\nChanges\nInitial TF template creation\n')

    def build(self, output=None, **kwargs):
        kwargs.setdefault("build_time", self.fixed_time)
        return package.build(self.source, output, **kwargs)

    def tearDown(self):
        self.tmp.cleanup()

    def test_reproducible_root_layout(self):
        a, _, _ = self.build(self.work / 'one')
        b, _, _ = self.build(self.work / 'two')
        self.assertEqual(a.read_bytes(), b.read_bytes())
        with tarfile.open(a) as archive:
            members = archive.getmembers()
            self.assertEqual(archive.getnames(), ['root'] + ['root/' + name for name in sorted(package.FILES)])
            self.assertTrue(members[0].isdir())
            self.assertTrue(all(member.isfile() for member in members[1:]))
            self.assertEqual({member.name.split('/')[0] for member in members}, {'root'})
            self.assertIn('root/main.tf', archive.getnames())
            self.assertIn('root/README.md', archive.getnames())

    def test_rejects_previous_flat_archive_layout(self):
        _, _, manifest = self.build(self.work / 'out')
        flat = self.work / 'flat.tgz'
        with tarfile.open(flat, 'w:gz') as tar:
            for name in sorted(package.FILES):
                tar.add(self.source / name, arcname=name, recursive=False)
        with self.assertRaisesRegex(ValueError, 'single root/'):
            package.verify_archive(flat, json.loads(manifest.read_text())['files_sha256'])

    def test_rejects_files_outside_root_and_unsafe_members(self):
        archive, _, manifest = self.build(self.work / 'out')
        hashes = json.loads(manifest.read_text())['files_sha256']
        for name, kind in [('outside.txt', tarfile.REGTYPE),
                           ('other-root', tarfile.DIRTYPE),
                           ('root/../outside.txt', tarfile.REGTYPE),
                           ('root/link', tarfile.SYMTYPE)]:
            with self.subTest(name=name):
                invalid = self.work / 'invalid.tgz'
                with tarfile.open(archive) as source, tarfile.open(invalid, 'w:gz') as target:
                    for entry in source.getmembers():
                        target.addfile(entry, source.extractfile(entry) if entry.isfile() else None)
                    entry = tarfile.TarInfo(name)
                    entry.type = kind
                    target.addfile(entry)
                with self.assertRaisesRegex(ValueError, 'single root/'):
                    package.verify_archive(invalid, hashes)

    def test_rejects_changed_archived_file_bytes(self):
        archive, _, manifest = self.build(self.work / 'out')
        invalid = self.work / 'changed.tgz'
        with tarfile.open(archive) as source, tarfile.open(invalid, 'w:gz') as target:
            for entry in source.getmembers():
                if entry.isfile():
                    data = source.extractfile(entry).read()
                    if entry.name == 'root/main.tf':
                        data += b'\n# changed after packaging\n'
                    entry.size = len(data)
                    target.addfile(entry, io.BytesIO(data))
                else:
                    target.addfile(entry)
        with self.assertRaisesRegex(ValueError, 'Archive/source hash mismatch'):
            package.verify_archive(invalid, json.loads(manifest.read_text())['files_sha256'])

    def test_rejects_active_variable_file(self):
        (self.source / 'terraform.tfvars').write_text('prefix = "local-only"\n')
        with self.assertRaises(ValueError):
            self.build(self.work / 'out')

    def test_rejects_state_file(self):
        (self.source / 'terraform.tfstate').write_text('{"resources": []}\n')
        with self.assertRaises(ValueError):
            self.build(self.work / 'out')

    def test_rejects_symlink(self):
        (self.work / 'outside.txt').write_text('outside-package')
        (self.source / 'unexpected-link').symlink_to(self.work / 'outside.txt')
        with self.assertRaises(ValueError):
            self.build(self.work / 'out')

    def test_rejects_missing_default_label(self):
        p = self.source / 'asav-images.json'
        d = json.loads(p.read_text())
        d['default_version'] = 'missing'
        p.write_text(json.dumps(d))
        with self.assertRaises(ValueError):
            self.build(self.work / 'out')

    def test_rejects_escaping_readme_link(self):
        (self.work / 'outside.txt').write_text('outside-package')
        with (self.source / 'README.md').open('a') as f:
            f.write('\n[Outside](../outside.txt)\n')
        with self.assertRaises(ValueError):
            self.build(self.work / 'out')

    def test_refuses_overwrite(self):
        a, _, _ = self.build(self.work / 'out')
        original = a.read_bytes()
        with self.assertRaises(ValueError):
            self.build(self.work / 'out')
        self.assertEqual(a.read_bytes(), original)

    def test_rejects_output_inside_source(self):
        with self.assertRaises(ValueError):
            self.build(self.source / 'dist')

    def test_finder_metadata_is_not_shipped(self):
        (self.source / '.DS_Store').write_bytes(b'finder metadata')
        archive, _, _ = self.build(self.work / 'out')
        with tarfile.open(archive) as tar:
            self.assertNotIn('root/.DS_Store', tar.getnames())


    def test_default_name_uses_changelog_version_and_ist_clock(self):
        archive, checksum, manifest = self.build(self.work / 'out')
        self.assertEqual(archive.name, 'asav-ibm-tf-1-0-0-120045-20261105.tgz')
        record = json.loads(manifest.read_text())
        self.assertEqual(record['archive_root'], 'root/')
        self.assertEqual(record['software_package_version'], '1.0.0')
        self.assertEqual(record['filename_timezone'], 'Asia/Kolkata')
        self.assertEqual(record['changelog']['changes'], ['Initial TF template creation'])
        self.assertIn(archive.name, checksum.read_text())

    def test_date_and_time_roll_over_together_in_ist(self):
        at = datetime(2026, 11, 5, 21, 45, tzinfo=timezone.utc)
        archive, _, _ = self.build(self.work / 'out', build_time=at)
        self.assertEqual(archive.name, 'asav-ibm-tf-1-0-0-031500-20261106.tgz')

    def test_custom_filename_keeps_changelog_version(self):
        archive, checksum, manifest = self.build(self.work / 'out', filename='my-asav-pilot.tgz')
        self.assertEqual(archive.name, 'my-asav-pilot.tgz')
        self.assertEqual(checksum.name, 'my-asav-pilot.sha256')
        self.assertEqual(json.loads(manifest.read_text())['software_package_version'], '1.0.0')

    def test_rejects_unsafe_or_wrong_extension_filename(self):
        for name in ['../escape.tgz', '/tmp/absolute.tgz', 'file.zip', '.hidden.tgz', '']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.build(self.work / 'out', filename=name)

    def test_version_argument_cannot_disagree_with_changelog(self):
        with self.assertRaises(ValueError):
            self.build(self.work / 'out', version='1.1.0')

    def test_default_output_is_used(self):
        self.assertEqual(package.DEFAULT_OUTPUT, SCRIPT.parent.parent / 'tf-releases/asav')
        with mock.patch.object(package, 'DEFAULT_OUTPUT', self.work / 'default-history'):
            archive, _, _ = self.build()
        self.assertEqual(archive.parent, (self.work / 'default-history').resolve())

    def test_verification_uses_project_relative_source_and_archive_filename(self):
        source = SCRIPT.parent.parent / 'solutions/asav-ibm-tf'
        archive, _, manifest = package.build(source, self.work / 'elsewhere', build_time=self.fixed_time)
        record = json.loads(manifest.read_text())
        self.assertEqual(record['source'], 'solutions/asav-ibm-tf')
        self.assertEqual(record['source_path_base'], 'project')
        self.assertEqual(record['archive_filename'], archive.name)
        self.assertNotIn('archive', record)
        self.assertNotIn(str(SCRIPT.parent.parent), manifest.read_text())
        self.assertNotIn(str(self.work), manifest.read_text())

    def test_custom_source_metadata_omits_local_parent_directories(self):
        archive, _, manifest = self.build(self.work / 'out')
        record = json.loads(manifest.read_text())
        self.assertEqual(record['source'], self.source.name)
        self.assertEqual(record['source_path_base'], 'custom_directory_name')
        self.assertEqual(record['archive_filename'], archive.name)
        self.assertNotIn(str(self.work), manifest.read_text())

    def test_verification_does_not_depend_on_output_directory(self):
        _, _, first = self.build(self.work / 'one')
        _, _, second = self.build(self.work / 'two')
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_latest_entry_controls_version(self):
        p = self.source / 'changelog.txt'
        p.write_text('2026-Nov-06\nversion 1.0.1\nChanges:\nExample next change\n' + '#' * 30 + '\n' + p.read_text())
        archive, _, manifest = self.build(self.work / 'out')
        self.assertTrue(archive.name.startswith('asav-ibm-tf-1-0-1-'))
        self.assertEqual(json.loads(manifest.read_text())['changelog']['date'], '2026-11-06')

    def test_rejects_duplicate_changelog_versions(self):
        p = self.source / 'changelog.txt'
        p.write_text(p.read_text() + '\n' + p.read_text())
        with self.assertRaises(ValueError):
            self.build(self.work / 'out')

    def test_rejects_oldest_first_changelog(self):
        p = self.source / 'changelog.txt'
        p.write_text(p.read_text() + '\n2026-Nov-06\nversion 1.0.1\nChanges\nExample next change\n')
        with self.assertRaises(ValueError):
            self.build(self.work / 'out')

    def test_rejects_invalid_changelog_date(self):
        p = self.source / 'changelog.txt'
        p.write_text(p.read_text().replace('2026-Nov-05', '2026-Feb-30'))
        with self.assertRaises(ValueError):
            self.build(self.work / 'out')

    def test_rejects_empty_change_entry(self):
        p = self.source / 'changelog.txt'
        p.write_text('2026-Nov-05\nversion 1.0.0\nChanges\n')
        with self.assertRaises(ValueError):
            self.build(self.work / 'out')

    def test_changelog_and_all_14_files_are_shipped(self):
        archive, _, _ = self.build(self.work / 'out')
        with tarfile.open(archive) as tar:
            self.assertEqual(sum(member.isfile() for member in tar.getmembers()), 14)
            self.assertEqual(len(tar.getmembers()), 15)
            self.assertEqual(tar.extractfile('root/changelog.txt').read(), (self.source / 'changelog.txt').read_bytes())

    def test_different_timestamps_keep_archive_bytes_reproducible(self):
        a, _, _ = self.build(self.work / 'one')
        b, _, _ = self.build(self.work / 'two', build_time=self.fixed_time + timedelta(seconds=1))
        self.assertNotEqual(a.name, b.name)
        self.assertEqual(a.read_bytes(), b.read_bytes())


if __name__ == '__main__':
    unittest.main()
