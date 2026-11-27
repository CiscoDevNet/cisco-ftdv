"""Retained release assets must remain internally verifiable across source edits."""
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from package_asav import FILES as ASAV_MODULE_FILES, build as build_asav
from verify_releases import PROJECT_ROOT, triplet_files, verify_releases, verify_triplet


class ReleaseArchives(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ibm-release-integrity-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def copy_triplet(self):
        original = sorted((PROJECT_ROOT / "tf-releases").glob("*/*.tgz"))[0]
        for source in (original, original.with_suffix(".sha256"), original.with_suffix(".verification.json")):
            shutil.copy2(source, self.root / source.name)
        return self.root / original.name

    def test_retained_product_assets(self):
        archives = sorted((PROJECT_ROOT / "tf-releases").glob("*/*.tgz"))
        self.assertTrue(archives)
        for archive in archives:
            with self.subTest(archive=archive.name):
                self.assertEqual(len(verify_triplet(archive)), 64)

    def test_tampered_archive_rejected(self):
        archive = self.copy_triplet()
        archive.write_bytes(archive.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "mismatch"):
            verify_triplet(archive)

    def test_missing_sidecar_rejected(self):
        archive = self.copy_triplet()
        archive.with_suffix(".sha256").unlink()
        with self.assertRaisesRegex(ValueError, "missing"):
            verify_triplet(archive)

    def test_manifest_payload_tampering_rejected(self):
        archive = self.copy_triplet()
        path = archive.with_suffix(".verification.json")
        report = json.loads(path.read_text())
        report["files_sha256"]["main.tf"] = "0" * 64
        path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, "file hash mismatch"):
            verify_triplet(archive)


    def test_current_schema_cannot_omit_legal_files(self):
        archive = self.copy_triplet()
        path = archive.with_suffix(".verification.json")
        report = json.loads(path.read_text())
        report["packaging_schema"] = 2
        report["files_sha256"].pop("LICENSE", None)
        report["files_sha256"].pop("NOTICE", None)
        path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, "requires LICENSE and NOTICE"):
            verify_triplet(archive)


class ChangedReleaseArchives(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="ibm-release-checkout-")
        self.addCleanup(temp.cleanup)
        self.repository = Path(temp.name).resolve()
        self.project = self.repository / "ibm-mp-templates"
        self.module = self.project / "solutions/asav-ibm-tf"
        self.releases = self.project / "tf-releases"
        released_asav = self.releases / "asav"
        released_asav.mkdir(parents=True)
        original = sorted((PROJECT_ROOT / "tf-releases/asav").glob("*.tgz"))[0]
        for source in triplet_files(original):
            shutil.copy2(source, released_asav / source.name)
        self.historical = released_asav / original.name
        for name in ASAV_MODULE_FILES:
            destination = self.module / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(PROJECT_ROOT / "solutions/asav-ibm-tf" / name, destination)
        for name in ("LICENSE", "NOTICE"):
            shutil.copy2(PROJECT_ROOT.parent / name, self.repository / name)
        self.git("init", "--quiet")
        self.commit("Historical release")
        readme = self.module / "README.md"
        readme.write_text(readme.read_text() + "\nRelease checkout differs from historical source.\n")

    def git(self, *args):
        subprocess.run(["git", "-C", str(self.repository), *args],
                       check=True, capture_output=True)

    def commit(self, message):
        self.git("add", ".")
        self.git("-c", "user.name=Release Check", "-c", "user.email=release-check@example.com",
                 "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
                 "commit", "--quiet", "-m", message)

    def verify(self, changed_since):
        with redirect_stdout(StringIO()):
            return verify_releases(self.releases, project_root=self.project,
                                   changed_since=changed_since)

    def build_candidate(self):
        return build_asav(self.module, self.releases / "asav", filename="new-release.tgz")[0]

    def test_source_only_change_preserves_historical_integrity(self):
        self.assertEqual(self.verify("HEAD"), 0)

    def test_new_triplet_matches_checkout_without_rechecking_historical_source(self):
        self.build_candidate()
        self.assertEqual(self.verify("HEAD"), 1)
        self.commit("New release")
        self.assertEqual(self.verify("HEAD^"), 1)

    def test_changed_sidecar_also_requires_source_match(self):
        manifest = self.historical.with_suffix(".verification.json")
        manifest.write_text(manifest.read_text() + "\n")
        with self.assertRaisesRegex(ValueError, "does not match checkout source: .*README.md"):
            self.verify("HEAD")

    def test_new_triplet_requires_canonical_legal_bytes(self):
        self.build_candidate()
        notice = self.repository / "NOTICE"
        notice.write_bytes(notice.read_bytes() + b"\nDifferent checkout notice\n")
        with self.assertRaisesRegex(ValueError, "does not match checkout source: NOTICE"):
            self.verify("HEAD")

    def test_orphan_sidecar_rejected_in_changed_mode(self):
        (self.releases / "asav/orphan.sha256").write_text("not a release")
        with self.assertRaisesRegex(ValueError, "orphan sidecars"):
            self.verify("HEAD")


if __name__ == "__main__":
    unittest.main()
