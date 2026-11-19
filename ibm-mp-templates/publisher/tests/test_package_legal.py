"""Legal-file packaging must preserve canonical text and fail closed."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import package_asav
import package_product
from package_legal import LEGAL_FILES, load_legal_files

PROJECT = Path(__file__).resolve().parents[2]
CASES = (("asav", package_asav), ("ftdv", package_product), ("fmcv", package_product))


class LegalPackaging(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ibm-legal-package-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def source(self, product):
        source = self.root / product
        shutil.copytree(PROJECT / "solutions" / (product + "-ibm-tf"), source)
        return source

    def build(self, product, builder, source, output):
        options = {"build_time": datetime(2026, 11, 18, tzinfo=timezone.utc)}
        if product != "asav":
            options["product"] = product
        return builder.build(source, output, **options)

    def test_exact_canonical_legal_files_all_products(self):
        for product, builder in CASES:
            with self.subTest(product=product):
                source = self.source(product)
                archive, _, report_path = self.build(product, builder, source, self.root / "out" / product)
                report = json.loads(report_path.read_text())
                self.assertEqual(report["packaging_schema"], 2)
                self.assertEqual(report["module_file_count"], 14)
                self.assertEqual(report["archive_file_count"], 16)
                self.assertEqual(len(report["files_sha256"]), 16)
                self.assertEqual(len([p for p in source.rglob("*") if p.is_file()]), 14)
                with tarfile.open(archive) as tar:
                    self.assertEqual(len(tar.getmembers()), 17)
                    for name in LEGAL_FILES:
                        original = (PROJECT.parent / name).read_bytes()
                        self.assertEqual(tar.extractfile("root/" + name).read(), original)
                        self.assertEqual(report["legal_files"][name], {
                            "source_path": name, "source_path_base": "repository",
                            "sha256": hashlib.sha256(original).hexdigest(),
                        })
                        self.assertFalse((source / name).exists())

    def test_missing_repository_legal_file_stops_build_all_products(self):
        for product, builder in CASES:
            with self.subTest(product=product):
                source = self.source(product)
                fake_project = self.root / (product + "-repo") / "ibm-mp-templates"
                fake_project.mkdir(parents=True)
                output = self.root / "output" / product
                with mock.patch.object(builder, "PROJECT_ROOT", fake_project), self.assertRaisesRegex(ValueError, "legal file is missing"):
                    self.build(product, builder, source, output)
                self.assertFalse(output.exists())

    def test_repository_notice_change_changes_archive_all_products(self):
        for product, builder in CASES:
            with self.subTest(product=product):
                source = self.source(product)
                fake_repo = self.root / (product + "-repo")
                fake_project = fake_repo / "ibm-mp-templates"
                fake_project.mkdir(parents=True)
                for name in LEGAL_FILES:
                    shutil.copy2(PROJECT.parent / name, fake_repo / name)
                with mock.patch.object(builder, "PROJECT_ROOT", fake_project):
                    first, _, _ = self.build(product, builder, source, self.root / "one" / product)
                    path = fake_repo / "NOTICE"
                    path.write_bytes(path.read_bytes() + b"\nTest-only notice fixture revision.\n")
                    second, _, report = self.build(product, builder, source, self.root / "two" / product)
                self.assertNotEqual(first.read_bytes(), second.read_bytes())
                self.assertEqual(json.loads(report.read_text())["legal_files"]["NOTICE"]["sha256"], hashlib.sha256((fake_repo / "NOTICE").read_bytes()).hexdigest())

    def test_empty_legal_file_rejected(self):
        for name in LEGAL_FILES:
            (self.root / name).write_text("fixture")
        (self.root / "NOTICE").write_text(" \n")
        with self.assertRaisesRegex(ValueError, "empty: NOTICE"):
            load_legal_files(self.root)

    def test_symlinked_legal_file_rejected(self):
        (self.root / "original").write_text("fixture")
        (self.root / "LICENSE").symlink_to(self.root / "original")
        with self.assertRaisesRegex(ValueError, "symlink: LICENSE"):
            load_legal_files(self.root)

    def test_legal_copies_inside_module_rejected(self):
        for product, builder in CASES:
            with self.subTest(product=product):
                source = self.source(product)
                (source / "LICENSE").write_text("Unreviewed duplicate license")
                with self.assertRaisesRegex(ValueError, "unexpected"):
                    self.build(product, builder, source, self.root / "out" / product)


if __name__ == "__main__":
    unittest.main()
