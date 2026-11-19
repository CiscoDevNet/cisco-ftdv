"""Retained release assets must remain internally verifiable across source edits."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from verify_releases import PROJECT_ROOT, verify_triplet


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


if __name__ == "__main__":
    unittest.main()
