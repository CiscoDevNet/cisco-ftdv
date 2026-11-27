"""Exercise the Catalog handoff with local Git history and a small archive."""

import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from prepare_catalog_handoff import INTEGRATION_REF, prepare_handoff, rewrite_markdown, write_readme


ARCHIVE = Path("ibm-mp-templates/tf-releases/asav/example.tgz")
MODULE = Path("ibm-mp-templates/solutions/asav-ibm-tf")
README = (
    "![Architecture](docs/diagram.png)\n"
    '[Example](<bootstrap/day 0.txt#settings> "Day-0 sample")\n'
    "[Variables](./main.tf?plain=1#L1)\n"
    "[Support](https://example.com/support)\n"
    "[Overview](#overview)\n"
)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class PrepareCatalogHandoffTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="catalog-handoff-test-")
        self.addCleanup(temp.cleanup)
        self.temp = Path(temp.name).resolve()
        self.repo = self.temp / "repo"
        self.repo.mkdir()
        self.git("init", "--quiet")
        self.git("config", "user.email", "test@example.com")
        self.git("config", "user.name", "Catalog Fixture")
        self.git("config", "commit.gpgsign", "false")
        self.archive = self.repo / ARCHIVE
        self.module = self.repo / MODULE
        self.files = {
            "README.md": README.encode(),
            "bootstrap/day 0.txt": b"example",
            "docs/diagram.png": b"diagram",
            "main.tf": b"# packaged Terraform\n",
        }
        for name, data in self.files.items():
            source = self.module / name
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(data)
        self.archive.parent.mkdir(parents=True)
        self.build_triplet()
        self.commit = self.save_commit()
        self.git("update-ref", INTEGRATION_REF, self.commit)

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True, text=True).stdout.strip()

    def save_commit(self):
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "Fixture release")
        return self.git("rev-parse", "HEAD")

    def build_triplet(self):
        with tarfile.open(self.archive, "w:gz") as tar:
            root = tarfile.TarInfo("root")
            root.type = tarfile.DIRTYPE
            tar.addfile(root)
            for name, data in sorted(self.files.items()):
                member = tarfile.TarInfo("root/" + name)
                member.size = len(data)
                tar.addfile(member, io.BytesIO(data))
        digest = sha256(self.archive.read_bytes())
        self.archive.with_suffix(".sha256").write_text(f"{digest}  {self.archive.name}\n")
        self.archive.with_suffix(".verification.json").write_text(json.dumps({
            "archive_filename": self.archive.name,
            "archive_sha256": digest,
            "files_sha256": {name: sha256(data) for name, data in self.files.items()},
        }))

    def prepare(self, commit=None):
        return prepare_handoff(self.repo, ARCHIVE.as_posix(), commit or self.commit)

    def test_pins_archive_and_links_to_exact_commit(self):
        # The working tree's module README is unrelated to the archived handoff.
        (self.module / "README.md").write_text("unreviewed working changes\n")
        archive_url, digest, readme = self.prepare()
        raw = f"https://raw.githubusercontent.com/CiscoDevNet/cisco-ftdv/{self.commit}"
        blob = f"https://github.com/CiscoDevNet/cisco-ftdv/blob/{self.commit}"
        self.assertEqual(archive_url, f"{raw}/{ARCHIVE.as_posix()}")
        self.assertEqual(digest, sha256(self.archive.read_bytes()))
        self.assertIn(f"![Architecture]({raw}/{MODULE.as_posix()}/docs/diagram.png)", readme)
        self.assertIn(f'[Example](<{blob}/{MODULE.as_posix()}/bootstrap/day%200.txt#settings> "Day-0 sample")', readme)
        self.assertIn(f"[Variables]({blob}/{MODULE.as_posix()}/main.tf?plain=1#L1)", readme)
        self.assertIn("[Support](https://example.com/support)\n[Overview](#overview)\n", readme)
        self.assertNotIn("unreviewed working changes", readme)

    def test_rejects_local_sidecar_changes(self):
        checksum = self.archive.with_suffix(".sha256")
        checksum.write_bytes(checksum.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "Local file differs.*sha256"):
            self.prepare()

    def test_rejects_triplet_that_was_committed_with_incorrect_digest(self):
        self.archive.with_suffix(".sha256").write_text("wrong\n")
        commit = self.save_commit()
        self.git("update-ref", INTEGRATION_REF, commit)
        with self.assertRaisesRegex(ValueError, "Archive/checksum/report mismatch"):
            self.prepare(commit)

    def test_requires_full_integration_commit(self):
        with self.assertRaisesRegex(ValueError, "full 40-character"):
            self.prepare(self.commit[:10])
        (self.module / "main.tf").write_text("# feature edit\n")
        feature_commit = self.save_commit()
        with self.assertRaisesRegex(ValueError, "reachable from origin/"):
            self.prepare(feature_commit)

    def test_rejects_pinned_link_when_source_does_not_match_package(self):
        (self.module / "main.tf").write_text("# newer source\n")
        commit = self.save_commit()
        self.git("update-ref", INTEGRATION_REF, commit)
        with self.assertRaisesRegex(ValueError, "Bundled README link differs.*main.tf"):
            self.prepare(commit)

    def test_rejects_unbundled_relative_link(self):
        self.files["README.md"] = b"[Missing](missing.md)\n"
        self.build_triplet()
        commit = self.save_commit()
        self.git("update-ref", INTEGRATION_REF, commit)
        with self.assertRaisesRegex(ValueError, "README link does not name a bundled file"):
            self.prepare(commit)

    def test_preserves_code_examples(self):
        readme = "Example `[link](file.tf)`\n\n```text\n[link](file.tf)\n```\n\n    [link](file.tf)\n"
        self.assertEqual(rewrite_markdown(readme, lambda *_: self.fail("changed code")), readme)

    def test_writes_new_temporary_output_outside_repository(self):
        path = self.temp / "catalog.md"
        self.assertEqual(write_readme(self.repo, path, README), path)
        self.assertEqual(path.read_text(), README)
        with self.assertRaises(FileExistsError):
            write_readme(self.repo, path, "would overwrite")
        with self.assertRaisesRegex(ValueError, "outside the repository"):
            write_readme(self.repo, self.repo / "catalog.md", README)


if __name__ == "__main__":
    unittest.main()
