#!/usr/bin/env python3
"""Verify retained archive triplets against their own manifests; no cloud calls."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def verify_triplet(archive):
    checksum = archive.with_suffix(".sha256")
    manifest = archive.with_suffix(".verification.json")
    if archive.name.startswith("DRAFT-"):
        raise ValueError("Keep draft review archives outside committed release folders")
    if not checksum.is_file() or not manifest.is_file():
        raise ValueError("Archive is missing its checksum or verification report")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    parts = checksum.read_text().split()
    report = json.loads(manifest.read_text())
    if parts != [digest, archive.name] or report.get("archive_sha256") != digest or report.get("archive_filename") != archive.name:
        raise ValueError("Archive/checksum/report mismatch: " + archive.name)
    hashes = report.get("files_sha256", {})
    if not isinstance(hashes, dict) or not {"README.md", "main.tf"}.issubset(hashes):
        raise ValueError("Manifest is missing the customer payload")
    if report.get("packaging_schema", 1) >= 2:
        if not {"LICENSE", "NOTICE"}.issubset(hashes):
            raise ValueError("Current packaging schema requires LICENSE and NOTICE")
        if report.get("module_file_count") != 14 or len(hashes) != 16 or report.get("archive_file_count") != len(hashes):
            raise ValueError("Manifest file counts do not match the declared payload")
        for name in ("LICENSE", "NOTICE"):
            expected_legal = {"source_path": name, "source_path_base": "repository", "sha256": hashes[name]}
            if report.get("legal_files", {}).get(name) != expected_legal:
                raise ValueError("Legal-file provenance/hash mismatch: " + name)
    for name, expected in hashes.items():
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or str(path) != name or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("Unsafe manifest path or invalid hash")
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        names = ["root"] + ["root/" + name for name in sorted(hashes)]
        if [m.name for m in members] != names or not members[0].isdir() or not all(m.isfile() for m in members[1:]):
            raise ValueError("Archive must contain only the root/ directory and its declared regular files")
        for name, expected in hashes.items():
            if hashlib.sha256(tar.extractfile("root/" + name).read()).hexdigest() != expected:
                raise ValueError("Archived file hash mismatch: " + name)
    return digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--releases-dir", type=Path, default=PROJECT_ROOT / "tf-releases")
    args = parser.parse_args()
    try:
        archives = sorted(args.releases_dir.glob("*/*.tgz"))
        if not archives:
            raise ValueError("No product release archives found")
        expected = set()
        for archive in archives:
            digest = verify_triplet(archive)
            expected.update((archive, archive.with_suffix(".sha256"), archive.with_suffix(".verification.json")))
            print(archive.parent.name + "/" + archive.name + ": PASS " + digest)
            declared = json.loads(archive.with_suffix(".verification.json").read_text())["files_sha256"]
            if not {"LICENSE", "NOTICE"}.issubset(declared):
                print("  LEGACY: LICENSE/NOTICE absent; preserve historical bytes, refresh before a new import.")
                if archive.parent.name == "asav":
                    print("  ASAv CATALOG UPDATE PENDING: import the refreshed reviewed package and rerun Partner Center validation.")
        actual = {p for p in args.releases_dir.rglob("*") if p.is_file()}
        if actual != expected:
            raise ValueError("Unexpected files or orphan sidecars in release folders")
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        parser.exit(1, str(error) + "\n")
    print("Stored-artifact integrity verified. This does not assert source-HEAD equality or IBM validation.")


if __name__ == "__main__":
    main()
