#!/usr/bin/env python3
"""Verify retained archives and optionally match changed releases to checkout source."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile

from package_asav import FILES as ASAV_MODULE_FILES
from package_legal import load_legal_files
from package_product import files_for

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def triplet_files(archive):
    return archive, archive.with_suffix(".sha256"), archive.with_suffix(".verification.json")


def verify_triplet(archive, *, source_project=None):
    _, checksum, manifest = triplet_files(archive)
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
    if source_project is not None:
        verify_source_match(archive, hashes, source_project)
    return digest


def verify_source_match(archive, hashes, project_root):
    product = archive.parent.name
    module = project_root / "solutions" / (product + "-ibm-tf")
    module_files = ASAV_MODULE_FILES if product == "asav" else files_for(product)
    expected = {name: hashlib.sha256(data).hexdigest()
                for name, data in load_legal_files(project_root.parent).items()}
    for name in module_files:
        path = module / name
        if not path.is_file() or path.resolve() != path:
            raise ValueError("Checkout module file is missing or a symlink: " + str(path))
        expected[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    mismatches = sorted(name for name in hashes.keys() | expected.keys()
                        if hashes.get(name) != expected.get(name))
    if mismatches:
        raise ValueError(
            f"Changed release {product}/{archive.name} does not match checkout source: "
            + ", ".join(mismatches)
        )


def changed_release_paths(releases_dir, repository_root, base_ref):
    relative_dir = releases_dir.relative_to(repository_root).as_posix()
    git = ["git", "-C", str(repository_root), "--literal-pathspecs"]
    base = subprocess.check_output(
        [*git, "rev-parse", "--verify", "--end-of-options", base_ref + "^{commit}"],
        stderr=subprocess.PIPE,
    ).decode("ascii").strip()
    tracked = subprocess.check_output(
        [*git, "diff", "--name-only", "--no-ext-diff", "--no-renames", "-z", base, "--", relative_dir],
        stderr=subprocess.PIPE,
    )
    untracked = subprocess.check_output(
        [*git, "ls-files", "--others", "-z", "--", relative_dir],
        stderr=subprocess.PIPE,
    )
    return {repository_root / os.fsdecode(path) for path in (tracked + untracked).split(b"\0") if path}


def verify_releases(releases_dir, *, project_root=PROJECT_ROOT, changed_since=None):
    releases_dir = releases_dir.resolve()
    project_root = project_root.resolve()
    archives = sorted(releases_dir.glob("*/*.tgz"))
    if not archives:
        raise ValueError("No product release archives found")
    changed = (changed_release_paths(releases_dir, project_root.parent, changed_since)
               if changed_since is not None else set())
    expected = set()
    source_matches = 0
    for archive in archives:
        members = triplet_files(archive)
        has_changes = not changed.isdisjoint(members)
        digest = verify_triplet(archive, source_project=project_root if has_changes else None)
        expected.update(members)
        print(archive.parent.name + "/" + archive.name + ": PASS " + digest)
        if has_changes:
            source_matches += 1
            print("  Changed release matches checkout module and canonical legal files.")
        declared = json.loads(members[2].read_text())["files_sha256"]
        if not {"LICENSE", "NOTICE"}.issubset(declared):
            print("  LEGACY: LICENSE/NOTICE absent; preserve historical bytes, refresh before a new import.")
    actual = {p for p in releases_dir.rglob("*") if p.is_file()}
    if actual != expected:
        raise ValueError("Unexpected files or orphan sidecars in release folders")
    return source_matches


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--releases-dir", type=Path, default=PROJECT_ROOT / "tf-releases")
    parser.add_argument("--changed-since", metavar="GIT_REF",
                        help="Match changed or newly added triplets to the checkout source since this Git commit")
    args = parser.parse_args()
    try:
        source_matches = verify_releases(args.releases_dir, changed_since=args.changed_since)
    except subprocess.CalledProcessError as error:
        parser.exit(1, "Could not compare releases with the Git base: "
                    + os.fsdecode(error.stderr).strip() + "\n")
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        parser.exit(1, str(error) + "\n")
    print("Stored-artifact integrity verified.")
    if args.changed_since is not None:
        print(f"Checkout source verified for {source_matches} changed release triplet(s).")
    print("IBM validation remains separate.")


if __name__ == "__main__":
    main()
