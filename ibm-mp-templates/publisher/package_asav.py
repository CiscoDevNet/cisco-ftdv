#!/usr/bin/env python3
"""Build a verified, reproducible Software/Terraform archive. No cloud calls."""
import argparse
import gzip
import hashlib
import io
import json
import re
import tarfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import unquote, urlsplit

FILES = (
    ".terraform.lock.hcl", "README.md", "asav-images.json",
    "bootstrap/asav-day0.example.txt", "changelog.txt", "data.tf",
    "docs/asav-existing-vpc.png", "docs/routing-guide.md",
    "locals.tf", "main.tf", "outputs.tf", "provider.tf", "variables.tf", "version.tf",
)
ARCHIVE_ROOT = "root"
SEMVER = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
RELEASE_TIMEZONE = timezone(timedelta(hours=5, minutes=30), name="Asia/Kolkata")
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = PROJECT_ROOT / "tf-releases" / "asav"
SECTIONS = (
    "## Before you begin", "## Required resources", "## Installing the software",
    "### Production configuration", "## Upgrading to a new version",
    "## Uninstalling the software",
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify_archive(archive, hashes):
    """Require one root directory, the exact customer payload and matching bytes."""
    expected = [ARCHIVE_ROOT] + [ARCHIVE_ROOT + "/" + name for name in sorted(FILES)]
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        if ([m.name for m in members] != expected or not members[0].isdir()
                or not all(m.isfile() for m in members[1:])):
            raise ValueError("Archive must contain a single root/ directory and exactly the allowed customer files")
        if any(digest(tar.extractfile(ARCHIVE_ROOT + "/" + name).read()) != hashes[name]
               for name in FILES):
            raise ValueError("Archive/source hash mismatch")


def read_latest_changelog(path):
    """Read newest-first release entries in the publisher's dated text format."""
    lines = [line.strip() for line in path.read_text().splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    starts = [i for i, line in enumerate(lines) if re.match(r"version\b", line, re.I)]
    if not starts:
        raise ValueError("changelog.txt needs a dated 'version MAJOR.MINOR.PATCH' entry")
    months = ("January February March April May June July August September October November December").split()
    month_numbers = {key.lower(): i for i, month in enumerate(months, 1)
                     for key in (month, month[:3])}
    entries = []
    for number, start in enumerate(starts):
        match = re.fullmatch(r"version\s+(" + SEMVER + r")", lines[start], re.I)
        date_match = re.fullmatch(r"([0-9]{4})-([A-Za-z]+)-([0-9]{2})", lines[start - 1]) if start else None
        if not match or not date_match:
            raise ValueError("Each changelog entry needs YYYY-Mon-DD and version MAJOR.MINOR.PATCH")
        year, month, day = date_match.groups()
        if month.lower() not in month_numbers:
            raise ValueError("Invalid English month in changelog.txt")
        date = datetime(int(year), month_numbers[month.lower()], int(day)).date()
        if start + 1 >= len(lines) or not re.fullmatch(r"changes:?", lines[start + 1], re.I):
            raise ValueError("Each changelog version needs a Changes heading")
        end = starts[number + 1] - 1 if number + 1 < len(starts) else len(lines)
        changes = lines[start + 2:end]
        if not changes:
            raise ValueError("Each changelog entry needs at least one change")
        entries.append({"version": match[1], "date": date.isoformat(), "changes": changes})
    versions = [tuple(map(int, entry["version"].split("."))) for entry in entries]
    if any(newer <= older for newer, older in zip(versions, versions[1:])):
        raise ValueError("Put unique changelog versions newest first")
    return entries[0]


def check_source(source):
    for file in source.rglob("*"):
        if file.is_symlink():
            raise ValueError("Symlinks are not allowed: " + str(file))
    actual = {p.relative_to(source).as_posix() for p in source.rglob("*")
              if p.is_file() and p.name != ".DS_Store" and not p.name.startswith("._")}
    if actual != set(FILES):
        raise ValueError("Package file mismatch. Missing: " + str(sorted(set(FILES) - actual))
                         + "; move unexpected files outside the module: " + str(sorted(actual - set(FILES))))
    readme = (source / "README.md").read_text()
    if any(section not in readme.splitlines() for section in SECTIONS):
        raise ValueError("README is missing an IBM installation/lifecycle section")
    catalog = json.loads((source / "asav-images.json").read_text())
    releases = catalog["releases"]
    if not releases or catalog["default_version"] not in releases:
        raise ValueError("Image catalog needs releases and a valid default_version")
    locals_text = (source / "locals.tf").read_text()
    catalog_id = re.search(r'asav_catalog_id\s*=\s*"([^"]+)"', locals_text).group(1)
    offering_id = re.search(r'asav_catalog_offering_id\s*=\s*"([^"]+)"', locals_text).group(1)
    prefix = "crn:v1:bluemix:public:globalcatalog-collection:global::" + catalog_id + ":version:" + offering_id + "/"
    for label, release in releases.items():
        if not label.strip() or not release["version_crn"].startswith(prefix):
            raise ValueError("Invalid image label or unapproved offering CRN: " + label)
        if not re.fullmatch(r"[0-9a-fA-F]{64}", release["catalog_sha256"]):
            raise ValueError("Invalid reference digest: " + label)
        for field in ("catalog_version", "catalog_version_locator"):
            if not isinstance(release[field], str) or not release[field].strip():
                raise ValueError("Missing " + field + ": " + label)
        if release["plan_crn"] is not None and not isinstance(release["plan_crn"], str):
            raise ValueError("plan_crn must be a string or null: " + label)
        for field in ("supported_regions", "supported_profiles", "secure_boot_modes"):
            values = release[field]
            if not isinstance(values, list) or not values or len(values) != len(set(values)):
                raise ValueError("Invalid/duplicate values for " + field + ": " + label)
            if field == "secure_boot_modes":
                if any(type(value) is not bool for value in values):
                    raise ValueError("Secure Boot modes must be JSON booleans: " + label)
            elif any(not isinstance(value, str) or not value.strip() for value in values):
                raise ValueError("Region/profile values must be nonempty strings: " + label)
    links = []
    for name in FILES:
        if not name.endswith(".md"):
            continue
        for target in re.findall(r'!?\[[^\]]*\]\(([^)]+)\)', (source / name).read_text()):
            target = target.strip().split(" ", 1)[0].strip("<>")
            url = urlsplit(target)
            if url.scheme or url.netloc or not url.path:
                continue
            resolved = ((source / name).parent / unquote(url.path)).resolve()
            if not resolved.is_relative_to(source) or not resolved.is_file():
                raise ValueError("Broken or external-to-package local link: " + name + " -> " + target)
            links.append({"from": name, "target": target})
    return catalog, links


def build(source, output=None, version=None, *, filename=None, build_time=None):
    source = source.resolve()
    output = (output if output is not None else DEFAULT_OUTPUT).resolve()
    if output == source or output.is_relative_to(source):
        raise ValueError("Output directory must be outside the Terraform module")
    try:
        source_reference = source.relative_to(PROJECT_ROOT).as_posix()
        source_path_base = "project"
    except ValueError:
        source_reference = source.name
        source_path_base = "custom_directory_name"
    catalog, links = check_source(source)
    changelog = read_latest_changelog(source / "changelog.txt")
    if version is not None and version != changelog["version"]:
        raise ValueError("--version must match the latest changelog version " + changelog["version"])
    version = changelog["version"]
    now = build_time if build_time is not None else datetime.now(RELEASE_TIMEZONE)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("Build time must include a timezone")
    local_time = now.astimezone(RELEASE_TIMEZONE)
    if filename is None:
        filename = "asav-ibm-tf-" + version.replace(".", "-") + local_time.strftime("-%H%M%S-%Y%m%d.tgz")
    if len(filename) > 200 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.tgz", filename):
        raise ValueError("--filename must be a basename ending in .tgz, using letters, digits, dots, underscores or hyphens")
    stem = filename[:-4]
    output.mkdir(parents=True, exist_ok=True)
    archive, manifest = output / filename, output / (stem + ".verification.json")
    checksums = output / (stem + ".sha256")
    if any(p.exists() for p in (archive, manifest, checksums)):
        raise ValueError("Refusing to overwrite existing release artifacts")
    hashes = {}
    with archive.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as tar:
                root_entry = tarfile.TarInfo(ARCHIVE_ROOT)
                root_entry.type, root_entry.mode, root_entry.mtime = tarfile.DIRTYPE, 0o755, 0
                root_entry.uid = root_entry.gid = 0
                root_entry.uname = root_entry.gname = ""
                tar.addfile(root_entry)
                for name in sorted(FILES):
                    data = (source / name).read_bytes()
                    hashes[name] = digest(data)
                    entry = tarfile.TarInfo(ARCHIVE_ROOT + "/" + name)
                    entry.size, entry.mode, entry.mtime = len(data), 0o644, 0
                    entry.uid = entry.gid = 0
                    entry.uname = entry.gname = ""
                    tar.addfile(entry, io.BytesIO(data))
    verify_archive(archive, hashes)
    archive_hash = digest(archive.read_bytes())
    checksums.write_text(archive_hash + "  " + archive.name + "\n")
    manifest.write_text(json.dumps({
        "created_at_utc": now.astimezone(timezone.utc).isoformat(),
        "build_time_local": local_time.isoformat(), "filename_timezone": "Asia/Kolkata",
        "status": "local_candidate_not_uploaded_or_IBM_validated",
        "software_package_version": version,
        "changelog": changelog,
        "module": "asav-ibm-tf", "source": source_reference,
        "source_path_base": source_path_base,
        "archive_filename": archive.name, "archive_sha256": archive_hash,
        "archive_root": ARCHIVE_ROOT + "/",
        "archive_layout": "single root/ folder containing all 14 customer files; README.md beside main.tf",
        "files_sha256": hashes, "relative_links_verified": links,
        "default_asav_image_label": catalog["default_version"],
        "packaged_image_labels": sorted(catalog["releases"]),
        "checks": ["single root/ directory", str(len(FILES)) + "-file allowlist", "changelog version/date", "README sections", "JSON/reference format", "relative links", "archive round trip"],
        "limits": "Does not validate live IAM, image availability, guest readiness, provider updates, licensing or IBM approval.",
    }, indent=2) + "\n")
    return archive, checksums, manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1] / "solutions/asav-ibm-tf")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT,
                        help="Archive directory; default: tf-releases/asav in the IBM project")
    parser.add_argument("--filename", help="Custom .tgz basename; version still comes from changelog.txt")
    parser.add_argument("--version", help="Optional consistency check; must equal the latest changelog version")
    args = parser.parse_args()
    try:
        for path in build(args.source, args.output_dir, args.version, filename=args.filename):
            print(path)
    except (ValueError, KeyError, TypeError, OSError, AttributeError) as error:
        parser.exit(1, "Package check failed: " + str(error) + "\n")


if __name__ == "__main__":
    main()
