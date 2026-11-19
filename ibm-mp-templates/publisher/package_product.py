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

from package_legal import LEGAL_FILES, legal_manifest, load_legal_files

def files_for(product):
    if product not in ("ftdv", "fmcv"):
        raise ValueError("product must be ftdv or fmcv")
    return (
    ".terraform.lock.hcl", "README.md", f"{product}-images.json",
    f"bootstrap/{product}-day0.example.json", "changelog.txt", "data.tf",
    f"docs/{product}-existing-vpc.png", "docs/operations-guide.md",
    "locals.tf", "main.tf", "outputs.tf", "provider.tf", "variables.tf", "version.tf",
)
def archive_files_for(product):
    return files_for(product) + LEGAL_FILES


ARCHIVE_ROOT = "root"
SEMVER = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
RELEASE_TIMEZONE = timezone(timedelta(hours=5, minutes=30), name="Asia/Kolkata")
PROJECT_ROOT = Path(__file__).resolve().parents[1]

SECTIONS = (
    "## Before you begin", "## Required resources", "## Installing the software",
    "### Production configuration", "## Upgrading to a new version",
    "## Uninstalling the software",
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify_archive(archive, hashes):
    """Require one root directory, required legal files and matching payload bytes."""
    FILES = tuple(hashes)
    if not set(LEGAL_FILES).issubset(hashes):
        raise ValueError("Archive must include LICENSE and NOTICE")
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


def check_source(source, product, *, draft=False):
    FILES = files_for(product)
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
    catalog = json.loads((source / f"{product}-images.json").read_text())
    releases = catalog["releases"]
    if not releases or catalog["default_version"] not in releases:
        raise ValueError("Image catalog needs releases and a valid default_version")
    locals_text = (source / "locals.tf").read_text()
    catalog_id = re.search(rf'{product}_catalog_id\s*=\s*"([^"]+)"', locals_text).group(1)
    offering_id = re.search(rf'{product}_catalog_offering_id\s*=\s*"([^"]+)"', locals_text).group(1)
    prefix = "crn:v1:bluemix:public:globalcatalog-collection:global::" + catalog_id + ":version:" + offering_id + "/"
    for label, release in releases.items():
        if not label.strip():
            raise ValueError("Empty image label")
        ready = release.get("catalog_reference_verified") is True
        scope = release.get("reference_access_scope", "unverified")
        if scope not in ("unverified", "public", "selected_accounts") or (ready and scope == "unverified"):
            raise ValueError("Invalid or unverified reference access scope: " + label)
        crn = release.get("version_crn")
        locator = release.get("catalog_version_locator")
        if not ready and not draft:
            raise ValueError("Catalog VSI version reference pending; normal release packaging is blocked. Use --draft for local review only.")
        if ready and (not isinstance(crn, str) or not crn.startswith(prefix) or not re.fullmatch(r"[0-9a-f-]{36}-global", crn[len(prefix):]) or locator != catalog_id + "." + crn[len(prefix):]):
            raise ValueError("Invalid image label or unapproved offering CRN: " + label)
        if not re.fullmatch(r"[0-9a-fA-F]{64}", release["catalog_sha256"]):
            raise ValueError("Invalid reference digest: " + label)
        if not ready and (crn is not None or locator is not None):
            raise ValueError("Unverified references must remain null; do not invent version CRNs")
        if type(release.get("minimum_boot_volume_gb")) is not int or release["minimum_boot_volume_gb"] <= 0:
            raise ValueError("Invalid minimum image boot size")
        for field in ("catalog_version",):
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


def build(source, output=None, version=None, *, product, filename=None, build_time=None, draft=False):
    FILES = files_for(product)
    source = source.resolve()
    output = (output if output is not None else PROJECT_ROOT / "tf-releases" / product).resolve()
    if output.is_relative_to(source) or output.is_relative_to((PROJECT_ROOT / "solutions").resolve()):
        raise ValueError("Output directory must be outside every Terraform deployment module")
    try:
        source_reference = source.relative_to(PROJECT_ROOT).as_posix()
        source_path_base = "project"
    except ValueError:
        source_reference = source.name
        source_path_base = "custom_directory_name"
    catalog, links = check_source(source, product, draft=draft)
    payload = {name: (source / name).read_bytes() for name in FILES}
    payload.update(load_legal_files(PROJECT_ROOT.parent))
    changelog = read_latest_changelog(source / "changelog.txt")
    if version is not None and version != changelog["version"]:
        raise ValueError("--version must match the latest changelog version " + changelog["version"])
    version = changelog["version"]
    now = build_time if build_time is not None else datetime.now(RELEASE_TIMEZONE)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("Build time must include a timezone")
    local_time = now.astimezone(RELEASE_TIMEZONE)
    if filename is None:
        filename = ("DRAFT-" if draft else "") + product + "-ibm-tf-" + version.replace(".", "-") + local_time.strftime("-%H%M%S-%Y%m%d.tgz")
    if len(filename) > 200 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.tgz", filename):
        raise ValueError("--filename must be a basename ending in .tgz, using letters, digits, dots, underscores or hyphens")
    if draft and not filename.startswith("DRAFT-"):
        raise ValueError("Draft filenames must start DRAFT-")
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
                for name in sorted(payload):
                    data = payload[name]
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
        "status": "DRAFT_NOT_FOR_IBM_IMPORT" if draft else "local_candidate_not_uploaded_or_IBM_validated",
        "catalog_references_verified": all(x.get("catalog_reference_verified") is True for x in catalog["releases"].values()),
        "reference_access_scopes": sorted({x.get("reference_access_scope", "unverified") for x in catalog["releases"].values()}),
        "software_package_version": version,
        "changelog": changelog,
        "module": product + "-ibm-tf", "source": source_reference,
        "source_path_base": source_path_base,
        "archive_filename": archive.name, "archive_sha256": archive_hash,
        "archive_root": ARCHIVE_ROOT + "/",
        "archive_layout": "single root/ folder containing 14 module files plus LICENSE and NOTICE; README.md beside main.tf",
        "packaging_schema": 2, "module_file_count": len(FILES),
        "archive_file_count": len(payload), "legal_files": legal_manifest(hashes),
        "files_sha256": hashes, "relative_links_verified": links,
        "default_image_label": catalog["default_version"],
        "packaged_image_labels": sorted(catalog["releases"]),
        "checks": ["single root/ directory", str(len(payload)) + "-file allowlist", "canonical repository LICENSE/NOTICE", "changelog version/date", "README sections", "JSON/reference format", "relative links", "archive round trip"],
        "limits": "Does not validate live IAM, image availability, guest readiness, provider updates, licensing or IBM approval.",
    }, indent=2) + "\n")
    return archive, checksums, manifest


def main(product=None):
    parser = argparse.ArgumentParser(description=__doc__)
    if product is None:
        parser.add_argument("product", choices=("ftdv", "fmcv"))
    parser.add_argument("--source", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--filename", help="Custom .tgz basename")
    parser.add_argument("--version", help="Must match the first/newest changelog entry")
    parser.add_argument("--draft", action="store_true", help="Build a labelled review artifact with unresolved Catalog references; not for IBM import")
    args = parser.parse_args()
    product = product or args.product
    try:
        for path in build(args.source or PROJECT_ROOT / "solutions" / (product + "-ibm-tf"), args.output_dir, args.version, product=product, filename=args.filename, draft=args.draft):
            print(path)
    except (ValueError, KeyError, TypeError, OSError, AttributeError) as error:
        parser.exit(1, "Package check failed: " + str(error) + "\n")

if __name__ == "__main__":
    main()
