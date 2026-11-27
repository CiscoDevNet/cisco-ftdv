"""Select a safe basename for a Terraform release archive."""

import re


def release_filename(product, version, local_time, *, filename=None, revision=None, draft=False):
    if revision is not None:
        if filename is not None:
            raise ValueError("--revision and --filename cannot be used together")
        if type(revision) is not int or revision < 1:
            raise ValueError("--revision must be a positive integer")

    if filename is None:
        version_part = version.replace(".", "-") if revision is None else f"{version}-v{revision}"
        draft_prefix = "DRAFT-" if draft else ""
        timestamp = local_time.strftime("%H%M%S-%Y%m%d")
        filename = f"{draft_prefix}{product}-ibm-tf-{version_part}-{timestamp}.tgz"

    if len(filename) > 200 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.tgz", filename):
        raise ValueError("--filename must be a basename ending in .tgz, using letters, digits, dots, underscores or hyphens")
    if draft and not filename.startswith("DRAFT-"):
        raise ValueError("Draft filenames must start DRAFT-")
    return filename
