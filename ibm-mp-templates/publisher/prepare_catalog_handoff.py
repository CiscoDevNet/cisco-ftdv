#!/usr/bin/env python3
"""Prepare a Catalog archive URL and README from a retained integration commit."""

import argparse
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import subprocess
import tarfile
import tempfile
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from verify_releases import PROJECT_ROOT, verify_triplet


INTEGRATION_REF = "refs/remotes/origin/cisco-secure-firewall-ibm-marketplace"
GITHUB_REPO = "CiscoDevNet/cisco-ftdv"
RELEASES_PATH = PurePosixPath("ibm-mp-templates/tf-releases")
PRODUCTS = ("asav", "ftdv", "fmcv")
MARKDOWN_LINK = re.compile(
    r"(?P<code>(?P<ticks>`+)[^`\n]*(?P=ticks)(?!`))|"
    r"(?P<head>(?<!\\)(?P<image>!)?\[(?:\[[^\[\]\n]*\]|[^\[\]\n])*\]\([ \t]*)"
    r"(?P<target><[^>\n]+>|[^\s)]+)"
    r"(?P<tail>[ \t]*(?:(?:\"[^\"\n]*\"|'[^'\n]*'|\([^()\n]*\))[ \t]*)?\))"
)
CODE_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")


def git(repo, *args):
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1")
    result = subprocess.run(["git", *args], cwd=repo, env=env, capture_output=True, check=False)
    return result


def tracked_file(repo, commit, path):
    result = git(repo, "show", f"{commit}:{path.as_posix()}")
    if result.returncode != 0:
        raise ValueError(f"Selected commit does not contain {path}")
    return result.stdout


def rewrite_markdown(readme, linked_url):
    """Rewrite inline Markdown file links while preserving code and other links."""
    def replace(match):
        if match["code"]:
            return match[0]
        target = match["target"]
        parsed = urlsplit(target.strip("<>"))
        if parsed.scheme or parsed.netloc or not parsed.path or parsed.path.startswith("/"):
            return match[0]

        path = PurePosixPath(posixpath.normpath(unquote(parsed.path)))
        url = urlsplit(linked_url(path, bool(match["image"])))
        rewritten = urlunsplit(url._replace(query=parsed.query, fragment=parsed.fragment))
        if target.startswith("<"):
            rewritten = "<" + rewritten + ">"
        return match["head"] + rewritten + match["tail"]

    fence = ""
    lines = []
    for line in readme.splitlines(keepends=True):
        marker = CODE_FENCE.match(line)
        if fence:
            if marker and marker[1].startswith(fence) and not marker[2].strip():
                fence = ""
        elif marker:
            fence = marker[1]
        elif not line.startswith(("    ", "\t")):
            line = MARKDOWN_LINK.sub(replace, line)
        lines.append(line)
    return "".join(lines)


def prepare_handoff(repo, archive_path, commit):
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("Provide a full 40-character integration commit SHA")
    path = PurePosixPath(archive_path)
    if (path.as_posix() != archive_path or len(path.parts) != 4 or path.parent.parent != RELEASES_PATH
            or path.parent.name not in PRODUCTS or path.suffix != ".tgz"):
        raise ValueError("Choose an archive path under ibm-mp-templates/tf-releases/PRODUCT/")
    if git(repo, "cat-file", "-t", commit).stdout != b"commit\n":
        raise ValueError("The selected commit is missing locally")
    if git(repo, "merge-base", "--is-ancestor", commit, INTEGRATION_REF).returncode != 0:
        raise ValueError("The selected commit must be reachable from origin/cisco-secure-firewall-ibm-marketplace locally")

    archive = repo / path
    tracked = {}
    for file in (path, path.with_suffix(".sha256"), path.with_suffix(".verification.json")):
        local = repo / file
        if local.resolve() != local or not local.is_file():
            raise ValueError(f"Expected a retained regular file at {file}")
        tracked[file] = tracked_file(repo, commit, file)
        if local.read_bytes() != tracked[file]:
            raise ValueError(f"Local file differs from the selected commit: {file}")
    digest = verify_triplet(archive)
    archive_bytes = tracked[path]
    if hashlib.sha256(archive_bytes).hexdigest() != digest:
        raise ValueError("Verified digest differs from the selected commit's archive")

    source = PurePosixPath("ibm-mp-templates/solutions") / f"{path.parent.name}-ibm-tf"
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as payload:
        readme = payload.extractfile("root/README.md").read().decode("utf-8")
        bundled = {member.name for member in payload.getmembers() if member.isfile()}

        def linked_url(target, is_image):
            name = "root/" + target.as_posix()
            if name not in bundled:
                raise ValueError(f"README link does not name a bundled file: {target}")
            file = target if target.as_posix() in {"LICENSE", "NOTICE"} else source / target
            if payload.extractfile(name).read() != tracked_file(repo, commit, file):
                raise ValueError(f"Bundled README link differs from its file at the selected commit: {file}")
            if is_image:
                return f"https://raw.githubusercontent.com/{GITHUB_REPO}/{commit}/{quote(file.as_posix())}"
            return f"https://github.com/{GITHUB_REPO}/blob/{commit}/{quote(file.as_posix())}"

        readme = rewrite_markdown(readme, linked_url)

    archive_url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{commit}/{quote(path.as_posix())}"
    return archive_url, digest, readme


def write_readme(repo, path, readme):
    output = path.resolve()
    temp_roots = {Path(tempfile.gettempdir()).resolve(), Path("/tmp").resolve()}
    if output.is_relative_to(repo) or not any(root in output.parents for root in temp_roots):
        raise ValueError("Write the Catalog README to a new temporary file outside the repository")
    with output.open("x", encoding="utf-8") as file:
        file.write(readme)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", help="Retained TGZ path relative to the repository root")
    parser.add_argument("--commit", required=True, help="Full SHA of the integration commit containing the triplet")
    parser.add_argument("--output", type=Path, help="Write the Catalog-ready Markdown to a new file in a temporary directory")
    args = parser.parse_args()
    try:
        repo = PROJECT_ROOT.parent
        url, digest, readme = prepare_handoff(repo, args.archive, args.commit)
        output = write_readme(repo, args.output, readme) if args.output else None
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        parser.exit(1, f"Catalog handoff check failed: {error}\n")
    print(f"Archive URL: {url}\nSHA-256: {digest}")
    if output:
        print(f"Catalog README: {output}")
    else:
        print("\nCatalog README:\n")
        print(readme, end="" if readme.endswith("\n") else "\n")


if __name__ == "__main__":
    main()
