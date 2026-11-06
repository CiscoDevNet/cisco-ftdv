#!/usr/bin/env python3
"""Check an extracted release with a mocked IBM provider; never deploys to IBM."""
import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from package_asav import ARCHIVE_ROOT, build


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--terraform", default="terraform", help="Terraform 1.13.4 executable")
    parser.add_argument("--installed-providers", type=Path, help="Optional existing .terraform/providers directory to reuse")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    work = Path(tempfile.mkdtemp(prefix="asav-ibm-tf-check-"))
    env = dict(os.environ, CHECKPOINT_DISABLE="1", TF_IN_AUTOMATION="1")
    print("Local check workspace: " + str(work), flush=True)
    version = subprocess.run([args.terraform, "version", "-json"], check=True, text=True, capture_output=True, env=env)
    if json.loads(version.stdout)["terraform_version"] != "1.13.4":
        parser.exit(1, "Use Terraform 1.13.4 for this pinned package.\n")
    try:
        archive, _, _ = build(repo / "solutions/asav-ibm-tf", work / "package")
    except (ValueError, KeyError, TypeError, OSError, AttributeError) as error:
        parser.exit(1, "Package check failed: " + str(error) + "\n")
    import tarfile
    extracted = work / "extracted"
    module = extracted / ARCHIVE_ROOT
    extracted.mkdir()
    with tarfile.open(archive) as tar:
        for entry in tar.getmembers():
            target = extracted / entry.name
            if entry.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(tar.extractfile(entry).read())
    shutil.copytree(repo / "publisher/tests", module / "tests")
    if args.installed_providers:
        def reuse_file(source, destination):
            try:
                os.link(source, destination)
            except OSError:
                shutil.copy2(source, destination)
        shutil.copytree(args.installed_providers.resolve(), module / ".terraform/providers",
                        symlinks=True, copy_function=reuse_file)
    results = []
    commands = (
        ("fmt", ["fmt", "-check", "-recursive", "-no-color"]),
        ("init", ["init", "-backend=false", "-input=false", "-lockfile=readonly", "-no-color"]),
        ("validate", ["validate", "-json"]),
        ("mock-tests", ["test", "-no-color"]),
    )
    for label, command in commands:
        result = subprocess.run([args.terraform, *command], cwd=module, env=env, text=True, capture_output=True)
        output = result.stdout + result.stderr
        (work / (label + ".log")).write_text(output)
        results.append({"check": label, "exit_code": result.returncode})
        print(label + ": " + ("PASS" if result.returncode == 0 else "FAIL"), flush=True)
        if label == "mock-tests":
            match = re.search(r"(\d+) passed, (\d+) failed", output)
            if match:
                results[-1].update(passed=int(match[1]), failed=int(match[2]))
        if result.returncode:
            print(output)
            (work / "checks.json").write_text(json.dumps(results, indent=2) + "\n")
            return result.returncode
    (work / "checks.json").write_text(json.dumps(results, indent=2) + "\n")
    print("Checks passed. Evidence: " + str(work / "checks.json"))
    print("Mocks test configuration decisions only; real update/destroy and guest behavior still require qualification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
