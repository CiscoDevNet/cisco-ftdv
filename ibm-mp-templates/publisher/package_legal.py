"""Read the repository's canonical legal files without altering their contents."""
from pathlib import Path

LEGAL_FILES = ("LICENSE", "NOTICE")


def load_legal_files(repository_root):
    """Require real, nonempty legal files at the explicitly selected repo root."""
    repository_root = Path(repository_root).resolve()
    payload = {}
    for name in LEGAL_FILES:
        path = repository_root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Canonical repository legal file is missing or a symlink: " + name)
        data = path.read_bytes()
        if not data.strip():
            raise ValueError("Canonical repository legal file is empty: " + name)
        payload[name] = data
    return payload


def legal_manifest(hashes):
    """Use portable paths and hashes; do not expose the build machine's paths."""
    return {
        name: {
            "source_path": name,
            "source_path_base": "repository",
            "sha256": hashes[name],
        }
        for name in LEGAL_FILES
    }
