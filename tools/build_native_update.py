#!/usr/bin/env python3
"""Build a verified Native Update from the checked-out Git source tree."""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "native-manifest.json"
PREFIXES = ("actions/", "assets/", "extensions/", "loader/", "modules/", "runtime/")

def digest(data):
    return hashlib.sha256(data).hexdigest()

def tracked_source():
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    names = [p.decode("utf-8") for p in raw.split(b"\0") if p]
    paths = sorted(p for p in names if p == "CHANGELOG.md" or p.startswith(PREFIXES))
    if not paths or "loader/iptables-manager.php" not in paths or "runtime/iptm-helper" not in paths:
        raise SystemExit("Incomplete native source tree")
    for name in paths:
        path = ROOT / name
        if not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", name) or any(p in (".", "..") for p in name.split("/")) or any(p.is_symlink() for p in [path, *path.parents] if p != ROOT and ROOT in p.parents) or not path.is_file():
            raise SystemExit(f"Unsafe source path: {name}")
    return paths

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=pathlib.Path, default=ROOT / "dist")
    parser.add_argument("--refresh-manifest", action="store_true", help="Recalculate manifest after staging source changes; does not publish")
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    version = manifest.get("version", "")
    if manifest.get("format") != "iptm-native" or manifest.get("schema") != 1 or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise SystemExit("Invalid native manifest")
    loader = (ROOT / "loader/iptables-manager.php").read_text(encoding="utf-8")
    if f"APP_VERSION = '{version}'" not in loader or f"/web/releases/{version}'" not in loader:
        raise SystemExit("Loader version does not match manifest")
    names = tracked_source()
    payload = {name: (ROOT / name).read_bytes() for name in names}
    hashes = {name: digest(data) for name, data in payload.items()}
    if args.refresh_manifest:
        manifest["sha256"] = hashes
        MANIFEST.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    elif manifest.get("sha256") != hashes:
        raise SystemExit("Manifest mismatch: refresh and commit manifest before publishing")
    payload["native-manifest.json"] = MANIFEST.read_bytes()
    args.output.mkdir(parents=True, exist_ok=True)
    archive = args.output / f"IPTM_{version}_UPDATE.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as out:
        for name, data in sorted(payload.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            mode = 0o755 if name == "runtime/iptm-helper" else 0o644
            info.external_attr = (0o100000 | mode) << 16
            out.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    with zipfile.ZipFile(archive) as check:
        if check.testzip() is not None or set(check.namelist()) != set(payload) or any(digest(check.read(name)) != expected for name, expected in hashes.items()):
            raise SystemExit("ZIP verification failed")
    checksum = archive.with_suffix(".zip.sha256")
    checksum.write_text(f"{digest(archive.read_bytes())}  {archive.name}\n", encoding="ascii")
    print(archive)
    print(checksum)

if __name__ == "__main__":
    main()
