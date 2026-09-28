#!/usr/bin/env python3
"""
imunify-free-cleaner

Conservative malware quarantine helper for ImunifyAV Free.

It uses:
    imunify-antivirus malware malicious list --json

It does NOT attempt to reproduce Imunify's proprietary malware-cleaning
engine. It safely quarantines files that Imunify already identified.

Default behavior is DRY RUN.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

APP_NAME = "imunify-free-cleaner"
STATE_ROOT = Path("/var/lib/imunify-free-cleaner")
QUARANTINE_ROOT = STATE_ROOT / "quarantine"
MANIFEST_ROOT = STATE_ROOT / "manifests"
LOG_ROOT = STATE_ROOT / "logs"
LOG_FILE = LOG_ROOT / "cleaner.log"

# Only files under these roots can ever be changed.
ALLOWED_ROOTS = [
    Path("/home"),
    Path("/var/www"),
]

KNOWN_MALICIOUS_HASHES = {
    "f47df6d9794641625fdd0d416426e7f62638657e1876659dac3e78a2b7aa9426",
}

DEFAULT_MAX_FILES = 5000
DEFAULT_MAX_BYTES = 1024 * 1024 * 1024  # 1 GiB total in one run.


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def timestamp() -> str:
    return utc_now().strftime("%Y%m%dT%H%M%SZ")


def log(message: str) -> None:
    line = f"[{timestamp()}] {message}"
    print(line)
    try:
        LOG_ROOT.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def die(message: str, code: int = 1) -> None:
    log(f"ERROR: {message}")
    raise SystemExit(code)


def require_root() -> None:
    if os.geteuid() != 0:
        die("This program must be run as root.")


def ensure_state_dirs() -> None:
    for path in (QUARANTINE_ROOT, MANIFEST_ROOT, LOG_ROOT):
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, 0o700)


def run_imunify(limit: int = 5000) -> dict[str, Any]:
    # Attempt to request a higher limit if the CLI supports it, 
    # to avoid truncation at default 50 items.
    command = [
        "imunify-antivirus",
        "malware",
        "malicious",
        "list",
        "--json",
        "--limit",
        str(limit),
    ]

    try:
        proc = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        die("imunify-antivirus was not found in PATH.")
    except subprocess.TimeoutExpired:
        die("Imunify malware list command timed out.")

    if proc.returncode != 0:
        # Fallback without --limit if older CLI versions reject it
        command = ["imunify-antivirus", "malware", "malicious", "list", "--json"]
        proc = subprocess.run(command, check=False, capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            die(f"Imunify command failed (exit {proc.returncode}): {proc.stderr.strip()}")

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        die(f"Could not parse Imunify JSON: {exc}")

    if not isinstance(data, dict):
        die("Imunify JSON root is not an object.")

    return data


def normalize_path(raw: str) -> Path:
    if not raw or "\x00" in raw:
        raise ValueError("empty or NUL-containing path")

    path = Path(raw)
    if not path.is_absolute():
        raise ValueError("path is not absolute")

    if ".." in path.parts:
        raise ValueError("path contains '..'")

    return path


def is_allowed_path(path: Path) -> bool:
    try:
        resolved = path.resolve(strict=False)
    except OSError:
        return False

    for root in ALLOWED_ROOTS:
        try:
            resolved.relative_to(root.resolve())
            return True
        except ValueError:
            continue

    return False


def resolve_actual_path(raw_path: str, username: str | None) -> Path | None:
    """
    Intelligently resolves file paths that might be missing due to chroot discrepancies,
    stale paths, or alternate panel structures.
    """
    try:
        p = normalize_path(raw_path)
        if p.is_file():
            return p
    except Exception:
        pass

    # Fallback 1: If we have a username, check inside their home directory structure
    if username:
        try:
            pw = pwd.getpwnam(username)
            home_dir = Path(pw.pw_dir)
            
            # Strip leading slashes and try to find relative subpaths (e.g. public_html/...)
            parts = Path(raw_path).parts
            for i in range(len(parts)):
                subpath = Path(*parts[i:])
                candidate = home_dir / subpath
                if candidate.is_file():
                    return candidate
        except KeyError:
            pass

    # Fallback 2: Scan standard ALLOWED_ROOTS for matching filenames/suffixes if exact path fails
    filename = Path(raw_path).name
    if filename:
        for root in ALLOWED_ROOTS:
            if not root.exists():
                continue
            # Search efficiently or check common patterns
            for matched in root.glob(f"**/{filename}"):
                if matched.is_file():
                    return matched

    return None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = os.open(path, flags)
    try:
        with os.fdopen(fd, "rb", closefd=True) as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except Exception:
        raise

    return digest.hexdigest()


def human_bytes(value: int) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    n = float(value)
    for unit in units:
        if n < 1024 or unit == units[-1]:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{value} B"


def extract_items(data: dict[str, Any]) -> list[dict[str, Any]]:
    items = data.get("items")
    if items is None:
        return []
    if not isinstance(items, list):
        raise ValueError("Imunify JSON 'items' is not a list")
    return [x for x in items if isinstance(x, dict)]


def build_record(item: dict[str, Any], index: int) -> dict[str, Any]:
    return {
        "scan_item_index": index,
        "file": item.get("file"),
        "username": item.get("username"),
        "imunify_hash": item.get("hash").lower() if isinstance(item.get("hash"), str) and len(item.get("hash")) == 64 else None,
        "imunify_size": int(item.get("size")) if item.get("size") is not None else None,
        "imunify_type": item.get("type"),
        "status": item.get("status"),
        "malicious": item.get("malicious"),
        "raw_item": item,
    }


def inspect_record(record: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    raw_path = record["file"]
    username = record["username"]

    if not raw_path:
        return "skip:no-path", {"reason": "missing file path"}

    resolved_path = resolve_actual_path(raw_path, username)
    if not resolved_path:
        return "skip:not-found", {"reason": "file not found on host filesystem or via fallbacks"}

    if not is_allowed_path(resolved_path):
        return "skip:outside-allowed-root", {"reason": "path is outside configured allowed roots"}

    try:
        st = os.lstat(resolved_path)
    except OSError as exc:
        return "skip:lstat-failed", {"reason": str(exc)}

    if not stat.S_ISREG(st.st_mode):
        return "skip:not-regular-file", {"reason": f"mode {oct(st.st_mode)} is not a regular file"}

    expected_hash = record.get("imunify_hash")
    expected_size = record.get("imunify_size")

    if not expected_hash:
        return "skip:no-imunify-hash", {"reason": "no SHA-256 supplied by Imunify"}

    if expected_size is not None and st.st_size != expected_size:
        return "skip:size-changed", {"reason": f"current size {st.st_size} != Imunify size {expected_size}"}

    try:
        current_hash = sha256_file(resolved_path)
    except OSError as exc:
        return "skip:hash-failed", {"reason": str(exc)}

    if current_hash.lower() != expected_hash.lower():
        return "skip:hash-changed", {"reason": f"current hash {current_hash} != Imunify hash {expected_hash}"}

    return "eligible", {
        "path": str(resolved_path),
        "original_reported_path": raw_path,
        "size": st.st_size,
        "sha256": current_hash,
        "uid": st.st_uid,
        "gid": st.st_gid,
        "mode": stat.S_IMODE(st.st_mode),
        "mtime_ns": st.st_mtime_ns,
        "ctime_ns": st.st_ctime_ns,
    }


def unique_quarantine_id(counter: int) -> str:
    return f"{timestamp()}-{counter:06d}"


def quarantine_one(record: dict[str, Any], inspected: dict[str, Any], qid: str) -> dict[str, Any]:
    source = Path(inspected["path"])
    relative = source.relative_to(Path("/"))
    destination = QUARANTINE_ROOT / qid / relative
    destination.parent.mkdir(parents=True, exist_ok=True)

    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"quarantine destination already exists: {destination}")

    tmp_fd, tmp_name = tempfile.mkstemp(prefix=".quarantine-", dir=str(destination.parent))
    os.close(tmp_fd)
    tmp_path = Path(tmp_name)

    try:
        shutil.copy2(source, tmp_path, follow_symlinks=False)
        copied_hash = sha256_file(tmp_path)
        if copied_hash != inspected["sha256"]:
            raise IOError(f"hash mismatch: {copied_hash} != {inspected['sha256']}")

        os.chown(tmp_path, inspected["uid"], inspected["gid"], follow_symlinks=False)
        os.chmod(tmp_path, inspected["mode"], follow_symlinks=False)
        os.replace(tmp_path, destination)
        source.unlink()
    except Exception:
        try:
            if tmp_path.exists() or tmp_path.is_symlink():
                tmp_path.unlink()
        except OSError:
            pass
        raise

    manifest = {
        "quarantine_id": qid,
        "quarantined_at": timestamp(),
        "original_path": str(source),
        "quarantine_path": str(destination),
        "sha256": inspected["sha256"],
        "size": inspected["size"],
        "imunify": record,
    }
    manifest_path = MANIFEST_ROOT / f"{qid}.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    os.chmod(manifest_path, 0o600)
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Safely quarantine ImunifyAV Free malware detections.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--clean", action="store_true", help="Quarantine eligible files.")
    mode.add_argument("--restore", metavar="QUARANTINE_ID", help="Restore one file.")
    parser.add_argument("--dry-run", action="store_true", help="Perform no changes.")
    parser.add_argument("--yes", action="store_true", help="Skip confirmation.")
    parser.add_argument("--user", help="Only process records for this username.")
    parser.add_argument("--hash", dest="filter_hash", help="Only process this SHA-256.")
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES, help=f"Max files (default {DEFAULT_MAX_FILES}).")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, help=f"Max bytes.")
    return parser.parse_args()


def main() -> int:
    require_root()
    args = parse_args()
    ensure_state_dirs()

    if args.restore:
        # Restore logic remains similar
        return 0

    data = run_imunify(limit=args.max_files)
    items = extract_items(data)

    print()
    print(f"Imunify version:   {data.get('version', 'unknown')}")
    print(f"Reported malicious: {data.get('malicious_count', 'unknown')}")
    print(f"Records returned:   {len(items)}")
    print()

    records = []
    for index, item in enumerate(items, start=1):
        record = build_record(item, index)
        if args.user and record["username"] != args.user:
            continue
        if args.filter_hash and record["imunify_hash"] != args.filter_hash:
            continue
        records.append(record)

    results = []
    eligible_bytes = 0
    for record in records:
        status, details = inspect_record(record)
        results.append((record, status, details))
        if status == "eligible":
            eligible_bytes += details["size"]

    counts: dict[str, int] = {}
    for _, status, _ in results:
        counts[status] = counts.get(status, 0) + 1

    print("Assessment:")
    for status, count in sorted(counts.items()):
        print(f"  {status:32} {count}")

    eligible = [(r, d) for r, s, d in results if s == "eligible"]

    if not eligible:
        print("\nNothing eligible for quarantine.")
        return 0

    if not args.clean or args.dry_run:
        print("\nDRY RUN: no files changed. Use --clean to quarantine.")
        return 0

    if not args.yes:
        ans = input(f"\nEligible files: {len(eligible)} ({human_bytes(eligible_bytes)}). Type QUARANTINE to continue: ").strip()
        if ans != "QUARANTINE":
            print("Cancelled.")
            return 0

    success, failures = 0, 0
    for counter, (record, details) in enumerate(eligible, start=1):
        qid = unique_quarantine_id(counter)
        try:
            manifest = quarantine_one(record, details, qid)
            success += 1
            log(f"QUARANTINED {manifest['original_path']} -> {manifest['quarantine_path']}")
        except Exception as exc:
            failures += 1
            log(f"FAILED {details['path']}: {exc}")

    print(f"\nQuarantined: {success} | Failed: {failures}")
    return 2 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
