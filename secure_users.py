#!/usr/bin/env python3
"""Lab 1 - Secure JSON storage and integrity verification.

Commands:
  python secure_users.py initialize
  python secure_users.py add
  python secure_users.py show
  python secure_users.py verify
  python secure_users.py verify-tampered users_tampered.json

The script encrypts passwords with Fernet and stores a SHA-256 integrity
fingerprint for the canonical plaintext record. A baseline secure users.json
can then be compared with the supplied plaintext tampered dataset.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

DEFAULT_DATA_FILE = Path("users.json")
DEFAULT_KEY_FILE = Path("lab1.key")
DEFAULT_BACKUP_FILE = Path("users_original_backup.json")

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def canonical_record(username: str, password: str, email: str) -> bytes:
    """Return deterministic bytes for integrity hashing."""
    obj = {"email": email, "password": password, "username": username}
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def record_hash(username: str, password: str, email: str) -> str:
    return hashlib.sha256(canonical_record(username, password, email)).hexdigest()


def load_json(path: Path) -> list[dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError as exc:
        raise SystemExit(f"ERROR: File not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"ERROR: Invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, list):
        raise SystemExit(f"ERROR: {path} must contain a JSON array.")
    return data


def save_json(path: Path, data: list[dict[str, Any]]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, path)


def load_or_create_key(path: Path) -> bytes:
    if path.exists():
        key = path.read_bytes().strip()
        # Validate that it is a usable Fernet key.
        Fernet(key)
        return key
    key = Fernet.generate_key()
    path.write_bytes(key + b"\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    print(f"Created encryption key: {path}")
    return key


def validate_input(username: str, password: str, email: str) -> None:
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("Username must be 3-32 characters using letters, numbers, _, -, or .")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if not EMAIL_RE.fullmatch(email):
        raise ValueError("Email address format is invalid.")


def is_secure_record(rec: dict[str, Any]) -> bool:
    return all(k in rec for k in ("username", "password", "email", "integrity_hash"))


def initialize(data_file: Path, key_file: Path, backup_file: Path) -> None:
    records = load_json(data_file)
    if records and all(is_secure_record(r) for r in records):
        print(f"{data_file} already contains encrypted records and integrity hashes.")
        return

    key = load_or_create_key(key_file)
    cipher = Fernet(key)

    if not backup_file.exists():
        shutil.copy2(data_file, backup_file)
        print(f"Created plaintext backup for lab comparison: {backup_file}")

    secured: list[dict[str, Any]] = []
    for i, rec in enumerate(records, start=1):
        try:
            username = str(rec["username"])
            password = str(rec["password"])
            email = str(rec["email"])
            validate_input(username, password, email)
        except (KeyError, ValueError) as exc:
            raise SystemExit(f"ERROR in record {i}: {exc}") from exc
        secured.append({
            "username": username,
            "password": cipher.encrypt(password.encode("utf-8")).decode("utf-8"),
            "email": email,
            "integrity_hash": record_hash(username, password, email),
        })

    save_json(data_file, secured)
    print(f"Secured {len(secured)} records in {data_file}.")
    print("Passwords are encrypted with Fernet; SHA-256 integrity hashes were stored per record.")


def add_user(data_file: Path, key_file: Path) -> None:
    records = load_json(data_file)
    if any(not is_secure_record(r) for r in records):
        raise SystemExit("ERROR: Run 'initialize' first so users.json uses the secure record format.")

    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    email = input("Email: ").strip()
    try:
        validate_input(username, password, email)
    except ValueError as exc:
        raise SystemExit(f"Input rejected: {exc}") from exc

    if any(str(r.get("username", "")).casefold() == username.casefold() for r in records):
        raise SystemExit("Input rejected: username already exists.")

    cipher = Fernet(load_or_create_key(key_file))
    records.append({
        "username": username,
        "password": cipher.encrypt(password.encode("utf-8")).decode("utf-8"),
        "email": email,
        "integrity_hash": record_hash(username, password, email),
    })
    save_json(data_file, records)
    print(f"User '{username}' stored securely in {data_file}.")


def verify_secure(data_file: Path, key_file: Path, verbose: bool = True) -> bool:
    records = load_json(data_file)
    if not key_file.exists():
        print(f"ERROR: Missing encryption key: {key_file}")
        return False
    cipher = Fernet(key_file.read_bytes().strip())
    ok = True

    for i, rec in enumerate(records, start=1):
        username = str(rec.get("username", f"record-{i}"))
        try:
            encrypted_password = str(rec["password"])
            email = str(rec["email"])
            stored_hash = str(rec["integrity_hash"])
            password = cipher.decrypt(encrypted_password.encode("utf-8")).decode("utf-8")
            computed_hash = record_hash(username, password, email)
            valid = hmac.compare_digest(stored_hash, computed_hash)
        except (KeyError, InvalidToken, UnicodeDecodeError):
            valid = False

        if verbose:
            print(f"[{'VALID' if valid else 'TAMPERED'}] {username}")
        ok = ok and valid

    if verbose:
        print("Integrity verification PASSED." if ok else "Integrity verification FAILED.")
    return ok


def verify_tampered(tampered_file: Path, baseline_file: Path, key_file: Path) -> bool:
    baseline = load_json(baseline_file)
    if not key_file.exists():
        raise SystemExit(f"ERROR: Missing encryption key: {key_file}")
    cipher = Fernet(key_file.read_bytes().strip())

    baseline_hashes: dict[str, str] = {}
    for rec in baseline:
        username = str(rec.get("username", ""))
        try:
            # Decrypt to independently validate the secure baseline first.
            password = cipher.decrypt(str(rec["password"]).encode("utf-8")).decode("utf-8")
            email = str(rec["email"])
            stored_hash = str(rec["integrity_hash"])
        except (KeyError, InvalidToken, UnicodeDecodeError) as exc:
            raise SystemExit(f"ERROR: Secure baseline is unreadable for '{username}'.") from exc
        if not hmac.compare_digest(stored_hash, record_hash(username, password, email)):
            raise SystemExit(f"ERROR: Secure baseline is already tampered for '{username}'.")
        baseline_hashes[username] = stored_hash

    tampered = load_json(tampered_file)
    all_valid = True
    print(f"Comparing {tampered_file} against trusted hashes stored in {baseline_file}:")
    for i, rec in enumerate(tampered, start=1):
        try:
            username = str(rec["username"])
            password = str(rec["password"])
            email = str(rec["email"])
        except KeyError:
            print(f"[TAMPERED] record-{i} (missing field)")
            all_valid = False
            continue
        current_hash = record_hash(username, password, email)
        expected_hash = baseline_hashes.get(username)
        valid = expected_hash is not None and hmac.compare_digest(expected_hash, current_hash)
        print(f"[{'VALID' if valid else 'TAMPERED'}] {username}")
        if not valid:
            print(f"  expected: {expected_hash or 'no baseline record'}")
            print(f"  observed: {current_hash}")
        all_valid = all_valid and valid

    if all_valid:
        print("No unauthorized modifications detected.")
    else:
        print("Tampering detected: one or more records do not match the trusted baseline.")
    return all_valid


def show_secure(data_file: Path) -> None:
    records = load_json(data_file)
    print(json.dumps(records, indent=4, ensure_ascii=False))


def main() -> int:
    parser = argparse.ArgumentParser(description="Lab 1 secure JSON storage and tamper detection")
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA_FILE, help="secure users JSON file")
    parser.add_argument("--key", type=Path, default=DEFAULT_KEY_FILE, help="Fernet key file")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("initialize", help="encrypt existing passwords and add integrity hashes")
    p_init.add_argument("--backup", type=Path, default=DEFAULT_BACKUP_FILE)
    sub.add_parser("add", help="prompt for and securely add a new user")
    sub.add_parser("show", help="display secure JSON (ciphertext and hashes)")
    sub.add_parser("verify", help="verify integrity of secure users.json")
    p_t = sub.add_parser("verify-tampered", help="compare supplied plaintext tampered dataset to trusted baseline")
    p_t.add_argument("tampered_file", type=Path)

    args = parser.parse_args()
    if args.command == "initialize":
        initialize(args.data, args.key, args.backup)
        return 0
    if args.command == "add":
        add_user(args.data, args.key)
        return 0
    if args.command == "show":
        show_secure(args.data)
        return 0
    if args.command == "verify":
        return 0 if verify_secure(args.data, args.key) else 1
    if args.command == "verify-tampered":
        return 0 if verify_tampered(args.tampered_file, args.data, args.key) else 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
