from __future__ import annotations

import html
import csv
import hashlib
import hmac
import io
import json
import os
import shutil
import sqlite3
import ssl
import subprocess
import sys
import platform
import secrets
import textwrap
import time
import urllib.parse
import zipfile
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


APP_HOST = "127.0.0.1"
APP_PORT = 8080
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "campus_pki_ra.sqlite3"
CA_DIR = DATA_DIR / "local_ca"
REMOTE_CA_DIR = DATA_DIR / "remote_ca_public"
CERT_DIR = DATA_DIR / "certificates"
CSR_DIR = DATA_DIR / "csr"
KEY_DIR = DATA_DIR / "private_keys"
DEPLOY_DIR = DATA_DIR / "deployment_bundles"
CRL_DIR = DATA_DIR / "certificate_revocation_lists"
TOOLS_DIR = BASE_DIR / "tools"
BUNDLED_OPENSSL_DIR = TOOLS_DIR / "openssl"
OPENSSL_CONF_PATH = DATA_DIR / "openssl.cnf"
CURRENT_ACTOR = "System"
REMOTE_BASE_CACHE: dict[tuple[str, str, str], str] = {}

MENU_ITEMS = [
    {"path": "/", "label": "Dashboard", "superadmin_only": False},
    {"path": "/register-user", "label": "Register User", "superadmin_only": False},
    {"path": "/register-device", "label": "Register Device", "superadmin_only": False},
    {"path": "/create-certificate", "label": "Create Certificate", "superadmin_only": False},
    {"path": "/deploy-certificate", "label": "Deploy Certificate", "superadmin_only": False},
    {"path": "/renew-certificate", "label": "Renew Certificate", "superadmin_only": False},
    {"path": "/revoke-certificate", "label": "Revoke Certificate", "superadmin_only": False},
    {"path": "/infrastructure-devices", "label": "Infrastructure Devices", "superadmin_only": False},
    {"path": "/user-logs", "label": "User Logs", "superadmin_only": False},
    {"path": "/action-logs", "label": "Action Logs", "superadmin_only": False},
    {"path": "/settings", "label": "Settings", "superadmin_only": True},
    {"path": "/admin-accounts", "label": "Admin Accounts", "superadmin_only": True},
]


def ensure_dirs() -> None:
    for path in (DATA_DIR, CA_DIR, REMOTE_CA_DIR, CERT_DIR, CSR_DIR, KEY_DIR, DEPLOY_DIR, CRL_DIR):
        path.mkdir(parents=True, exist_ok=True)
    ensure_openssl_config()


def ensure_openssl_config() -> None:
    if OPENSSL_CONF_PATH.exists():
        return
    OPENSSL_CONF_PATH.write_text(
        """[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
C = NG
O = Campus PKI
CN = Campus PKI
""",
        encoding="utf-8",
    )


def connect_db() -> sqlite3.Connection:
    ensure_dirs()
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db() -> None:
    with connect_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                openssl_mode TEXT NOT NULL DEFAULT 'local',
                openssl_server_ip TEXT,
                openssl_username TEXT,
                openssl_password TEXT,
                openssl_path TEXT NOT NULL DEFAULT 'openssl',
                remote_base_path TEXT NOT NULL DEFAULT '~/campus_pki_ra',
                remote_ssh_key_path TEXT,
                ldap_server_ip TEXT,
                ldap_bind_dn TEXT,
                ldap_password TEXT,
                ldap_base_dn TEXT,
                organization TEXT NOT NULL DEFAULT 'Nigerian Higher Education Institution',
                ca_common_name TEXT NOT NULL DEFAULT 'Campus Wi-Fi Local CA',
                default_valid_days INTEGER NOT NULL DEFAULT 365,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            INSERT OR IGNORE INTO settings (id) VALUES (1);

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_type TEXT NOT NULL CHECK (user_type IN ('Staff', 'Student')),
                first_name TEXT NOT NULL,
                middle_name TEXT,
                surname TEXT NOT NULL,
                email TEXT,
                department TEXT,
                faculty TEXT,
                identifier TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_type TEXT NOT NULL CHECK (device_type IN ('User', 'Access', 'Server')),
                mac_address TEXT NOT NULL UNIQUE,
                user_id INTEGER REFERENCES users(id),
                function TEXT,
                location_faculty TEXT,
                location_department TEXT,
                device_identifier TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject_type TEXT NOT NULL,
                subject_id INTEGER,
                common_name TEXT NOT NULL,
                serial_number TEXT NOT NULL UNIQUE,
                cert_path TEXT,
                key_path TEXT,
                csr_path TEXT,
                p12_path TEXT,
                status TEXT NOT NULL DEFAULT 'Issued',
                valid_from TEXT,
                valid_to TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                renewed_from INTEGER REFERENCES certificates(id),
                deployed_at TEXT,
                revoked_at TEXT,
                revoke_reason TEXT
            );

            CREATE TABLE IF NOT EXISTS institution_departments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                faculty TEXT NOT NULL,
                department TEXT NOT NULL,
                UNIQUE (faculty, department)
            );

            CREATE TABLE IF NOT EXISTS admin_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                full_name TEXT,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'Operator',
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_login_at TEXT
            );

            CREATE TABLE IF NOT EXISTS admin_roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                role_name TEXT NOT NULL UNIQUE,
                permissions TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS admin_sessions (
                token TEXT PRIMARY KEY,
                account_id INTEGER NOT NULL REFERENCES admin_accounts(id),
                expires_at INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_username TEXT,
                action TEXT NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS user_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_username TEXT,
                action TEXT NOT NULL,
                user_id INTEGER,
                user_identifier TEXT,
                details TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        columns = [row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()]
        if "email" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
        if "middle_name" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN middle_name TEXT")
        if "department" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN department TEXT")
        if "faculty" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN faculty TEXT")
        setting_columns = [row["name"] for row in conn.execute("PRAGMA table_info(settings)").fetchall()]
        if "remote_base_path" not in setting_columns:
            conn.execute("ALTER TABLE settings ADD COLUMN remote_base_path TEXT NOT NULL DEFAULT '~/campus_pki_ra'")
        if "remote_ssh_key_path" not in setting_columns:
            conn.execute("ALTER TABLE settings ADD COLUMN remote_ssh_key_path TEXT")
        cert_columns = [row["name"] for row in conn.execute("PRAGMA table_info(certificates)").fetchall()]
        if "deployed_at" not in cert_columns:
            conn.execute("ALTER TABLE certificates ADD COLUMN deployed_at TEXT")
        device_columns = [row["name"] for row in conn.execute("PRAGMA table_info(devices)").fetchall()]
        if "location_faculty" not in device_columns:
            conn.execute("ALTER TABLE devices ADD COLUMN location_faculty TEXT")
        if "location_department" not in device_columns:
            conn.execute("ALTER TABLE devices ADD COLUMN location_department TEXT")
        if "device_identifier" not in device_columns:
            conn.execute("ALTER TABLE devices ADD COLUMN device_identifier TEXT")
        audit_columns = [row["name"] for row in conn.execute("PRAGMA table_info(audit_log)").fetchall()]
        if "actor_username" not in audit_columns:
            conn.execute("ALTER TABLE audit_log ADD COLUMN actor_username TEXT")
        user_log_columns = [row["name"] for row in conn.execute("PRAGMA table_info(user_logs)").fetchall()]
        if "actor_username" not in user_log_columns:
            conn.execute("ALTER TABLE user_logs ADD COLUMN actor_username TEXT")
        account_schema = conn.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'admin_accounts'").fetchone()
        if account_schema and "CHECK (role IN" in (account_schema["sql"] or ""):
            conn.executescript(
                """
                PRAGMA foreign_keys = OFF;
                ALTER TABLE admin_accounts RENAME TO admin_accounts_old;
                CREATE TABLE admin_accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    full_name TEXT,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'Operator',
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_login_at TEXT
                );
                INSERT INTO admin_accounts (id, username, full_name, password_hash, role, is_active, created_at, last_login_at)
                SELECT id, username, full_name, password_hash, role, is_active, created_at, last_login_at FROM admin_accounts_old;
                DROP TABLE admin_accounts_old;
                PRAGMA foreign_keys = ON;
                """
            )
        device_schema = conn.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'devices'").fetchone()
        if device_schema and "Access" not in (device_schema["sql"] or ""):
            conn.executescript(
                """
                PRAGMA foreign_keys = OFF;
                ALTER TABLE devices RENAME TO devices_old;
                CREATE TABLE devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_type TEXT NOT NULL CHECK (device_type IN ('User', 'Access', 'Server')),
                    mac_address TEXT NOT NULL UNIQUE,
                    user_id INTEGER REFERENCES users(id),
                    function TEXT,
                    location_faculty TEXT,
                    location_department TEXT,
                    device_identifier TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                INSERT INTO devices (id, device_type, mac_address, user_id, function, location_faculty, location_department, device_identifier, created_at)
                SELECT id, device_type, mac_address, user_id, function, location_faculty, location_department, device_identifier, created_at FROM devices_old;
                DROP TABLE devices_old;
                PRAGMA foreign_keys = ON;
                """
            )
        existing_departments = conn.execute("SELECT COUNT(*) FROM institution_departments").fetchone()[0]
        if existing_departments == 0:
            conn.execute(
                "INSERT OR IGNORE INTO institution_departments (faculty, department) VALUES (?, ?)",
                ("General", "General Department"),
            )
        default_permissions = json.dumps([item["path"] for item in MENU_ITEMS if item["path"] not in {"/settings", "/admin-accounts", "/action-logs"}])
        conn.execute(
            "INSERT OR IGNORE INTO admin_roles (role_name, permissions) VALUES (?, ?)",
            ("Operator", default_permissions),
        )


def get_settings() -> sqlite3.Row:
    with connect_db() as conn:
        return conn.execute("SELECT * FROM settings WHERE id = 1").fetchone()


def get_faculty_departments() -> dict[str, list[str]]:
    with connect_db() as conn:
        rows = conn.execute("SELECT faculty, department FROM institution_departments ORDER BY faculty, department").fetchall()
    result: dict[str, list[str]] = {}
    for row in rows:
        result.setdefault(row["faculty"], []).append(row["department"])
    return result


def parse_faculty_departments(text: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        faculty, departments = line.split(":", 1)
        faculty = faculty.strip()
        values = [department.strip() for department in departments.split(",") if department.strip()]
        if faculty and values:
            result[faculty] = values
    return result


def save_faculty_departments(text: str) -> None:
    parsed = parse_faculty_departments(text)
    with connect_db() as conn:
        conn.execute("DELETE FROM institution_departments")
        for faculty, departments in parsed.items():
            for department in departments:
                conn.execute(
                    "INSERT OR IGNORE INTO institution_departments (faculty, department) VALUES (?, ?)",
                    (faculty, department),
                )


def faculty_departments_text() -> str:
    data = get_faculty_departments()
    return "\n".join(f"{faculty}: {', '.join(departments)}" for faculty, departments in data.items())


def faculty_options(selected: str | None = None) -> str:
    data = get_faculty_departments()
    options = ['<option value="">Select faculty</option>']
    for faculty in data:
        options.append(f'<option value="{esc(faculty)}" {"selected" if faculty == selected else ""}>{esc(faculty)}</option>')
    return "".join(options)


def department_options(selected: str | None = None, faculty: str | None = None) -> str:
    data = get_faculty_departments()
    departments = data.get(faculty or "", [])
    if not departments:
        departments = sorted({department for values in data.values() for department in values})
    options = ['<option value="">Select department</option>']
    for department in departments:
        options.append(f'<option value="{esc(department)}" {"selected" if department == selected else ""}>{esc(department)}</option>')
    return "".join(options)


def safe_folder(value: str | None) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in (value or "Unassigned").strip())
    return cleaned or "Unassigned"


def bundled_openssl_candidates() -> list[Path]:
    system = platform.system().lower()
    exact_candidates: list[Path]
    if system == "windows":
        exact_candidates = [
            BUNDLED_OPENSSL_DIR / "windows" / "bin" / "openssl.exe",
            BUNDLED_OPENSSL_DIR / "bin" / "openssl.exe",
            BUNDLED_OPENSSL_DIR / "openssl.exe",
        ]
    elif system == "darwin":
        exact_candidates = [
            BUNDLED_OPENSSL_DIR / "macos" / "bin" / "openssl",
            BUNDLED_OPENSSL_DIR / "bin" / "openssl",
            BUNDLED_OPENSSL_DIR / "openssl",
        ]
    else:
        exact_candidates = [
            BUNDLED_OPENSSL_DIR / "linux" / "bin" / "openssl",
            BUNDLED_OPENSSL_DIR / "bin" / "openssl",
            BUNDLED_OPENSSL_DIR / "openssl",
        ]

    discovered: list[Path] = []
    if BUNDLED_OPENSSL_DIR.exists():
        names = ["openssl.exe"] if system == "windows" else ["openssl"]
        for name in names:
            discovered.extend(BUNDLED_OPENSSL_DIR.rglob(name))
    return exact_candidates + [path for path in discovered if path not in exact_candidates]


def resolve_openssl_path(configured_path: str | None = None) -> str:
    for candidate in bundled_openssl_candidates():
        if candidate.exists():
            return str(candidate)
    return configured_path or "openssl"


def bundled_openssl_hint() -> str:
    candidates = bundled_openssl_candidates()
    found = next((candidate for candidate in candidates if candidate.exists()), None)
    if found:
        return f"Bundled OpenSSL detected at {found}"
    return f"No bundled OpenSSL detected. Place it at {candidates[0]}"


def current_actor() -> str:
    return CURRENT_ACTOR or "System"


def audit(action: str, details: str = "", actor_username: str | None = None) -> None:
    with connect_db() as conn:
        conn.execute(
            "INSERT INTO audit_log (actor_username, action, details) VALUES (?, ?, ?)",
            (actor_username or current_actor(), action, details),
        )


def log_user_operation(action: str, user_id: int | None, user_identifier: str, details: str, actor_username: str | None = None) -> None:
    with connect_db() as conn:
        conn.execute(
            "INSERT INTO user_logs (actor_username, action, user_id, user_identifier, details) VALUES (?, ?, ?, ?, ?)",
            (actor_username or current_actor(), action, user_id, user_identifier, details),
        )


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("ascii"), 200_000)
    return f"pbkdf2_sha256$200000${salt}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, rounds, salt, digest = stored_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("ascii"), int(rounds)).hex()
        return hmac.compare_digest(candidate, digest)
    except Exception:
        return False


def admin_account_count() -> int:
    with connect_db() as conn:
        return conn.execute("SELECT COUNT(*) FROM admin_accounts").fetchone()[0]


def all_menu_paths(include_superadmin: bool = True) -> list[str]:
    return [item["path"] for item in MENU_ITEMS if include_superadmin or not item["superadmin_only"]]


def role_permissions(role_name: str) -> set[str]:
    if role_name == "Superadmin":
        return set(all_menu_paths(True))
    with connect_db() as conn:
        row = conn.execute("SELECT permissions FROM admin_roles WHERE role_name = ?", (role_name,)).fetchone()
    if not row:
        return set()
    try:
        values = json.loads(row["permissions"])
        return {str(value) for value in values}
    except json.JSONDecodeError:
        return set()


def can_access(account: sqlite3.Row | None, path: str) -> bool:
    if not account:
        return False
    if account["role"] == "Superadmin":
        return True
    return path in role_permissions(account["role"])


def menu_label(path: str) -> str:
    for item in MENU_ITEMS:
        if item["path"] == path:
            return item["label"]
    return path


def parse_cookies(cookie_header: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in cookie_header.split(";"):
        if "=" in part:
            key, value = part.strip().split("=", 1)
            cookies[key] = urllib.parse.unquote(value)
    return cookies


def current_admin(cookie_header: str) -> sqlite3.Row | None:
    token = parse_cookies(cookie_header).get("ra_session")
    if not token:
        return None
    now = int(time.time())
    with connect_db() as conn:
        conn.execute("DELETE FROM admin_sessions WHERE expires_at < ?", (now,))
        return conn.execute(
            """
            SELECT admin_accounts.*
            FROM admin_sessions JOIN admin_accounts ON admin_accounts.id = admin_sessions.account_id
            WHERE admin_sessions.token = ?
              AND admin_sessions.expires_at >= ?
              AND admin_accounts.is_active = 1
            """,
            (token, now),
        ).fetchone()


def create_session(account_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + 8 * 60 * 60
    with connect_db() as conn:
        conn.execute("DELETE FROM admin_sessions WHERE expires_at < ?", (int(time.time()),))
        conn.execute("INSERT INTO admin_sessions (token, account_id, expires_at) VALUES (?, ?, ?)", (token, account_id, expires_at))
        conn.execute("UPDATE admin_accounts SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?", (account_id,))
    return token


def clear_session(cookie_header: str) -> None:
    token = parse_cookies(cookie_header).get("ra_session")
    if token:
        with connect_db() as conn:
            conn.execute("DELETE FROM admin_sessions WHERE token = ?", (token,))


def now_slug() -> str:
    return time.strftime("%Y%m%d%H%M%S")


def normalize_mac(value: str) -> str:
    cleaned = value.strip().replace("-", ":").upper()
    parts = cleaned.split(":")
    if len(parts) == 6 and all(len(part) == 2 for part in parts):
        return ":".join(parts)
    compact = cleaned.replace(":", "")
    if len(compact) == 12:
        return ":".join(compact[i : i + 2] for i in range(0, 12, 2))
    return cleaned


def import_users_csv(content: bytes) -> tuple[int, int, list[str]]:
    text = content.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    created = 0
    skipped = 0
    errors: list[str] = []
    if not reader.fieldnames:
        return 0, 0, ["CSV file has no header row."]

    with connect_db() as conn:
        valid_faculties: dict[str, tuple[str, set[str]]] = {}
        for row in conn.execute("SELECT faculty, department FROM institution_departments").fetchall():
            faculty_key = row["faculty"].strip().casefold()
            department_value = row["department"].strip()
            if faculty_key not in valid_faculties:
                valid_faculties[faculty_key] = (row["faculty"], set())
            valid_faculties[faculty_key][1].add(department_value.casefold())
        for row_number, row in enumerate(reader, start=2):
            normalized = {str(key).strip().lower(): (value or "").strip() for key, value in row.items() if key}
            user_type = normalized.get("user_type", "").title()
            first_name = normalized.get("first_name", "")
            middle_name = normalized.get("middle_name", "")
            surname = normalized.get("surname", "")
            email = normalized.get("email", "")
            department = normalized.get("department", "")
            faculty = normalized.get("faculty", "")
            identifier = (
                normalized.get("identifier")
                or normalized.get("staff_number")
                or normalized.get("matriculation_number")
                or normalized.get("matric_number")
                or ""
            )
            if user_type not in {"Staff", "Student"} or not first_name or not surname or not email or not identifier:
                skipped += 1
                errors.append(f"Row {row_number} skipped: missing or invalid required data.")
                continue
            faculty_key = faculty.casefold()
            department_key = department.casefold()
            if faculty_key not in valid_faculties:
                skipped += 1
                errors.append(
                    f"Row {row_number} skipped: faculty '{faculty}' is not configured. Add it under Settings first."
                )
                continue
            canonical_faculty, valid_departments = valid_faculties[faculty_key]
            if department_key not in valid_departments:
                skipped += 1
                errors.append(
                    f"Row {row_number} skipped: department '{department}' is not configured under faculty '{canonical_faculty}'. Add it under Settings first."
                )
                continue
            try:
                conn.execute(
                    """
                    INSERT INTO users (user_type, first_name, middle_name, surname, email, department, faculty, identifier)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (user_type, first_name, middle_name, surname, email, department, faculty, identifier),
                )
                created += 1
            except sqlite3.IntegrityError:
                skipped += 1
    if created:
        audit("Bulk Register Users", f"{created} user(s) imported from CSV")
    return created, skipped, errors


def user_common_name(user: sqlite3.Row) -> str:
    return user["email"] or f"{user['identifier']}@campus.local"


def device_common_name(device: sqlite3.Row) -> str:
    if device["device_type"] == "User":
        user = None
        user_id = row_get(device, "user_id")
        if user_id:
            with connect_db() as conn:
                user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if user:
            base = user["email"] or f"{user['identifier']}@campus.local"
            return f"{base}-{user['identifier']}-{device['mac_address'].replace(':', '')}"
    if device["device_type"] in {"Access", "Server"} and device["function"]:
        safe_function = "".join(ch if ch.isalnum() else "-" for ch in device["function"].lower()).strip("-")
        return f"{safe_function}-{device['mac_address'].replace(':', '')}.campus.local"
    return f"device-{device['mac_address'].replace(':', '')}.campus.local"


def display_name(first_name: str | None, middle_name: str | None, surname: str | None) -> str:
    return " ".join(part for part in (first_name, middle_name, surname) if part)


def row_get(row: sqlite3.Row, key: str, default: Any = None) -> Any:
    return row[key] if key in row.keys() else default


def device_option_label(device: sqlite3.Row) -> str:
    if device["device_type"] == "User":
        name = display_name(row_get(device, "first_name"), row_get(device, "middle_name"), row_get(device, "surname"))
        details = " | ".join(
            part
            for part in (
                name,
                row_get(device, "identifier"),
                row_get(device, "department"),
                row_get(device, "faculty"),
            )
            if part
        )
        return f"{device['mac_address']} - {details}" if details else str(device["mac_address"])
    location = f"{row_get(device, 'location_department') or 'Unassigned department'}, {row_get(device, 'location_faculty') or 'Unassigned faculty'}"
    return (
        f"{device['mac_address']} - {device['device_type']} - "
        f"{row_get(device, 'device_identifier') or 'Unspecified identifier'} - "
        f"{device['function'] or 'Unspecified function'} - {location}"
    )


def certificate_storage_dirs(subject_type: str, subject_id: int | None) -> tuple[Path, Path, Path, Path]:
    faculty = "Unassigned"
    department = "Unassigned"
    if subject_type == "Device" and subject_id:
        with connect_db() as conn:
            row = conn.execute(
                """
                SELECT devices.*, users.faculty AS user_faculty, users.department AS user_department
                FROM devices LEFT JOIN users ON users.id = devices.user_id
                WHERE devices.id = ?
                """,
                (subject_id,),
            ).fetchone()
        if row:
            if row["device_type"] == "User":
                faculty = row["user_faculty"] or faculty
                department = row["user_department"] or department
            else:
                faculty = row["location_faculty"] or faculty
                department = row["location_department"] or department
    base_parts = (safe_folder(faculty), safe_folder(department))
    cert_dir = CERT_DIR.joinpath(*base_parts)
    key_dir = KEY_DIR.joinpath(*base_parts)
    csr_dir = CSR_DIR.joinpath(*base_parts)
    deploy_dir = DEPLOY_DIR.joinpath(*base_parts)
    for path in (cert_dir, key_dir, csr_dir, deploy_dir):
        path.mkdir(parents=True, exist_ok=True)
    return cert_dir, key_dir, csr_dir, deploy_dir


def current_crl_paths() -> tuple[Path, Path]:
    ensure_dirs()
    return CRL_DIR / "campus_certificate_revocation_list.csv", CRL_DIR / "campus_certificate_revocation_list.txt"


def refresh_local_crl() -> tuple[Path, Path]:
    csv_path, text_path = current_crl_paths()
    with connect_db() as conn:
        revoked = conn.execute(
            """
            SELECT serial_number, common_name, revoked_at, revoke_reason, valid_to
            FROM certificates
            WHERE status = 'Revoked'
            ORDER BY revoked_at DESC, id DESC
            """
        ).fetchall()
    csv_lines = ["serial_number,common_name,revoked_at,revoke_reason,valid_to"]
    text_lines = [
        "Campus PKI Registration Authority Certificate Revocation List",
        f"Generated At: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"Revoked Certificate Count: {len(revoked)}",
        "",
    ]
    for cert in revoked:
        csv_lines.append(",".join(csv_escape(cert[key] or "") for key in ("serial_number", "common_name", "revoked_at", "revoke_reason", "valid_to")))
        text_lines.extend([
            f"Serial Number: {cert['serial_number']}",
            f"Common Name: {cert['common_name']}",
            f"Revoked At: {cert['revoked_at'] or ''}",
            f"Reason: {cert['revoke_reason'] or ''}",
            f"Original Valid To: {cert['valid_to'] or ''}",
            "",
        ])
    csv_path.write_text("\n".join(csv_lines) + "\n", encoding="utf-8")
    text_path.write_text("\n".join(text_lines), encoding="utf-8")
    return csv_path, text_path


def csv_escape(value: Any) -> str:
    text = "" if value is None else str(value)
    if any(ch in text for ch in [",", '"', "\n", "\r"]):
        return '"' + text.replace('"', '""') + '"'
    return text


def ca_public_certificate_paths() -> list[Path]:
    paths: list[Path] = []
    for candidate in (
        REMOTE_CA_DIR / "remote_campus_ca.crt",
        REMOTE_CA_DIR / "remote_campus_ca_public_key.pem",
        REMOTE_CA_DIR / "campus_ca.crt",
        CA_DIR / "campus_ca.crt",
    ):
        if candidate.exists() and candidate not in paths:
            paths.append(candidate)
    paths.extend(path for path in sorted(REMOTE_CA_DIR.glob("*.crt")) if path not in paths)
    paths.extend(path for path in sorted(REMOTE_CA_DIR.glob("*.pem")) if path not in paths)
    return paths


def certificate_is_active(cert: sqlite3.Row) -> bool:
    return cert["status"] == "Issued" and (cert["valid_to"] or "") >= time.strftime("%Y-%m-%d")


def build_deployment_bundle(cert: sqlite3.Row) -> tuple[bool, str, Path | None]:
    if not certificate_is_active(cert):
        return False, "Only issued and unexpired certificates can be bundled for download.", None
    bundle_dir = DEPLOY_DIR / f"deploy_{safe_folder(cert['serial_number'])}"
    if bundle_dir.exists():
        shutil.rmtree(bundle_dir)
    bundle_dir.mkdir(parents=True, exist_ok=True)
    copied = 0
    for key in ("cert_path", "p12_path"):
        value = cert[key]
        if value and Path(value).exists():
            shutil.copy2(value, bundle_dir / Path(value).name)
            copied += 1
    if copied == 0:
        return False, "Certificate files are missing from the local repository.", None
    ca_dir = bundle_dir / "ca_public_certificate"
    ca_dir.mkdir(exist_ok=True)
    for ca_path in ca_public_certificate_paths():
        shutil.copy2(ca_path, ca_dir / ca_path.name)
    crl_dir = bundle_dir / "revocation_list"
    crl_dir.mkdir(exist_ok=True)
    for crl_path in refresh_local_crl():
        shutil.copy2(crl_path, crl_dir / crl_path.name)
    zip_path = DEPLOY_DIR / f"deploy_{safe_folder(cert['serial_number'])}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(bundle_dir.rglob("*")):
            if path.is_file():
                bundle.write(path, path.relative_to(bundle_dir))
    return True, "Deployment bundle prepared.", zip_path


def update_cert_common_names_for_user(user_id: int) -> int:
    updated = 0
    with connect_db() as conn:
        devices = conn.execute("SELECT * FROM devices WHERE user_id = ?", (user_id,)).fetchall()
        for device in devices:
            common_name = device_common_name(device)
            result = conn.execute(
                "UPDATE certificates SET common_name = ? WHERE subject_type = 'Device' AND subject_id = ?",
                (common_name, device["id"]),
            )
            updated += result.rowcount
    return updated


def delete_user_cascade(user_id: int) -> tuple[bool, str]:
    with connect_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            return False, "User not found."
        devices = conn.execute("SELECT * FROM devices WHERE user_id = ?", (user_id,)).fetchall()
        device_ids = [device["id"] for device in devices]
        certs: list[sqlite3.Row] = []
        for device_id in device_ids:
            certs.extend(conn.execute("SELECT * FROM certificates WHERE subject_type = 'Device' AND subject_id = ?", (device_id,)).fetchall())

    deleted_files = 0
    for cert in certs:
        for key in ("cert_path", "key_path", "csr_path", "p12_path"):
            value = cert[key]
            if value:
                path = Path(value)
                if path.exists():
                    path.unlink()
                    deleted_files += 1

    with connect_db() as conn:
        for device_id in device_ids:
            conn.execute("DELETE FROM certificates WHERE subject_type = 'Device' AND subject_id = ?", (device_id,))
        conn.execute("DELETE FROM devices WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))

    details = f"Deleted user, {len(device_ids)} attached device(s), {len(certs)} certificate record(s), and {deleted_files} certificate file(s)."
    log_user_operation("Delete User", user_id, user["identifier"], details)
    audit("Delete User", f"{user['identifier']} / {details}")
    return True, details


def selected_certificate_subjects(form: dict[str, Any]) -> list[tuple[str, int, str]]:
    subjects: list[tuple[str, int, str]] = []
    mode = form.get("mode", "single")
    with connect_db() as conn:
        if mode == "single":
            subject_selector = form.get("single_subject", "")
            if not subject_selector:
                return []
            subject_id = int(subject_selector)
            device = conn.execute("SELECT * FROM devices WHERE id = ?", (subject_id,)).fetchone()
            if device:
                subjects.append(("Device", subject_id, device_common_name(device)))
            return subjects

        for raw_id in form_list(form, "device_ids"):
            device = conn.execute("SELECT * FROM devices WHERE id = ?", (int(raw_id),)).fetchone()
            if device:
                subjects.append(("Device", int(raw_id), device_common_name(device)))
    return subjects


def command_environment(executable: str) -> tuple[dict[str, str], str | None]:
    env = os.environ.copy()
    ensure_dirs()
    env["OPENSSL_CONF"] = str(OPENSSL_CONF_PATH)
    exe_path = Path(executable)
    cwd = None
    if exe_path.exists():
        bin_dir = str(exe_path.parent)
        env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
        cwd = bin_dir
    return env, cwd


def run_command(args: list[str], timeout: int = 30) -> tuple[bool, str]:
    try:
        env, cwd = command_environment(args[0])
        result = subprocess.run(args, check=False, capture_output=True, text=True, timeout=timeout, env=env, cwd=cwd)
        output = (result.stdout + "\n" + result.stderr).strip()
        return result.returncode == 0, output
    except FileNotFoundError:
        return False, f"Command not found: {args[0]}"
    except subprocess.TimeoutExpired:
        return False, "Command timed out."


def sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def openssl_dn_value(value: Any) -> str:
    text = "" if value is None else str(value)
    replacements = {
        "\\": "\\\\",
        "/": "\\/",
        "+": "\\+",
        ",": "\\,",
        ";": "\\;",
        "<": "\\<",
        ">": "\\>",
        '"': '\\"',
        "\n": " ",
        "\r": " ",
    }
    return "".join(replacements.get(ch, ch) for ch in text)


def openssl_subject(**parts: Any) -> str:
    return "".join(f"/{key}={openssl_dn_value(value)}" for key, value in parts.items())


def ssh_base_args(settings: sqlite3.Row) -> list[str]:
    if not settings["openssl_server_ip"] or not settings["openssl_username"]:
        return []
    args = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
    if settings["remote_ssh_key_path"]:
        args.extend(["-i", settings["remote_ssh_key_path"]])
    args.append(f"{settings['openssl_username']}@{settings['openssl_server_ip']}")
    return args


def scp_base_args(settings: sqlite3.Row) -> list[str]:
    args = ["scp", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
    if settings["remote_ssh_key_path"]:
        args.extend(["-i", settings["remote_ssh_key_path"]])
    return args


def remote_exec(settings: sqlite3.Row, command: str, timeout: int = 120) -> tuple[bool, str]:
    args = ssh_base_args(settings)
    if not args:
        return False, "Remote OpenSSL mode requires server IP address and username in Settings."
    return run_command(args + [command], timeout=timeout)


def remote_home_dir(settings: sqlite3.Row) -> tuple[bool, str]:
    ok, output = remote_exec(settings, 'printf "REMOTE_HOME=%s\\n" "$HOME"')
    if not ok or not output.strip():
        return False, output or "Could not resolve remote home directory."
    for line in output.splitlines():
        if line.startswith("REMOTE_HOME="):
            home = line.split("=", 1)[1].strip().rstrip("/")
            if home:
                return True, home
    return False, "Could not parse remote home directory from SSH output."


def resolve_remote_base_path(settings: sqlite3.Row) -> tuple[bool, str]:
    configured = (settings["remote_base_path"] or "~/campus_pki_ra").strip().rstrip("/")
    cache_key = (settings["openssl_server_ip"] or "", settings["openssl_username"] or "", configured)
    if cache_key in REMOTE_BASE_CACHE:
        return True, REMOTE_BASE_CACHE[cache_key]
    if configured == "~" or configured.startswith("~/"):
        ok, home = remote_home_dir(settings)
        if not ok:
            return False, home
        suffix = configured[2:] if configured.startswith("~/") else ""
        resolved = f"{home}/{suffix}".rstrip("/")
    else:
        resolved = configured
    REMOTE_BASE_CACHE[cache_key] = resolved
    return True, resolved


def remote_copy_from(settings: sqlite3.Row, remote_path: str, local_path: Path) -> tuple[bool, str]:
    if not settings["openssl_server_ip"] or not settings["openssl_username"]:
        return False, "Remote OpenSSL mode requires server IP address and username in Settings."
    local_path.parent.mkdir(parents=True, exist_ok=True)
    remote_ref = f"{settings['openssl_username']}@{settings['openssl_server_ip']}:{remote_path}"
    return run_command(scp_base_args(settings) + [remote_ref, str(local_path)], timeout=120)


def remote_copy_dir_contents_from(settings: sqlite3.Row, remote_path: str, local_dir: Path) -> tuple[bool, str]:
    if not settings["openssl_server_ip"] or not settings["openssl_username"]:
        return False, "Remote OpenSSL mode requires server IP address and username in Settings."
    local_dir.mkdir(parents=True, exist_ok=True)
    remote_ref = f"{settings['openssl_username']}@{settings['openssl_server_ip']}:{remote_path.rstrip('/')}/*"
    return run_command(scp_base_args(settings) + [remote_ref, str(local_dir)], timeout=180)


def create_certificate_remote(
    settings: sqlite3.Row,
    common_name: str,
    serial_number: str,
    valid_days: int,
    subject_type: str,
    subject_id: int | None,
) -> tuple[bool, str, dict[str, str]]:
    cert_dir, key_dir, csr_dir, deploy_dir = certificate_storage_dirs(subject_type, subject_id)
    safe_name = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in common_name)
    stem = f"{serial_number}_{safe_name}"
    key_path = key_dir / f"{stem}.key"
    csr_path = csr_dir / f"{stem}.csr"
    cert_path = cert_dir / f"{stem}.crt"
    p12_path = deploy_dir / f"{stem}.p12"

    ok, remote_base_or_error = resolve_remote_base_path(settings)
    if not ok:
        return False, "Remote OpenSSL path resolution failed. " + remote_base_or_error, {}
    remote_base = remote_base_or_error
    remote_dir = f"{remote_base}/{safe_folder(subject_type)}/{safe_folder(str(subject_id or 'general'))}/{stem}"
    subject = openssl_subject(C="NG", O=settings["organization"], CN=common_name)
    ca_subject = openssl_subject(C="NG", O=settings["organization"], CN=settings["ca_common_name"])
    remote_key = f"{remote_dir}/{stem}.key"
    remote_csr = f"{remote_dir}/{stem}.csr"
    remote_cert = f"{remote_dir}/{stem}.crt"
    remote_p12 = f"{remote_dir}/{stem}.p12"
    remote_ca_key = f"{remote_base}/ca/campus_ca.key"
    remote_ca_cert = f"{remote_base}/ca/campus_ca.crt"
    remote_ca_pubkey = f"{remote_base}/ca/campus_ca_public_key.pem"

    commands = [
        f"mkdir -p {sh_quote(remote_dir)} {sh_quote(remote_base + '/ca')}",
        (
            f"test -f {sh_quote(remote_ca_key)} -a -f {sh_quote(remote_ca_cert)} || "
            f"openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes "
            f"-keyout {sh_quote(remote_ca_key)} -out {sh_quote(remote_ca_cert)} -subj {sh_quote(ca_subject)}"
        ),
        f"openssl genrsa -out {sh_quote(remote_key)} 2048",
        f"openssl req -new -key {sh_quote(remote_key)} -out {sh_quote(remote_csr)} -subj {sh_quote(subject)}",
        (
            f"openssl x509 -req -in {sh_quote(remote_csr)} -CA {sh_quote(remote_ca_cert)} "
            f"-CAkey {sh_quote(remote_ca_key)} -CAcreateserial -out {sh_quote(remote_cert)} "
            f"-days {int(valid_days)} -sha256"
        ),
        (
            f"openssl pkcs12 -export -out {sh_quote(remote_p12)} -inkey {sh_quote(remote_key)} "
            f"-in {sh_quote(remote_cert)} -certfile {sh_quote(remote_ca_cert)} -passout pass:"
        ),
        f"openssl x509 -in {sh_quote(remote_ca_cert)} -pubkey -noout -out {sh_quote(remote_ca_pubkey)}",
    ]
    output: list[str] = []
    ok, message = remote_exec(settings, " && ".join(commands), timeout=240)
    output.append(message)
    if not ok:
        return False, "Remote OpenSSL command failed. " + "\n".join(output), {}

    remote_cache_parent = DEPLOY_DIR / "_remote_copy_cache"
    local_stage = remote_cache_parent / stem
    if local_stage.exists():
        shutil.rmtree(local_stage)
    local_stage.mkdir(parents=True, exist_ok=True)
    ok, message = remote_copy_dir_contents_from(settings, remote_dir, local_stage)
    output.append(message)
    if not ok or not local_stage.exists():
        return False, "Remote certificate was created but folder copy-back failed. " + "\n".join(output), {}

    for local_stage_file, final_path in (
        (local_stage / f"{stem}.key", key_path),
        (local_stage / f"{stem}.csr", csr_path),
        (local_stage / f"{stem}.crt", cert_path),
        (local_stage / f"{stem}.p12", p12_path),
    ):
        if not local_stage_file.exists():
            return False, f"Remote certificate was copied back but {local_stage_file.name} is missing.", {}
        final_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(local_stage_file, final_path)

    if not (REMOTE_CA_DIR / "remote_campus_ca.crt").exists():
        ok, message = remote_copy_from(settings, remote_ca_cert, REMOTE_CA_DIR / "remote_campus_ca.crt")
        output.append(message)
        if not ok:
            return False, "Remote certificate was created but CA certificate copy-back failed. " + "\n".join(output), {}
    if not (REMOTE_CA_DIR / "remote_campus_ca_public_key.pem").exists():
        ok, message = remote_copy_from(settings, remote_ca_pubkey, REMOTE_CA_DIR / "remote_campus_ca_public_key.pem")
        output.append(message)
        if not ok:
            return False, "Remote certificate was created but CA public key copy-back failed. " + "\n".join(output), {}
    shutil.rmtree(local_stage, ignore_errors=True)

    valid_from = time.strftime("%Y-%m-%d")
    valid_to = time.strftime("%Y-%m-%d", time.localtime(time.time() + valid_days * 86400))
    with connect_db() as conn:
        conn.execute(
            """
            INSERT INTO certificates
                (subject_type, subject_id, common_name, serial_number, cert_path, key_path, csr_path, p12_path, valid_from, valid_to)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (subject_type, subject_id, common_name, serial_number, str(cert_path), str(key_path), str(csr_path), str(p12_path), valid_from, valid_to),
        )
    audit("Create Remote Certificate", f"{common_name} / {serial_number}")
    return True, "Remote certificate created and copied to local repository.", {
        "cert_path": str(cert_path),
        "key_path": str(key_path),
        "csr_path": str(csr_path),
        "p12_path": str(p12_path),
    }


def openssl_available(openssl_path: str) -> bool:
    ok, _ = run_command([openssl_path, "version"])
    return ok


def ensure_local_ca(settings: sqlite3.Row) -> tuple[bool, str]:
    openssl_path = resolve_openssl_path(settings["openssl_path"])
    ca_key = CA_DIR / "campus_ca.key"
    ca_cert = CA_DIR / "campus_ca.crt"
    if ca_key.exists() and ca_cert.exists():
        return True, "Local CA already exists."
    if not openssl_available(openssl_path):
        return False, (
            "OpenSSL is not available. Add a portable OpenSSL build to the app's "
            "tools/openssl folder or update Settings with a valid executable path."
        )
    subject = openssl_subject(C="NG", O=settings["organization"], CN=settings["ca_common_name"])
    args = [
        openssl_path,
        "req",
        "-x509",
        "-newkey",
        "rsa:4096",
        "-sha256",
        "-days",
        "3650",
        "-nodes",
        "-keyout",
        str(ca_key),
        "-out",
        str(ca_cert),
        "-subj",
        subject,
    ]
    ok, output = run_command(args)
    return ok, output or "Local CA created."


def create_certificate(common_name: str, serial_number: str, valid_days: int, subject_type: str, subject_id: int | None) -> tuple[bool, str, dict[str, str]]:
    settings = get_settings()
    if settings["openssl_mode"] == "remote":
        return create_certificate_remote(settings, common_name, serial_number, valid_days, subject_type, subject_id)
    ok, message = ensure_local_ca(settings)
    if not ok:
        return False, message, {}

    openssl_path = resolve_openssl_path(settings["openssl_path"])
    safe_name = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in common_name)
    stem = f"{serial_number}_{safe_name}"
    cert_dir, key_dir, csr_dir, deploy_dir = certificate_storage_dirs(subject_type, subject_id)
    key_path = key_dir / f"{stem}.key"
    csr_path = csr_dir / f"{stem}.csr"
    cert_path = cert_dir / f"{stem}.crt"
    p12_path = deploy_dir / f"{stem}.p12"
    ca_key = CA_DIR / "campus_ca.key"
    ca_cert = CA_DIR / "campus_ca.crt"
    subject = openssl_subject(C="NG", O=settings["organization"], CN=common_name)

    commands = [
        [openssl_path, "genrsa", "-out", str(key_path), "2048"],
        [openssl_path, "req", "-new", "-key", str(key_path), "-out", str(csr_path), "-subj", subject],
        [
            openssl_path,
            "x509",
            "-req",
            "-in",
            str(csr_path),
            "-CA",
            str(ca_cert),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-out",
            str(cert_path),
            "-days",
            str(valid_days),
            "-sha256",
        ],
        [
            openssl_path,
            "pkcs12",
            "-export",
            "-out",
            str(p12_path),
            "-inkey",
            str(key_path),
            "-in",
            str(cert_path),
            "-certfile",
            str(ca_cert),
            "-passout",
            "pass:",
        ],
    ]

    outputs: list[str] = []
    for command in commands:
        ok, output = run_command(command)
        outputs.append(output)
        if not ok:
            return False, "\n".join(outputs), {}

    valid_from = time.strftime("%Y-%m-%d")
    valid_to = time.strftime("%Y-%m-%d", time.localtime(time.time() + valid_days * 86400))
    with connect_db() as conn:
        conn.execute(
            """
            INSERT INTO certificates
                (subject_type, subject_id, common_name, serial_number, cert_path, key_path, csr_path, p12_path, valid_from, valid_to)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                subject_type,
                subject_id,
                common_name,
                serial_number,
                str(cert_path),
                str(key_path),
                str(csr_path),
                str(p12_path),
                valid_from,
                valid_to,
            ),
        )
    audit("Create Certificate", f"{common_name} / {serial_number}")
    return True, "Certificate created successfully.", {
        "cert_path": str(cert_path),
        "key_path": str(key_path),
        "csr_path": str(csr_path),
        "p12_path": str(p12_path),
    }


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def parse_form(body: bytes) -> dict[str, Any]:
    parsed = urllib.parse.parse_qs(body.decode("utf-8"), keep_blank_values=True)
    return {key: [value.strip() for value in values] if len(values) > 1 else values[0].strip() for key, values in parsed.items()}


def parse_multipart(body: bytes, content_type: str) -> dict[str, Any]:
    marker = "boundary="
    if marker not in content_type:
        return {}
    boundary = content_type.split(marker, 1)[1].strip().strip('"')
    delimiter = ("--" + boundary).encode("utf-8")
    fields: dict[str, Any] = {}
    for part in body.split(delimiter):
        part = part.strip()
        if not part or part == b"--":
            continue
        if part.endswith(b"--"):
            part = part[:-2].strip()
        if b"\r\n\r\n" not in part:
            continue
        raw_headers, content = part.split(b"\r\n\r\n", 1)
        content = content.rstrip(b"\r\n")
        headers = raw_headers.decode("utf-8", errors="replace").split("\r\n")
        disposition = next((line for line in headers if line.lower().startswith("content-disposition:")), "")
        attrs: dict[str, str] = {}
        for segment in disposition.split(";"):
            if "=" in segment:
                key, value = segment.strip().split("=", 1)
                attrs[key.lower()] = value.strip().strip('"')
        name = attrs.get("name")
        if not name:
            continue
        if "filename" in attrs:
            fields[name] = {"filename": attrs["filename"], "content": content}
        else:
            text = content.decode("utf-8-sig", errors="replace").strip()
            if name in fields:
                existing = fields[name]
                if isinstance(existing, list):
                    existing.append(text)
                else:
                    fields[name] = [existing, text]
            else:
                fields[name] = text
    return fields


def form_list(form: dict[str, Any], key: str) -> list[str]:
    value = form.get(key)
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return [str(value)]


@dataclass
class Response:
    body: str | bytes
    status: int = 200
    headers: dict[str, str] | None = None


def redirect(location: str, headers: dict[str, str] | None = None) -> Response:
    response_headers = {"Location": location}
    if headers:
        response_headers.update(headers)
    return Response("", 303, response_headers)


class App:
    current_user: sqlite3.Row | None = None

    def render_auth(self, title: str, subtitle: str, fields: str, notice: str = "", mode: str = "login") -> str:
        notice_html = f'<div class="auth-notice">{esc(notice)}</div>' if notice else ""
        button_text = "Create Superadmin" if mode == "setup" else "Login"
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(title)} | Campus PKI RA</title>
  <link rel="stylesheet" href="/static/styles.css">
</head>
<body class="auth-body">
  <main class="auth-shell">
    <section class="auth-form-panel">
      <div class="auth-logo">
        <span class="auth-mark">PKI</span>
        <div><strong>Campus RA</strong><small>Local Certificate Authority Desk</small></div>
      </div>
      <div class="auth-heading">
        <h1>{esc(title)}</h1>
        <p>{esc(subtitle)}</p>
      </div>
      {notice_html}
      <form method="post" class="auth-form">
        {fields}
        <button type="submit">{button_text}</button>
      </form>
    </section>
    <section class="auth-visual">
      <div class="auth-visual-copy">
        <h2>Secure campus Wi-Fi access</h2>
        <p>Provision, deploy, renew, and revoke EAP-TLS certificates from a protected local Registration Authority console.</p>
      </div>
    </section>
  </main>
</body>
</html>"""

    def setup_page(self, form: dict[str, Any] | None = None) -> Response:
        if admin_account_count() > 0:
            return redirect("/login")
        notice = ""
        if form:
            username = form.get("username", "").strip()
            password = form.get("password", "")
            confirm = form.get("confirm_password", "")
            full_name = form.get("full_name", "").strip()
            if not username or not password:
                notice = "Username and password are required."
            elif len(password) < 8:
                notice = "Password must be at least 8 characters."
            elif password != confirm:
                notice = "Passwords do not match."
            else:
                with connect_db() as conn:
                    conn.execute(
                        "INSERT INTO admin_accounts (username, full_name, password_hash, role) VALUES (?, ?, ?, 'Superadmin')",
                        (username, full_name, hash_password(password)),
                    )
                audit("Initial Superadmin Setup", username, username)
                return redirect("/login")
        fields = """
        <label>Full Name<input name="full_name" autocomplete="name"></label>
        <label>Superadmin Username<input name="username" required autocomplete="username"></label>
        <label>Password<input type="password" name="password" required autocomplete="new-password"></label>
        <label>Confirm Password<input type="password" name="confirm_password" required autocomplete="new-password"></label>
        """
        return Response(self.render_auth("Initial Setup", "Create the first superadmin account for this computer.", fields, notice, "setup"))

    def login_page(self, form: dict[str, Any] | None = None) -> Response:
        if admin_account_count() == 0:
            return redirect("/setup")
        notice = ""
        if form:
            username = form.get("username", "").strip()
            password = form.get("password", "")
            with connect_db() as conn:
                account = conn.execute(
                    "SELECT * FROM admin_accounts WHERE username = ? AND is_active = 1",
                    (username,),
                ).fetchone()
            if account and verify_password(password, account["password_hash"]):
                token = create_session(account["id"])
                audit("Admin Login", username, username)
                return redirect("/", {"Set-Cookie": f"ra_session={urllib.parse.quote(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800"})
            notice = "Invalid username or password."
        fields = """
        <label>Username<input name="username" required autocomplete="username"></label>
        <label>Password<input type="password" name="password" required autocomplete="current-password"></label>
        """
        return Response(self.render_auth("Log In", "Enter your Registration Authority account details.", fields, notice, "login"))

    def logout(self, cookie_header: str) -> Response:
        actor = current_admin(cookie_header)
        clear_session(cookie_header)
        if actor:
            audit("Admin Logout", actor["username"], actor["username"])
        return redirect("/login", {"Set-Cookie": "ra_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"})

    def admin_accounts(self, form: dict[str, Any] | None = None) -> Response:
        notice = ""
        if form:
            action = form.get("action", "")
            if action == "create_role":
                role_name = form.get("role_name", "").strip()
                permissions = [path for path in form_list(form, "permissions") if path in all_menu_paths(False)]
                if not role_name:
                    notice = "Role name is required."
                elif role_name == "Superadmin":
                    notice = "Superadmin is reserved and cannot be recreated."
                elif not permissions:
                    notice = "Select at least one menu permission for the role."
                else:
                    try:
                        with connect_db() as conn:
                            conn.execute(
                                "INSERT INTO admin_roles (role_name, permissions) VALUES (?, ?)",
                                (role_name, json.dumps(permissions)),
                            )
                        audit("Create Admin Role", f"{role_name}: {', '.join(menu_label(path) for path in permissions)}")
                        notice = "Role created successfully."
                    except sqlite3.IntegrityError:
                        notice = "A role with that name already exists."
            else:
                username = form.get("username", "").strip()
                full_name = form.get("full_name", "").strip()
                role = form.get("role", "Operator")
                password = form.get("password", "")
                if not username or not password:
                    notice = "Username and password are required."
                elif len(password) < 8:
                    notice = "Password must be at least 8 characters."
                else:
                    with connect_db() as conn:
                        role_exists = conn.execute("SELECT 1 FROM admin_roles WHERE role_name = ?", (role,)).fetchone()
                    if not role_exists:
                        notice = "Select a valid role."
                    else:
                        try:
                            with connect_db() as conn:
                                conn.execute(
                                    "INSERT INTO admin_accounts (username, full_name, password_hash, role) VALUES (?, ?, ?, ?)",
                                    (username, full_name, hash_password(password), role),
                                )
                            audit("Create Admin Account", f"{username} / {role}")
                            notice = "Account created successfully."
                        except sqlite3.IntegrityError:
                            notice = "An account with that username already exists."
        with connect_db() as conn:
            roles = conn.execute("SELECT * FROM admin_roles ORDER BY role_name").fetchall()
            accounts = conn.execute("SELECT username, full_name, role, is_active, created_at, last_login_at FROM admin_accounts ORDER BY role DESC, username").fetchall()
        role_options = "".join(f'<option value="{esc(role["role_name"])}">{esc(role["role_name"])}</option>' for role in roles)
        permission_checks = "".join(
            f'<label class="check-row"><input type="checkbox" name="permissions" value="{esc(item["path"])}"> {esc(item["label"])}</label>'
            for item in MENU_ITEMS
            if not item["superadmin_only"]
        )
        role_rows = "".join(
            f"<tr><td>{esc(role['role_name'])}</td><td>{esc(', '.join(menu_label(path) for path in sorted(role_permissions(role['role_name']))))}</td><td>{esc(role['created_at'])}</td></tr>"
            for role in roles
        ) or '<tr><td colspan="3" class="muted">No roles.</td></tr>'
        rows = "".join(
            f"<tr><td>{esc(a['username'])}</td><td>{esc(a['full_name'])}</td><td>{esc(a['role'])}</td><td>{'Active' if a['is_active'] else 'Disabled'}</td><td>{esc(a['last_login_at'])}</td></tr>"
            for a in accounts
        ) or '<tr><td colspan="5" class="muted">No accounts.</td></tr>'
        content = f"""
<section class="panel form-panel">
  <div class="panel-head"><h2>Create Role</h2></div>
  <form method="post">
    <input type="hidden" name="action" value="create_role">
    <label>Role Name<input name="role_name" required placeholder="Certificate Officer"></label>
    <div class="span-all check-grid">{permission_checks}</div>
    <button type="submit">Create Role</button>
  </form>
</section>
<section class="panel form-panel">
  <form method="post">
    <input type="hidden" name="action" value="create_account">
    <label>Full Name<input name="full_name"></label>
    <label>Username<input name="username" required></label>
    <label>Password<input type="password" name="password" required></label>
    <label>Role<select name="role">{role_options}</select></label>
    <button type="submit">Create Account</button>
  </form>
</section>
<section class="panel">
  <div class="panel-head"><h2>Roles</h2></div>
  <table><thead><tr><th>Role</th><th>Menu Permissions</th><th>Created</th></tr></thead><tbody>{role_rows}</tbody></table>
</section>
<section class="panel">
  <div class="panel-head"><h2>RA Accounts</h2></div>
  <table><thead><tr><th>Username</th><th>Name</th><th>Role</th><th>Status</th><th>Last Login</th></tr></thead><tbody>{rows}</tbody></table>
</section>
"""
        return Response(self.render("Admin Accounts", "Admin Accounts", content, notice))

    def render(self, active: str, title: str, content: str, notice: str = "") -> str:
        nav = [
            (item["path"], item["label"])
            for item in MENU_ITEMS
            if can_access(self.current_user, item["path"])
        ]
        items = "\n".join(
            f'<a class="nav-link {"active" if label == active else ""}" href="{href}">{label}</a>'
            for href, label in nav
        )
        account_name = self.current_user["username"] if self.current_user else "Guest"
        account_role = self.current_user["role"] if self.current_user else ""
        notice_html = f'<div class="notice">{esc(notice)}</div>' if notice else ""
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(title)} | Campus PKI RA</title>
  <link rel="stylesheet" href="/static/styles.css">
</head>
<body>
  <aside class="sidebar">
    <div class="brand">
      <span class="mark">PKI</span>
      <div>
        <strong>Campus RA</strong>
        <small>EAP-TLS Certificate Desk</small>
      </div>
    </div>
    <nav>{items}</nav>
    <div class="account-box">
      <strong>{esc(account_name)}</strong>
      <small>{esc(account_role)}</small>
      <a href="/logout">Log out</a>
    </div>
  </aside>
  <main class="main">
    <header class="topbar">
      <div>
        <h1>{esc(title)}</h1>
        <p>Local registration authority console for campus WPA3/EAP-TLS certificate workflows.</p>
      </div>
      <span class="status-dot">127.0.0.1:8080</span>
    </header>
    {notice_html}
    {content}
  </main>
  <script>window.FACULTY_DEPARTMENTS = {json.dumps(get_faculty_departments())};</script>
  <script src="/static/app.js"></script>
</body>
</html>"""

    def dashboard(self) -> Response:
        with connect_db() as conn:
            counts = {
                "Users": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
                "Devices": conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
                "Certificates": conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0],
                "Revoked": conn.execute("SELECT COUNT(*) FROM certificates WHERE status = 'Revoked'").fetchone()[0],
            }
            certs = conn.execute("SELECT * FROM certificates ORDER BY id DESC LIMIT 6").fetchall()
        cards = "".join(f'<div class="metric"><span>{esc(k)}</span><strong>{v}</strong></div>' for k, v in counts.items())
        row_html: list[str] = []
        for c in certs:
            if certificate_is_active(c):
                actions = (
                    f'<a class="mini-button" href="/download-certificate?id={c["id"]}&kind=cert">Download Certificate</a> '
                    f'<a class="mini-button" href="/download-certificate?id={c["id"]}&kind=bundle">Download Bundle</a>'
                )
            else:
                actions = '<span class="muted">Download unavailable</span>'
            row_html.append(
                f"<tr><td>{esc(c['serial_number'])}</td><td>{esc(c['common_name'])}</td><td>{esc(c['status'])}</td><td>{esc(c['valid_to'])}</td><td>{actions}</td></tr>"
            )
        rows = "".join(row_html) or '<tr><td colspan="5" class="muted">No certificates created yet.</td></tr>'
        content = f"""
<section class="metrics">{cards}</section>
<section class="panel">
  <div class="panel-head"><h2>Recent Certificates</h2></div>
  <table><thead><tr><th>Serial</th><th>Common Name</th><th>Status</th><th>Valid To</th><th>Downloads</th></tr></thead><tbody>{rows}</tbody></table>
</section>
"""
        return Response(self.render("Dashboard", "Dashboard", content))

    def download_certificate(self, query: dict[str, list[str]]) -> Response:
        cert_id = int((query.get("id") or ["0"])[0] or "0")
        kind = ((query.get("kind") or ["cert"])[0] or "cert").lower()
        with connect_db() as conn:
            cert = conn.execute("SELECT * FROM certificates WHERE id = ?", (cert_id,)).fetchone()
        if not cert:
            return Response(self.render("Dashboard", "Download Not Found", '<section class="panel">Certificate record was not found.</section>'), 404)
        if not certificate_is_active(cert):
            return Response(self.render("Dashboard", "Download Blocked", '<section class="panel">Revoked or expired certificates cannot be downloaded.</section>'), 403)
        if kind == "bundle":
            ok, message, path = build_deployment_bundle(cert)
            if not ok or not path:
                return Response(self.render("Dashboard", "Bundle Error", f'<section class="panel">{esc(message)}</section>'), 500)
            filename = path.name
            content_type = "application/zip"
        else:
            path = Path(cert["cert_path"] or "")
            if not path.exists():
                return Response(self.render("Dashboard", "Download Not Found", '<section class="panel">Certificate file is missing from the local repository.</section>'), 404)
            filename = path.name
            content_type = "application/x-x509-ca-cert"
        audit("Download Certificate Bundle" if kind == "bundle" else "Download Certificate", cert["serial_number"])
        return Response(
            path.read_bytes(),
            200,
            {
                "Content-Type": content_type,
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Cache-Control": "no-store",
            },
        )

    def register_user(self, form: dict[str, str] | None = None) -> Response:
        notice = ""
        edit_user = None
        if form:
            action = form.get("action", "")
            if action == "edit_select":
                with connect_db() as conn:
                    edit_user = conn.execute("SELECT * FROM users WHERE id = ?", (int(form.get("user_id") or "0"),)).fetchone()
            elif action == "update_user":
                user_id = int(form.get("user_id") or "0")
                with connect_db() as conn:
                    old_user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
                    if not old_user:
                        notice = "User not found."
                    else:
                        conn.execute(
                            """
                            UPDATE users
                            SET user_type = ?, first_name = ?, middle_name = ?, surname = ?, email = ?, department = ?, faculty = ?, identifier = ?
                            WHERE id = ?
                            """,
                            (
                                form["user_type"],
                                form["first_name"],
                                form.get("middle_name"),
                                form["surname"],
                                form.get("email"),
                                form.get("department"),
                                form.get("faculty"),
                                form["identifier"],
                                user_id,
                            ),
                        )
                        notice = "User updated successfully."
                if notice == "User updated successfully.":
                    updated_certs = update_cert_common_names_for_user(user_id)
                    log_user_operation("Edit User", user_id, form["identifier"], f"Updated user details and adjusted {updated_certs} certificate common-name record(s).")
                    audit("Edit User", f"{form['identifier']} / adjusted {updated_certs} certificate common-name record(s)")
            elif action == "delete_user":
                ok, message = delete_user_cascade(int(form.get("user_id") or "0"))
                notice = message if ok else message
            elif "csv_file" in form and isinstance(form["csv_file"], dict) and form["csv_file"].get("content"):
                created, skipped, errors = import_users_csv(form["csv_file"]["content"])
                notice = f"Bulk upload complete: {created} user(s) added, {skipped} skipped."
                if errors:
                    notice += " " + " ".join(errors[:3])
            else:
                try:
                    with connect_db() as conn:
                        conn.execute(
                            """
                            INSERT INTO users (user_type, first_name, middle_name, surname, email, department, faculty, identifier)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                form["user_type"],
                                form["first_name"],
                                form.get("middle_name"),
                                form["surname"],
                                form.get("email"),
                                form.get("department"),
                                form.get("faculty"),
                                form["identifier"],
                            ),
                        )
                    audit("Register User", f"{form['user_type']} {form['identifier']}")
                    log_user_operation("Register User", None, form["identifier"], f"Registered {form['user_type']} user.")
                    notice = "User registered successfully."
                except sqlite3.IntegrityError:
                    notice = "A user with that staff or matriculation number already exists."
        with connect_db() as conn:
            users = conn.execute("SELECT * FROM users ORDER BY id DESC LIMIT 20").fetchall()
        rows = "".join(
            f"""
            <tr>
              <td>{esc(u['user_type'])}</td><td>{esc(display_name(u['first_name'], u['middle_name'], u['surname']))}</td><td>{esc(u['email'])}</td><td>{esc(u['department'])}</td><td>{esc(u['faculty'])}</td><td>{esc(u['identifier'])}</td>
              <td class="actions-cell">
                <form method="post" class="inline-form"><input type="hidden" name="action" value="edit_select"><input type="hidden" name="user_id" value="{u['id']}"><button type="submit">Edit</button></form>
                <form method="post" class="inline-form"><input type="hidden" name="action" value="delete_user"><input type="hidden" name="user_id" value="{u['id']}"><button type="submit">Delete</button></form>
              </td>
            </tr>
            """
            for u in users
        ) or '<tr><td colspan="7" class="muted">No users registered.</td></tr>'
        edit_form = ""
        if edit_user:
            edit_form = f"""
<section class="panel form-panel">
  <div class="panel-head"><h2>Edit User</h2></div>
  <form method="post">
    <input type="hidden" name="action" value="update_user">
    <input type="hidden" name="user_id" value="{edit_user['id']}">
    <label>User Type<select name="user_type" data-user-type><option {"selected" if edit_user['user_type'] == 'Staff' else ""}>Staff</option><option {"selected" if edit_user['user_type'] == 'Student' else ""}>Student</option></select></label>
    <label>First Name<input name="first_name" value="{esc(edit_user['first_name'])}" required></label>
    <label>Middle Name<input name="middle_name" value="{esc(edit_user['middle_name'])}"></label>
    <label>Surname<input name="surname" value="{esc(edit_user['surname'])}" required></label>
    <label>Email<input type="email" name="email" value="{esc(edit_user['email'])}" required></label>
    <label>Faculty<select name="faculty" data-faculty-select required>{faculty_options(edit_user['faculty'])}</select></label>
    <label>Department<select name="department" data-department-select required>{department_options(edit_user['department'], edit_user['faculty'])}</select></label>
    <label><span data-identifier-label>Staff Number</span><input name="identifier" value="{esc(edit_user['identifier'])}" required></label>
    <button type="submit">Save User Changes</button>
  </form>
</section>
"""
        content = f"""
{edit_form}
<section class="panel form-panel">
  <form method="post">
    <label>User Type<select name="user_type" data-user-type><option>Staff</option><option>Student</option></select></label>
    <label>First Name<input name="first_name" required></label>
    <label>Middle Name<input name="middle_name"></label>
    <label>Surname<input name="surname" required></label>
    <label>Email<input type="email" name="email" required></label>
    <label>Faculty<select name="faculty" data-faculty-select required>{faculty_options()}</select></label>
    <label>Department<select name="department" data-department-select required>{department_options()}</select></label>
    <label><span data-identifier-label>Staff Number</span><input name="identifier" required></label>
    <button type="submit">Register User</button>
  </form>
</section>
<section class="panel form-panel">
  <div class="panel-head"><h2>Bulk User Upload</h2></div>
  <p class="helper">CSV columns: user_type, first_name, middle_name, surname, email, department, faculty, identifier. Identifier may also be staff_number or matriculation_number.</p>
  <form method="post" enctype="multipart/form-data">
    <label>CSV File<input type="file" name="csv_file" accept=".csv,text/csv" required></label>
    <button type="submit">Upload Users</button>
  </form>
</section>
<section class="panel">
  <div class="panel-head"><h2>Registered Users</h2></div>
  <table><thead><tr><th>Type</th><th>Name</th><th>Email</th><th>Department</th><th>Faculty</th><th>Identifier</th><th>Actions</th></tr></thead><tbody>{rows}</tbody></table>
</section>
"""
        return Response(self.render("Register User", "Register User", content, notice))

    def register_device(self, form: dict[str, str] | None = None) -> Response:
        notice = ""
        if form:
            if form.get("action") == "unassign":
                device_id = int(form.get("device_id") or "0")
                unassigned_mac = ""
                with connect_db() as conn:
                    device = conn.execute("SELECT * FROM devices WHERE id = ? AND device_type = 'User' AND user_id IS NOT NULL", (device_id,)).fetchone()
                    if device:
                        unassigned_mac = device["mac_address"]
                        conn.execute("UPDATE devices SET user_id = NULL, function = '' WHERE id = ?", (device_id,))
                        notice = "Device unassigned successfully. The user can now be assigned to another device."
                    else:
                        notice = "Select an assigned user device to unassign."
                if unassigned_mac:
                    audit("Unassign Device", unassigned_mac)
                form = None
            else:
                device_type = form["device_type"]
                user_id = int(form["user_id"]) if device_type == "User" and form.get("user_id") else None
                function = "User" if device_type == "User" else form.get("function", "")
                location_faculty = "" if device_type == "User" else form.get("location_faculty", "")
                location_department = "" if device_type == "User" else form.get("location_department", "")
                device_identifier = "" if device_type == "User" else form.get("device_identifier", "")
                if device_type == "User" and not user_id:
                    notice = "User device must be tied to a registered user."
                elif device_type in {"Access", "Server"} and (not function or not location_faculty or not location_department or not device_identifier):
                    notice = f"{device_type} device must include function, location, and device identifier."
                else:
                    try:
                        with connect_db() as conn:
                            conn.execute(
                                """
                                INSERT INTO devices (device_type, mac_address, user_id, function, location_faculty, location_department, device_identifier)
                                VALUES (?, ?, ?, ?, ?, ?, ?)
                                """,
                                (device_type, normalize_mac(form["mac_address"]), user_id, function, location_faculty, location_department, device_identifier),
                            )
                        audit("Register Device", f"{device_type} {form['mac_address']}")
                        notice = "Device registered successfully."
                    except sqlite3.IntegrityError:
                        notice = "A device with that MAC address already exists."
        with connect_db() as conn:
            users = conn.execute(
                """
                SELECT id, first_name, middle_name, surname, identifier, department, faculty
                FROM users
                WHERE NOT EXISTS (
                    SELECT 1 FROM devices
                    WHERE devices.user_id = users.id
                      AND devices.device_type = 'User'
                )
                ORDER BY surname
                """
            ).fetchall()
            devices = conn.execute(
                """
                SELECT devices.*, users.first_name, users.middle_name, users.surname, users.identifier, users.department, users.faculty
                FROM devices LEFT JOIN users ON users.id = devices.user_id
                ORDER BY devices.id DESC LIMIT 20
                """
            ).fetchall()
            assigned_devices = conn.execute(
                """
                SELECT devices.*, users.first_name, users.middle_name, users.surname, users.identifier
                FROM devices JOIN users ON users.id = devices.user_id
                WHERE devices.device_type = 'User'
                ORDER BY users.surname, users.first_name
                """
            ).fetchall()
        options = "".join(
            f"<option value=\"{u['id']}\" data-search=\"{esc(display_name(u['first_name'], u['middle_name'], u['surname']))} {esc(u['identifier'])} {esc(u['department'])} {esc(u['faculty'])}\">{esc(display_name(u['first_name'], u['middle_name'], u['surname']))} ({esc(u['identifier'])}) - {esc(u['department'])}, {esc(u['faculty'])}</option>"
            for u in users
        )
        rows = "".join(
            f"<tr><td>{esc(d['device_type'])}</td><td>{esc(d['mac_address'])}</td><td>{esc(display_name(d['first_name'], d['middle_name'], d['surname']))}</td><td>{esc(d['department'] or d['location_department'])}</td><td>{esc(d['faculty'] or d['location_faculty'])}</td><td>{esc(d['device_identifier'])}</td><td>{esc(d['function'])}</td></tr>"
            for d in devices
        ) or '<tr><td colspan="7" class="muted">No devices registered.</td></tr>'
        unassign_options = "".join(
            f"<option value=\"{d['id']}\">{esc(d['mac_address'])} - {esc(display_name(d['first_name'], d['middle_name'], d['surname']))} ({esc(d['identifier'])})</option>"
            for d in assigned_devices
        )
        content = f"""
<section class="panel form-panel">
  <form method="post">
    <label>Device Type<select name="device_type" data-device-type><option>User</option><option>Access</option><option>Server</option></select></label>
    <label>MAC Address<input name="mac_address" required placeholder="AA:BB:CC:DD:EE:FF"></label>
    <label data-user-device-field>Search Assigned User<input data-select-filter="assigned-user-select" placeholder="Type name, department, faculty, or identifier"></label>
    <label data-user-device-field>Assigned User<select id="assigned-user-select" name="user_id"><option value="">Select user for user device</option>{options}</select></label>
    <label data-server-device-field>Location Faculty<select name="location_faculty" data-faculty-select>{faculty_options()}</select></label>
    <label data-server-device-field>Device Location<select name="location_department" data-department-select>{department_options()}</select></label>
    <label data-server-device-field>Device Identifier<input name="device_identifier" placeholder="AP-BLOCK-A-01, RADIUS-01"></label>
    <label data-server-device-field>Function<input name="function" placeholder="Access Point, FreeRADIUS, OpenSSL CA"></label>
    <button type="submit">Register Device</button>
  </form>
</section>
<section class="panel form-panel">
  <div class="panel-head"><h2>Unassign User Device</h2></div>
  <form method="post">
    <input type="hidden" name="action" value="unassign">
    <label>Assigned Device<select name="device_id" required><option value="">Select assigned user device</option>{unassign_options}</select></label>
    <button type="submit">Unassign Device</button>
  </form>
</section>
<section class="panel">
  <div class="panel-head"><h2>Registered Devices</h2></div>
  <table><thead><tr><th>Type</th><th>MAC Address</th><th>User</th><th>Department</th><th>Faculty</th><th>Device Identifier</th><th>Function</th></tr></thead><tbody>{rows}</tbody></table>
</section>
"""
        return Response(self.render("Register Device", "Register Device", content, notice))

    def create_certificate_page(self, form: dict[str, str] | None = None) -> Response:
        notice = ""
        if form:
            subjects = selected_certificate_subjects(form)
            if not subjects:
                notice = "Select at least one registered user or device before creating certificates."
            else:
                mode = form.get("mode", "single")
                prefix = form.get("serial_prefix", "CERT")
                valid_days = int(form.get("valid_days") or get_settings()["default_valid_days"])
                created = 0
                messages = []
                timestamp = now_slug()
                for index, (subject_type, subject_id, common_name) in enumerate(subjects, start=1):
                    if mode == "single" and form.get("serial_number"):
                        serial = form["serial_number"]
                    else:
                        serial = f"{prefix}-{timestamp}-{index:03d}"
                    ok, message, _paths = create_certificate(common_name, serial, valid_days, subject_type, subject_id)
                    messages.append(message)
                    if ok:
                        created += 1
                notice = f"{created} certificate(s) created for registered subject(s). " + ("; ".join(messages[:2]))
        with connect_db() as conn:
            devices = conn.execute(
                """
                SELECT devices.*, users.first_name, users.middle_name, users.surname, users.identifier, users.department, users.faculty
                FROM devices LEFT JOIN users ON users.id = devices.user_id
                WHERE NOT EXISTS (
                    SELECT 1 FROM certificates
                    WHERE certificates.subject_type = 'Device'
                      AND certificates.subject_id = devices.id
                      AND certificates.status != 'Revoked'
                )
                ORDER BY devices.device_type, devices.mac_address
                """
            ).fetchall()
        single_options = []
        for device in devices:
            label = device_option_label(device)
            single_options.append(
                f"<option value=\"{device['id']}\" data-search=\"{esc(label)}\">{esc(label)}</option>"
            )
        device_options = "".join(
            f"<option value=\"{device['id']}\" data-search=\"{esc(device_option_label(device))}\">{esc(device_option_label(device))}</option>"
            for device in devices
        )
        no_subjects = "" if single_options else '<p class="helper">No registered device is currently eligible. Register a device or revoke its existing certificate before creating another.</p>'
        content = f"""
<section class="panel form-panel">
  {no_subjects}
  <form method="post">
    <label>Creation Mode<select name="mode" data-cert-mode><option value="single">Single Certificate</option><option value="batch">Batched Certificates</option></select></label>
    <label data-single-cert-field>Search Registered Device<input data-select-filter="single-device-select" placeholder="Type MAC, name, department, faculty, identifier, or function"></label>
    <label data-single-cert-field>Registered Devices<select id="single-device-select" name="single_subject"><option value="">Select registered device</option>{"".join(single_options)}</select></label>
    <label data-single-cert-field>Serial Number<input name="serial_number" placeholder="Leave blank to auto-generate"></label>
    <label data-batch-cert-field>Search Batch Devices<input data-select-filter="batch-device-select" placeholder="Type MAC, name, department, faculty, identifier, or function"></label>
    <label data-batch-cert-field>Batch Devices<select id="batch-device-select" name="device_ids" multiple size="8">{device_options}</select></label>
    <label data-batch-cert-field>Batch Serial Prefix<input name="serial_prefix" value="CERT"></label>
    <label>Validity Days<input type="number" min="1" max="3650" name="valid_days" value="365"></label>
    <button type="submit">Create Certificate</button>
  </form>
</section>
"""
        return Response(self.render("Create Certificate", "Create Certificate", content, notice))

    def deploy_certificate(self, form: dict[str, str] | None = None) -> Response:
        notice = ""
        if form:
            cert_ids = [int(value) for value in form_list(form, "certificate_ids")]
            if form.get("deploy_all") == "1":
                with connect_db() as conn:
                    cert_ids = [
                        row["id"]
                        for row in conn.execute("SELECT id FROM certificates WHERE status = 'Issued' AND deployed_at IS NULL ORDER BY id").fetchall()
                    ]
            deployed = 0
            messages = []
            with connect_db() as conn:
                certs_to_deploy = [
                    conn.execute("SELECT * FROM certificates WHERE id = ? AND status = 'Issued' AND deployed_at IS NULL", (cert_id,)).fetchone()
                    for cert_id in cert_ids
                ]
            deployed_ids: list[int] = []
            deployed_serials: list[str] = []
            for cert in certs_to_deploy:
                if cert:
                    ok, message, _ = build_deployment_bundle(cert)
                    if not ok:
                        messages.append(f"Certificate {cert['serial_number']} skipped: {message}")
                        continue
                    deployed_ids.append(cert["id"])
                    deployed_serials.append(cert["serial_number"])
                    deployed += 1
            if deployed_ids:
                with connect_db() as conn:
                    conn.executemany("UPDATE certificates SET deployed_at = CURRENT_TIMESTAMP WHERE id = ?", [(cert_id,) for cert_id in deployed_ids])
                for serial in deployed_serials:
                    audit("Deploy Certificate", serial)
            notice = f"{deployed} certificate(s) deployed." + (" " + " ".join(messages[:3]) if messages else "")
        with connect_db() as conn:
            certs = conn.execute(
                """
                SELECT certificates.*, devices.mac_address, devices.device_identifier, devices.function,
                       users.first_name, users.middle_name, users.surname, users.identifier, users.department, users.faculty
                FROM certificates
                LEFT JOIN devices ON devices.id = certificates.subject_id AND certificates.subject_type = 'Device'
                LEFT JOIN users ON users.id = devices.user_id
                WHERE certificates.status = 'Issued' AND certificates.deployed_at IS NULL
                ORDER BY certificates.id DESC
                """
            ).fetchall()
        options = "".join(
            f"<option value=\"{c['id']}\" data-search=\"{esc(c['serial_number'])} {esc(c['common_name'])} {esc(c['mac_address'])} {esc(c['device_identifier'])} {esc(c['function'])} {esc(display_name(c['first_name'], c['middle_name'], c['surname']))} {esc(c['identifier'])} {esc(c['department'])} {esc(c['faculty'])}\">{esc(c['serial_number'])} - {esc(c['mac_address'])} - {esc(c['common_name'])}</option>"
            for c in certs
        )
        content = f"""
<section class="panel form-panel">
  <form method="post">
    <label>Search Undeployed Certificates<input data-select-filter="deploy-cert-select" placeholder="Type serial, MAC, user, department, faculty, or function"></label>
    <label>Undeployed Certificates<select id="deploy-cert-select" name="certificate_ids" multiple size="8">{options}</select></label>
    <button type="submit">Deploy Selected</button>
    <button type="submit" name="deploy_all" value="1">Deploy All Undeployed</button>
  </form>
</section>
"""
        return Response(self.render("Deploy Certificate", "Deploy Certificate", content, notice))

    def renew_certificate(self, form: dict[str, str] | None = None) -> Response:
        notice = ""
        if form:
            valid_days = int(form.get("valid_days") or "365")
            cert_ids = [int(value) for value in form_list(form, "certificate_ids")]
            renewed = 0
            messages = []
            with connect_db() as conn:
                renewable_certs = [
                    conn.execute(
                        """
                        SELECT * FROM certificates
                        WHERE id = ?
                          AND (status = 'Revoked' OR status = 'Expired' OR date(valid_to) < date('now'))
                          AND NOT EXISTS (SELECT 1 FROM certificates child WHERE child.renewed_from = certificates.id)
                        """,
                        (cert_id,),
                    ).fetchone()
                    for cert_id in cert_ids
                ]
            renewal_updates: list[tuple[int, str, str, str]] = []
            for old in renewable_certs:
                if not old:
                    continue
                serial = f"REN-{now_slug()}-{old['id']}"
                ok, message, _paths = create_certificate(old["common_name"], serial, valid_days, old["subject_type"], old["subject_id"])
                messages.append(message)
                if ok:
                    renewal_updates.append((old["id"], serial, old["serial_number"], old["status"]))
                    renewed += 1
            if renewal_updates:
                with connect_db() as conn:
                    for old_id, serial, _old_serial, old_status in renewal_updates:
                        if old_status != "Revoked":
                            conn.execute("UPDATE certificates SET status = 'Renewed' WHERE id = ?", (old_id,))
                        conn.execute("UPDATE certificates SET renewed_from = ? WHERE serial_number = ?", (old_id, serial))
                for _old_id, _serial, old_serial, old_status in renewal_updates:
                    audit("Renew Certificate", f"{old_serial} renewed from {old_status}; original status preserved where revoked")
            notice = f"{renewed} certificate(s) renewed. " + ("; ".join(messages[:2]))
        with connect_db() as conn:
            certs = conn.execute(
                """
                SELECT certificates.*, devices.mac_address, devices.device_identifier, devices.function,
                       users.first_name, users.middle_name, users.surname, users.identifier, users.department, users.faculty
                FROM certificates
                LEFT JOIN devices ON devices.id = certificates.subject_id AND certificates.subject_type = 'Device'
                LEFT JOIN users ON users.id = devices.user_id
                WHERE (certificates.status = 'Revoked' OR certificates.status = 'Expired' OR date(certificates.valid_to) < date('now'))
                  AND NOT EXISTS (SELECT 1 FROM certificates child WHERE child.renewed_from = certificates.id)
                ORDER BY certificates.id DESC
                """
            ).fetchall()
        options = "".join(
            f"<option value=\"{c['id']}\" data-search=\"{esc(c['serial_number'])} {esc(c['common_name'])} {esc(c['mac_address'])} {esc(c['device_identifier'])} {esc(c['function'])} {esc(display_name(c['first_name'], c['middle_name'], c['surname']))} {esc(c['identifier'])} {esc(c['department'])} {esc(c['faculty'])}\">{esc(c['serial_number'])} - {esc(c['status'])} - {esc(c['mac_address'])} - {esc(c['common_name'])}</option>"
            for c in certs
        )
        content = f"""
<section class="panel form-panel">
  <form method="post">
    <label>Search Renewable Certificates<input data-select-filter="renew-cert-select" placeholder="Type serial, MAC, user, department, faculty, or function"></label>
    <label>Expired or Revoked Certificates<select id="renew-cert-select" name="certificate_ids" multiple size="8">{options}</select></label>
    <label>New Validity Days<input type="number" min="1" max="3650" name="valid_days" value="365"></label>
    <button type="submit">Renew Selected</button>
  </form>
</section>
"""
        return Response(self.render("Renew Certificate", "Renew Certificate", content, notice))

    def revoke_certificate(self, form: dict[str, str] | None = None) -> Response:
        notice = ""
        if form:
            cert_id = int(form["certificate_id"])
            reason = form["revoke_reason"]
            with connect_db() as conn:
                conn.execute(
                    "UPDATE certificates SET status = 'Revoked', revoked_at = CURRENT_TIMESTAMP, revoke_reason = ? WHERE id = ?",
                    (reason, cert_id),
                )
            refresh_local_crl()
            audit("Revoke Certificate", f"{cert_id}: {reason}")
            notice = "Certificate revoked and local certificate revocation list refreshed."
        with connect_db() as conn:
            certs = conn.execute("SELECT * FROM certificates WHERE status = 'Issued' ORDER BY id DESC").fetchall()
        options = "".join(f"<option value=\"{c['id']}\">{esc(c['serial_number'])} - {esc(c['common_name'])}</option>" for c in certs)
        content = f"""
<section class="panel form-panel">
  <form method="post">
    <label>Certificate<select name="certificate_id" required>{options}</select></label>
    <label>Reason<select name="revoke_reason"><option>Key compromise</option><option>User left institution</option><option>Device lost</option><option>Certificate superseded</option><option>Administrative revocation</option></select></label>
    <button type="submit">Revoke Certificate</button>
  </form>
</section>
"""
        return Response(self.render("Revoke Certificate", "Revoke Certificate", content, notice))

    def infrastructure_devices(self) -> Response:
        with connect_db() as conn:
            devices = conn.execute(
                """
                SELECT *
                FROM devices
                WHERE device_type IN ('Access', 'Server')
                ORDER BY device_type, location_faculty, location_department, mac_address
                """
            ).fetchall()
        rows = "".join(
            f"<tr><td>{esc(d['device_type'])}</td><td>{esc(d['mac_address'])}</td><td>{esc(d['device_identifier'])}</td><td>{esc(d['function'])}</td><td>{esc(d['location_department'])}</td><td>{esc(d['location_faculty'])}</td></tr>"
            for d in devices
        ) or '<tr><td colspan="6" class="muted">No Access or Server devices registered.</td></tr>'
        content = f"""
<section class="panel">
  <div class="panel-head"><h2>Access and Server Devices</h2></div>
  <table><thead><tr><th>Type</th><th>MAC Address</th><th>Device Identifier</th><th>Function</th><th>Department</th><th>Faculty</th></tr></thead><tbody>{rows}</tbody></table>
</section>
"""
        return Response(self.render("Infrastructure Devices", "Infrastructure Devices", content))

    def user_logs(self) -> Response:
        with connect_db() as conn:
            logs = conn.execute("SELECT * FROM user_logs ORDER BY id DESC LIMIT 200").fetchall()
        rows = "".join(
            f"<tr><td>{esc(log['created_at'])}</td><td>{esc(log['actor_username'] or 'System')}</td><td>{esc(log['action'])}</td><td>{esc(log['user_identifier'])}</td><td>{esc(log['details'])}</td></tr>"
            for log in logs
        ) or '<tr><td colspan="5" class="muted">No user operations logged yet.</td></tr>'
        content = f"""
<section class="panel">
  <div class="panel-head"><h2>User Operation Logs</h2></div>
  <table><thead><tr><th>Date</th><th>Performed By</th><th>Action</th><th>User Identifier</th><th>Details</th></tr></thead><tbody>{rows}</tbody></table>
</section>
"""
        return Response(self.render("User Logs", "User Logs", content))

    def action_logs(self) -> Response:
        with connect_db() as conn:
            logs = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 300").fetchall()
        rows = "".join(
            f"<tr><td>{esc(log['created_at'])}</td><td>{esc(log['actor_username'] or 'System')}</td><td>{esc(log['action'])}</td><td>{esc(log['details'])}</td></tr>"
            for log in logs
        ) or '<tr><td colspan="4" class="muted">No application actions logged yet.</td></tr>'
        content = f"""
<section class="panel">
  <div class="panel-head"><h2>Application Action Logs</h2></div>
  <table><thead><tr><th>Date</th><th>Performed By</th><th>Action</th><th>Details</th></tr></thead><tbody>{rows}</tbody></table>
</section>
"""
        return Response(self.render("Action Logs", "Action Logs", content))

    def settings(self, form: dict[str, str] | None = None) -> Response:
        notice = ""
        if form:
            with connect_db() as conn:
                conn.execute(
                    """
                    UPDATE settings SET
                        openssl_mode = ?, openssl_server_ip = ?, openssl_username = ?, openssl_password = ?,
                        openssl_path = ?, remote_base_path = ?, remote_ssh_key_path = ?,
                        organization = ?, ca_common_name = ?, default_valid_days = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = 1
                    """,
                    (
                        form["openssl_mode"],
                        form.get("openssl_server_ip"),
                        form.get("openssl_username"),
                        form.get("openssl_password"),
                        form.get("openssl_path") or "openssl",
                        form.get("remote_base_path") or "~/campus_pki_ra",
                        form.get("remote_ssh_key_path"),
                        form.get("organization") or "Nigerian Higher Education Institution",
                        form.get("ca_common_name") or "Campus Wi-Fi Local CA",
                        int(form.get("default_valid_days") or "365"),
                    ),
                )
            save_faculty_departments(form.get("faculty_departments", ""))
            audit("Update Settings", "Server and CA parameters updated")
            notice = "Settings saved."
        s = get_settings()
        detected_openssl = bundled_openssl_hint()
        effective_openssl = resolve_openssl_path(s["openssl_path"])
        content = f"""
<section class="panel form-panel wide">
  <p class="helper">{esc(detected_openssl)}. Effective command: {esc(effective_openssl)}</p>
  <form method="post">
    <label>OpenSSL Mode<select name="openssl_mode"><option {"selected" if s["openssl_mode"] == "local" else ""} value="local">Local OpenSSL on this computer</option><option {"selected" if s["openssl_mode"] == "remote" else ""} value="remote">Remote OpenSSL server</option></select></label>
    <label>OpenSSL Server IP<input name="openssl_server_ip" value="{esc(s['openssl_server_ip'])}"></label>
    <label>OpenSSL Username<input name="openssl_username" value="{esc(s['openssl_username'])}"></label>
    <label>OpenSSL Password<input type="password" name="openssl_password" value="{esc(s['openssl_password'])}"></label>
    <label>OpenSSL Executable Path<input name="openssl_path" value="{esc(s['openssl_path'])}" placeholder="Leave as openssl unless using a custom path"></label>
    <label>Remote Repository Path<input name="remote_base_path" value="{esc(s['remote_base_path'])}" placeholder="~/campus_pki_ra"></label>
    <label>Remote SSH Key Path<input name="remote_ssh_key_path" value="{esc(s['remote_ssh_key_path'])}" placeholder="Optional key path for ssh/scp"></label>
    <label>Institution / Organization<input name="organization" value="{esc(s['organization'])}"></label>
    <label>CA Common Name<input name="ca_common_name" value="{esc(s['ca_common_name'])}"></label>
    <label>Default Validity Days<input type="number" min="1" max="3650" name="default_valid_days" value="{esc(s['default_valid_days'])}"></label>
    <label class="span-all">Faculties and Departments<textarea name="faculty_departments" rows="8" placeholder="Science: Computer Science, Mathematics&#10;Engineering: Electrical Engineering, Mechanical Engineering">{esc(faculty_departments_text())}</textarea></label>
    <button type="submit">Save Settings</button>
  </form>
</section>
"""
        return Response(self.render("Settings", "Settings", content, notice))

    def route(self, method: str, path: str, body: bytes, content_type: str = "", cookie_header: str = "") -> Response:
        global CURRENT_ACTOR
        parsed_url = urllib.parse.urlparse(path)
        request_path = parsed_url.path
        query = urllib.parse.parse_qs(parsed_url.query)
        CURRENT_ACTOR = "System"
        if method == "POST":
            form = parse_multipart(body, content_type) if content_type.startswith("multipart/form-data") else parse_form(body)
        else:
            form = None
        if request_path == "/setup":
            return self.setup_page(form)
        if request_path == "/login":
            return self.login_page(form)
        if request_path == "/logout":
            return self.logout(cookie_header)
        self.current_user = current_admin(cookie_header)
        if not self.current_user:
            return redirect("/setup" if admin_account_count() == 0 else "/login")
        CURRENT_ACTOR = self.current_user["username"]
        protected_paths = {item["path"] for item in MENU_ITEMS}
        if request_path in protected_paths and not can_access(self.current_user, request_path):
            return Response(self.render("Dashboard", "Access Denied", '<section class="panel">Your account role does not have permission to access this menu.</section>'), 403)
        if request_path == "/download-certificate":
            if not can_access(self.current_user, "/"):
                return Response(self.render("Dashboard", "Access Denied", '<section class="panel">Your account role does not have permission to access this download.</section>'), 403)
            return self.download_certificate(query)
        if request_path == "/":
            return self.dashboard()
        if request_path == "/register-user":
            return self.register_user(form)
        if request_path == "/register-device":
            return self.register_device(form)
        if request_path == "/create-certificate":
            return self.create_certificate_page(form)
        if request_path == "/deploy-certificate":
            return self.deploy_certificate(form)
        if request_path == "/renew-certificate":
            return self.renew_certificate(form)
        if request_path == "/revoke-certificate":
            return self.revoke_certificate(form)
        if request_path == "/infrastructure-devices":
            return self.infrastructure_devices()
        if request_path == "/user-logs":
            return self.user_logs()
        if request_path == "/action-logs":
            return self.action_logs()
        if request_path == "/settings":
            return self.settings(form)
        if request_path == "/admin-accounts":
            return self.admin_accounts(form)
        if request_path == "/health":
            return Response(json.dumps({"ok": True}), headers={"Content-Type": "application/json"})
        return Response(self.render("Dashboard", "Not Found", "<section class=\"panel\">Page not found.</section>"), 404)


CSS = r"""
:root {
  --ink: #18212f;
  --muted: #647083;
  --line: #d9e1ea;
  --panel: #ffffff;
  --bg: #f4f7fb;
  --nav: #142033;
  --nav-2: #1f6f78;
  --accent: #2d7d46;
  --warn: #a45f12;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: Arial, Helvetica, sans-serif;
  color: var(--ink);
  background: var(--bg);
  display: grid;
  grid-template-columns: 280px 1fr;
  min-height: 100vh;
}
.auth-body {
  display: block;
  background: #fff;
}
.auth-shell {
  min-height: 100vh;
  display: grid;
  grid-template-columns: minmax(420px, 47vw) 1fr;
}
.auth-form-panel {
  display: flex;
  flex-direction: column;
  justify-content: center;
  padding: 48px min(9vw, 96px);
  background: #fff;
}
.auth-logo {
  display: flex;
  align-items: center;
  gap: 14px;
  margin-bottom: 82px;
  color: #062b4a;
}
.auth-mark {
  width: 56px;
  height: 56px;
  display: grid;
  place-items: center;
  background: linear-gradient(135deg, #0b375c 0 44%, #e25345 45% 55%, #f5f7fb 56%);
  color: transparent;
  border-radius: 2px;
}
.auth-logo strong {
  display: block;
  font-size: 34px;
  letter-spacing: 3px;
}
.auth-logo small {
  display: block;
  font-size: 12px;
  letter-spacing: 4px;
}
.auth-heading {
  text-align: center;
  margin-bottom: 44px;
}
.auth-heading h1 {
  font-size: 34px;
  margin-bottom: 22px;
}
.auth-heading p {
  font-size: 21px;
  color: #294766;
}
.auth-form {
  display: grid;
  grid-template-columns: 1fr;
  gap: 24px;
}
.auth-form input {
  min-height: 72px;
  border-radius: 10px;
  font-size: 22px;
  padding: 14px 20px;
}
.auth-form button {
  min-height: 72px;
  margin-top: 28px;
  background: #c2a383;
  border-radius: 10px;
  font-size: 22px;
}
.auth-notice {
  border: 1px solid #f0c9c0;
  background: #fff5f2;
  color: #933925;
  padding: 12px 14px;
  border-radius: 8px;
  margin-bottom: 18px;
}
.auth-visual {
  position: relative;
  min-height: 100vh;
  overflow: hidden;
  background:
    linear-gradient(90deg, rgba(20, 32, 51, .15), rgba(20, 32, 51, .62)),
    radial-gradient(circle at 72% 24%, rgba(255,255,255,.65), transparent 20%),
    linear-gradient(135deg, #33656c 0%, #b5765e 48%, #3b2e2a 100%);
}
.auth-visual::before {
  content: "";
  position: absolute;
  inset: 0;
  background:
    linear-gradient(115deg, transparent 0 34%, rgba(255,255,255,.16) 35% 36%, transparent 37%),
    repeating-linear-gradient(90deg, rgba(255,255,255,.04) 0 1px, transparent 1px 80px);
}
.auth-visual-copy {
  position: absolute;
  left: 7.5%;
  right: 7.5%;
  bottom: 12%;
  color: white;
}
.auth-visual-copy h2 {
  font-size: clamp(44px, 5.4vw, 78px);
  line-height: 1.12;
  margin: 0 0 22px;
}
.auth-visual-copy p {
  color: rgba(255,255,255,.92);
  font-size: clamp(20px, 2vw, 32px);
  line-height: 1.35;
  max-width: 760px;
}
.sidebar {
  background: var(--nav);
  color: white;
  padding: 22px 18px;
}
.brand {
  display: flex;
  gap: 12px;
  align-items: center;
  padding-bottom: 22px;
  border-bottom: 1px solid rgba(255,255,255,.14);
}
.mark {
  width: 48px;
  height: 48px;
  display: grid;
  place-items: center;
  background: var(--nav-2);
  border-radius: 6px;
  font-weight: 700;
}
.brand small { display: block; color: #b7c4d6; margin-top: 3px; }
nav { display: grid; gap: 7px; margin-top: 20px; }
.nav-link {
  color: #e7edf6;
  text-decoration: none;
  padding: 12px 12px;
  border-radius: 6px;
}
.nav-link.active, .nav-link:hover { background: rgba(255,255,255,.12); }
.account-box {
  margin-top: 22px;
  padding: 14px 12px;
  border-top: 1px solid rgba(255,255,255,.14);
  display: grid;
  gap: 4px;
}
.account-box small { color: #b7c4d6; }
.account-box a { color: #fff; margin-top: 8px; }
.main { padding: 28px; min-width: 0; }
.topbar {
  display: flex;
  justify-content: space-between;
  gap: 20px;
  align-items: flex-start;
  margin-bottom: 22px;
}
h1 { margin: 0 0 6px; font-size: 28px; letter-spacing: 0; }
h2 { margin: 0; font-size: 18px; letter-spacing: 0; }
p { margin: 0; color: var(--muted); line-height: 1.45; }
.status-dot {
  border: 1px solid var(--line);
  background: #fff;
  padding: 8px 10px;
  border-radius: 6px;
  color: var(--accent);
  white-space: nowrap;
}
.metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(140px, 1fr));
  gap: 14px;
  margin-bottom: 18px;
}
.metric, .panel, .notice {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
}
.metric { padding: 16px; }
.metric span { color: var(--muted); display: block; margin-bottom: 8px; }
.metric strong { font-size: 30px; }
.panel { padding: 18px; margin-bottom: 18px; overflow-x: auto; }
.panel-head { margin-bottom: 14px; }
.helper {
  margin: 0 0 16px;
  padding: 10px 12px;
  background: #f7f9fc;
  border: 1px solid var(--line);
  border-radius: 6px;
  color: var(--muted);
}
.notice {
  padding: 12px 14px;
  margin-bottom: 18px;
  border-color: #bfd8c8;
  background: #f0faf3;
  color: #245b35;
}
form {
  display: grid;
  grid-template-columns: repeat(2, minmax(220px, 1fr));
  gap: 14px;
  align-items: end;
}
.wide form { grid-template-columns: repeat(3, minmax(210px, 1fr)); }
label { display: grid; gap: 6px; font-size: 13px; color: var(--muted); }
input, select, textarea {
  min-height: 40px;
  border: 1px solid #cbd6e2;
  border-radius: 6px;
  padding: 9px 10px;
  font: inherit;
  color: var(--ink);
  background: white;
  width: 100%;
}
textarea { resize: vertical; }
.span-all { grid-column: 1 / -1; }
.check-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(180px, 1fr));
  gap: 10px;
  align-items: start;
}
.check-row {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--ink);
}
.check-row input {
  width: auto;
  min-height: auto;
}
select[multiple] {
  min-height: 148px;
}
button {
  min-height: 40px;
  border: 0;
  border-radius: 6px;
  padding: 10px 14px;
  background: var(--accent);
  color: white;
  font-weight: 700;
  cursor: pointer;
}
button:hover { filter: brightness(.94); }
.inline-form {
  display: inline-grid;
  grid-template-columns: 1fr;
  margin-right: 6px;
}
.inline-form button {
  min-height: 32px;
  padding: 6px 10px;
}
.mini-button {
  display: inline-block;
  margin: 2px 4px 2px 0;
  border-radius: 5px;
  padding: 7px 9px;
  background: var(--accent);
  color: white;
  font-size: 12px;
  font-weight: 700;
  text-decoration: none;
}
.mini-button:hover { filter: brightness(.94); }
.actions-cell {
  white-space: nowrap;
}
table { width: 100%; border-collapse: collapse; min-width: 640px; }
th, td { text-align: left; border-bottom: 1px solid var(--line); padding: 11px 10px; vertical-align: top; }
th { color: var(--muted); font-size: 13px; font-weight: 700; }
.muted { color: var(--muted); }
.hidden { display: none !important; }
@media (max-width: 900px) {
  .auth-shell { grid-template-columns: 1fr; }
  .auth-form-panel { min-height: 100vh; padding: 32px 20px; }
  .auth-visual { display: none; }
  body { grid-template-columns: 1fr; }
  .sidebar { position: static; }
  nav { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .main { padding: 18px; }
  .topbar { display: grid; }
  .metrics { grid-template-columns: repeat(2, 1fr); }
  form, .wide form { grid-template-columns: 1fr; }
}
"""


JS = r"""
function setHidden(element, hidden) {
  if (!element) return;
  element.classList.toggle("hidden", hidden);
  element.querySelectorAll("input, select").forEach((field) => {
    field.disabled = hidden;
  });
}

function syncUserType() {
  const type = document.querySelector("[data-user-type]");
  const label = document.querySelector("[data-identifier-label]");
  if (!type || !label) return;
  label.textContent = type.value === "Staff" ? "Staff Number" : "Matriculation Number";
}

function syncDeviceType() {
  const type = document.querySelector("[data-device-type]");
  if (!type) return;
  const isUser = type.value === "User";
  document.querySelectorAll("[data-user-device-field]").forEach((field) => setHidden(field, !isUser));
  document.querySelectorAll("[data-server-device-field]").forEach((field) => setHidden(field, isUser));
}

function syncCertificateMode() {
  const mode = document.querySelector("[data-cert-mode]");
  if (!mode) return;
  const isBatch = mode.value === "batch";
  document.querySelectorAll("[data-single-cert-field]").forEach((field) => setHidden(field, isBatch));
  document.querySelectorAll("[data-batch-cert-field]").forEach((field) => setHidden(field, !isBatch));
}

function syncDepartmentSelect(facultySelect) {
  const form = facultySelect.closest("form") || document;
  const departmentSelect = form.querySelector('[data-department-select]');
  if (!departmentSelect) return;
  const selected = departmentSelect.value;
  const departments = (window.FACULTY_DEPARTMENTS || {})[facultySelect.value] || [];
  departmentSelect.innerHTML = '<option value="">Select department</option>';
  departments.forEach((department) => {
    const option = document.createElement("option");
    option.value = department;
    option.textContent = department;
    option.selected = department === selected;
    departmentSelect.appendChild(option);
  });
}

function syncSelectFilter(input) {
  const select = document.getElementById(input.dataset.selectFilter);
  if (!select) return;
  const query = input.value.trim().toLowerCase();
  Array.from(select.options).forEach((option) => {
    if (!option.value) {
      option.hidden = false;
      return;
    }
    const haystack = `${option.textContent || ""} ${option.dataset.search || ""}`.toLowerCase();
    const visible = !query || haystack.includes(query);
    option.hidden = !visible;
    if (!visible) option.selected = false;
  });
}

document.addEventListener("DOMContentLoaded", () => {
  syncUserType();
  syncDeviceType();
  syncCertificateMode();
  document.querySelector("[data-user-type]")?.addEventListener("change", syncUserType);
  document.querySelector("[data-device-type]")?.addEventListener("change", syncDeviceType);
  document.querySelector("[data-cert-mode]")?.addEventListener("change", syncCertificateMode);
  document.querySelectorAll("[data-faculty-select]").forEach((select) => {
    syncDepartmentSelect(select);
    select.addEventListener("change", () => syncDepartmentSelect(select));
  });
  document.querySelectorAll("[data-select-filter]").forEach((input) => {
    syncSelectFilter(input);
    input.addEventListener("input", () => syncSelectFilter(input));
  });
});
"""


class Handler(BaseHTTPRequestHandler):
    app = App()

    def do_GET(self) -> None:
        self.handle_request()

    def do_POST(self) -> None:
        self.handle_request()

    def handle_request(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/static/styles.css":
            self.send_response(200)
            self.send_header("Content-Type", "text/css; charset=utf-8")
            self.end_headers()
            self.wfile.write(CSS.encode("utf-8"))
            return
        if parsed.path == "/static/app.js":
            self.send_response(200)
            self.send_header("Content-Type", "text/javascript; charset=utf-8")
            self.end_headers()
            self.wfile.write(JS.encode("utf-8"))
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        try:
            route_path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
            response = self.app.route(self.command, route_path, body, self.headers.get("Content-Type", ""), self.headers.get("Cookie", ""))
        except Exception as exc:
            response = Response(
                self.app.render(
                    "Dashboard",
                    "Application Error",
                    f"<section class=\"panel\"><pre>{esc(type(exc).__name__)}: {esc(exc)}</pre></section>",
                ),
                500,
            )
        self.send_response(response.status)
        headers = response.headers or {"Content-Type": "text/html; charset=utf-8"}
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        if isinstance(response.body, bytes):
            self.wfile.write(response.body)
        else:
            self.wfile.write(response.body.encode("utf-8"))

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))


def run_server(host: str = APP_HOST, port: int = APP_PORT) -> None:
    init_db()
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Campus PKI RA app running at http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    run_server()
