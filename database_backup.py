import base64
import json
import os

import dns_rotation
import host_monitor

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"TVPS-BACKUP-1\n"
MAX_SIZE = 8 * 1024 * 1024
SUFFIX = ".tvps"
# s = encrypted text at rest, i = integer, t = text, ? = nullable
TABLES = {
    "admins": (("user_id", "i"),),
    "servers": (("id", "i"), ("user_id", "i"), ("host", "t"), ("port", "i"), ("username", "t"), ("secret", "s?")),
    "server_folders": (("id", "i"), ("user_id", "i"), ("name", "t")),
    "server_folder_members": (("server_id", "i"), ("folder_id", "i")),
    "kamatera_accounts": (("user_id", "i"), ("credentials", "s"), ("command_id", "t?")),
    "linode_accounts": (("user_id", "i"), ("token", "s")),
    "hetzner_projects": (("id", "i"), ("user_id", "i"), ("name", "t"), ("token", "s")),
    "cloudflare_accounts": (("user_id", "i"), ("token", "s")),
    "vultr_accounts": (("user_id", "i"), ("token", "s")),
    "host_monitors": (("user_id", "i"), ("hosts", "t"), ("next_at", "i")),
    "dns_rotations": (("id", "i"), ("user_id", "i"), ("zone_id", "t"), ("record_id", "t"),
                      ("name", "t"), ("kind", "t"), ("expected", "t"), ("steps", "t"),
                      ("due_at", "i"), ("attempts", "n"), ("status", "t"), ("note", "t")),
}


class BackupError(Exception):
    pass


def password_cipher(password, salt):
    key = Scrypt(salt=salt, length=32, n=2**16, r=8, p=1).derive(password.encode())
    return Fernet(base64.urlsafe_b64encode(key))


def snapshot(db):
    return {
        table: db.execute(f"SELECT {', '.join(name for name, _ in columns)} FROM {table}").fetchall()
        for table, columns in TABLES.items()
    }


def export_file(rows, storage_cipher, password):
    try:
        contents = {
            table: [
                [base64.b64encode(storage_cipher.decrypt(value)).decode("ascii") if kind.startswith("s") and value is not None else value
                 for value, (_, kind) in zip(row, TABLES[table])]
                for row in entries
            ]
            for table, entries in rows.items()
        }
    except InvalidToken:
        raise BackupError("Cannot decrypt stored credentials") from None
    data = json.dumps(contents, ensure_ascii=False, separators=(",", ":")).encode()
    if len(data) > MAX_SIZE * 3 // 4 - 128:
        raise BackupError("Backup too large")
    salt = os.urandom(16)
    result = MAGIC + salt + password_cipher(password, salt).encrypt(data)
    if len(result) > MAX_SIZE:
        raise BackupError("Backup too large")
    return result


def restore_file(data, password, storage_cipher):
    if not len(MAGIC) + 16 < len(data) <= MAX_SIZE or not data.startswith(MAGIC):
        raise BackupError("Invalid backup")
    end = len(MAGIC) + 16
    try:
        payload = password_cipher(password, data[len(MAGIC):end]).decrypt(data[end:])
        contents = json.loads(payload)
        optional = {"dns_rotations", "vultr_accounts", "server_folders", "server_folder_members", "host_monitors"}
        if not isinstance(contents, dict) or not TABLES.keys() - optional <= contents.keys() <= TABLES.keys():
            raise ValueError
        rows = {table: restore_rows(contents.get(table, []), columns, storage_cipher) for table, columns in TABLES.items()}
        servers = {row[0]: row[1] for row in rows["servers"]}
        folders = {row[0]: row[1] for row in rows["server_folders"]}
        for server_id, folder_id in rows["server_folder_members"]:
            if server_id not in servers or folder_id not in folders or servers[server_id] != folders[folder_id]:
                raise ValueError
        for _, hosts, next_at in rows["host_monitors"]:
            if next_at > 253402200000:
                raise ValueError
            host_monitor.read_hosts(hosts)
        for fields in rows["dns_rotations"]:
            rotation = dns_rotation.Rotation(*fields)
            if rotation.status not in {"active", "done", "failed", "cancelled"} or rotation.due_at > 253402200000:
                raise ValueError
            dns_rotation.read_steps(rotation)
        return rows
    except (InvalidToken, ValueError, RecursionError):
        raise BackupError("Invalid backup or password") from None


def restore_rows(entries, columns, cipher):
    if not isinstance(entries, list):
        raise ValueError
    result = []
    for row in entries:
        if not isinstance(row, list) or len(row) != len(columns):
            raise ValueError
        normalized = []
        for value, (name, kind) in zip(row, columns):
            if value is None and kind.endswith("?"):
                normalized.append(None)
            elif kind == "i" and type(value) is int and 0 < value < 2**63 and (name != "port" or value <= 65535):
                normalized.append(value)
            elif kind == "n" and type(value) is int and 0 <= value < 2**63:
                normalized.append(value)
            elif kind.startswith("t") and isinstance(value, str):
                normalized.append(value)
            elif kind.startswith("s") and isinstance(value, str):
                normalized.append(cipher.encrypt(base64.b64decode(value, validate=True)))
            else:
                raise ValueError
        result.append(normalized)
    return result


def replace_data(db, rows):
    with db:
        for table in reversed(TABLES):
            db.execute(f"DELETE FROM {table}")
        for table, columns in TABLES.items():
            names = ", ".join(name for name, _ in columns)
            markers = ", ".join("?" for _ in columns)
            db.executemany(f"INSERT INTO {table} ({names}) VALUES ({markers})", rows[table])
