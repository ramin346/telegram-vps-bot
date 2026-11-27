import base64
import json
import os

import dns_rotation
import host_monitor
import replacement

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
    "cloud_saved_names": (("server_id", "i"), ("name", "t")),
    "cloud_saved_pending": (("id", "i"), ("user_id", "i"), ("provider", "t"), ("remote_id", "t"),
                            ("account_id", "i?"), ("folder_id", "i"), ("region", "t"), ("name", "t"),
                            ("username", "t"), ("secret", "s?"), ("next_at", "i"), ("expires_at", "i"), ("status", "t")),
    "kamatera_accounts": (("user_id", "i"), ("credentials", "s"), ("command_id", "t?")),
    "linode_accounts": (("user_id", "i"), ("token", "s")),
    "hetzner_projects": (("id", "i"), ("user_id", "i"), ("name", "t"), ("token", "s")),
    "cloudflare_accounts": (("user_id", "i"), ("token", "s")),
    "cloudflare_profiles": (("id", "i"), ("user_id", "i"), ("name", "t"), ("token", "s")),
    "vultr_accounts": (("user_id", "i"), ("token", "s")),
    "cherry_accounts": (("user_id", "i"), ("token", "s")),
    "host_monitors": (("user_id", "i"), ("hosts", "t"), ("next_at", "i")),
    "host_monitor_settings": (("user_id", "i"), ("interval", "i")),
    "node_replacements": (
        ("id", "i"), ("user_id", "i"), ("rotation_id", "i"), ("target", "t"), ("provider", "t"),
        ("account_id", "i?"), ("project_id", "i?"), ("recipe", "s?"), ("old_id", "t?"),
        ("state", "t"), ("next_at", "i"), ("remote_id", "t?"), ("deadline", "i"), ("evidence", "n"), ("note", "t"),
    ),
    "dns_rotations": (("id", "i"), ("user_id", "i"), ("zone_id", "t"), ("record_id", "t"),
                      ("name", "t"), ("kind", "t"), ("expected", "t"), ("steps", "t"),
                      ("due_at", "i"), ("attempts", "n"), ("status", "t"), ("note", "t"), ("account_id", "i?")),
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
        optional = {"node_replacements", "host_monitor_settings", "cherry_accounts", "cloud_saved_names", "cloud_saved_pending", "dns_rotations", "vultr_accounts", "server_folders", "server_folder_members", "host_monitors", "cloudflare_profiles"}
        if not isinstance(contents, dict) or not TABLES.keys() - optional <= contents.keys() <= TABLES.keys():
            raise ValueError
        rotations = contents.get("dns_rotations", [])
        if isinstance(rotations, list):
            contents["dns_rotations"] = [
                row + [None] if isinstance(row, list) and len(row) == len(TABLES["dns_rotations"]) - 1 else row
                for row in rotations
            ]
        rows = {table: restore_rows(contents.get(table, []), columns, storage_cipher) for table, columns in TABLES.items()}
        servers = {row[0]: row[1] for row in rows["servers"]}
        folders = {row[0]: row[1] for row in rows["server_folders"]}
        for server_id, folder_id in rows["server_folder_members"]:
            if server_id not in servers or folder_id not in folders or servers[server_id] != folders[folder_id]:
                raise ValueError
        for pending in rows["cloud_saved_pending"]:
            _, user_id, provider, remote, account, folder, *_rest, status = pending
            if folders.get(folder) != user_id or provider not in {"kamatera", "hetzner", "linode", "vultr", "cherry"}:
                raise ValueError
            if status not in {"pending", "failed"} or not remote or (provider in {"hetzner", "linode", "cherry"} and not remote.isdecimal()):
                raise ValueError
            if provider == "hetzner" and account not in {row[0] for row in rows["hetzner_projects"] if row[1] == user_id}:
                raise ValueError
        for _, hosts, next_at in rows["host_monitors"]:
            if next_at > 253402200000:
                raise ValueError
            host_monitor.read_hosts(hosts)
        profiles = {row[0]: row[1] for row in rows["cloudflare_profiles"]}
        for fields in rows["dns_rotations"]:
            rotation = dns_rotation.Rotation(*fields)
            if rotation.status not in {"active", "done", "failed", "cancelled"} or rotation.due_at > 253402200000:
                raise ValueError
            if rotation.account_id is not None and profiles.get(rotation.account_id) != rotation.user_id:
                raise ValueError
            dns_rotation.read_steps(rotation)
        for _, seconds in rows["host_monitor_settings"]:
            if not host_monitor.MIN_INTERVAL <= seconds <= host_monitor.MAX_INTERVAL:
                raise ValueError
        for fields in rows["node_replacements"]:
            rule = replacement.Rule(*fields)
            if rule.provider not in replacement.PROVIDERS or rule.state not in replacement.TERMINAL | {"watching", "creating", "provisioning", "installing", "deleting"}:
                raise ValueError
            if rule.state in {"watching", "provisioning"} and not rule.recipe:
                raise ValueError
            if rule.state == "provisioning" and not rule.remote_id:
                raise ValueError
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
            elif kind.startswith("i") and type(value) is int and 0 < value < 2**63 and (name != "port" or value <= 65535):
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
