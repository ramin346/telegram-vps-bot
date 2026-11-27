from ipaddress import ip_address
import time
from typing import NamedTuple


class PendingServer(NamedTuple):
    id: int
    user_id: int
    provider: str
    remote_id: str
    account_id: int | None
    folder_id: int
    region: str
    name: str
    username: str
    secret: bytes | None
    next_at: int
    expires_at: int
    status: str


def init(db):
    with db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS cloud_saved_names (
                server_id INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE, name TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS cloud_saved_pending (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
                provider TEXT NOT NULL, remote_id TEXT NOT NULL, account_id INTEGER,
                folder_id INTEGER NOT NULL REFERENCES server_folders(id) ON DELETE CASCADE,
                region TEXT NOT NULL, name TEXT NOT NULL, username TEXT NOT NULL, secret BLOB,
                next_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending'
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS cloud_saved_pending_due ON cloud_saved_pending(status, next_at)")


def public_address(values):
    found = []
    for value in values:
        if not isinstance(value, str):
            continue
        try:
            address = ip_address(value.removesuffix("/128"))
        except ValueError:
            continue
        if address.is_global and not address.is_multicast:
            found.append(address)
    return str(min(found, key=lambda address: address.version)) if found else None


def instance_address(provider, instance):
    if provider == "linode":
        return public_address([*(instance.get("ipv4") or []), instance.get("ipv6")])
    if provider == "hetzner":
        public = instance.get("public_net") or {}
        return public_address([(public.get(version) or {}).get("ip") for version in ("ipv4", "ipv6")])
    if provider == "vultr":
        return public_address([instance.get("main_ip"), instance.get("v6_main_ip")])
    if provider == "cherry":
        addresses = instance.get("ip_addresses") or []
        primary = [entry.get("address") for entry in addresses if isinstance(entry, dict) and entry.get("type") == "primary-ip"]
        return public_address(primary) or public_address([entry.get("address") for entry in addresses if isinstance(entry, dict)])
    return public_address([
        ip for network in instance.get("networks") or [] if isinstance(network, dict)
        for ip in network.get("ips") or []
    ])


def save_profile(db, user_id, folder_id, name, username, address, secret):
    db.execute("""
        INSERT INTO servers (user_id, host, port, username, secret) VALUES (?, ?, 22, ?, ?)
        ON CONFLICT (user_id, host, port, username) DO UPDATE SET secret = COALESCE(excluded.secret, servers.secret)
    """, (user_id, address, username, secret))
    server_id = db.execute(
        "SELECT id FROM servers WHERE user_id = ? AND host = ? AND port = 22 AND username = ?",
        (user_id, address, username),
    ).fetchone()[0]
    db.execute("""
        INSERT INTO server_folder_members (server_id, folder_id) VALUES (?, ?)
        ON CONFLICT (server_id) DO UPDATE SET folder_id = excluded.folder_id
    """, (server_id, folder_id))
    db.execute("""
        INSERT INTO cloud_saved_names (server_id, name) VALUES (?, ?)
        ON CONFLICT (server_id) DO UPDATE SET name = excluded.name
    """, (server_id, name))


def add(db, user_id, provider, remote_id, region, name, username, secret, *, account_id=None, address=None):
    now = int(time.time())
    with db:
        db.execute("INSERT OR IGNORE INTO server_folders (user_id, name) VALUES (?, ?)", (user_id, region))
        folder_id = db.execute(
            "SELECT id FROM server_folders WHERE user_id = ? AND name = ?", (user_id, region),
        ).fetchone()[0]
        if address:
            save_profile(db, user_id, folder_id, name, username, address, secret)
        else:
            db.execute("""
                INSERT INTO cloud_saved_pending (
                    user_id, provider, remote_id, account_id, folder_id, region, name, username, secret, next_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (user_id, provider, str(remote_id), account_id, folder_id, region, name, username, secret, now, now + 86400))


def due(db):
    return [PendingServer(*row) for row in db.execute("""
        SELECT * FROM cloud_saved_pending WHERE status = 'pending' AND next_at <= ? ORDER BY next_at, id LIMIT 8
    """, (int(time.time()),))]


def finish(db, pending, address=None, secret=None, *, failed=False):
    live = db.execute("SELECT * FROM cloud_saved_pending WHERE id = ?", (pending.id,)).fetchone()
    if live != tuple(pending):
        return
    now = int(time.time())
    with db:
        if address:
            save_profile(db, pending.user_id, pending.folder_id, pending.name, pending.username, address, secret or pending.secret)
            db.execute("DELETE FROM cloud_saved_pending WHERE id = ?", (pending.id,))
        elif failed or now >= pending.expires_at:
            db.execute("UPDATE cloud_saved_pending SET status = 'failed', secret = NULL WHERE id = ?", (pending.id,))
        else:
            db.execute("UPDATE cloud_saved_pending SET next_at = ? WHERE id = ?", (now + 60, pending.id))
