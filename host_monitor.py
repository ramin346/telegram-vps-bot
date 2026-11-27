import asyncio
from collections import defaultdict
from ipaddress import ip_address, ip_network
import json
import re
import time

import httpx

import host_checks

INTERVAL = 3 * 60 * 60
RETRY_INTERVAL = 5 * 60
MIN_INTERVAL = 15 * 60
MAX_INTERVAL = 30 * 86400
AWS_RANGES = "https://ip-ranges.amazonaws.com/ip-ranges.json"
AWS_NAME = re.compile(r"\b(?:amazon|aws|amzn)\b", re.IGNORECASE)
PROBE_LIMIT = asyncio.Semaphore(3)


def init(db):
    with db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS host_monitors (
                user_id INTEGER PRIMARY KEY, hosts TEXT NOT NULL, next_at INTEGER NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS host_monitor_settings (
                user_id INTEGER PRIMARY KEY, interval INTEGER NOT NULL
            )
        """)


def interval(db, user_id):
    row = db.execute("SELECT interval FROM host_monitor_settings WHERE user_id = ?", (user_id,)).fetchone()
    return row[0] if row else INTERVAL


def set_interval(db, user_id, seconds):
    if not MIN_INTERVAL <= seconds <= MAX_INTERVAL:
        raise ValueError
    next_at = int(time.time()) + seconds
    with db:
        db.execute("""
            INSERT INTO host_monitor_settings VALUES (?, ?)
            ON CONFLICT (user_id) DO UPDATE SET interval = excluded.interval
        """, (user_id, seconds))
        db.execute("UPDATE host_monitors SET next_at = ? WHERE user_id = ?", (next_at, user_id))
        db.execute("""
            UPDATE node_replacements SET next_at = ?, evidence = 0 WHERE user_id = ? AND state = 'watching'
        """, (next_at, user_id))


def read_hosts(value):
    rows = json.loads(value)
    if not isinstance(rows, list) or not rows or any(
        not isinstance(host, str) or host_checks.parse_host(host) != host for host in rows
    ) or len(rows) != len(set(rows)):
        raise ValueError
    return rows


def get(db, user_id):
    row = db.execute("SELECT hosts, next_at FROM host_monitors WHERE user_id = ?", (user_id,)).fetchone()
    return (read_hosts(row[0]), row[1]) if row else ([], None)


def save(db, user_id, hosts):
    with db:
        if not hosts:
            db.execute("DELETE FROM host_monitors WHERE user_id = ?", (user_id,))
            return
        db.execute("""
            INSERT INTO host_monitors (user_id, hosts, next_at) VALUES (?, ?, ?)
            ON CONFLICT (user_id) DO UPDATE SET hosts = excluded.hosts
        """, (user_id, json.dumps(hosts, separators=(",", ":")), int(time.time()) + interval(db, user_id)))


def due(db):
    return db.execute(
        "SELECT user_id FROM host_monitors WHERE next_at <= ? ORDER BY next_at LIMIT 5", (int(time.time()),),
    ).fetchall()


def move_due(db, user_id, old_due, *, retry=False):
    now = int(time.time())
    period = interval(db, user_id)
    next_at = now + RETRY_INTERVAL if retry else old_due + ((max(0, now - old_due) // period) + 1) * period
    with db:
        db.execute(
            "UPDATE host_monitors SET next_at = ? WHERE user_id = ? AND next_at = ?", (next_at, user_id, old_due),
        )


async def aws_networks(client):
    try:
        data = await host_checks.get_json(client, AWS_RANGES)
        return [
            ip_network(item[key])
            for group, key in (("prefixes", "ip_prefix"), ("ipv6_prefixes", "ipv6_prefix"))
            for item in data[group]
        ]
    except (host_checks.CheckError, ValueError, KeyError, TypeError):
        return []


def ping_status(nodes, results):
    if not nodes:
        return "unknown"
    timeout_nodes = 0
    for node in nodes:
        value = results.get(node)
        packets = value[0] if isinstance(value, list) and value and isinstance(value[0], list) else []
        statuses = [packet[0] for packet in packets if isinstance(packet, list) and packet]
        if "OK" in statuses:
            return "ok"
        if "TIMEOUT" in statuses:
            timeout_nodes += 1
    return "down" if timeout_nodes == len(nodes) else "unknown"


async def check_ip(client, ip, networks):
    address = ip_address(ip)
    if any(address in network for network in networks):
        return "aws"
    async with PROBE_LIMIT:
        info = await host_checks.ip_metadata(client, ip)
        connection = info.get("connection") or {}
        provider = " ".join(str(connection.get(key) or "") for key in ("isp", "org", "domain")).strip()
        if AWS_NAME.search(provider):
            return "aws"
        if not provider:
            return "provider_unknown"
        try:
            nodes, results = await host_checks.ping_iran(ip)
        except host_checks.CheckError:
            return "unknown"
    return ping_status(nodes, results)


async def resolve(host):
    try:
        return await host_checks.public_ips(host)
    except host_checks.CheckError:
        return []


async def run(hosts):
    async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
        networks, *resolved = await asyncio.gather(aws_networks(client), *(resolve(host) for host in hosts))
        unique = dict.fromkeys(ip for addresses in resolved for ip in addresses)
        statuses = await asyncio.gather(*(check_ip(client, ip, networks) for ip in unique))
    status_by_ip = dict(zip(unique, statuses))
    groups = defaultdict(list)
    for host, addresses in zip(hosts, resolved):
        if not addresses:
            groups["dns"].append(host)
        for ip in addresses:
            groups[status_by_ip[ip]].append(f"{host} · {ip}")
    return groups


def report(groups):
    problems = any(groups.get(group) for group in ("down", "unknown", "provider_unknown", "dns"))
    if groups.get("ok") and not problems:
        summary = "✅ همهٔ سرورهای تست‌شده از ایران پینگ می‌دهند."
    elif not groups.get("ok") and not problems:
        summary = "هیچ IP واجد شرایطی برای پینگ پیدا نشد."
    else:
        summary = "نتیجهٔ پایش IP از ایران"
    sections = [
        ("down", "🔴 بدون پاسخ از نودهای ایران"),
        ("unknown", "⚪ نتیجهٔ پینگ نامشخص"),
        ("dns", "⚪ IP عمومی پیدا نشد"),
        ("provider_unknown", "⚪ ISP نامشخص؛ پینگ نشد"),
        ("aws", "☁️ Amazon/AWS · پینگ نشد"),
        ("ok", "🟢 پاسخ موفق از ایران"),
    ]
    lines = [summary]
    for group, title in sections:
        if groups.get(group):
            lines.extend(("", title, *[f"• {entry}" for entry in groups[group]]))
    return "\n".join(lines)
