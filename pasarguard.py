"""PasarGuard panel API and per-user connection settings."""

from contextlib import asynccontextmanager
from ipaddress import ip_address
import asyncio
import json
import re
import secrets
import socket
import time
from urllib.parse import urlsplit

import httpx


class PanelError(Exception):
    pass


def init(db):
    with db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS pasarguard_accounts (
                user_id INTEGER PRIMARY KEY, url TEXT NOT NULL, credentials BLOB NOT NULL,
                core_id INTEGER, inbound TEXT, next_number INTEGER NOT NULL DEFAULT 1
            )
        """)


        db.execute("""
            CREATE TABLE IF NOT EXISTS pasarguard_installs (
                id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires INTEGER NOT NULL,
                payload BLOB NOT NULL
            )
        """)


def save_install(db, cipher, user_id, node):
    ticket = secrets.token_hex(12)
    now = int(time.time())
    with db:
        db.execute("DELETE FROM pasarguard_installs WHERE expires <= ?", (now,))
        db.execute(
            "INSERT INTO pasarguard_installs VALUES (?, ?, ?, ?)",
            (ticket, user_id, now + 86400, cipher.encrypt(json.dumps({"node": node}).encode())),
        )
    return ticket


def load_install(db, cipher, user_id, ticket):
    row = db.execute(
        "SELECT payload FROM pasarguard_installs WHERE id = ? AND user_id = ? AND expires > ?",
        (ticket, user_id, int(time.time())),
    ).fetchone()
    if not row:
        raise PanelError("درخواست نصب نود معتبر نیست یا مهلت آن تمام شده است.")
    return json.loads(cipher.decrypt(row[0]))


def update_install(db, cipher, user_id, ticket, draft):
    with db:
        db.execute(
            "UPDATE pasarguard_installs SET payload = ? WHERE id = ? AND user_id = ?",
            (cipher.encrypt(json.dumps(draft).encode()), ticket, user_id),
        )


class Panel:
    def __init__(self, client, base, host, hostname):
        self.client = client
        self.base = base
        self.host = host
        self.hostname = hostname
        self.token = None
        self.api_key = None

    async def request(self, method, path, **kwargs):
        headers = {"Host": self.host}
        if self.api_key:
            headers["X-Api-Key"] = self.api_key
        elif self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            response = await self.client.request(
                method, self.base + "/api/" + path, headers=headers,
                extensions={"sni_hostname": self.hostname}, **kwargs,
            )
            response.raise_for_status()
            return response.json() if response.content else None
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            if status == 404 and path in {"cores", "admin/token"}:
                raise PanelError(
                    f"مسیر /api/{path} در این آدرس پیدا نشد (HTTP 404). "
                    "آدرس ورود پنل، پورت و مسیر پراکسی معکوس را بررسی کن."
                ) from None
            if status == 403 and path == "cores":
                raise PanelError("کلید به خواندن Core دسترسی ندارد (HTTP 403). مجوز cores:read را در پنل بررسی کن.") from None
            raise PanelError(f"پنل پاسارگارد خطای HTTP {status} داد.") from None
        except (httpx.RequestError, ValueError):
            raise PanelError("ارتباط امن با پنل پاسارگارد برقرار نشد یا پاسخ پنل معتبر نبود.") from None

    async def cores(self):
        data = await self.request("GET", "cores")
        return data["cores"]

    async def inbounds(self, core_id):
        core = await self.request("GET", f"core/{core_id}")
        config = core["config"]
        excluded = set(core.get("exclude_inbound_tags") or ())
        return sorted({
            item["tag"] for item in config.get("inbounds", [])
            if item.get("tag") and item["tag"] not in excluded
        })

    async def ensure_node(self, node):
        for existing in await self.nodes():
            if existing["address"] != node["address"] and existing["name"] != node["name"]:
                continue
            if all(existing.get(field) == node[field] for field in (
                "address", "api_key", "port", "api_port", "connection_type", "core_config_id",
            )):
                return
            raise PanelError("نودی با همین آدرس یا نام و تنظیمات متفاوت در پنل وجود دارد.")
        await self.request("POST", "node", json=node)

    async def nodes(self):
        nodes = []
        while True:
            data = await self.request("GET", "nodes", params={"offset": len(nodes), "limit": 100})
            nodes.extend(data["nodes"])
            if not data["nodes"] or len(nodes) >= data["total"]:
                return nodes

    async def hosts(self):
        return await self.request("GET", "hosts")

    @staticmethod
    def host_exists(remark, ip, inbound, hosts):
        for host in hosts:
            if host["remark"] == remark:
                if host["inbound_tag"] == inbound and set(host["address"]) == {ip}:
                    return True
                raise PanelError(f"اسم «{remark}» قبلاً برای Host دیگری استفاده شده است. اسم دیگری انتخاب کن.")
        return False

    async def ensure_host(self, remark, ip, inbound, hosts):
        if self.host_exists(remark, ip, inbound, hosts):
            return
        await self.request("POST", "host/", json={
            "remark": remark, "address": [ip], "inbound_tag": inbound, "priority": 0,
        })


def parse_url(value):
    try:
        url = urlsplit(value)
        if (url.scheme != "https" or not url.hostname or url.username is not None
                or not re.fullmatch(r"[A-Za-z0-9.:-]+", url.hostname)
                or not re.fullmatch(r"(?:/[A-Za-z0-9_-]+)*/?", url.path)):
            raise ValueError
        dashboard = re.search(r"/dashboard(?:/|$)", url.path)
        if dashboard:
            url = url._replace(path=url.path[:dashboard.start()], query="", fragment="")
        elif url.query or url.fragment:
            raise ValueError
        path = url.path.rstrip("/").removesuffix("/api")
        return url._replace(path=path), url.port or 443
    except ValueError:
        raise PanelError("آدرس پنل باید یک آدرس HTTPS معتبر باشد.") from None


@asynccontextmanager
async def connect(url_text, credentials):
    url, port = parse_url(url_text)
    try:
        results = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(url.hostname, port, type=socket.SOCK_STREAM), 10,
        )
        addresses = list(dict.fromkeys(ip_address(result[4][0]) for result in results))
    except (OSError, TimeoutError, ValueError):
        raise PanelError("آدرس پنل پیدا نشد.") from None
    if not addresses or any(not ip.is_global or ip.is_multicast for ip in addresses):
        raise PanelError("پنل باید با یک آدرس عمومی HTTPS در دسترس باشد.")
    ip = addresses[0]
    address = f"[{ip}]" if ip.version == 6 else str(ip)
    async with httpx.AsyncClient(timeout=20, trust_env=False) as client:
        panel = Panel(client, f"https://{address}:{port}{url.path.rstrip('/')}", url.netloc, url.hostname)
        if len(credentials) == 1:
            credential = credentials[0]
            if credential.startswith("pg_key_"):
                panel.api_key = credential
            else:
                panel.token = credential
        else:
            result = await panel.request(
                "POST", "admin/token", data={"username": credentials[0], "password": credentials[1]},
            )
            panel.token = result["access_token"]
        yield panel


def save_account(db, cipher, user_id, url, credentials):
    with db:
        db.execute("""
            INSERT INTO pasarguard_accounts(user_id, url, credentials) VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                core_id = CASE WHEN url = excluded.url THEN core_id END,
                inbound = CASE WHEN url = excluded.url THEN inbound END,
                next_number = CASE WHEN url = excluded.url THEN next_number ELSE 1 END,
                url = excluded.url, credentials = excluded.credentials
        """, (user_id, url, cipher.encrypt(json.dumps(credentials).encode())))


def account(db, cipher, user_id):
    row = db.execute("""
        SELECT url, credentials, core_id, inbound FROM pasarguard_accounts WHERE user_id = ?
    """, (user_id,)).fetchone()
    if not row:
        raise PanelError("ابتدا اتصال پنل را در بخش پاسارگارد تنظیم کن.")
    url, encrypted, core_id, inbound = row
    return url, json.loads(cipher.decrypt(encrypted)), core_id, inbound
