import asyncio
from datetime import datetime
from decimal import Decimal, InvalidOperation
from html import escape
from io import StringIO
from ipaddress import IPv6Address, ip_address
import json
import logging
import os
from pathlib import Path
import re
import secrets
import shlex
import sqlite3
import subprocess
import tempfile
import time
from types import SimpleNamespace
from urllib.parse import quote
from zoneinfo import ZoneInfo

import httpx
import paramiko
from cryptography.fernet import Fernet, InvalidToken
from telegram import (
    CopyTextButton, InlineKeyboardButton, InlineKeyboardMarkup,
)
from telegram.error import TelegramError
from telegram.ext import (
    Application, CallbackQueryHandler, CommandHandler, MessageHandler, filters,
)

import cherry
import cloudflare
import cloud_saved
import database_backup
import dns_rotation
import hetzner
import host_checks
import host_monitor
import kamatera
import linode
import navigation
import pasarguard
import panel_install
import replacement
import vultr

ROOT = Path(__file__).resolve().parent
SCRIPT = "https://github.com/PasarGuard/scripts/raw/main/pg-node.sh"
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
CERTIFICATE = re.compile(r"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----")
UUID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$", re.I)

INSTALL = r"""
set -eu
if [ -e /opt/pg-node ] || [ -e /var/lib/pg-node ]; then
    echo 'Existing installation or data found at /opt/pg-node or /var/lib/pg-node.' >&2
    exit 73
fi
export TERM=xterm DEBIAN_FRONTEND=noninteractive APP_DIR=/opt/pg-node DATA_DIR=/var/lib/pg-node
script=$(curl -fsSL --connect-timeout 15 --max-time 90 SCRIPT_URL)
test -n "$script"
bash -c "$script" @ install -y < /dev/null
""".replace("SCRIPT_URL", shlex.quote(SCRIPT))

READ_NODE = r"""
set -eu
sed -n 's/^API_KEY[[:space:]]*=[[:space:]]*//p' /opt/pg-node/.env
openssl x509 -in /var/lib/pg-node/certs/ssl_cert.pem -outform PEM
"""

ENABLE = r"""
set -eu
set -- $SSH_CONNECTION
case "${4:-}" in ''|*[!0-9]*) exit 64;; esac
SUDO ufw allow "$4/tcp"
SUDO ufw --force enable
SUDO ufw status
"""

LABELS = {
    "ssh": "💻 اجرای دستور SSH",
    "node": "📦 نصب نود پاسارگارد",
    "ssl": "🔐 گرفتن گواهی SSL",
    "on": "🟢 روشن کردن UFW",
    "off": "🔴 خاموش کردن UFW",
    "update": "🔄 آپدیت ربات",
}


def save_host_keys(host_keys, path):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as staged:
        temporary = Path(staged.name)
    try:
        host_keys.save(str(temporary))
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)



def connect(host, port, username, password=None, pkey=None):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    path = Path.home() / ".ssh" / "telegram-vps-known-hosts"
    host_keys = client.get_host_keys()
    try:
        client.load_system_host_keys()
        if path.exists():
            host_keys.load(str(path))
        known_count = len(host_keys)
        client.connect(
            host, port=port, username=username, password=password, pkey=pkey,
            key_filename=os.getenv("SSH_KEY_PATH") if password is None and pkey is None else None,
            look_for_keys=False, allow_agent=False, timeout=15,
            banner_timeout=15, auth_timeout=15,
        )
        if len(host_keys) != known_count:
            save_host_keys(host_keys, path)
    except BaseException:
        client.close()
        raise
    return client


def run(client, command, timeout=90, input_data=None):
    transport = client.get_transport()
    deadline = time.monotonic() + timeout
    with transport.open_session(timeout=15) as channel:
        channel.settimeout(15)
        channel.set_combine_stderr(True)
        channel.exec_command(command)
        if input_data is not None:
            channel.sendall(input_data)
        channel.shutdown_write()
        tail = bytearray()
        while time.monotonic() < deadline:
            if channel.recv_ready():
                chunk = channel.recv(32768)
                tail.extend(chunk)
                del tail[:-65536]
            elif channel.exit_status_ready():
                output = tail.decode("utf-8", errors="replace")
                return channel.recv_exit_status(), ANSI.sub("", output)
            else:
                time.sleep(0.05)
        raise TimeoutError


def install_node(client, sudo):
    status, _ = run(
        client, sudo + "flock -n /run/lock/telegram-pg-node.lock bash -c " + shlex.quote(INSTALL),
        timeout=1800,
    )
    if status:
        return status, None
    status, output = run(client, sudo + "bash -c " + shlex.quote(READ_NODE))
    if status:
        return status, None
    key = next((line.strip() for line in output.splitlines() if UUID.fullmatch(line.strip())), "")
    cert = CERTIFICATE.search(output)
    return 0, (key, cert.group() if cert else "")


def update_checkout():
    def git(*args):
        return subprocess.run(
            ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True,
            timeout=60, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        ).stdout.strip()

    if git("status", "--porcelain"):
        raise ValueError("Checkout is dirty")
    old = git("rev-parse", "HEAD")
    tracking = git("rev-parse", "--symbolic-full-name", "@{upstream}")
    if not tracking.startswith("refs/remotes/origin/"):
        raise ValueError("The current branch must track origin")
    git("fetch", "--", "origin")
    upstream = git("rev-parse", tracking)
    compile(git("show", f"{upstream}:bot.py"), "bot.py", "exec")
    git("merge", "--ff-only", upstream)
    return old != git("rev-parse", "HEAD")


def load_admins():
    path = Path.home() / ".local" / "share" / "telegram-vps-bot"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    db = sqlite3.connect(path / "admins.sqlite3")
    db.execute("PRAGMA foreign_keys = ON")
    with db:
        db.execute("CREATE TABLE IF NOT EXISTS admins (user_id INTEGER PRIMARY KEY)")
    return db, {row[0] for row in db.execute("SELECT user_id FROM admins")}


def init_servers(db):
    key_path = Path.home() / ".local" / "share" / "telegram-vps-bot" / "servers.key"
    with db:
        db.execute("PRAGMA secure_delete = ON")
        db.execute("""
            CREATE TABLE IF NOT EXISTS servers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                username TEXT NOT NULL,
                secret BLOB,
                UNIQUE (user_id, host, port, username)
            )
        """)
    with db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS kamatera_accounts (
                user_id INTEGER PRIMARY KEY, credentials BLOB NOT NULL, command_id TEXT
            )
        """)
    with db:
        db.execute("CREATE TABLE IF NOT EXISTS linode_accounts (user_id INTEGER PRIMARY KEY, token BLOB NOT NULL)")
    with db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS hetzner_projects (
                id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL,
                name TEXT COLLATE NOCASE NOT NULL, token BLOB NOT NULL,
                UNIQUE (user_id, name)
            )
        """)
        legacy = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'hetzner_accounts'"
        ).fetchone()
        if legacy:
            db.execute("""
                INSERT INTO hetzner_projects (user_id, name, token)
                SELECT user_id, 'پیش‌فرض', token FROM hetzner_accounts
                WHERE user_id NOT IN (SELECT user_id FROM hetzner_projects WHERE name = 'پیش‌فرض')
            """)
            db.execute("DELETE FROM hetzner_accounts")
    with db:
        db.execute("CREATE TABLE IF NOT EXISTS cloudflare_accounts (user_id INTEGER PRIMARY KEY, token BLOB NOT NULL)")
    with db:
        db.execute("CREATE TABLE IF NOT EXISTS vultr_accounts (user_id INTEGER PRIMARY KEY, token BLOB NOT NULL)")
    with db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS server_folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT COLLATE NOCASE NOT NULL,
                UNIQUE (user_id, name)
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS server_folder_members (
                server_id INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
                folder_id INTEGER NOT NULL REFERENCES server_folders(id) ON DELETE CASCADE
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS server_folder_members_by_folder ON server_folder_members(folder_id)")
    with db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS cloudflare_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
                name TEXT COLLATE NOCASE NOT NULL, token BLOB NOT NULL, UNIQUE (user_id, name)
            )
        """)
    with db:
        db.execute("CREATE TABLE IF NOT EXISTS cherry_accounts (user_id INTEGER PRIMARY KEY, token BLOB NOT NULL)")
    cloud_saved.init(db)
    replacement.init(db)
    dns_rotation.init(db)
    host_monitor.init(db)
    pasarguard.init(db)
    has_saved_secrets = db.execute("""
        SELECT 1 FROM servers WHERE secret IS NOT NULL
        UNION ALL SELECT 1 FROM kamatera_accounts
        UNION ALL SELECT 1 FROM linode_accounts
        UNION ALL SELECT 1 FROM hetzner_projects
        UNION ALL SELECT 1 FROM cloudflare_accounts
        UNION ALL SELECT 1 FROM cloudflare_profiles
        UNION ALL SELECT 1 FROM vultr_accounts
        UNION ALL SELECT 1 FROM cherry_accounts
        UNION ALL SELECT 1 FROM pasarguard_accounts
        UNION ALL SELECT 1 FROM pasarguard_installs
        UNION ALL SELECT 1 FROM cloud_saved_pending WHERE secret IS NOT NULL
        UNION ALL SELECT 1 FROM node_replacements WHERE recipe IS NOT NULL LIMIT 1
    """).fetchone()
    if not key_path.exists() and not has_saved_secrets:
        try:
            def private_file(name, flags):
                return os.open(name, flags, 0o600)

            with open(key_path, "xb", opener=private_file) as key_file:
                key_file.write(Fernet.generate_key())
        except FileExistsError:
            pass
    return Fernet(key_path.read_bytes())


def save_server(user_id, address, username, password):
    secret = SERVER_CIPHER.encrypt(password.encode()) if password is not None else None
    with ADMIN_DB:
        ADMIN_DB.execute("""
            INSERT INTO servers (user_id, host, port, username, secret) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (user_id, host, port, username) DO UPDATE SET secret = excluded.secret
        """, (user_id, *address, username, secret))


def server_label(host, port, username):
    address = f"[{host}]" if ":" in host else host
    return f"{username}@{address}:{port}"


def private_owner(update):
    return (
        update.effective_chat.type == "private"
        and update.effective_user.id in OWNER_IDS
    )


def private_operator(update):
    return update.effective_chat.type == "private" and update.effective_user.id == MAIN_OWNER_ID


def user_has_access(user_id):
    return user_id in OWNER_IDS or user_id in ADDED_ADMINS


def private_admin(update):
    return update.effective_chat.type == "private" and user_has_access(update.effective_user.id)


def clear(context):
    clear_user_data(context.user_data)


def clear_user_data(state):
    job = state.pop("expiry_job", None)
    if job:
        job.schedule_removal()
    client = state.pop("client", None)
    if client:
        client.close()
    state.clear()


def menu(owner):
    rows = [[InlineKeyboardButton(LABELS[name], callback_data=name)] for name in ("ssh", "node", "ssl")]
    rows.append([InlineKeyboardButton(LABELS[name], callback_data=name) for name in ("on", "off")])
    rows.append([
        InlineKeyboardButton("🖥 سرورهای من", callback_data="my_servers"),
        InlineKeyboardButton("📡 پینگ و اطلاعات IP", callback_data="host_checks"),
    ])
    rows.extend([
        [InlineKeyboardButton("☁️ سرور کاماترا", callback_data="kamatera"),
         InlineKeyboardButton("☁️ سرور Linode", callback_data="linode")],
        [InlineKeyboardButton("☁️ سرور هتزنر", callback_data="hetzner"),
         InlineKeyboardButton("☁️ سرور Vultr", callback_data="vultr")],
        [InlineKeyboardButton("🌐 Cloudflare", callback_data="cloudflare"),
         InlineKeyboardButton("🍒 سرور Cherry", callback_data="cherry")],
    ])
    rows.append([InlineKeyboardButton("🛡 پاسارگارد", callback_data="pg")])
    if owner:
        rows.append([InlineKeyboardButton("👑 پنل مدیریت", callback_data="license_panel")])
    return InlineKeyboardMarkup(rows)


async def navigation_button(update, context):
    query = update.callback_query
    await query.answer()
    if not private_admin(update):
        return
    chat_id = update.effective_chat.id
    page = navigation.previous(chat_id) if query.data == navigation.BACK else None
    clear(context)
    if page is None:
        navigation.reset(chat_id)
        await query.message.reply_text("عملیات سرور را انتخاب کن.", reply_markup=menu(private_operator(update)))
        return
    state, markup = navigation.reissue(page, context.bot)
    context.user_data.update(state)
    await query.message.reply_text(page.text, reply_markup=markup)


async def start(update, context):
    if private_admin(update):
        navigation.reset(update.effective_chat.id)
        clear(context)
        await update.message.reply_text("عملیات سرور را انتخاب کن.", reply_markup=menu(private_operator(update)))
    elif update.effective_chat.type == "private":
        await update.message.reply_text(
            f"برای استفاده از ربات به لایسنس نیاز داری. آیدی عددی تو: {update.effective_user.id}\n"
            "این آیدی را برای مدیر ربات بفرست تا دسترسی را فعال کند."
        )


async def update_bot(message, context):
    clear(context)
    if os.getenv("ENABLE_UPDATE") != "1":
        await message.reply_text("آپدیت در تنظیمات سرویس فعال نشده است.")
        return
    try:
        changed = await asyncio.to_thread(update_checkout)
    except (ValueError, SyntaxError, OSError, subprocess.SubprocessError):
        await message.reply_text("آپدیت انجام نشد. وضعیت Git، دسترسی origin و شاخهٔ پیگیری‌شده را بررسی کن.")
        return
    if not changed:
        await message.reply_text("ربات به‌روز است.")
        return
    try:
        await message.reply_text("نسخهٔ جدید دریافت شد. سرویس دوباره راه‌اندازی می‌شود.")
    finally:
        context.application.stop_running()


async def update_command(update, context):
    if private_operator(update):
        await update_bot(update.message, context)


async def select(update, context):
    query = update.callback_query
    await query.answer()
    if not private_admin(update) or query.data not in LABELS:
        return
    if query.data == "update":
        if private_operator(update):
            await update_bot(query.message, context)
        return
    clear(context)
    context.user_data["action"] = query.data
    if query.data == "ssl":
        await query.message.reply_text("ایمیل Certbot را بفرست. برای لغو /cancel را بزن.")
        return
    await show_servers(update, context)


async def ask_address(message):
    await message.reply_text(
        "آی‌پی یا آدرس سرور را بفرست. "
        "برای پورت سفارشی از host:port یا [IPv6]:port استفاده کن.",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("بازگشت", callback_data="cancel")]]),
    )


def server_list_token(state):
    state["servers_token"] = secrets.token_hex(6)
    return state["servers_token"]


async def show_server_folders(update, context, page=0, *, moving=None):
    message = update.callback_query.message if update.callback_query else update.message
    state = context.user_data
    user_id = update.effective_user.id
    folders = ADMIN_DB.execute("""
        SELECT id, name FROM server_folders WHERE user_id = ? ORDER BY id LIMIT 9 OFFSET ?
    """, (user_id, page * 8)).fetchall()
    token = server_list_token(state)
    if moving is None:
        state.pop("moving_server", None)
        state.pop("folder_id", None)
        rows = [[InlineKeyboardButton("📁 ساخت پوشه", callback_data=f"s:{token}:folder_new:0")]]
        verb = "folder"
        page_verb = "folders_page"
    else:
        state["moving_server"] = moving
        rows = []
        verb = "move_to"
        page_verb = "move_page"
    rows.append([InlineKeyboardButton("📄 بدون پوشه", callback_data=f"s:{token}:{verb}:0")])
    rows.extend(
        [InlineKeyboardButton(f"📂 {name}", callback_data=f"s:{token}:{verb}:{folder_id}")]
        for folder_id, name in folders[:8]
    )
    navigation = []
    if page:
        navigation.append(InlineKeyboardButton("قبلی", callback_data=f"s:{token}:{page_verb}:{page - 1}"))
    if len(folders) > 8:
        navigation.append(InlineKeyboardButton("بعدی", callback_data=f"s:{token}:{page_verb}:{page + 1}"))
    if navigation:
        rows.append(navigation)
    back = "cancel" if moving is None else f"s:{token}:pick:{moving}"
    rows.append([InlineKeyboardButton("بازگشت", callback_data=back)])
    await message.reply_text(
        "سرورهای من" if moving is None else "پوشهٔ مقصد را انتخاب کن.",
        reply_markup=InlineKeyboardMarkup(rows),
    )


async def create_server_folder(update, context):
    message = update.message
    name = message.text.strip()
    if not name or len(name) > 48 or not name.isprintable():
        await message.reply_text("نام پوشه را در یک خط و با حداکثر ۴۸ کاراکتر بفرست.")
        return
    try:
        with ADMIN_DB:
            ADMIN_DB.execute(
                "INSERT INTO server_folders (user_id, name) VALUES (?, ?)", (update.effective_user.id, name),
            )
    except sqlite3.IntegrityError:
        await message.reply_text("پوشه‌ای با این نام داری. نام دیگری بفرست.")
        return
    context.user_data.pop("folder_pending", None)
    await message.reply_text(f"پوشهٔ «{name}» ساخته شد.")
    await show_server_folders(update, context)


def move_server_to_folder(db, user_id, server_id, folder_id):
    with db:
        server = db.execute("SELECT 1 FROM servers WHERE user_id = ? AND id = ?", (user_id, server_id)).fetchone()
        if server is None:
            return False
        if not folder_id:
            db.execute("DELETE FROM server_folder_members WHERE server_id = ?", (server_id,))
            return True
        folder = db.execute("SELECT 1 FROM server_folders WHERE user_id = ? AND id = ?", (user_id, folder_id)).fetchone()
        if folder is None:
            return False
        db.execute("""
            INSERT INTO server_folder_members (server_id, folder_id) VALUES (?, ?)
            ON CONFLICT (server_id) DO UPDATE SET folder_id = excluded.folder_id
        """, (server_id, folder_id))
    return True


async def show_servers(update, context, page=0):
    message = update.effective_message
    user_id = update.effective_user.id
    state = context.user_data
    folder_id = state.get("folder_id")
    if folder_id is None:
        rows = ADMIN_DB.execute(
            """
            SELECT s.id, s.host, s.port, s.username, n.name FROM servers s
            LEFT JOIN cloud_saved_names n ON n.server_id = s.id
            WHERE s.user_id = ? ORDER BY s.id DESC LIMIT 9 OFFSET ?
            """,
            (user_id, page * 8),
        ).fetchall()
    else:
        rows = ADMIN_DB.execute("""
            SELECT s.id, s.host, s.port, s.username, n.name FROM servers s
            LEFT JOIN cloud_saved_names n ON n.server_id = s.id
            LEFT JOIN server_folder_members m ON m.server_id = s.id
            WHERE s.user_id = ? AND COALESCE(m.folder_id, 0) = ?
            ORDER BY s.id DESC LIMIT 9 OFFSET ?
        """, (user_id, folder_id, page * 8)).fetchall()
    if not rows and page:
        return await show_servers(update, context, page - 1)
    if not rows and state.get("action") == "panel_install":
        await message.reply_text("ابتدا سرور را در «سرورهای من» ذخیره کن.", reply_markup=panel_menu())
        return
    if not rows and state.get("action"):
        await ask_address(message)
        return
    token = server_list_token(state)
    keyboard = [
        [InlineKeyboardButton((f"{name} · {host}" if name else server_label(host, port, username))[:64], callback_data=f"s:{token}:pick:{row_id}")]
        for row_id, host, port, username, name in rows[:8]
    ]
    navigation = []
    if page:
        navigation.append(InlineKeyboardButton("قبلی", callback_data=f"s:{token}:page:{page - 1}"))
    if len(rows) > 8:
        navigation.append(InlineKeyboardButton("بعدی", callback_data=f"s:{token}:page:{page + 1}"))
    if navigation:
        keyboard.append(navigation)
    if state.get("action") and state["action"] != "panel_install":
        keyboard.append([InlineKeyboardButton("➕ سرور جدید", callback_data=f"s:{token}:new:0")])
    back = "cancel" if folder_id is None else f"s:{token}:folders_page:0"
    keyboard.append([InlineKeyboardButton("بازگشت", callback_data=back)])
    title = "یک سرور انتخاب کن." if rows else "در این پوشه سروری نیست."
    if folder_id is not None:
        folder = ADMIN_DB.execute(
            "SELECT name FROM server_folders WHERE user_id = ? AND id = ?", (user_id, folder_id),
        ).fetchone()
        name = folder[0] if folder else "بدون پوشه"
        title = f"📂 {name}\n{title}"
        if folder_id:
            counts = ADMIN_DB.execute("""
                SELECT status, COUNT(*) FROM cloud_saved_pending
                WHERE user_id = ? AND folder_id = ? GROUP BY status
            """, (user_id, folder_id)).fetchall()
            for status, count in counts:
                title += f"\n{count} سرور منتظر IP" if status == "pending" else f"\nدریافت IP برای {count} سرور ناموفق بود."
    await message.reply_text(
        title,
        reply_markup=InlineKeyboardMarkup(keyboard),
    )


async def my_servers(update, context):
    await update.callback_query.answer()
    if private_admin(update):
        clear(context)
        await show_server_folders(update, context)


async def show_saved_password_retry(message, state):
    token = server_list_token(state)
    server_id = state["saved_server_id"]
    await message.reply_text(
        "اگر رمز SSH عوض شده، رمز جدید را وارد کن تا دوباره اتصال را تست کنم.",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔑 وارد کردن رمز جدید", callback_data=f"s:{token}:new_password:{server_id}")],
            [InlineKeyboardButton("لغو", callback_data="cancel")],
        ]),
    )


async def server_button(update, context):
    query = update.callback_query
    state = context.user_data
    _, token, verb, value = query.data.split(":")
    if not private_admin(update) or token != state.get("servers_token"):
        await query.answer("این منو بسته شده است.")
        return
    await query.answer()
    user_id = update.effective_user.id
    number = int(value)
    if verb == "folders_page":
        await show_server_folders(update, context, number)
        return
    if verb == "folder_new":
        state.pop("servers_token", None)
        state["folder_pending"] = True
        await query.message.reply_text("نام پوشه را بفرست. برای لغو /cancel را بزن.")
        return
    if verb == "folder":
        if number and not ADMIN_DB.execute(
            "SELECT 1 FROM server_folders WHERE user_id = ? AND id = ?", (user_id, number),
        ).fetchone():
            await show_server_folders(update, context)
            return
        state["folder_id"] = number
        await show_servers(update, context)
        return
    if verb == "move_page":
        await show_server_folders(update, context, number, moving=state["moving_server"])
        return
    if verb == "move_to":
        server_id = state.pop("moving_server")
        if move_server_to_folder(ADMIN_DB, user_id, server_id, number):
            state["folder_id"] = number
            await query.message.reply_text("پوشهٔ سرور به‌روزرسانی شد.")
        else:
            await query.message.reply_text("سرور یا پوشه پیدا نشد.")
        await show_servers(update, context)
        return
    if verb == "page":
        await show_servers(update, context, number)
        return
    if verb == "new":
        state.pop("servers_token")
        await ask_address(query.message)
        return
    server_id = number
    row = ADMIN_DB.execute(
        "SELECT host, port, username, secret FROM servers WHERE user_id = ? AND id = ?", (user_id, server_id),
    ).fetchone()
    if row is None:
        await show_servers(update, context)
        return
    host, port, username, secret = row
    action = state.get("action")
    if verb == "delete" and not action:
        with ADMIN_DB:
            ADMIN_DB.execute("DELETE FROM servers WHERE user_id = ? AND id = ?", (user_id, server_id))
        await query.message.reply_text("سرور از فهرست ذخیره‌شده حذف شد.")
        await show_servers(update, context)
        return
    if verb == "move" and not action:
        await show_server_folders(update, context, moving=server_id)
        return
    if verb == "pick" and not action:
        state.pop("moving_server", None)
        token = server_list_token(state)
        folder = ADMIN_DB.execute("""
            SELECT f.name FROM server_folder_members m JOIN server_folders f ON f.id = m.folder_id
            WHERE m.server_id = ? AND f.user_id = ?
        """, (server_id, user_id)).fetchone()
        await query.message.reply_text(
            f"{server_label(host, port, username)}\nپوشه: {folder[0] if folder else 'بدون پوشه'}",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("اتصال SSH", callback_data=f"s:{token}:connect:{server_id}")],
                [InlineKeyboardButton("📂 افزودن به پوشه", callback_data=f"s:{token}:move:{server_id}")],
                [InlineKeyboardButton("حذف سرور", callback_data=f"s:{token}:delete:{server_id}")],
                [InlineKeyboardButton("بازگشت به فهرست", callback_data=f"s:{token}:page:0")],
            ]),
        )
        return
    if verb == "new_password" and state.get("saved_server_id") == server_id:
        state.pop("servers_token")
        state["password_only"] = True
        await ask_password(query.message, owner=False)
        return
    if verb == "pick" and action == "panel_install":
        state.pop("servers_token")
        state.update(address=(host, port), username=username, saved_server_id=server_id, panel_install_step="domain")
        await query.message.reply_text("ساب‌دامنهٔ پنل را بفرست. مثلاً panel.example.com.")
        return
    if verb == "connect" or (verb == "pick" and action):
        state.pop("servers_token")
        state.update(action=action or "ssh", address=(host, port), username=username, saved_server_id=server_id)
        if secret is None and not (private_owner(update) and os.getenv("SSH_KEY_PATH")):
            await ask_password(query.message, private_owner(update))
            return
        try:
            password = SERVER_CIPHER.decrypt(secret).decode() if secret is not None else None
        except InvalidToken:
            await query.message.reply_text("رمز ذخیره‌شده خوانده نشد.")
            await show_saved_password_retry(query.message, state)
            return
        if not await login_server(update, context, password, remember=False):
            await show_saved_password_retry(query.message, state)


async def license_panel(message):
    await message.reply_text("👑 پنل مدیریت ربات", reply_markup=InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ فعال‌سازی لایسنس", callback_data="lic:add"),
         InlineKeyboardButton("📋 لایسنس‌های فعال", callback_data="lic:list")],
        [InlineKeyboardButton("💾 پشتیبان‌گیری و بازیابی", callback_data="backup"),
         InlineKeyboardButton(LABELS["update"], callback_data="update")],
        [InlineKeyboardButton("بازگشت", callback_data="cancel")],
    ]))


async def list_licenses(message, state, page=0):
    choices = [(user_id, str(user_id)) for user_id in sorted(ADDED_ADMINS - OWNER_IDS)]
    state["choices"] = choices
    await show_cloud_picker(message, state, page, "لایسنس فعال را انتخاب کن.", "licp", "پنل مدیریت", "license_panel")


async def license_button(update, context):
    query = update.callback_query
    if not private_operator(update):
        await query.answer()
        return
    message = query.message
    action = query.data
    state = context.user_data.get("license", {})
    if action.startswith("licp:"):
        _, nonce, action = action.split(":", 2)
        if nonce != state.get("nonce"):
            await query.answer("این منو بسته شده است.")
            return
    else:
        clear(context)
        state = context.user_data["license"] = {}
    await query.answer()
    if action == "license_panel":
        await license_panel(message)
    elif action == "lic:add":
        state["enter_id"] = True
        await message.reply_text("آیدی عددی تلگرام کاربر را بفرست. برای لغو /cancel را بزن.")
    elif action == "lic:list":
        await list_licenses(message, state)
    elif action.startswith("page:"):
        page = int(action.split(":")[1])
        if page * 8 < len(state["choices"]):
            await list_licenses(message, state, page)
    elif action.startswith("pick:"):
        index = int(action.split(":")[1])
        if index >= len(state["choices"]):
            return
        user_id = state["choices"][index][0]
        state["revoke_id"] = user_id
        await message.reply_text(
            f"لایسنس {user_id} فعال است. دسترسی این کاربر لغو شود؟",
            reply_markup=nonce_keyboard(state, [[("لغو لایسنس", "revoke"), ("انصراف", "back")]], "licp"),
        )
    elif action == "back":
        await list_licenses(message, state)
    elif action == "revoke":
        state.pop("nonce", None)
        user_id = state.pop("revoke_id")
        async with ROTATION_LOCK:
            with ADMIN_DB:
                ADMIN_DB.execute("DELETE FROM admins WHERE user_id = ?", (user_id,))
                ADMIN_DB.execute(
                    "UPDATE dns_rotations SET status = 'cancelled', note = ? WHERE user_id = ? AND status = 'active'",
                    ("لایسنس کاربر لغو شد.", user_id),
                )
            ADDED_ADMINS.discard(user_id)
            navigation.reset(user_id)
            user_state = context.application.user_data.get(user_id)
            if user_state is not None:
                clear_user_data(user_state)
        await message.reply_text(f"لایسنس {user_id} لغو شد.")
        await list_licenses(message, state)


async def activate_license(update, context):
    value = update.message.text.strip()
    if not re.fullmatch(r"\d{1,16}", value) or not 0 < int(value) < 2**52:
        await update.message.reply_text("فقط آیدی عددی معتبر تلگرام را بفرست.")
        return
    user_id = int(value)
    if user_id in OWNER_IDS:
        await update.message.reply_text("این کاربر از قبل دسترسی ادمین اصلی دارد. آیدی دیگری بفرست.")
        return
    with ADMIN_DB:
        ADMIN_DB.execute("INSERT OR IGNORE INTO admins (user_id) VALUES (?)", (user_id,))
    ADDED_ADMINS.add(user_id)
    clear(context)
    await update.message.reply_text(f"لایسنس {user_id} فعال است. کاربر می‌تواند /start را در چت خصوصی ربات بزند.")
    await license_panel(update.message)


async def cancel(update, context):
    if not private_admin(update):
        return
    if update.callback_query:
        await update.callback_query.answer()
    navigation.reset(update.effective_chat.id)
    clear(context)
    await update.effective_message.reply_text("اتصال بسته شد. عملیات بعدی را انتخاب کن.", reply_markup=menu(private_operator(update)))


def parse_address(value):
    host = value.strip()
    if ":" in host and not host.startswith("[") and host.count(":") > 1:
        return str(IPv6Address(host)), 22
    match = re.fullmatch(r"(?:\[([0-9a-fA-F:.]+)\]|([a-zA-Z0-9_.-]+))(?::([0-9]{1,5}))?", host)
    if not match:
        raise ValueError
    port = int(match[3] or 22)
    if not 1 <= port <= 65535:
        raise ValueError
    return str(IPv6Address(match[1])) if match[1] else match[2], port


async def ask_password(message, owner):
    prompt = "رمز SSH را بفرست. بعد از ورود موفق، اطلاعات برای حساب تلگرام تو ذخیره می‌شود. ربات تلاش می‌کند پیام رمز را حذف کند."
    if owner and os.getenv("SSH_KEY_PATH"):
        prompt += " برای ورود با کلید تنظیم‌شده، یک نقطه (.) بفرست."
    await message.reply_text(prompt + " گفت‌وگو با ربات تلگرام رمزنگاری سرتاسری ندارد.")


async def send_code(message, value, copy=False):
    for offset in range(0, len(value), 1800):
        chunk = value[offset:offset + 1800]
        keyboard = None
        if copy and len(value) <= 256:
            keyboard = InlineKeyboardMarkup([[InlineKeyboardButton("کپی", copy_text=CopyTextButton(chunk))]])
        await message.reply_text(f"<pre>{escape(chunk)}</pre>", parse_mode="HTML", reply_markup=keyboard)


SSL_CERT_CHAIN = re.compile(
    r"(?:-----BEGIN CERTIFICATE-----\n(?:[A-Za-z0-9+/=]+\n)+-----END CERTIFICATE-----\n+)+"
)
SSL_PRIVATE_KEY = re.compile(
    r"-----BEGIN (PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)-----\n"
    r"(?:[A-Za-z0-9+/=]+\n)+-----END \1-----\n"
)
SSL_EMAIL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._%+\-]{0,63}@[A-Za-z0-9.-]+")


def ssl_domain(value):
    domain = cloudflare.domain(value)
    if "." not in domain or not any(char.isalpha() for char in domain.rsplit(".", 1)[-1]):
        raise ValueError
    return domain


def issue_ssl_certificate(client, sudo, email, domain):
    certbot_command = shlex.join([
        "certbot", "certonly", "--standalone", "--non-interactive", "--agree-tos",
        "--no-directory-hooks", "--keep-until-expiring", "--email", email,
        "--cert-name", domain, "-d", domain,
    ])
    for command, timeout, label in (
        ("apt update", 600, "apt update"),
        ("env DEBIAN_FRONTEND=noninteractive apt install -y certbot", 600, "نصب Certbot"),
        (certbot_command, 300, "صدور گواهی Certbot"),
        ("certbot certificates", 90, "بررسی گواهی Certbot"),
    ):
        status, output = run(client, sudo + command, timeout=timeout)
        if status:
            return None, f"خطا در {label} (کد {status})\n{output.strip()[-3000:]}"

    path = f"/etc/letsencrypt/live/{domain}"
    pem_values = []
    for filename, pattern in (("fullchain.pem", SSL_CERT_CHAIN), ("privkey.pem", SSL_PRIVATE_KEY)):
        status, output = run(client, sudo + "cat -- " + shlex.quote(f"{path}/{filename}"))
        pem = output.strip() + "\n"
        if status or len(output) >= 65536 or not pattern.fullmatch(pem):
            return None, f"خواندن کامل فایل {filename} ناموفق بود."
        pem_values.append(pem)
    return tuple(pem_values), None


async def send_ssl_pem(message, label, value):
    # Keep complete PEM lines and reserve space below Telegram's 4096-character limit.
    chunks = [""]
    for line in value.splitlines(keepends=True):
        if len(chunks[-1]) + len(line) > 3500:
            chunks.append("")
        chunks[-1] += line
    for index, chunk in enumerate(chunks, 1):
        title = f"{label} ({index}/{len(chunks)})" if len(chunks) > 1 else label
        markup = None
        if len(chunks) == 1 and len(value) <= 256:
            markup = InlineKeyboardMarkup([[InlineKeyboardButton("کپی", copy_text=CopyTextButton(value))]])
        await message.reply_text(
            f"{title}\n<pre>{escape(chunk)}</pre>", parse_mode="HTML", reply_markup=markup,
        )


async def ssl_request_text(update, context):
    state = context.user_data
    message = update.message
    value = (message.text or "").strip()
    if "ssl_email" not in state:
        try:
            if not SSL_EMAIL.fullmatch(value) or ".." in value or value.split("@")[0].endswith("."):
                raise ValueError
            email_domain = ssl_domain(value.split("@")[1])
            email = value.split("@")[0] + "@" + email_domain
            if len(email) > 254:
                raise ValueError
        except ValueError:
            await message.reply_text("یک آدرس ایمیل معتبر بفرست.")
            return
        state["ssl_email"] = email
        await message.reply_text("ساب‌دامنهٔ گواهی را بفرست. مثلاً node.example.com.")
        return
    try:
        state["ssl_domain"] = ssl_domain(value)
    except ValueError:
        await message.reply_text("نام کامل دامنه یا ساب‌دامنه را بدون URL، پورت یا wildcard بفرست.")
        return
    await message.reply_text(
        "برای ادامه، سروری را انتخاب کن که DNS این نام به آن اشاره می‌کند و پورت ۸۰ آن در دسترس است. "
        "ادامهٔ صدور به معنی پذیرش شرایط Let’s Encrypt است."
    )
    await show_servers(update, context)


async def operate(message, state, client, command=None):
    action = state["action"]
    sudo = "" if state["username"] == "root" else "sudo -n "
    if action == "panel_install":
        await message.reply_text("نصب پنل شروع شد. این مرحله ممکن است چند دقیقه طول بکشد.")
        try:
            url, username, password = await asyncio.to_thread(
                panel_install.install, run, client, sudo, state["panel_domain"], state["panel_email"],
            )
        except panel_install.InstallError as error:
            await message.reply_text(str(error))
            return
        for label, value in (("آدرس ورود", url), ("نام کاربری", username), ("رمز مدیر", password)):
            await message.reply_text(
                f"{label}\n<pre>{escape(value)}</pre>", parse_mode="HTML",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("کپی", copy_text=CopyTextButton(value))]]),
            )
        return
    if action == "ssl":
        pem, error = await asyncio.to_thread(
            issue_ssl_certificate, client, sudo, state["ssl_email"], state["ssl_domain"],
        )
        if error:
            await send_code(message, error)
        else:
            await send_ssl_pem(message, "Certificate content", pem[0])
            await send_ssl_pem(message, "Key content", pem[1])
        return
    if action == "node":
        await message.reply_text("نصب شروع شد. این مرحله ممکن است چند دقیقه طول بکشد.")
        status, data = await asyncio.to_thread(install_node, client, sudo)
        if status == 73:
            await message.reply_text("پوشهٔ نصب یا دادهٔ قبلی پاسارگارد وجود دارد. نصب انجام نشد.")
        elif status:
            await message.reply_text(f"نصب یا خواندن اطلاعات نود با کد {status} ناموفق بود.")
        else:
            for label, value in zip(("کلید API", "گواهی TLS (PEM)"), data):
                await message.reply_text(label if value else f"{label} در خروجی پیدا نشد.")
                if value:
                    await send_code(message, value, copy=True)
            if all(data):
                await offer_panel_registration(message, client, sudo, *data)
        return
    if action == "on":
        command = ENABLE.replace("SUDO ", sudo)
    elif action == "off":
        command = sudo + "ufw --force disable && " + sudo + "ufw status"
    status, output = await asyncio.to_thread(run, client, command)
    await message.reply_text(f"کد خروج: {status}")
    if output.strip():
        await send_code(message, output.strip()[-6000:])


def kamatera_account(user_id):
    return ADMIN_DB.execute(
        "SELECT credentials, command_id FROM kamatera_accounts WHERE user_id = ?", (user_id,),
    ).fetchone()


async def kamatera_token(user_id):
    account = kamatera_account(user_id)
    if not account:
        raise kamatera.APIError()
    client_id, secret = SERVER_CIPHER.decrypt(account[0]).decode().split("\n", 1)
    return await kamatera.authenticate(client_id, secret)


def store_created_server(user_id, provider, remote_id, region, name, *, instance=None, password=None,
                         account_id=None, username="root"):
    address = cloud_saved.instance_address(provider, instance) if instance else None
    secret = SERVER_CIPHER.encrypt(password.encode()) if isinstance(password, str) and password else None
    try:
        cloud_saved.add(
            ADMIN_DB, user_id, provider, remote_id, region, name, username, secret,
            account_id=account_id, address=address,
        )
    except sqlite3.Error:
        return "VPS ساخته شد، اما ذخیرهٔ آن در «سرورهای من» ناموفق بود."
    if address:
        return f"در «سرورهای من ← {region}» ذخیره شد."
    return f"پس از تخصیص IP، در «سرورهای من ← {region}» ذخیره می‌شود."


async def kamatera_created_instance(pending):
    token = await kamatera_token(pending.user_id)
    command = await kamatera.command_status(token, pending.remote_id)
    if command["status"] != "complete":
        return None, command["status"] == "error"
    match = re.search(r"^Name:\s*([^\r\n]+)", str(command.get("log") or ""), re.M)
    name = match[1].strip() if match else command.get("server") or pending.name
    candidates = [
        row for row in await kamatera.list_servers(token)
        if row.get("name") == name and str(row.get("datacenter")).casefold() == pending.region.casefold()
    ]
    if len(candidates) != 1:
        return None, False
    return await kamatera.server_details(token, candidates[0]["id"]), False


async def resolve_created_server(pending):
    user_id = pending.user_id
    if not user_has_access(user_id):
        cloud_saved.finish(ADMIN_DB, pending, failed=True)
        return
    failed = False
    instance = None
    try:
        if pending.provider == "kamatera":
            instance, failed = await kamatera_created_instance(pending)
        elif pending.provider == "linode":
            token = linode_token(user_id)
            if token:
                instance = await linode.details(token, int(pending.remote_id))
        elif pending.provider == "hetzner":
            token = hetzner_token(user_id, pending.account_id)
            if token:
                instance = await hetzner.server_details(token, int(pending.remote_id))
        elif pending.provider == "vultr":
            token = vultr_token(user_id)
            if token:
                instance = await vultr.details(token, pending.remote_id)
        elif pending.provider == "cherry":
            token = cherry_token(user_id)
            if token:
                instance = await cherry.details(token, int(pending.remote_id))
                failed = instance.get("status") == "failed deployment"
    except (kamatera.APIError, linode.APIError, hetzner.APIError, vultr.APIError, cherry.APIError, InvalidToken):
        pass
    address = cloud_saved.instance_address(pending.provider, instance) if instance else None
    secret = None
    if address and pending.provider in {"vultr", "cherry"}:
        password = instance.get("password" if pending.provider == "cherry" else "default_password")
        if isinstance(password, str) and password:
            secret = SERVER_CIPHER.encrypt(password.encode())
    if not user_has_access(user_id):
        cloud_saved.finish(ADMIN_DB, pending, failed=True)
        return
    cloud_saved.finish(ADMIN_DB, pending, address, secret, failed=failed)


async def cloud_saved_job(context):
    await asyncio.gather(*(resolve_created_server(pending) for pending in cloud_saved.due(ADMIN_DB)))


async def kamatera_button(update, context):
    query = update.callback_query
    await query.answer()
    if not private_admin(update):
        return
    message = query.message
    user_id = update.effective_user.id
    state = context.user_data
    action = query.data
    if action.startswith("km:make:"):
        draft = state.get("kamatera", {})
        if draft.get("confirmation") != action:
            await message.reply_text("این تأیید قدیمی است. از منوی کاماترا دوباره شروع کن.")
            return
        form = draft["form"]
        try:
            token = await kamatera_token(user_id)
        except (kamatera.APIError, InvalidToken):
            await message.reply_text("ورود به API ناموفق بود. کلید کاماترا را بررسی کن.")
            return
        if await offer_replacement(message, context, user_id, "kamatera", form, token, image=draft["image"]):
            draft.pop("confirmation", None)
            return
        clear(context)
        try:
            command_id = await kamatera.create_server(token, form)
        except kamatera.APIError as exc:
            if exc.status and 400 <= exc.status < 500:
                await message.reply_text(f"کاماترا درخواست ساخت را با خطای HTTP {exc.status} رد کرد.")
            else:
                await message.reply_text("نتیجهٔ ساخت مشخص نیست. قبل از ارسال دوباره، صف عملیات را در پنل کاماترا بررسی کن.")
            return
        try:
            with ADMIN_DB:
                ADMIN_DB.execute(
                    "UPDATE kamatera_accounts SET command_id = ? WHERE user_id = ?", (command_id, user_id),
                )
        except sqlite3.Error:
            await message.reply_text(f"درخواست ساخت ثبت شد، اما ذخیرهٔ شناسه در ربات ناموفق بود. شناسه: {command_id}")
            return
        storage = store_created_server(
            user_id, "kamatera", command_id, form["datacenter"], form["name"], password=form["password"],
            username="Administrator" if "windows" in draft["image"].casefold() else "root",
        )
        await message.reply_text(
            f"درخواست ساخت ثبت شد. شناسهٔ عملیات: {command_id}\n{storage}",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("بررسی وضعیت", callback_data="km:status")]]),
        )
        return

    if action == "km:new":
        clear_for_creation(context, "kamatera")
    else:
        clear(context)
    if action == "kamatera":
        await message.reply_text("مدیریت کاماترا", reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("ثبت یا تعویض کلید API", callback_data="km:key")],
            [InlineKeyboardButton("ساخت VPS", callback_data="km:new")],
            [InlineKeyboardButton("سرورهای موجود", callback_data="km:servers")],
            [InlineKeyboardButton("وضعیت آخرین درخواست", callback_data="km:status")],
            [InlineKeyboardButton("بازگشت", callback_data="cancel")],
        ]))
        return
    if action == "km:key":
        state["kamatera"] = {"step": "key"}
        await message.reply_text(
            "Access Key مربوط به API سرور کاماترا را بفرست. بعد Secret Key را می‌پرسم. ربات تلاش می‌کند پیام‌ها را حذف کند. "
            "چت ربات رمزنگاری سرتاسری ندارد."
        )
        return
    account = kamatera_account(user_id)
    if not account:
        await message.reply_text("اول کلید API کاماترا را در منوی کاماترا ثبت کن.")
        return
    try:
        token = await kamatera_token(user_id)
        if action == "km:servers":
            servers = await kamatera.list_servers(token)
            state["kamatera_servers"] = {"servers": servers}
            await show_kamatera_servers(message, state["kamatera_servers"])
            return
        if action == "km:status":
            if not account[1]:
                await message.reply_text("هنوز درخواست ساختی ثبت نشده است.")
                return
            result = await kamatera.command_status(token, account[1])
            status = {"complete": "ساخت کامل شد", "error": "ساخت ناموفق بود"}.get(
                result["status"], "در صف یا در حال انجام",
            )
            name = str(result.get("server") or "")[:120]
            await message.reply_text(f"عملیات {account[1]} — {status}" + (f"\nسرور: {name}" if name else ""))
            return
        data = await kamatera.options(token, "datacenters")
        if not isinstance(data, dict):
            raise kamatera.APIError()
    except (kamatera.APIError, InvalidToken):
        await message.reply_text("دریافت اطلاعات از کاماترا ناموفق بود. کلید API را بررسی کن.")
        return
    locations = {
        code: f"{details.get('city', '')} {details.get('country', '')}".strip()
        for code, details in data.items() if isinstance(details, dict)
    }
    if not locations:
        await message.reply_text("کاماترا دیتاسنتری برای این حساب برنگرداند.")
        return
    state["kamatera"] = {"step": "location", "locations": locations, "form": {}}
    await show_kamatera_create(message, state["kamatera"])


CREATE_STEPS = ("location", "image", "cpu", "ram", "disk", "name")
CREATE_PROMPTS = {
    "location": "دیتاسنتر را انتخاب کن.",
    "image": "ایمیج سیستم‌عامل را انتخاب کن.",
    "cpu": "تعداد و نوع CPU را انتخاب کن.",
    "ram": "مقدار رم را انتخاب کن.",
    "disk": "حجم دیسک را انتخاب کن.",
    "name": "نام VPS را بفرست.",
}


def kamatera_create_choices(draft):
    step = draft["step"]
    if step == "location":
        return [(code, f"{label} · {code}" if label else code) for code, label in draft["locations"].items()]
    if step == "image":
        return [(key, str(image.get("description") or key)) for key, image in draft["images"].items()]
    if step == "cpu":
        return [(cpu, cpu) for cpu in draft["cpu_choices"]]
    if step == "ram":
        return [(ram, f"{ram} MB") for ram in draft["cpu_choices"][draft["form"]["cpu"]]]
    if step == "disk":
        return [(disk, f"{disk} GB") for disk in draft["disks"]]
    return []


async def show_kamatera_create(message, draft, page=0, *, edit=False, notice=None):
    step = draft["step"]
    choices = kamatera_create_choices(draft)
    page_size = 8
    offset = page * page_size
    token = draft["picker"] = secrets.token_hex(8)
    rows = [
        [InlineKeyboardButton(label[:64], callback_data=f"kmc:{token}:pick:{index}")]
        for index, (_, label) in enumerate(choices[offset:offset + page_size], offset)
    ]
    nav = []
    if page:
        nav.append(InlineKeyboardButton("◀ قبلی", callback_data=f"kmc:{token}:page:{page - 1}"))
    if offset + page_size < len(choices):
        nav.append(InlineKeyboardButton("بعدی ▶", callback_data=f"kmc:{token}:page:{page + 1}"))
    if nav:
        rows.append(nav)
    back = [InlineKeyboardButton("لغو", callback_data="cancel")]
    if step != "location":
        back.insert(0, InlineKeyboardButton("بازگشت", callback_data=f"kmc:{token}:back:0"))
    rows.append(back)
    prompt = CREATE_PROMPTS[step]
    if notice:
        prompt = notice + "\n\n" + prompt
    send = message.edit_text if edit else message.reply_text
    await send(prompt, reply_markup=InlineKeyboardMarkup(rows))


async def kamatera_create_button(update, context):
    query = update.callback_query
    if not private_admin(update):
        await query.answer()
        return
    draft = context.user_data.get("kamatera", {})
    _, token, action, raw_index = query.data.split(":")
    if token != draft.get("picker") or draft.get("step") not in CREATE_STEPS:
        await query.answer("این منو بسته شده است.")
        return
    await query.answer()
    message = query.message
    step = draft["step"]
    if action == "back":
        draft["step"] = CREATE_STEPS[CREATE_STEPS.index(step) - 1]
        await show_kamatera_create(message, draft, edit=True)
        return
    index = int(raw_index)
    choices = kamatera_create_choices(draft)
    if action == "page":
        if index * 8 < len(choices):
            await show_kamatera_create(message, draft, index, edit=True)
        return
    if index >= len(choices):
        return
    value = choices[index][0]
    form = draft["form"]
    if step in {"location", "image"}:
        try:
            bearer = await kamatera_token(update.effective_user.id)
            if step == "location":
                data = await kamatera.options(bearer, "images/" + quote(value, safe=""))
                if not isinstance(data, list):
                    raise kamatera.APIError()
                images = {i["id"]: i for i in data if isinstance(i, dict) and isinstance(i.get("id"), str)}
                if not images:
                    await show_kamatera_create(message, draft, index // 8, edit=True, notice="این دیتاسنتر ایمیجی ندارد.")
                    return
                draft["images"] = images
                form["datacenter"] = value
            else:
                data = await kamatera.options(bearer, "image/" + quote(value, safe=""))
                image = draft["images"][value]
                cpu, disks = kamatera_sizes(data, image)
                if not cpu or not disks:
                    await show_kamatera_create(
                        message, draft, index // 8, edit=True, notice="این ایمیج گزینهٔ سازگار برای ساخت ساعتی ندارد.",
                    )
                    return
                draft.update(cpu_choices=cpu, disks=disks, image=str(image.get("description") or value))
                form["disk_src_0"] = value
        except (kamatera.APIError, InvalidToken):
            await show_kamatera_create(message, draft, index // 8, edit=True, notice="دریافت گزینه‌ها ناموفق بود. دوباره تلاش کن.")
            return
    else:
        form[{"cpu": "cpu", "ram": "ram", "disk": "disk_size_0"}[step]] = value
    draft["step"] = CREATE_STEPS[CREATE_STEPS.index(step) + 1]
    await show_kamatera_create(message, draft, edit=True)


def kamatera_sizes(data, image):
    if not isinstance(data, dict):
        raise kamatera.APIError()
    billing, cpu, ram, disk = (data.get(name) for name in ("billing", "cpu", "ram", "disk"))
    if not isinstance(billing, list) or not isinstance(cpu, list) or not isinstance(ram, dict) or not isinstance(disk, list):
        raise kamatera.APIError()
    if "hourly" not in billing:
        return {}, []
    requirements = data.get("imageRequirements") or {}
    try:
        min_cpu = int(requirements.get("minCpu") or 0)
        min_ram = int(requirements.get("minRamMb") or 0)
        min_disk = max(int(requirements.get("minDiskSize") or 0), int(image.get("sizeGB") or 0))
    except (AttributeError, ValueError, TypeError):
        raise kamatera.APIError() from None
    choices = {}
    for option in cpu:
        if not isinstance(option, str) or not re.fullmatch(r"[0-9]{1,4}[A-Z]", option) or int(option[:-1]) < min_cpu:
            continue
        sizes = ram.get(option[-1], [])
        if not isinstance(sizes, list):
            continue
        compatible = sorted({size for size in sizes if type(size) is int and size >= max(1, min_ram)})
        if compatible:
            choices[option] = compatible
    return choices, sorted({size for size in disk if type(size) is int and size >= max(1, min_disk)})


POWER_LABELS = {"on": "روشن کردن", "off": "خاموش کردن", "restart": "ری‌استارت"}
POWER_STATUS = {"on": "روشن", "off": "خاموش"}


def kamatera_controls(state, rows):
    token = state["token"] = secrets.token_hex(8)
    return InlineKeyboardMarkup([
        [InlineKeyboardButton(label, callback_data=f"kms:{token}:{action}") for label, action in row]
        for row in rows
    ])


async def show_kamatera_servers(message, state, page=0):
    servers = state["servers"]
    offset = page * 8
    rows = [
        [(f"{row.get('name') or row['id']} · {POWER_STATUS.get(row.get('power'), 'نامشخص')}"[:64], f"detail:{index}")]
        for index, row in enumerate(servers[offset:offset + 8], offset)
    ]
    navigation = []
    if page:
        navigation.append(("قبلی", f"page:{page - 1}"))
    if offset + 8 < len(servers):
        navigation.append(("بعدی", f"page:{page + 1}"))
    if navigation:
        rows.append(navigation)
    markup = kamatera_controls(state, rows) if rows else None
    keyboard = list(markup.inline_keyboard) if markup else []
    keyboard.append([
        InlineKeyboardButton("به‌روزرسانی فهرست", callback_data="km:servers"),
        InlineKeyboardButton("منوی کاماترا", callback_data="kamatera"),
    ])
    await message.reply_text(
        "سرور کاماترا را انتخاب کن." if servers else "برای این حساب سرور کاماترایی پیدا نشد.",
        reply_markup=InlineKeyboardMarkup(keyboard),
    )


def kamatera_operation_controls(state, index, status_label):
    rows = [[(status_label, "status:0")]]
    if not state["deleting"]:
        rows[0].append(("وضعیت سرور", f"detail:{index}"))
    markup = kamatera_controls(state, rows)
    if state["deleting"]:
        return InlineKeyboardMarkup([
            *markup.inline_keyboard,
            [InlineKeyboardButton("به‌روزرسانی فهرست سرورها", callback_data="km:servers")],
        ])
    return markup


async def kamatera_server_button(update, context):
    query = update.callback_query
    if not private_admin(update):
        await query.answer()
        return
    state = context.user_data.get("kamatera_servers")
    _, token, action, value = query.data.split(":")
    if not state or token != state["token"]:
        await query.answer("این منو بسته شده است.")
        return
    await query.answer()
    message = query.message
    if action == "page":
        await show_kamatera_servers(message, state, int(value))
        return
    index = int(value) if action == "detail" else state["selected"]
    server = state["servers"][index]
    server_id = server["id"]
    name = str(server.get("name") or server_id)[:120]
    if action == "power":
        state["power"] = value
        await message.reply_text(
            f"عملیات «{POWER_LABELS[value]}» روی «{name}» انجام شود؟",
            reply_markup=kamatera_controls(state, [
                [("تأیید عملیات", "confirm:0"), ("انصراف", f"detail:{index}")],
            ]),
        )
        return
    if action == "delete":
        await message.reply_text(
            f"سرور «{name}» با شناسهٔ {server_id} و داده‌های آن برای همیشه حذف می‌شوند. "
            "اگر سرور روشن باشد، کاماترا آن را هم متوقف می‌کند.",
            reply_markup=kamatera_controls(state, [
                [("🗑 تأیید حذف دائمی", "confirm:delete"), ("انصراف", f"detail:{index}")],
            ]),
        )
        return
    if action == "confirm":
        state["token"] = None
    try:
        bearer = await kamatera_token(update.effective_user.id)
        if action == "confirm":
            deleting = value == "delete"
            if deleting:
                command_id = await kamatera.terminate_server(bearer, server_id)
            else:
                command_id = await kamatera.set_power(bearer, server_id, state.pop("power"))
            state.update(command_id=command_id, deleting=deleting)
            label = "درخواست حذف ثبت شد" if deleting else "درخواست ثبت شد"
            await message.reply_text(
                f"{label}. شناسهٔ عملیات: {command_id}",
                reply_markup=kamatera_operation_controls(state, index, "وضعیت عملیات"),
            )
            return
        if action == "status":
            result = await kamatera.command_status(bearer, state["command_id"])
            status = {"complete": "انجام شد", "error": "ناموفق بود"}.get(result["status"], "در صف یا در حال انجام")
            await message.reply_text(
                f"عملیات {state['command_id']} — {status}",
                reply_markup=kamatera_operation_controls(state, index, "بررسی دوباره"),
            )
            return
        detail = await kamatera.server_details(bearer, server_id)
    except (kamatera.APIError, InvalidToken) as exc:
        if action == "confirm":
            status = exc.status if isinstance(exc, kamatera.APIError) else None
            text = (
                f"درخواست با خطای HTTP {status} رد شد." if status and 400 <= status < 500
                else "نتیجهٔ درخواست مشخص نیست. وضعیت سرور یا صف پنل کاماترا را بررسی کن."
            )
        else:
            text = "دریافت اطلاعات سرور از کاماترا ناموفق بود."
        await message.reply_text(text, reply_markup=kamatera_controls(state, [[("بازگشت به فهرست", f"page:{index // 8}")]]))
        return

    state["selected"] = index
    server["name"] = str(detail.get("name") or name)[:120]
    networks = detail.get("networks") or []
    addresses = [
        ip for network in networks if isinstance(network, dict)
        for ip in (network.get("ips") or []) if isinstance(ip, str)
    ]
    await message.reply_text(
        f"سرور: {str(detail.get('name') or name)[:120]}\n"
        f"وضعیت: {POWER_STATUS.get(detail.get('power'), 'نامشخص')}\n"
        f"دیتاسنتر: {detail.get('datacenter') or '—'}\n"
        f"آدرس‌ها: {', '.join(addresses)[:1500] or '—'}\n"
        f"دیسک (GB): {detail.get('disks') or '—'}\n"
        f"تعرفه: {detail.get('billing') or '—'}",
        reply_markup=kamatera_controls(state, [
            [(label, f"power:{power}") for power, label in POWER_LABELS.items()],
            [("🗑 حذف سرور", "delete:0")],
            [("تازه‌سازی وضعیت", f"detail:{index}"), ("بازگشت به فهرست", f"page:{index // 8}")],
        ]),
    )


async def delete_secret_message(message):
    try:
        await message.delete()
    except TelegramError:
        await message.reply_text("حذف پیام ممکن نشد. پیام حاوی اطلاعات محرمانه را دستی پاک کن.")


async def kamatera_text(update, context):
    message = update.message
    draft = context.user_data["kamatera"]
    step = draft["step"]
    value = message.text.strip()
    user_id = update.effective_user.id
    if step in {"key", "key_secret"}:
        await delete_secret_message(message)
        fields = [field.strip() for field in value.splitlines()]
        if step == "key" and len(fields) == 1 and fields[0]:
            draft.update(step="key_secret", client_id=fields[0])
            await message.reply_text("حالا Secret Key کاماترا را بفرست.")
            return
        if step == "key_secret":
            if len(fields) != 1 or not fields[0]:
                await message.reply_text("فقط مقدار Secret Key را در یک خط بفرست.")
                return
            fields.insert(0, draft["client_id"])
        if len(fields) != 2 or not all(fields):
            await message.reply_text("اول Access Key را بفرست. همچنین می‌توانی Access Key و Secret Key را در دو خطِ یک پیام بفرستی.")
            return
        try:
            await kamatera.authenticate(*fields)
        except kamatera.APIError:
            draft.pop("client_id", None)
            draft["step"] = "key"
            await message.reply_text("احراز هویت ناموفق بود. Access Key مربوط به API سرور را دوباره بفرست. کلیدهای Object Storage برای این بخش نیستند.")
            return
        with ADMIN_DB:
            ADMIN_DB.execute(
                """INSERT INTO kamatera_accounts VALUES (?, ?, NULL)
                   ON CONFLICT(user_id) DO UPDATE SET credentials=excluded.credentials, command_id=NULL""",
                (user_id, SERVER_CIPHER.encrypt("\n".join(fields).encode())),
            )
        clear(context)
        await message.reply_text("کلید API کاماترا تأیید و رمزگذاری شد.")
        return

    form = draft["form"]
    if step in CREATE_STEPS[:-1]:
        await message.reply_text("برای انتخاب از دکمه‌های همین مرحله استفاده کن.")
        return
    if step == "name":
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}", value):
            await message.reply_text("نام سرور را با حروف انگلیسی، عدد، خط تیره یا زیرخط بفرست.")
            return
        form["name"] = value
        draft.pop("picker", None)
        draft["step"] = "password"
        await message.reply_text("رمز اولیهٔ VPS را بفرست. ۹ تا ۳۲ کاراکتر با حرف کوچک، حرف بزرگ و عدد. ربات تلاش می‌کند پیام رمز را حذف کند.")
        return
    if step == "password":
        await delete_secret_message(message)
        if not (9 <= len(value) <= 32 and re.search(r"[a-z]", value) and re.search(r"[A-Z]", value) and re.search(r"[0-9]", value)):
            await message.reply_text("رمز باید ۹ تا ۳۲ کاراکتر و شامل حرف کوچک، حرف بزرگ و عدد باشد.")
            return
        form["password"] = value
        confirmation = "km:make:" + secrets.token_hex(8)
        draft.update(step="confirm", confirmation=confirmation)
        await message.reply_text(
            f"سرور: {form['name']}\nدیتاسنتر: {form['datacenter']}\nایمیج: {draft['image']}\n"
            f"CPU: {form['cpu']} | RAM: {form['ram']} MB | Disk: {form['disk_size_0']} GB\n"
            "یک VPS با IP عمومی و تعرفهٔ ساعتی ساخته می‌شود. هزینه طبق تعرفهٔ حسابت در کاماترا محاسبه می‌شود.",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton(replacement_confirm_label(context), callback_data=confirmation)],
                [InlineKeyboardButton("لغو", callback_data="cancel")],
            ]),
        )


LINODE_PICKERS = {
    "region": "منطقهٔ Linode را انتخاب کن.",
    "image": "ایمیج سیستم‌عامل را انتخاب کن.",
    "type": "پلن Linode را انتخاب کن.",
    "servers": "یک VPS را انتخاب کن.",
}


def linode_token(user_id):
    row = ADMIN_DB.execute("SELECT token FROM linode_accounts WHERE user_id = ?", (user_id,)).fetchone()
    return SERVER_CIPHER.decrypt(row[0]).decode() if row else None


def nonce_keyboard(state, rows, prefix):
    nonce = state["nonce"] = secrets.token_hex(8)
    return InlineKeyboardMarkup([
        [InlineKeyboardButton(label, callback_data=f"{prefix}:{nonce}:{action}") for label, action in row]
        for row in rows
    ])


def linode_keyboard(state, rows):
    return nonce_keyboard(state, rows, "lp")


async def show_linode_picker(message, state, page=0):
    await show_cloud_picker(message, state, page, LINODE_PICKERS[state["step"]], "lp", "منوی Linode", "linode")


async def show_cloud_picker(
    message, state, page, prompt, prefix, menu_label, menu_action, *,
    extra_buttons=(), empty_prompt="گزینه‌ای برای نمایش پیدا نشد.",
):
    choices = state["choices"]
    offset = page * 8
    rows = [
        [(label[:64], f"pick:{index}")]
        for index, (_, label) in enumerate(choices[offset:offset + 8], offset)
    ]
    navigation = []
    if page:
        navigation.append(("قبلی", f"page:{page - 1}"))
    if offset + 8 < len(choices):
        navigation.append(("بعدی", f"page:{page + 1}"))
    if navigation:
        rows.append(navigation)
    markup = nonce_keyboard(state, rows, prefix)
    keyboard = [*markup.inline_keyboard, *extra_buttons, [InlineKeyboardButton(menu_label, callback_data=menu_action)]]
    await message.reply_text(
        prompt if choices else empty_prompt,
        reply_markup=InlineKeyboardMarkup(keyboard),
    )


async def offer_panel_registration(message, client, sudo, api_key, cert):
    read_settings = "grep -E '^(SERVICE_PORT|SERVICE_PROTOCOL|API_PORT)[[:space:]]*=' /opt/pg-node/.env"
    try:
        ssh_host = client.get_transport().sock.getpeername()[0]
        ip = str(ip_address(ssh_host))
        code, output = await asyncio.to_thread(run, client, sudo + read_settings)
        if code:
            raise ValueError
        settings = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        settings = {key.strip(): value.strip().strip('"\'') for key, value in settings.items()}
        protocol = settings["SERVICE_PROTOCOL"]
        port = int(settings["SERVICE_PORT"])
        api_port = int(settings.get("API_PORT", 62051))
        if protocol not in {"grpc", "rest"} or not all(1 <= value <= 65535 for value in (port, api_port)):
            raise ValueError
    except (OSError, AttributeError, KeyError, ValueError, paramiko.SSHException):
        await message.reply_text("خواندن IP، پروتکل یا پورت‌های نود برای ثبت در پنل ناموفق بود.")
        return
    ticket = pasarguard.save_install(ADMIN_DB, SERVER_CIPHER, message.chat_id, {
        "name": ip, "address": ip, "server_ca": cert, "api_key": api_key,
        "port": port, "api_port": api_port, "connection_type": protocol, "keep_alive": 60,
    })
    await message.reply_text("نود آمادهٔ ثبت در پنل پاسارگارد است.", reply_markup=InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ اضافه‌کردن به پنل پاسارگارد", callback_data=f"pg:add:{ticket}")],
    ]))


def panel_menu():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📦 نصب پاسارگارد", callback_data="pg:install")],
        [InlineKeyboardButton("🔑 تنظیم اتصال پنل", callback_data="pg:key")],
        [InlineKeyboardButton("🎯 اینباند پیش‌فرض Host نودها", callback_data="pg:default")],
        [InlineKeyboardButton("🔀 تغییر اینباند Host موجود", callback_data="pg:hosts")],
    ])


async def panel_install_text(update, context):
    state = context.user_data
    message = update.message
    value = message.text.strip()
    step = state["panel_install_step"]
    if step == "domain":
        try:
            state["panel_domain"] = ssl_domain(value)
        except ValueError:
            await message.reply_text("نام کامل ساب‌دامنه را بدون URL یا پورت بفرست.")
            return
        state["panel_install_step"] = "email"
        await message.reply_text("ایمیل صدور گواهی Let’s Encrypt را بفرست.")
    elif step == "email":
        try:
            if len(value) > 254 or not SSL_EMAIL.fullmatch(value) or ".." in value:
                raise ValueError
            local, domain = value.split("@")
            if local.endswith("."):
                raise ValueError
            state["panel_email"] = f"{local}@{ssl_domain(domain)}"
        except ValueError:
            await message.reply_text("یک آدرس ایمیل معتبر بفرست.")
            return
        state["panel_install_step"] = "confirm"
        nonce = state["panel_install_nonce"] = secrets.token_hex(8)
        host, port = state["address"]
        await message.reply_text(
            f"پنل روی {server_label(host, port, state['username'])} نصب شود؟\n"
            f"ساب‌دامنه: {state['panel_domain']}\nایمیل گواهی: {state['panel_email']}\n"
            "DNS ساب‌دامنه باید به سرور اشاره کند. پورت ۸۰ برای صدور گواهی و ۸۰۰۰ برای پنل باید از اینترنت در دسترس باشند. "
            "ادامه به معنی پذیرش شرایط Let’s Encrypt است.",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("✅ تأیید نصب", callback_data=f"pg:install:confirm:{nonce}"),
            ]]),
        )
    else:
        await message.reply_text("برای شروع نصب، دکمهٔ تأیید را بزن.")


async def panel_install_button(update, context):
    query = update.callback_query
    await query.answer()
    if not private_admin(update):
        return
    state = context.user_data
    if query.data == "pg:install":
        clear(context)
        state["action"] = "panel_install"
        await show_servers(update, context)
        return
    if (state.get("panel_install_step") != "confirm"
            or query.data.rsplit(":", 1)[1] != state.get("panel_install_nonce")):
        await query.message.reply_text("این درخواست نصب منقضی شده است.", reply_markup=panel_menu())
        return
    row = ADMIN_DB.execute(
        "SELECT host, port, username, secret FROM servers WHERE user_id = ? AND id = ?",
        (update.effective_user.id, state["saved_server_id"]),
    ).fetchone()
    if not row or row[:3] != (*state["address"], state["username"]):
        clear(context)
        await query.message.reply_text("سرور انتخاب‌شده تغییر کرده است. دوباره انتخابش کن.", reply_markup=panel_menu())
        return
    state["panel_install_step"] = "connect"
    secret = row[3]
    if secret is None and not (private_owner(update) and os.getenv("SSH_KEY_PATH")):
        await ask_password(query.message, private_owner(update))
        return
    try:
        password = SERVER_CIPHER.decrypt(secret).decode() if secret is not None else None
    except InvalidToken:
        await query.message.reply_text("رمز ذخیره‌شده خوانده نشد.")
        await show_saved_password_retry(query.message, state)
        return
    if not await login_server(update, context, password, remember=False):
        await show_saved_password_retry(query.message, state)


async def panel_credentials_text(update, context):
    message = update.message
    values = message.text.strip().splitlines()
    await delete_secret_message(message)
    try:
        if len(values) not in (2, 3) or not all(line.strip() for line in values):
            raise pasarguard.PanelError("آدرس و توکن را در دو خط یا آدرس، نام کاربری و رمز را در سه خط بفرست.")
        url, *credentials = (line.strip() for line in values)
        async with pasarguard.connect(url, credentials) as panel:
            await panel.cores()
        pasarguard.save_account(ADMIN_DB, SERVER_CIPHER, update.effective_user.id, url.rstrip("/"), credentials)
    except (pasarguard.PanelError, KeyError, TypeError) as error:
        await message.reply_text(str(error) if isinstance(error, pasarguard.PanelError) else "پاسخ API پنل معتبر نبود.")
        return
    clear(context)
    await message.reply_text("اتصال پنل ذخیره شد. حالا اینباند پیش‌فرض را انتخاب کن.", reply_markup=panel_menu())


async def panel_picker(message, state, step, choices, prompt):
    state.update(step=step, choices=choices, prompt=prompt)
    await show_cloud_picker(message, state, 0, prompt, "pgp", "🛡 منوی پاسارگارد", "pg")


async def panel_button(update, context):
    query = update.callback_query
    await query.answer()
    if not private_admin(update):
        return
    user_id = update.effective_user.id
    message = query.message
    action = query.data
    try:
        if action in ("pg", "pg:key"):
            clear(context)
            if action == "pg":
                await message.reply_text("پنل پاسارگارد", reply_markup=panel_menu())
            else:
                context.user_data["pasarguard"] = {"step": "credentials"}
                await message.reply_text(
                    "آدرس HTTPS پنل و کلید API یا توکن دسترسی را در دو خط بفرست. "
                    "برای ورود خودکار می‌توانی آدرس، نام کاربری و رمز پنل را در سه خط بفرستی."
                )
            return
        url, credentials, core_id, inbound = pasarguard.account(ADMIN_DB, SERVER_CIPHER, user_id)
        state = context.user_data.get("pasarguard", {})
        if action.startswith("pgp:"):
            _, nonce, selection = action.split(":", 2)
            if nonce != state.get("nonce"):
                raise pasarguard.PanelError("این دکمه قدیمی است. دوباره از منوی پاسارگارد وارد شو.")
            if selection.startswith("page:"):
                await show_cloud_picker(
                    message, state, int(selection.split(":")[1]), state["prompt"], "pgp", "🛡 منوی پاسارگارد", "pg",
                )
                return
        else:
            clear(context)
            state = context.user_data["pasarguard"] = {"url": url}
        if action.startswith(("pg:add:", "pg:confirm:")):
            if not inbound or core_id is None:
                raise pasarguard.PanelError("ابتدا Core و اینباند پیش‌فرض Host را انتخاب کن.")
            ticket = action.split(":")[2]
            draft = pasarguard.load_install(ADMIN_DB, SERVER_CIPHER, user_id, ticket)
            node = draft["node"]
            target = [url, core_id, inbound]
            if draft.get("target", target) != target:
                raise pasarguard.PanelError("تنظیمات مقصد این ثبت تغییر کرده است. تنظیمات قبلی را بررسی کن.")
            if draft.get("completed"):
                await message.reply_text(f"نود و Host {draft['remark']} قبلاً ثبت شده‌اند.")
                return
            if action.startswith("pg:add:"):
                if "target" not in draft:
                    draft["target"] = target
                    pasarguard.update_install(ADMIN_DB, SERVER_CIPHER, user_id, ticket, draft)
                await message.reply_text(
                    f"نود {node['name']} و یک Host با همین IP روی اینباند {inbound} ثبت شود؟",
                    reply_markup=InlineKeyboardMarkup([[
                        InlineKeyboardButton("✅ ثبت نود و Host", callback_data=f"pg:confirm:{ticket}"),
                    ]]),
                )
                return
            async with pasarguard.connect(url, credentials) as panel:
                if inbound not in await panel.inbounds(core_id):
                    raise pasarguard.PanelError("اینباند پیش‌فرض دیگر روی Core انتخابی در دسترس نیست.")
                hosts = await panel.hosts()
                await panel.ensure_node(dict(node, core_config_id=core_id))
                if "remark" not in draft:
                    draft["remark"] = pasarguard.reserve_remark(ADMIN_DB, user_id, hosts)
                    pasarguard.update_install(ADMIN_DB, SERVER_CIPHER, user_id, ticket, draft)
                try:
                    await panel.ensure_host(draft["remark"], node["address"], inbound, hosts)
                except pasarguard.PanelError as error:
                    raise pasarguard.PanelError(
                        f"نود در پنل ثبت شده، اما ثبت Host کامل نشد. {error} برای تلاش دوباره همان دکمهٔ ثبت را بزن."
                    ) from None
            draft["completed"] = True
            draft["node"] = {"name": node["name"], "address": node["address"]}
            pasarguard.update_install(ADMIN_DB, SERVER_CIPHER, user_id, ticket, draft)
            await message.reply_text(f"✅ نود {node['name']} و Host {draft['remark']} روی اینباند {inbound} ثبت شدند.")
            return
        async with pasarguard.connect(url, credentials) as panel:
            if action == "pg:default":
                await panel_picker(message, state, "core", [
                    (core["id"], f"{core['name']} · {core['id']}") for core in await panel.cores()
                ], "Core نودهای جدید را انتخاب کن.")
                return
            if action == "pg:hosts":
                await panel_picker(message, state, "host", [
                    (host["id"], f"{host['remark']} · {host['inbound_tag'] or '—'}") for host in await panel.hosts()
                ], "Host موردنظر را برای تغییر اینباند انتخاب کن.")
                return
            if state["url"] != url:
                raise pasarguard.PanelError("اتصال پنل تغییر کرده است. فهرست را دوباره باز کن.")
            if selection == "confirm":
                if state["step"] != "confirm_host":
                    return
                host_id, tag = state["host_id"], state["tag"]
                host = await panel.request("GET", f"host/{host_id}")
                if host["inbound_tag"] != state["previous_tag"]:
                    raise pasarguard.PanelError("اینباند Host در پنل تغییر کرده است. Host را دوباره انتخاب کن.")
                await panel.request("PUT", f"host/{host_id}", json=dict(host, inbound_tag=tag))
                clear(context)
                await message.reply_text(f"اینباند Host {host['remark']} به {tag} تغییر کرد.", reply_markup=panel_menu())
                return
            index = int(selection.split(":")[1])
            value, _ = state["choices"][index]
            if state["step"] == "core":
                state["core_id"] = value
                await panel_picker(message, state, "default_inbound", [
                    (tag, tag) for tag in await panel.inbounds(value)
                ], "اینباندی را انتخاب کن که Host نودهای جدید روی آن ساخته شود.")
            elif state["step"] == "default_inbound":
                with ADMIN_DB:
                    ADMIN_DB.execute(
                        "UPDATE pasarguard_accounts SET core_id = ?, inbound = ? WHERE user_id = ?",
                        (state["core_id"], value, user_id),
                    )
                clear(context)
                await message.reply_text(
                    f"اینباند پیش‌فرض {value} ذخیره شد. Host نودهای جدید با IP نود و نام‌های HERM1، HERM2 و … ساخته می‌شوند.",
                    reply_markup=panel_menu(),
                )
            elif state["step"] == "host":
                host = await panel.request("GET", f"host/{value}")
                state.update(host_id=value, previous_tag=host["inbound_tag"], host_remark=host["remark"])
                tags = set()
                for core in await panel.cores():
                    tags.update(await panel.inbounds(core["id"]))
                await panel_picker(message, state, "host_inbound", [
                    (tag, tag) for tag in sorted(tags) if tag != host["inbound_tag"]
                ], f"اینباند جدید برای {host['remark']} را انتخاب کن.")
            elif state["step"] == "host_inbound":
                state.update(step="confirm_host", tag=value)
                await message.reply_text(
                    f"اینباند Host {state['host_remark']} به {value} تغییر کند؟",
                    reply_markup=nonce_keyboard(state, [[("✅ تأیید تغییر", "confirm")]], "pgp"),
                )
    except (pasarguard.PanelError, InvalidToken, KeyError, TypeError, IndexError) as error:
        await message.reply_text(
            str(error) if isinstance(error, pasarguard.PanelError) else "خواندن تنظیمات یا پاسخ پنل ناموفق بود.",
            reply_markup=panel_menu(),
        )


async def show_linode_details(message, state, token):
    instance = await linode.details(token, state["instance"])
    state.update(step="instance", instance_label=str(instance.get("label") or state["instance"])[:120])
    ips = ", ".join(str(ip) for ip in (instance.get("ipv4") or []))
    if instance.get("ipv6"):
        ips = f"{ips}, {instance['ipv6']}" if ips else instance["ipv6"]
    await message.reply_text(
        f"سرور: {state['instance_label']}\nوضعیت: {instance.get('status', '—')}\n"
        f"منطقه: {instance.get('region', '—')}\nپلن: {instance.get('type', '—')}\nIP: {ips or '—'}",
        reply_markup=linode_keyboard(state, [
            [(label, operation) for operation, label in linode.POWER.items()],
            [("🗑 حذف سرور", "delete")],
            [("تازه‌سازی وضعیت", "refresh"), ("بازگشت به فهرست", "list")],
        ]),
    )


async def linode_button(update, context):
    query = update.callback_query
    if not private_admin(update):
        await query.answer()
        return
    message = query.message
    user_id = update.effective_user.id
    action = query.data
    state = context.user_data.get("linode", {})
    if action.startswith("lp:"):
        _, nonce, action = action.split(":", 2)
        if nonce != state.get("nonce"):
            await query.answer("این منو بسته شده است.")
            return
    else:
        if action == "li:new":
            clear_for_creation(context, "linode")
        else:
            clear(context)
        state = {}
    await query.answer()
    if action == "linode":
        await message.reply_text("مدیریت Linode", reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("ثبت یا تعویض توکن", callback_data="li:key")],
            [InlineKeyboardButton("ساخت VPS", callback_data="li:new"),
             InlineKeyboardButton("سرورهای موجود", callback_data="li:servers")],
            [InlineKeyboardButton("بازگشت", callback_data="cancel")],
        ]))
        return
    if action == "li:key":
        context.user_data["linode"] = {"step": "key"}
        await message.reply_text(
            "Personal Access Token با دسترسی Linodes: Read/Write را بفرست. "
            "ربات تلاش می‌کند پیام را حذف کند. چت ربات رمزنگاری سرتاسری ندارد."
        )
        return
    try:
        token = linode_token(user_id)
    except InvalidToken:
        token = None
    if not token:
        await message.reply_text("ابتدا توکن Linode را ثبت کن.")
        return
    try:
        if action in {"li:new", "li:servers"}:
            if action == "li:new":
                rows = await linode.regions()
                state.update(step="region", form={}, choices=[
                    (row["id"], f"{row.get('label') or row['id']} · {row['id']}") for row in rows
                ])
            else:
                rows = await linode.catalog("/linode/instances", token)
                state.update(step="servers", choices=[
                    (row["id"], f"{row.get('label') or row['id']} · {row.get('status', '—')}") for row in rows
                ])
            context.user_data["linode"] = state
            await show_linode_picker(message, state)
            return
        if action.startswith("page:"):
            page = int(action.split(":")[1])
            if page * 8 < len(state["choices"]):
                await show_linode_picker(message, state, page)
            return
        if action.startswith("pick:"):
            await linode_pick(message, state, token, int(action.split(":")[1]))
            return
        if action == "list":
            state["step"] = "servers"
            await show_linode_picker(message, state)
            return
        if action == "refresh":
            await show_linode_details(message, state, token)
            return
        if action == "delete" and state["step"] == "instance":
            state["step"] = "delete_confirm"
            await message.reply_text(
                f"سرور «{state['instance_label']}» با شناسهٔ {state['instance']} و داده‌های روی آن برای همیشه حذف می‌شوند.",
                reply_markup=linode_keyboard(state, [[("تأیید حذف دائمی", "confirm"), ("انصراف", "refresh")]]),
            )
            return
        if action in linode.POWER and state["step"] == "instance":
            state.update(step="power_confirm", operation=action)
            await message.reply_text(
                f"عملیات «{linode.POWER[action]}» روی «{state['instance_label']}» انجام شود؟",
                reply_markup=linode_keyboard(state, [[("تأیید عملیات", "confirm"), ("انصراف", "refresh")]]),
            )
            return
        if action != "confirm":
            return
        step = state["step"]
        state.pop("nonce", None)
        if step == "create_confirm":
            form = state["form"]
            if await offer_replacement(message, context, user_id, "linode", form, token, image=state["image_label"]):
                return
            clear(context)
            result = await linode.create(token, form)
            storage = store_created_server(
                user_id, "linode", result["id"], form["region"], form["label"],
                instance=result, password=form["root_pass"],
            )
            await message.reply_text(
                f"درخواست ساخت Linode ثبت شد. شناسه: {result.get('id', '—')}. "
                f"\n{storage}"
            )
        elif step == "delete_confirm":
            instance_id = state["instance"]
            clear(context)
            await linode.delete_instance(token, instance_id)
            await message.reply_text(
                f"سرور Linode با شناسهٔ {instance_id} حذف شد.",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("سرورهای موجود", callback_data="li:servers")],
                ]),
            )
        elif step == "power_confirm":
            await linode.set_power(token, state["instance"], state["operation"])
            await message.reply_text(
                "درخواست تغییر وضعیت ثبت شد.",
                reply_markup=linode_keyboard(state, [[("تازه‌سازی وضعیت", "refresh")]]),
            )
    except linode.APIError as exc:
        if action == "confirm" and (exc.status is None or exc.status >= 500):
            text = "نتیجهٔ درخواست مشخص نیست. پیش از تکرار، وضعیت را در «سرورهای موجود» یا پنل Linode بررسی کن."
        else:
            text = "دریافت اطلاعات یا اجرای درخواست Linode ناموفق بود."
            if exc.status:
                text += f" HTTP {exc.status}"
        await message.reply_text(text)


async def linode_pick(message, state, token, index):
    choices = state["choices"]
    if index >= len(choices):
        return
    value = choices[index][0]
    step = state["step"]
    if step == "servers":
        state["instance"] = value
        await show_linode_details(message, state, token)
        return
    form = state["form"]
    if step == "region":
        plans, images = await linode.region_options(value)
        if not plans or not images:
            await message.reply_text("برای این منطقه پلن یا ایمیج سازگار پیدا نشد. منطقهٔ دیگری را انتخاب کن.")
            return
        form["region"] = value
        state.update(step="image", plans=plans, choices=[(row, str(row.get("label") or row["id"])) for row in images])
        await show_linode_picker(message, state)
        return
    if step == "image":
        form["image"] = value["id"]
        state["image_label"] = str(value.get("label") or value["id"])[:120]
        plans = [row for row in state["plans"] if row.get("disk", 0) >= (value.get("size") or 0)]
        if not plans:
            await message.reply_text("برای این ایمیج پلن سازگار پیدا نشد. ایمیج دیگری انتخاب کن.")
            return
        state.update(step="type", choices=[
            (row, f"{row.get('label') or row['id']} · ${linode.price(row, form['region'])['monthly']:g}/mo")
            for row in plans
        ])
        await show_linode_picker(message, state)
        return
    form["type"] = value["id"]
    state.update(step="name", plan=value)
    state.pop("nonce")
    await message.reply_text("نام VPS را بفرست. برای لغو /cancel را بزن.")


async def linode_text(update, context):
    message = update.message
    state = context.user_data["linode"]
    step = state["step"]
    value = message.text.strip()
    if step == "key":
        await delete_secret_message(message)
        if not re.fullmatch(r"[A-Za-z0-9_-]{16,256}", value):
            await message.reply_text("توکن Linode را در یک خط بفرست.")
            return
        try:
            await linode.verify(value)
        except linode.APIError:
            await message.reply_text("توکن تأیید نشد. توکن و دسترسی Linodes را بررسی کن.")
            return
        with ADMIN_DB:
            ADMIN_DB.execute(
                "INSERT INTO linode_accounts VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET token=excluded.token",
                (update.effective_user.id, SERVER_CIPHER.encrypt(value.encode())),
            )
        clear(context)
        await message.reply_text(
            "توکن Linode تأیید و رمزگذاری شد.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("منوی Linode", callback_data="linode")]]),
        )
    elif step == "name":
        if not re.fullmatch(r"[A-Za-z](?:(?!--|__|\.\.)[A-Za-z0-9_.-]){2,63}", value):
            await message.reply_text("نامی بین ۳ تا ۶۴ کاراکتر بفرست که با حرف انگلیسی شروع شود. خط تیره، نقطه و زیرخطِ تکراری مجاز نیست.")
            return
        state["form"]["label"] = value
        state["step"] = "password"
        await message.reply_text("رمز root را بفرست. یک رمز قوی بین ۷ تا ۱۲۸ کاراکتر انتخاب کن. ربات تلاش می‌کند پیام را حذف کند.")
    elif step == "password":
        await delete_secret_message(message)
        if not 7 <= len(value) <= 128:
            await message.reply_text("رمز باید بین ۷ و ۱۲۸ کاراکتر باشد.")
            return
        form = state["form"]
        form["root_pass"] = value
        price = linode.price(state["plan"], form["region"])
        state["step"] = "create_confirm"
        await message.reply_text(
            f"سرور: {form['label']}\nمنطقه: {form['region']}\nایمیج: {state['image_label']}\n"
            f"پلن: {state['plan'].get('label') or form['type']}\n"
            f"قیمت اعلام‌شده: ${price['hourly']:g}/ساعت، ${price['monthly']:g}/ماه (USD)",
            reply_markup=linode_keyboard(state, [[(replacement_confirm_label(context), "confirm")]]),
        )
    else:
        await message.reply_text("از دکمه‌های همین مرحله استفاده کن یا /cancel را بزن.")


HETZNER_PROMPTS = {
    "accounts": "حساب یا پروژهٔ هتزنر را انتخاب کن.",
    "location": "لوکیشن را انتخاب کن.",
    "type": "پلن را انتخاب کن.",
    "image": "سیستم‌عامل را انتخاب کن.",
    "ssh": "کلید SSH پروژه را انتخاب کن. برای دریافت رمز اولیهٔ root، گزینهٔ بدون کلید را بزن.",
    "servers": "یک VPS هتزنر را انتخاب کن.",
}
HETZNER_OPERATIONS = {
    **hetzner.POWER, "delete": "حذف دائمی", "password": "بازنشانی رمز root",
}


def hetzner_token(user_id, account_id):
    row = ADMIN_DB.execute(
        "SELECT token FROM hetzner_projects WHERE user_id = ? AND id = ?", (user_id, account_id),
    ).fetchone()
    return SERVER_CIPHER.decrypt(row[0]).decode() if row else None


def hetzner_keyboard(state, rows):
    return nonce_keyboard(state, rows, "hp")


async def show_hetzner_picker(message, state, page=0):
    step = state["step"]
    if step == "accounts":
        await show_cloud_picker(message, state, page, HETZNER_PROMPTS[step], "hp", "➕ افزودن حساب", "he:add")
    else:
        prompt = f"حساب: {state['account_name']}\n{HETZNER_PROMPTS[step]}"
        await show_cloud_picker(message, state, page, prompt, "hp", "تغییر حساب", "hetzner")


async def show_hetzner_account(message, state):
    state["step"] = "account"
    await message.reply_text(
        f"حساب هتزنر: {state['account_name']}",
        reply_markup=hetzner_keyboard(state, [
            [("ساخت VPS", "new"), ("سرورهای موجود", "list")],
            [("تعویض توکن همین حساب", "replace"), ("تغییر حساب", "accounts")],
        ]),
    )


async def show_hetzner_server(message, state, token):
    server = await hetzner.server_details(token, state["instance"])
    state.update(step="instance", name=str(server.get("name") or state["instance"])[:120])
    net = server.get("public_net") or {}
    addresses = [(net.get(key) or {}).get("ip") for key in ("ipv4", "ipv6")]
    location = (server.get("location") or (server.get("datacenter") or {}).get("location") or {}).get("name")
    plan = (server.get("server_type") or {}).get("name")
    rows = [[(label, operation) for operation, label in hetzner.POWER.items()]]
    if not (server.get("protection") or {}).get("delete"):
        rows.append([("🗑 حذف سرور", "delete")])
    rows.append([("🔑 بازنشانی رمز root", "password")])
    rows.append([("تازه‌سازی", "refresh"), ("بازگشت به فهرست", "list")])
    await message.reply_text(
        f"حساب: {state['account_name']}\nسرور: {state['name']}\nوضعیت: {server.get('status') or '—'}\n"
        f"لوکیشن: {location or '—'}\nپلن: {plan or '—'}\nIP: {', '.join(ip for ip in addresses if ip) or '—'}"
        + ("\nمحافظت در برابر حذف فعال است." if (server.get("protection") or {}).get("delete") else ""),
        reply_markup=hetzner_keyboard(state, rows),
    )


async def hetzner_button(update, context):
    query = update.callback_query
    if not private_admin(update):
        await query.answer()
        return
    state = context.user_data.get("hetzner", {})
    action = query.data
    if action.startswith("hp:"):
        _, nonce, action = action.split(":", 2)
        if nonce != state.get("nonce"):
            await query.answer("این منو بسته شده است.")
            return
    else:
        if action == "hetzner":
            clear_for_creation(context, "hetzner")
        else:
            clear(context)
        state = {}
    await query.answer()
    message = query.message
    user_id = update.effective_user.id
    if action in {"hetzner", "accounts"}:
        rows = ADMIN_DB.execute(
            "SELECT id, name FROM hetzner_projects WHERE user_id = ? ORDER BY id", (user_id,),
        ).fetchall()
        state = {"step": "accounts", "choices": rows}
        context.user_data["hetzner"] = state
        await show_hetzner_picker(message, state)
        return
    if action == "he:add":
        context.user_data["hetzner"] = {"step": "account_name"}
        await message.reply_text("یک نام برای حساب یا پروژهٔ هتزنر بفرست. برای لغو /cancel را بزن.")
        return
    if action == "replace":
        state.pop("nonce", None)
        state["step"] = "key"
        await ask_hetzner_token(message, state["account_name"])
        return
    if action.startswith("page:"):
        page = int(action.split(":")[1])
        if page * 8 < len(state["choices"]):
            await show_hetzner_picker(message, state, page)
        return
    if state.get("step") == "accounts" and action.startswith("pick:"):
        index = int(action.split(":")[1])
        if index < len(state["choices"]):
            account_id, account_name = state["choices"][index]
            state = {"account_id": account_id, "account_name": account_name}
            context.user_data["hetzner"] = state
            await show_hetzner_account(message, state)
        return
    try:
        token = hetzner_token(user_id, state.get("account_id"))
    except InvalidToken:
        token = None
    if not token:
        await message.reply_text("اول توکن هتزنر را ثبت کن.")
        return
    try:
        if action == "new":
            locations, plans = await asyncio.gather(
                hetzner.catalog(token, "locations"), hetzner.catalog(token, "server_types"),
            )
            state.update(step="location", form={}, plans=plans, choices=[
                (loc["name"], f"{loc.get('city') or loc['name']} · {loc['name']}")
                for loc in locations if any(hetzner.regional_price(plan, loc["name"]) for plan in plans)
            ])
        elif action == "list":
            servers = await hetzner.catalog(token, "servers")
            state.update(step="servers", choices=[
                (row["id"], f"{row.get('name') or row['id']} · {row.get('status', '—')}") for row in servers
            ])
        elif action.startswith("pick:"):
            await hetzner_pick(message, state, token, int(action.split(":")[1]))
            return
        elif action == "refresh":
            await show_hetzner_server(message, state, token)
            return
        elif action == "reset_status":
            result = await hetzner.action_status(token, state["reset_action_id"])
            await show_hetzner_reset_result(message, state, result)
            return
        elif action in HETZNER_OPERATIONS and state["step"] == "instance":
            state.update(step="operation_confirm", operation=action)
            prompt = f"حساب: {state['account_name']}\nعملیات «{HETZNER_OPERATIONS[action]}» روی «{state['name']}» با شناسهٔ {state['instance']} انجام شود؟"
            if action == "delete":
                prompt += "\nسرور و داده‌های روی دیسک آن برای همیشه حذف می‌شوند."
            elif action == "password":
                prompt += "\nهتزنر رمز جدید تولید می‌کند و رمز قبلی جایگزین می‌شود."
            await message.reply_text(prompt, reply_markup=hetzner_keyboard(state, [
                [("تأیید", "confirm"), ("انصراف", "refresh")],
            ]))
            return
        elif action == "confirm":
            await hetzner_confirm(message, context, state, token, user_id)
            return
        else:
            return
        context.user_data["hetzner"] = state
        await show_hetzner_picker(message, state)
    except hetzner.APIError as exc:
        if action == "confirm" and (exc.status is None or exc.status >= 500):
            text = "نتیجهٔ درخواست مشخص نیست. پیش از تکرار، وضعیت را در پنل هتزنر بررسی کن."
        else:
            text = "درخواست هتزنر ناموفق بود."
            if exc.status:
                text += f" HTTP {exc.status}"
        await message.reply_text(text)


async def hetzner_pick(message, state, token, index):
    if index >= len(state["choices"]):
        return
    value, label = state["choices"][index]
    step = state["step"]
    if step == "servers":
        state["instance"] = value
        await show_hetzner_server(message, state, token)
        return
    form = state["form"]
    if step == "location":
        form["location"] = value
        state.update(step="type", choices=[
            (plan, f"{plan['name']} · €{price[1]}/mo")
            for plan in state["plans"] if (price := hetzner.regional_price(plan, value))
        ])
    elif step == "type":
        images = await hetzner.catalog(token, "images", type="system", architecture=value["architecture"], status="available")
        choices = [
            (row["id"], str(row.get("description") or row.get("name") or row["id"]))
            for row in images if not row.get("deprecated") and (row.get("disk_size") or 0) <= value["disk"]
        ]
        if not choices:
            await message.reply_text("ایمیج سازگار پیدا نشد. پلن دیگری انتخاب کن.")
            return
        form["server_type"] = value["name"]
        state.update(step="image", choices=choices, price=hetzner.regional_price(value, form["location"]))
    elif step == "image":
        keys = await hetzner.catalog(token, "ssh_keys")
        form["image"] = value
        state.update(step="ssh", image=label, choices=[
            (None, "بدون کلید SSH — دریافت رمز root"),
            *((row["id"], str(row.get("name") or row["id"])) for row in keys),
        ])
    elif step == "ssh":
        form["ssh_keys"] = [value] if value is not None else []
        state.update(step="name", ssh_label=label)
        state.pop("nonce")
        await message.reply_text("نام VPS را بفرست. برای لغو /cancel را بزن.")
        return
    await show_hetzner_picker(message, state)


async def hetzner_confirm(message, context, state, token, user_id):
    state.pop("nonce", None)
    account = {key: state[key] for key in ("account_id", "account_name")}
    if state["step"] == "create_confirm":
        form = state["form"]
        if await offer_replacement(message, context, user_id, "hetzner", form, token, account=state["account_id"], image=state["image"]):
            return
        clear(context)
        result = await hetzner.create(token, form)
        instance_id = result["server"]["id"]
        password = result.get("root_password")
        storage = store_created_server(
            user_id, "hetzner", instance_id, form["location"], form["name"],
            instance=result["server"], password=password, account_id=account["account_id"],
        )
        if password:
            instance_state = {**account, "step": "instance", "instance": instance_id, "name": form["name"]}
            context.user_data["hetzner"] = instance_state
            controls = hetzner_keyboard(instance_state, [[("🔑 بازنشانی رمز root", "password")]])
            await message.reply_text(
                f"درخواست ساخت سرور {instance_id} ثبت شد.\n{storage}\n\nرمز اولیهٔ root:\n{password}",
                protect_content=True,
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("کپی رمز", copy_text=CopyTextButton(password))],
                    *controls.inline_keyboard,
                ]),
            )
        else:
            context.user_data["hetzner"] = account
            await message.reply_text(
                f"درخواست ساخت سرور {instance_id} ثبت شد.\n{storage}",
                reply_markup=hetzner_keyboard(account, [[("سرورهای موجود", "list")]]),
            )
        return
    operation = state["operation"]
    instance = state["instance"]
    if operation == "password":
        action, password = await hetzner.reset_root_password(token, instance)
        state["reset_action_id"] = action["id"]
        await show_hetzner_reset_result(message, state, action, password)
        return
    await hetzner.change_server(token, instance, operation)
    if operation == "delete":
        clear(context)
        context.user_data["hetzner"] = account
        await message.reply_text(
            f"درخواست حذف سرور {instance} ثبت شد.",
            reply_markup=hetzner_keyboard(account, [[("سرورهای موجود", "list")]]),
        )
    else:
        await message.reply_text(
            "درخواست تغییر وضعیت ثبت شد.",
            reply_markup=hetzner_keyboard(state, [[("تازه‌سازی وضعیت", "refresh")]]),
        )


async def show_hetzner_reset_result(message, state, action, password=None):
    status = action.get("status")
    rows = []
    if status == "success":
        title = "بازنشانی رمز root در هتزنر انجام شد."
    elif status == "error":
        title = "هتزنر گزارش داد بازنشانی رمز root ناموفق بود."
        password = None
    else:
        title = "درخواست بازنشانی ثبت شد. تا اعلام موفقیت هتزنر صبر کن."
        rows.append([("بررسی وضعیت بازنشانی", "reset_status")])
    rows.append([("جزئیات سرور", "refresh")])
    markup = hetzner_keyboard(state, rows)
    text = f"حساب: {state['account_name']}\nسرور: {state['name']}\n{title}"
    if password:
        text += f"\n\nرمز جدید اعلام‌شده از هتزنر:\n{password}"
        markup = InlineKeyboardMarkup([
            [InlineKeyboardButton("کپی رمز", copy_text=CopyTextButton(password))],
            *markup.inline_keyboard,
        ])
    await message.reply_text(text, protect_content=bool(password), reply_markup=markup)


async def ask_hetzner_token(message, account_name):
    await message.reply_text(
        f"توکن API حساب «{account_name}» با دسترسی Read & Write را بفرست. "
        "ربات تلاش می‌کند پیام را حذف کند. چت ربات رمزنگاری سرتاسری ندارد."
    )


async def hetzner_text(update, context):
    message = update.message
    state = context.user_data["hetzner"]
    value = message.text.strip()
    if state.get("step") == "account_name":
        if not 1 <= len(value) <= 40 or not value.isprintable():
            await message.reply_text("نام حساب را در یک خط و حداکثر ۴۰ کاراکتر بفرست.")
            return
        if ADMIN_DB.execute(
            "SELECT 1 FROM hetzner_projects WHERE user_id = ? AND name = ?", (update.effective_user.id, value),
        ).fetchone():
            await message.reply_text("این نام برای حساب دیگری ثبت شده است. نام دیگری بفرست.")
            return
        state.update(step="key", account_name=value)
        await ask_hetzner_token(message, value)
        return
    if state.get("step") == "key":
        await delete_secret_message(message)
        if not re.fullmatch(r"[A-Za-z0-9_-]{16,256}", value):
            await message.reply_text("توکن هتزنر را در یک خط بفرست.")
            return
        try:
            await hetzner.request("GET", "/servers", value, params={"per_page": 1})
        except hetzner.APIError:
            await message.reply_text("توکن تأیید نشد. توکن پروژه و دسترسی آن را بررسی کن.")
            return
        user_id = update.effective_user.id
        encrypted = SERVER_CIPHER.encrypt(value.encode())
        account_id = state.get("account_id")
        with ADMIN_DB:
            if account_id is None:
                cursor = ADMIN_DB.execute(
                    "INSERT INTO hetzner_projects (user_id, name, token) VALUES (?, ?, ?)",
                    (user_id, state["account_name"], encrypted),
                )
                state["account_id"] = cursor.lastrowid
            else:
                ADMIN_DB.execute(
                    "UPDATE hetzner_projects SET token = ? WHERE user_id = ? AND id = ?",
                    (encrypted, user_id, account_id),
                )
        await message.reply_text("توکن این حساب تأیید و رمزگذاری شد.")
        await show_hetzner_account(message, state)
    elif state.get("step") == "name":
        if len(value) > 63 or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", value):
            await message.reply_text("نام را با حروف انگلیسی، عدد و خط تیره بفرست. با خط تیره شروع یا تمام نشود.")
            return
        state["form"]["name"] = value
        state["step"] = "create_confirm"
        form = state["form"]
        hourly, monthly = state["price"]
        await message.reply_text(
            f"حساب: {state['account_name']}\nسرور: {value}\nلوکیشن: {form['location']}\nپلن: {form['server_type']}\n"
            f"ایمیج: {state['image']}\nورود: {state['ssh_label']}\n"
            f"قیمت پلن با مالیات: €{hourly}/ساعت، €{monthly}/ماه\n"
            "IPv4 عمومی فعال است و جداگانه طبق تعرفهٔ هتزنر حساب می‌شود.",
            reply_markup=hetzner_keyboard(state, [[(replacement_confirm_label(context), "confirm")]]),
        )
    else:
        await message.reply_text("از دکمه‌های همین مرحله استفاده کن یا /cancel را بزن.")


ROTATION_LOCK = asyncio.Lock()
ROTATION_STATUS = {"active": "فعال", "done": "تمام‌شده", "failed": "متوقف با خطا", "cancelled": "لغوشده"}


async def dns_rotation_job(context):
    for user_id, rotation_id in dns_rotation.due(ADMIN_DB):
        async with ROTATION_LOCK:
            row = dns_rotation.get(ADMIN_DB, user_id, rotation_id)
            if not row or row.status != "active" or row.due_at > int(time.time()):
                continue
            try:
                token = cf_token(user_id, row.account_id) if user_has_access(user_id) else None
            except InvalidToken:
                token = None
            await dns_rotation.apply_step(ADMIN_DB, row, token)


async def cf_rotation_list(message, state, user_id, page=0):
    if page == 0:
        entries = dns_rotation.for_zone(ADMIN_DB, user_id, state["zone"]["id"], state["account_id"])
        state.update(step="rotation_list", choices=[
            (rotation_id, f"{name} · {ROTATION_STATUS.get(status, status)}") for rotation_id, name, status in entries
        ])
    await show_cloud_picker(
        message, state, page, f"برنامه‌های تعویض IP · {state['zone']['name']}", "cp",
        "منوی Cloudflare", "cloudflare",
    )


async def cf_rotation_details(message, state, user_id, rotation_id):
    row = dns_rotation.get(ADMIN_DB, user_id, rotation_id)
    if not row or (row.zone_id, row.account_id) != (state["zone"]["id"], state["account_id"]):
        await cf_rotation_list(message, state, user_id)
        return
    state.update(step="rotation_details", rotation_id=row.id, rotation_steps_shown=row.steps)
    steps = dns_rotation.read_steps(row)
    text = f"{row.name} · {row.kind}\nوضعیت: {ROTATION_STATUS.get(row.status, row.status)}\nمرحله‌های باقی‌مانده: {len(steps)}"
    rows = [[("🔄 تازه‌سازی", "rot_refresh"), ("↩️ فهرست برنامه‌ها", "rot_list")]]
    if row.status == "active":
        date = datetime.fromtimestamp(row.due_at, ZoneInfo("Asia/Tehran")).strftime("%Y-%m-%d %H:%M:%S")
        text += f"\nIP مرحلهٔ بعد: {steps[0][1]}\nزمان اجرای بعدی: {date} به وقت تهران"
        rows.insert(0, [("⚡ الان عوض کن", "rot_now"), ("🛑 لغو برنامه", "rot_cancel")])
    if row.status in {"active", "done"}:
        rows.append([("🔁 جایگزینی خودکار نود", "rot_replace")])
    rows.append([("🗑 حذف برنامه", "rot_delete")])
    if row.note:
        text += "\n" + row.note
    await message.reply_text(text, reply_markup=cf_keyboard(state, rows))


async def cf_rotation_next(message, state):
    state["step"] = "rotation_delay"
    state.pop("nonce", None)
    prompt = (
        "چند ساعت بعد از فعال‌شدن برنامه، IP عوض شود؟"
        if not state["rotation_steps"] else "چند ساعت بعد از اعمال موفق مرحلهٔ قبلی، IP بعدی تنظیم شود؟"
    )
    await message.reply_text(prompt + " مثلاً ۳ یا ۱.۵. برای لغو /cancel را بزن.")


async def cf_rotation_text(message, state, value):
    if state["step"] == "rotation_delay":
        try:
            value = value.replace("٫", ".")
            if not re.fullmatch(r"\d{1,7}(?:\.\d{1,4})?", value):
                raise ValueError
            seconds = int(Decimal(value) * 3600)
            if not 1 <= seconds <= dns_rotation.MAX_DELAY:
                raise ValueError
        except (ValueError, InvalidOperation):
            await message.reply_text("تعداد ساعت را با عددی مثبت و حداکثر ۸۷۶۰۰ وارد کن.")
            return
        state.update(step="rotation_ip", rotation_delay=seconds)
        await message.reply_text(f"IP بعدی رکورد {state['record']['type']} را بفرست.")
        return
    try:
        target = cloudflare.destination(value, state["record"]["type"])
    except ValueError:
        await message.reply_text("IP با نوع رکورد سازگار نیست. دوباره بفرست.")
        return
    steps = state["rotation_steps"]
    previous = steps[-1][1] if steps else cloudflare.destination(state["record"]["content"], state["record"]["type"])
    if target == previous:
        await message.reply_text("این IP با مرحلهٔ قبلی یکی است. IP دیگری بفرست.")
        return
    steps.append((state.pop("rotation_delay"), target))
    state["step"] = "rotation_add"
    await message.reply_text(
        f"مرحلهٔ {len(steps)} اضافه شد. IP بعدی هم اضافه شود؟",
        reply_markup=cf_keyboard(state, [[("➕ IP بعدی", "rot_next"), ("🏁 اتمام", "rot_review")]]),
    )


async def cf_rotation_review(message, state, page=0):
    state["step"] = "rotation_review"
    steps = state["rotation_steps"]
    start = page * 10
    lines = [
        f"{index}. {seconds / 3600:.6g} ساعت بعد ← {target}"
        for index, (seconds, target) in enumerate(steps[start:start + 10], start + 1)
    ]
    nav = []
    if page:
        nav.append(("◀ قبلی", f"rot_page:{page - 1}"))
    if start + 10 < len(steps):
        nav.append(("بعدی ▶", f"rot_page:{page + 1}"))
    rows = [nav] if nav else []
    rows.extend([[("✅ تأیید و فعال‌سازی", "rot_confirm")], [("➕ IP بعدی", "rot_next"), ("انصراف", "dns")]])
    await message.reply_text(
        f"تعویض IP برای {state['record']['name']} · {len(steps)} مرحله\n"
        + "\n".join(lines) + "\nزمان هر مرحله از اجرای موفق مرحلهٔ قبل حساب می‌شود.",
        reply_markup=cf_keyboard(state, rows),
    )


async def cf_rotation_button(message, state, token, user_id, action, context):
    if action == "rot_list":
        await cf_rotation_list(message, state, user_id)
    elif action == "rot_replace":
        row = dns_rotation.get(ADMIN_DB, user_id, state["rotation_id"])
        if not row or (row.zone_id, row.account_id) != (state["zone"]["id"], state["account_id"]):
            return
        targets = list(dict.fromkeys([row.expected, *(ip for _, ip in dns_rotation.read_steps(row))]))
        clear(context)
        draft = context.user_data["replacement"] = {
            "mode": "targets", "rotation_id": row.id, "choices": [(ip, ip) for ip in targets],
        }
        await show_cloud_picker(message, draft, 0, "IP مورد پایش را انتخاب کن.", "rp", "منوی Cloudflare", "cloudflare")
    elif action == "rot_refresh":
        await cf_rotation_details(message, state, user_id, state["rotation_id"])
    elif action == "rot_now":
        state.pop("nonce", None)
        rotation_id = state["rotation_id"]
        async with ROTATION_LOCK:
            row = dns_rotation.get(ADMIN_DB, user_id, rotation_id)
            same_step = (
                row and (row.zone_id, row.account_id) == (state["zone"]["id"], state["account_id"]) and row.status == "active"
                and row.steps == state["rotation_steps_shown"]
            )
            if same_step:
                await dns_rotation.apply_step(ADMIN_DB, row, token)
                updated = dns_rotation.get(ADMIN_DB, user_id, rotation_id)
        if not same_step:
            await message.reply_text("این مرحله دیگر در صف نیست. وضعیت برنامه تازه شد.")
        elif updated.steps != row.steps:
            await message.reply_text(f"IP رکورد در Cloudflare به {updated.expected} تغییر کرد.")
        elif updated.status == "active":
            await message.reply_text("تغییر فوری تأیید نشد. ربات در زمان نمایش‌داده‌شده دوباره تلاش می‌کند.")
        await cf_rotation_details(message, state, user_id, rotation_id)
    elif action == "rot_delete":
        row = dns_rotation.get(ADMIN_DB, user_id, state["rotation_id"])
        if not row or (row.zone_id, row.account_id) != (state["zone"]["id"], state["account_id"]):
            await cf_rotation_list(message, state, user_id)
            return
        await message.reply_text(
            f"برنامهٔ تعویض IP «{row.name}» حذف شود؟ مرحله‌های باقی‌مانده اجرا نخواهند شد.",
            reply_markup=cf_keyboard(state, [
                [("🗑 تأیید حذف برنامه", "rot_remove"), ("انصراف", "rot_refresh")],
            ]),
        )
    elif action == "rot_remove":
        state.pop("nonce", None)
        async with ROTATION_LOCK:
            removed = dns_rotation.delete(ADMIN_DB, user_id, state["zone"]["id"], state["rotation_id"], state["account_id"])
        if removed:
            await message.reply_text("برنامهٔ تعویض IP حذف شد.")
        await cf_rotation_list(message, state, user_id)
    elif action == "rot_cancel":
        async with ROTATION_LOCK:
            row = dns_rotation.get(ADMIN_DB, user_id, state["rotation_id"])
            if row and (row.zone_id, row.account_id) == (state["zone"]["id"], state["account_id"]):
                dns_rotation.stop(ADMIN_DB, row, "cancelled")
        await cf_rotation_details(message, state, user_id, state["rotation_id"])
    elif action == "rotate":
        record = state["record"]
        if record["type"] in {"A", "AAAA"}:
            state["rotation_steps"] = []
            await cf_rotation_next(message, state)
    elif action == "rot_next":
        await cf_rotation_next(message, state)
    elif action == "rot_review":
        await cf_rotation_review(message, state)
    elif action.startswith("rot_page:"):
        page = int(action.split(":")[1])
        if page * 10 < len(state["rotation_steps"]):
            await cf_rotation_review(message, state, page)
    elif action == "rot_confirm":
        state.pop("nonce", None)
        original = state["record"]
        try:
            async with ROTATION_LOCK:
                latest = await cloudflare.record(token, state["zone"]["id"], original["id"])
                if any(latest.get(key) != original.get(key) for key in ("name", "type", "content")):
                    await message.reply_text("رکورد تغییر کرده است. دوباره انتخابش کن.")
                    await cf_dns_menu(message, state)
                    return
                latest["content"] = cloudflare.destination(latest["content"], latest["type"])
                rotation_id = dns_rotation.schedule(
                    ADMIN_DB, user_id, state["zone"]["id"], latest, state["rotation_steps"], state["account_id"],
                )
        except sqlite3.IntegrityError:
            await message.reply_text("برای این رکورد از قبل برنامهٔ فعال وجود دارد.")
            await cf_rotation_list(message, state, user_id)
            return
        await cf_rotation_details(message, state, user_id, rotation_id)


CF_FIELDS = {"name": "نام ساب‌دامنه", "content": "مقصد", "proxied": "Proxy", "ttl": "TTL"}


def cf_token(user_id, account_id=None):
    if account_id is None:
        row = ADMIN_DB.execute("SELECT token FROM cloudflare_accounts WHERE user_id = ?", (user_id,)).fetchone()
    else:
        row = ADMIN_DB.execute(
            "SELECT token FROM cloudflare_profiles WHERE user_id = ? AND id = ?", (user_id, account_id),
        ).fetchone()
    return SERVER_CIPHER.decrypt(row[0]).decode() if row else None


async def cf_account_list(message, state, user_id, page=0):
    choices = ADMIN_DB.execute(
        "SELECT id, name FROM cloudflare_profiles WHERE user_id = ? ORDER BY id", (user_id,),
    ).fetchall()
    if ADMIN_DB.execute("SELECT 1 FROM cloudflare_accounts WHERE user_id = ?", (user_id,)).fetchone():
        choices.insert(0, (None, "پیش‌فرض"))
    state.update(step="accounts", choices=choices)
    await show_cloud_picker(
        message, state, page, "حساب Cloudflare را انتخاب کن.", "cp", "➕ افزودن حساب", "cf:add",
    )


async def cf_account_menu(message, state):
    state["step"] = "account"
    await message.reply_text(
        f"حساب Cloudflare: {state['account_name']}",
        reply_markup=cf_keyboard(state, [
            [("🌐 مدیریت DNS", "zones"), ("🔑 تعویض توکن همین حساب", "replace")],
            [("تغییر حساب", "accounts")],
        ]),
    )


async def cf_ask_token(message, state):
    state["step"] = "key"
    state.pop("nonce", None)
    await message.reply_text(
        f"API Token حساب «{state['account_name']}» را با دسترسی Zone Read و DNS Edit بفرست. "
        "ربات تلاش می‌کند پیام حاوی توکن را حذف کند."
    )


def cf_keyboard(state, rows):
    return nonce_keyboard(state, rows, "cp")


async def cf_picker(message, state, page=0):
    prompt = f"حساب {state['account_name']} · دامنه را انتخاب کن." if state["step"] == "zones" else f"ساب‌دامنه‌های {state['zone']['name']} را انتخاب کن."
    await show_cloud_picker(message, state, page, prompt, "cp", "منوی Cloudflare", "cloudflare")


async def cf_dns_menu(message, state):
    state["step"] = "dns"
    await message.reply_text(
        f"مدیریت DNS · {state['zone']['name']}\nحساب: {state['account_name']}",
        reply_markup=cf_keyboard(state, [
            [("➕ افزودن ساب‌دامنه", "add"), ("✏️ تغییر ساب‌دامنه", "edit_list")],
            [("🔍 جست‌وجوی ساب‌دامنه", "search"), ("📋 نمایش ساب‌دامنه‌ها", "list")],
            [("🕒 برنامه‌های تعویض IP", "rot_list"), ("تغییر دامنه", "zones")],
            [("تغییر حساب", "accounts")],
        ]),
    )


async def cf_list_records(message, state, token, search="", *, editable=False):
    zone = state["zone"]
    records = await cloudflare.records(token, zone["id"], search)
    state.update(step="records", choices=[
        (row["id"], f"{row['name']} · {row['type']}")
        for row in records if cloudflare.is_subdomain(row["name"], zone["name"])
        and (not editable or row["type"] in cloudflare.HOST_TYPES)
    ])
    await cf_picker(message, state)


async def cf_record_menu(message, state, token, record_id):
    zone = state["zone"]
    row = await cloudflare.record(token, zone["id"], record_id)
    if not cloudflare.is_subdomain(row["name"], zone["name"]):
        await cf_dns_menu(message, state)
        return
    state.update(step="record", record=row, changes={})
    rows = []
    if row["type"] in cloudflare.HOST_TYPES:
        rows.append([("تغییر نام", "field:name"), ("تغییر مقصد", "field:content")])
        settings = []
        if row.get("proxiable"):
            settings.append(("تغییر Proxy", "field:proxied"))
        if not row.get("proxied"):
            settings.append(("تغییر TTL", "field:ttl"))
        if settings:
            rows.append(settings)
    if row["type"] in {"A", "AAAA"}:
        rows.append([("🔁 تعویض خودکار IP", "rotate")])
    rows.extend([[("🗑 حذف رکورد", "delete")], [("بازگشت به DNS", "dns")]])
    await message.reply_text(
        f"{row['name']} · {row['type']}\nمقصد: {str(row.get('content') or '—')[:1000]}\n"
        f"Proxy: {'روشن' if row.get('proxied') else 'خاموش'}\nTTL: {cf_ttl_label(row.get('ttl'))}",
        reply_markup=cf_keyboard(state, rows),
    )


def cf_ttl_label(value):
    return "خودکار" if value == 1 else f"{value} ثانیه" if value is not None else "—"


async def cf_input(message, state, field):
    state["step"] = field
    if field in {"name", "content"}:
        state.pop("nonce", None)
        if field == "name":
            prompt = "نام ساب‌دامنه را بفرست، مثل app یا app.example.com."
        else:
            kind = state["form"]["type"] if state["mode"] == "create" else state["record"]["type"]
            prompt = f"مقصد رکورد {kind} را بفرست."
        await message.reply_text(prompt + " برای لغو /cancel را بزن.")
        return
    rows = (
        [[("☁️ Proxy روشن", "proxy:on"), ("DNS only", "proxy:off")]]
        if field == "proxied" else
        [[(cf_ttl_label(value), f"ttl:{value}") for value in cloudflare.TTL_VALUES[i:i + 2]]
         for i in range(0, len(cloudflare.TTL_VALUES), 2)]
    )
    rows.append([("انصراف", "dns")])
    await message.reply_text(f"{CF_FIELDS[field]} را انتخاب کن.", reply_markup=cf_keyboard(state, rows))


async def cf_review(message, state):
    state["step"] = "review"
    mode = state["mode"]
    labels = {"create": "ساخت", "edit": "ویرایش", "delete": "حذف"}
    current = state.get("record") or {}
    fields = state["form"] if mode == "create" else state.get("changes", {})
    row = {**current, **fields}
    text = f"حساب: {state['account_name']}\nدامنه: {state['zone']['name']}\nعملیات: {labels[mode]} رکورد\nنام: {row['name']} · {row['type']}"
    if row["name"] != current.get("name") and current:
        text += f"\nنام قبلی: {current['name']}"
    if mode != "delete":
        text += (
            f"\nمقصد: {row.get('content', '—')}\nProxy: {'روشن' if row.get('proxied') else 'خاموش'}"
            f"\nTTL: {cf_ttl_label(row.get('ttl'))}"
        )
    await message.reply_text(
        text, reply_markup=cf_keyboard(state, [[("تأیید", "confirm"), ("انصراف", "dns")]]),
    )


async def cf_commit(message, state, token):
    state.pop("nonce", None)
    zone = state["zone"]
    mode = state["mode"]
    if mode == "create":
        await cloudflare.request("POST", cloudflare.records_path(zone["id"]), token, payload=state["form"])
    else:
        original = state["record"]
        latest = await cloudflare.record(token, zone["id"], original["id"])
        if not cloudflare.is_subdomain(latest["name"], zone["name"]) or any(
            original.get(key) != latest.get(key)
            for key in ("modified_on", "name", "type", "content", "proxied", "ttl")
        ):
            await message.reply_text("رکورد از زمان انتخاب تغییر کرده است. آن را دوباره انتخاب کن.")
            await cf_dns_menu(message, state)
            return
        path = cloudflare.records_path(zone["id"], original["id"])
        if mode == "delete":
            await cloudflare.request("DELETE", path, token)
        else:
            await cloudflare.request("PATCH", path, token, payload=state["changes"])
    await message.reply_text("تغییر DNS در Cloudflare ثبت شد.")
    await cf_dns_menu(message, state)


async def cloudflare_button(update, context):
    query = update.callback_query
    if not private_admin(update):
        await query.answer()
        return
    action = query.data
    state = context.user_data.get("cloudflare", {})
    if action.startswith("cp:"):
        _, nonce, action = action.split(":", 2)
        if nonce != state.get("nonce"):
            await query.answer("این منو بسته شده است.")
            return
    else:
        clear(context)
        state = {}
        context.user_data["cloudflare"] = state
    await query.answer()
    message = query.message
    user_id = update.effective_user.id
    if action in {"cloudflare", "cf:zones", "accounts"}:
        state.clear()
        await cf_account_list(message, state, user_id)
        return
    if action in {"cf:key", "cf:add"}:
        state["step"] = "account_name"
        await message.reply_text("یک نام برای حساب Cloudflare بفرست. برای لغو /cancel را بزن.")
        return
    if state.get("step") == "accounts" and action.startswith(("pick:", "page:")):
        verb, raw = action.split(":")
        index = int(raw)
        if verb == "page":
            if index * 8 < len(state["choices"]):
                await cf_account_list(message, state, user_id, index)
        elif index < len(state["choices"]):
            account_id, account_name = state["choices"][index]
            state.clear()
            state.update(account_id=account_id, account_name=account_name)
            await cf_account_menu(message, state)
        return
    if action == "replace":
        await cf_ask_token(message, state)
        return
    try:
        token = cf_token(user_id, state["account_id"])
    except InvalidToken:
        token = None
    if not token:
        await message.reply_text("ابتدا API Token را ثبت کن.")
        return
    try:
        if action == "zones":
            rows = await cloudflare.zones(token)
            state.update(step="zones", choices=[(row, row["name"]) for row in rows])
            await cf_picker(message, state)
        elif action.startswith(("pick:", "page:")):
            verb, raw = action.split(":")
            index = int(raw)
            if verb == "page":
                if index * 8 < len(state["choices"]):
                    if state["step"] == "rotation_list":
                        await cf_rotation_list(message, state, update.effective_user.id, index)
                    else:
                        await cf_picker(message, state, index)
            elif index < len(state["choices"]):
                value = state["choices"][index][0]
                if state["step"] == "zones":
                    state["zone"] = value
                    await cf_dns_menu(message, state)
                elif state["step"] == "rotation_list":
                    await cf_rotation_details(message, state, update.effective_user.id, value)
                else:
                    await cf_record_menu(message, state, token, value)
        elif action in {"list", "edit_list"}:
            await cf_list_records(message, state, token, editable=action == "edit_list")
        elif action == "search":
            state["step"] = "search"
            state.pop("nonce", None)
            await message.reply_text("تمام یا بخشی از نام ساب‌دامنه را بفرست. برای لغو /cancel را بزن.")
        elif action == "dns":
            await cf_dns_menu(message, state)
        elif action == "add":
            state.update(step="type", mode="create", form={}, record=None)
            await message.reply_text("نوع رکورد را انتخاب کن.", reply_markup=cf_keyboard(state, [
                [(kind, f"type:{kind}") for kind in cloudflare.HOST_TYPES], [("انصراف", "dns")],
            ]))
        elif action.startswith("type:"):
            state["form"]["type"] = action.split(":")[1]
            await cf_input(message, state, "name")
        elif action.startswith("field:"):
            state.update(mode="edit", changes={})
            await cf_input(message, state, action.split(":")[1])
        elif action.startswith("proxy:"):
            values = state["form"] if state["mode"] == "create" else state["changes"]
            values["proxied"] = action.endswith(":on")
            if values["proxied"]:
                values["ttl"] = 1
            if state["mode"] == "create" and not values["proxied"]:
                await cf_input(message, state, "ttl")
            else:
                await cf_review(message, state)
        elif action.startswith("ttl:"):
            values = state["form"] if state["mode"] == "create" else state["changes"]
            values["ttl"] = int(action.split(":")[1])
            await cf_review(message, state)
        elif action == "delete":
            state.update(mode="delete", changes={})
            await cf_review(message, state)
        elif action == "confirm":
            async with ROTATION_LOCK:
                await cf_commit(message, state, token)
        elif action == "rotate" or action.startswith("rot_"):
            await cf_rotation_button(message, state, token, update.effective_user.id, action, context)
    except cloudflare.APIError as exc:
        await cf_error(message, state, exc, action in {"confirm", "rot_confirm"})


async def cf_error(message, state, exc, writing=False):
    if writing and (exc.status is None or exc.status >= 500 or (200 <= exc.status < 300 and not exc.codes)):
        text = "نتیجهٔ تغییر مشخص نیست. پیش از تکرار، فهرست رکوردها را بررسی کن."
    else:
        codes = ", ".join(str(code) for code in exc.codes)
        text = "درخواست Cloudflare ناموفق بود." + (f" کد Cloudflare: {codes}" if codes else "")
    markup = cf_keyboard(state, [[("بازگشت به DNS", "dns")]]) if state.get("zone") else None
    await message.reply_text(text, reply_markup=markup)


async def cloudflare_text(update, context):
    message = update.message
    state = context.user_data["cloudflare"]
    step = state.get("step")
    value = message.text.strip()
    user_id = update.effective_user.id
    if step == "account_name":
        if not 1 <= len(value) <= 40 or not value.isprintable():
            await message.reply_text("نام حساب را در یک خط و حداکثر ۴۰ کاراکتر بفرست.")
            return
        if value == "پیش‌فرض" or ADMIN_DB.execute(
            "SELECT 1 FROM cloudflare_profiles WHERE user_id = ? AND name = ?", (user_id, value),
        ).fetchone():
            await message.reply_text("این نام در دسترس نیست. نام دیگری بفرست.")
            return
        state["account_name"] = value
        await cf_ask_token(message, state)
        return
    if step == "key":
        await delete_secret_message(message)
        if not re.fullmatch(r"[A-Za-z0-9_-]{16,256}", value):
            await message.reply_text("API Token را در یک خط بفرست.")
            return
        try:
            await cloudflare.request("GET", "/zones", value, params={"per_page": 5})
        except cloudflare.APIError:
            await message.reply_text("توکن تأیید نشد. دسترسی Zone Read و محدودهٔ دامنه‌ها را بررسی کن.")
            return
        encrypted = SERVER_CIPHER.encrypt(value.encode())
        async with ROTATION_LOCK:
            with ADMIN_DB:
                if "account_id" not in state:
                    cursor = ADMIN_DB.execute(
                        "INSERT INTO cloudflare_profiles (user_id, name, token) VALUES (?, ?, ?)",
                        (user_id, state["account_name"], encrypted),
                    )
                    state["account_id"] = cursor.lastrowid
                elif state["account_id"] is None:
                    ADMIN_DB.execute("UPDATE cloudflare_accounts SET token = ? WHERE user_id = ?", (encrypted, user_id))
                else:
                    ADMIN_DB.execute(
                        "UPDATE cloudflare_profiles SET token = ? WHERE user_id = ? AND id = ?",
                        (encrypted, user_id, state["account_id"]),
                    )
        await message.reply_text("توکن این حساب رمزگذاری و ذخیره شد.")
        await cf_account_menu(message, state)
        return
    if step in {"rotation_delay", "rotation_ip"}:
        await cf_rotation_text(message, state, value)
        return
    if step == "search":
        if not value or len(value) > 253 or not value.isprintable():
            await message.reply_text("بخشی از نام ساب‌دامنه را در یک خط بفرست.")
            return
        try:
            token = cf_token(user_id, state["account_id"])
            if not token:
                raise cloudflare.APIError()
            try:
                search = cloudflare.domain(value, wildcard=True)
            except ValueError:
                search = value
            await cf_list_records(message, state, token, search)
        except InvalidToken:
            await message.reply_text("توکن خوانده نشد. دوباره آن را ثبت کن.")
        except cloudflare.APIError as exc:
            await cf_error(message, state, exc)
        return
    if step not in {"name", "content"}:
        await message.reply_text("از دکمه‌های همین مرحله استفاده کن یا /cancel را بزن.")
        return
    values = state["form"] if state["mode"] == "create" else state["changes"]
    try:
        if step == "name":
            values["name"] = cloudflare.subdomain(value, state["zone"]["name"])
        else:
            kind = state["form"]["type"] if state["mode"] == "create" else state["record"]["type"]
            values["content"] = cloudflare.destination(value, kind)
    except (UnicodeError, ValueError):
        await message.reply_text("مقدار معتبر نیست. دوباره بفرست.")
        return
    if state["mode"] == "edit":
        await cf_review(message, state)
    else:
        await cf_input(message, state, "content" if step == "name" else "proxied")


async def backup_button(update, context):
    query = update.callback_query
    if not private_operator(update):
        await query.answer()
        return
    await query.answer()
    action = query.data
    message = query.message
    if action.startswith("db:apply:"):
        state = context.user_data.get("backup", {})
        if state.get("confirmation") != action or time.monotonic() >= state["deadline"]:
            await message.reply_text("این تأیید منقضی شده است. بازیابی را دوباره شروع کن.")
            return
        rows = state["rows"]
        clear(context)
        try:
            async with ROTATION_LOCK:
                database_backup.replace_data(ADMIN_DB, rows)
        except sqlite3.Error:
            await message.reply_text("بازیابی ناموفق بود. اطلاعات قبلی در پایگاه داده حفظ شد.")
            return
        ADDED_ADMINS.clear()
        ADDED_ADMINS.update(row[0] for row in rows["admins"])
        navigation.reset()
        for user_state in context.application.user_data.values():
            clear_user_data(user_state)
        await message.reply_text("دیتابیس بازیابی شد.", reply_markup=menu(True))
        return

    clear(context)
    if action == "backup":
        await message.reply_text("پشتیبان‌گیری و بازیابی دیتابیس", reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("⬇️ دریافت فایل پشتیبان", callback_data="db:export")],
            [InlineKeyboardButton("⬆️ بازیابی از فایل", callback_data="db:import")],
            [InlineKeyboardButton("بازگشت", callback_data="cancel")],
        ]))
    elif action == "db:export":
        context.user_data["backup"] = {"step": "export", "deadline": time.monotonic() + 600}
        await message.reply_text(
            "یک عبارت عبور قوی با حداقل ۱۲ کاراکتر برای رمزگذاری فایل بفرست. "
            "برای بازیابی به همان عبارت نیاز داری. ربات تلاش می‌کند پیام عبارت عبور را حذف کند."
        )
    elif action == "db:import":
        context.user_data["backup"] = {"step": "document", "deadline": time.monotonic() + 600}
        await message.reply_text("فایل پشتیبان ربات با پسوند .tvps را به‌صورت فایل بفرست. برای لغو /cancel را بزن.")


async def backup_document(update, context):
    if not private_operator(update):
        return
    state = context.user_data.get("backup", {})
    if state.get("step") != "document":
        return
    message = update.message
    if time.monotonic() >= state["deadline"]:
        clear(context)
        await message.reply_text("مهلت بارگذاری تمام شد. بازیابی را دوباره شروع کن.")
        return
    doc = message.document
    if not (doc.file_name or "").lower().endswith(database_backup.SUFFIX) or not (
        doc.file_size is not None and 0 < doc.file_size <= database_backup.MAX_SIZE
    ):
        await message.reply_text("یک فایل پشتیبان .tvps با حجم حداکثر ۸ مگابایت بفرست.")
        return
    try:
        telegram_file = await doc.get_file()
        data = await telegram_file.download_as_bytearray()
    except TelegramError:
        await message.reply_text("دریافت فایل از تلگرام ناموفق بود. دوباره بفرست.")
        return
    if len(data) > database_backup.MAX_SIZE or not data.startswith(database_backup.MAGIC):
        await message.reply_text("فایل معتبر نیست. فایل پشتیبان ربات را بفرست.")
        return
    state.update(step="import", document=bytes(data), deadline=time.monotonic() + 600)
    await message.reply_text("عبارت عبور فایل پشتیبان را بفرست. ربات تلاش می‌کند پیام را حذف کند.")


async def backup_text(update, context):
    state = context.user_data["backup"]
    message = update.message
    step = state["step"]
    if step in {"export", "import"}:
        await delete_secret_message(message)
    if time.monotonic() >= state["deadline"]:
        clear(context)
        await message.reply_text("مهلت این مرحله تمام شد. از منوی پشتیبان‌گیری دوباره شروع کن.")
        return
    if step not in {"export", "import"}:
        await message.reply_text("فایل را بفرست یا از دکمه‌های بازیابی استفاده کن. برای لغو /cancel را بزن.")
        return
    password = message.text
    if not 12 <= len(password) <= 256 or not password.strip():
        await message.reply_text("عبارت عبور را با ۱۲ تا ۲۵۶ کاراکتر بفرست.")
        return
    if step == "export":
        try:
            rows = database_backup.snapshot(ADMIN_DB)
            data = await asyncio.to_thread(database_backup.export_file, rows, SERVER_CIPHER, password)
        except (database_backup.BackupError, sqlite3.Error):
            await message.reply_text("ساخت بکاپ ناموفق بود. حجم داده یا کلید رمزگذاری را بررسی کن.")
            return
        clear(context)
        await message.reply_document(
            document=data, filename="telegram-vps-backup.tvps",
            caption="فایل رمزگذاری‌شدهٔ دیتابیس. برای بازیابی روی VPS جدید، فایل و عبارت عبور را لازم داری.",
        )
        return
    try:
        rows = await asyncio.to_thread(database_backup.restore_file, state["document"], password, SERVER_CIPHER)
    except database_backup.BackupError:
        await message.reply_text("فایل یا عبارت عبور معتبر نیست. دوباره تلاش کن.")
        return
    confirmation = "db:apply:" + secrets.token_hex(8)
    state.clear()
    state.update(step="confirm", rows=rows, confirmation=confirmation, deadline=time.monotonic() + 600)
    await message.reply_text(
        f"بکاپ خوانده شد: {len(rows['servers'])} سرور ذخیره‌شده، "
        f"{len(rows['admins'])} ادمین اضافه‌شده و "
        f"{sum(len(rows[name]) for name in ('kamatera_accounts', 'linode_accounts', 'hetzner_projects', 'cloudflare_accounts', 'cloudflare_profiles', 'vultr_accounts', 'cherry_accounts'))} حساب سرویس.\n"
        "با تأیید، اطلاعات ذخیره‌شدهٔ فعلی ربات با اطلاعات این فایل جایگزین می‌شود.",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("تأیید جایگزینی دیتابیس", callback_data=confirmation)],
            [InlineKeyboardButton("لغو", callback_data="cancel")],
        ]),
    )


VULTR_PROMPTS = {
    "region": "منطقهٔ Vultr را انتخاب کن.",
    "image": "سیستم‌عامل را انتخاب کن.",
    "plan": "پلن موجود در منطقه را انتخاب کن.",
    "servers": "یک سرور Vultr را انتخاب کن.",
}
VULTR_OPERATIONS = {**vultr.POWER, "delete": "حذف دائمی"}


def vultr_token(user_id):
    row = ADMIN_DB.execute("SELECT token FROM vultr_accounts WHERE user_id = ?", (user_id,)).fetchone()
    return SERVER_CIPHER.decrypt(row[0]).decode() if row else None


def vultr_keyboard(state, rows):
    return nonce_keyboard(state, rows, "vp")


async def vultr_picker(message, state, page=0):
    await show_cloud_picker(message, state, page, VULTR_PROMPTS[state["step"]], "vp", "منوی Vultr", "vultr")


async def show_vultr_instance(message, state, token):
    instance = await vultr.details(token, state["instance"])
    state.update(step="instance", label=str(instance.get("label") or instance["id"])[:120])
    ips = [value for key in ("main_ip", "v6_main_ip") if (value := instance.get(key)) and value not in {"0.0.0.0", "::"}]
    await message.reply_text(
        f"سرور: {state['label']}\nوضعیت ساخت: {instance.get('status') or '—'}\n"
        f"وضعیت برق: {instance.get('power_status') or '—'}\nمنطقه: {instance.get('region') or '—'}\n"
        f"پلن: {instance.get('plan') or '—'}\nIP: {', '.join(ips) or '—'}",
        reply_markup=vultr_keyboard(state, [
            [(label, operation) for operation, label in vultr.POWER.items()],
            [("🔑 رمز اولیه", "password"), ("🗑 حذف سرور", "delete")],
            [("🔄 تازه‌سازی", "refresh"), ("بازگشت به فهرست", "list")],
        ]),
    )


async def show_vultr_password(message, state, password, title):
    buttons = list(vultr_keyboard(state, [[("جزئیات سرور", "refresh"), ("سرورهای موجود", "list")]]).inline_keyboard)
    if isinstance(password, str) and password:
        title += f"\n\nرمز اولیه:\n{password}"
        if len(password) <= 256:
            buttons.insert(0, [InlineKeyboardButton("کپی رمز", copy_text=CopyTextButton(password))])
    else:
        title += "\nVultr هنوز رمز اولیه را برنگردانده است. بعد از آماده‌شدن سرور «رمز اولیه» را بررسی کن."
    await message.reply_text(title, protect_content=bool(password), reply_markup=InlineKeyboardMarkup(buttons))


async def vultr_button(update, context):
    query = update.callback_query
    if not private_admin(update):
        await query.answer()
        return
    action = query.data
    state = context.user_data.get("vultr", {})
    if action.startswith("vp:"):
        _, nonce, action = action.split(":", 2)
        if nonce != state.get("nonce"):
            await query.answer("این منو بسته شده است.")
            return
    else:
        if action == "vu:new":
            clear_for_creation(context, "vultr")
        else:
            clear(context)
        state = {}
        context.user_data["vultr"] = state
    await query.answer()
    message = query.message
    if action == "vultr":
        await message.reply_text("مدیریت Vultr", reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔑 ثبت یا تعویض API Key", callback_data="vu:key")],
            [InlineKeyboardButton("➕ ساخت VPS", callback_data="vu:new"),
             InlineKeyboardButton("🖥 سرورهای موجود", callback_data="vu:list")],
            [InlineKeyboardButton("بازگشت", callback_data="cancel")],
        ]))
        return
    if action == "vu:key":
        state["step"] = "key"
        await message.reply_text("API Key ولتر را بفرست. ربات تلاش می‌کند پیام حاوی کلید را حذف کند.")
        return
    try:
        token = vultr_token(update.effective_user.id)
    except InvalidToken:
        token = None
    if not token:
        await message.reply_text("ابتدا API Key ولتر را ثبت کن.")
        return
    try:
        if action == "vu:new":
            rows = await vultr.catalog("/regions", "regions")
            state.update(step="region", form={}, choices=[
                (row["id"], f"{row.get('city') or row['id']} · {row.get('country', row['id'])}") for row in rows
            ])
            await vultr_picker(message, state)
        elif action in {"vu:list", "list"}:
            rows = await vultr.catalog("/instances", "instances", token)
            state.update(step="servers", choices=[
                (row["id"], f"{row.get('label') or row['id']} · {row.get('power_status') or row.get('status', '—')}")
                for row in rows
            ])
            await vultr_picker(message, state)
        elif action.startswith(("page:", "pick:")):
            verb, index = action.split(":")
            index = int(index)
            if verb == "page":
                if index * 8 < len(state["choices"]):
                    await vultr_picker(message, state, index)
            elif index < len(state["choices"]):
                await vultr_pick(message, state, token, index)
        elif action == "refresh":
            await show_vultr_instance(message, state, token)
        elif action == "password":
            instance = await vultr.details(token, state["instance"])
            await show_vultr_password(message, state, instance.get("default_password"), f"رمز اولیهٔ سرور {state['label']}")
        elif action in VULTR_OPERATIONS and state["step"] == "instance":
            state.update(step="operation_confirm", operation=action)
            text = f"«{VULTR_OPERATIONS[action]}» برای سرور «{state['label']}» با شناسهٔ {state['instance']} انجام شود؟"
            if action == "delete":
                text += "\nسرور و داده‌های روی دیسک آن برای همیشه حذف می‌شوند."
            await message.reply_text(
                text, reply_markup=vultr_keyboard(state, [[("تأیید", "confirm"), ("انصراف", "refresh")]]),
            )
        elif action == "confirm":
            await vultr_confirm(message, context, state, token, update.effective_user.id)
    except vultr.APIError as exc:
        text = "درخواست Vultr ناموفق بود."
        if action == "confirm" and (exc.status is None or exc.status >= 500):
            text = "نتیجهٔ درخواست مشخص نیست. پیش از تکرار، وضعیت را در فهرست سرورها بررسی کن."
        elif exc.status:
            text += f" HTTP {exc.status}"
        await message.reply_text(text, reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("منوی Vultr", callback_data="vultr")],
        ]))


async def vultr_pick(message, state, token, index):
    value, label = state["choices"][index]
    step = state["step"]
    if step == "servers":
        state["instance"] = value
        await show_vultr_instance(message, state, token)
        return
    form = state["form"]
    if step == "region":
        plans, images = await vultr.region_options(value)
        if not plans or not images:
            await message.reply_text("در این منطقه پلن و ایمیج سازگار پیدا نشد. منطقهٔ دیگری انتخاب کن.")
            return
        form["region"] = value
        state.update(step="image", plans=plans, choices=[(row["id"], row["name"]) for row in images])
    elif step == "image":
        form["os_id"] = value
        state.update(step="plan", image=label, choices=[
            (plan, f"{plan['id']} · ${vultr.monthly_price(plan, form['region']):g}/mo") for plan in state["plans"]
        ])
    else:
        form["plan"] = value["id"]
        state.update(step="name", price=vultr.monthly_price(value, form["region"]))
        state.pop("nonce", None)
        await message.reply_text("نام VPS را بفرست. برای لغو /cancel را بزن.")
        return
    await vultr_picker(message, state)


async def vultr_confirm(message, context, state, token, user_id):
    state.pop("nonce", None)
    if state["step"] == "create_confirm":
        form = state["form"]
        if await offer_replacement(message, context, user_id, "vultr", form, token, image=state["image"]):
            return
        clear(context)
        instance = await vultr.create(token, form)
        storage = store_created_server(
            user_id, "vultr", instance["id"], form["region"], form["label"],
            instance=instance, password=instance.get("default_password"),
        )
        state = {"step": "instance", "instance": instance["id"], "label": form["label"]}
        context.user_data["vultr"] = state
        await show_vultr_password(message, state, instance.get("default_password"),
                                  f"درخواست ساخت VPS ثبت شد. شناسه: {instance['id']}\n{storage}")
        return
    operation = state["operation"]
    await vultr.change_instance(token, state["instance"], operation)
    if operation == "delete":
        clear(context)
        await message.reply_text("درخواست حذف VPS ثبت شد.", reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("بازگشت به سرورها", callback_data="vu:list")],
        ]))
    else:
        await message.reply_text("درخواست تغییر وضعیت ثبت شد.", reply_markup=vultr_keyboard(state, [
            [("🔄 تازه‌سازی", "refresh"), ("بازگشت به فهرست", "list")],
        ]))


async def vultr_text(update, context):
    message = update.message
    state = context.user_data["vultr"]
    value = message.text.strip()
    step = state.get("step")
    if step == "key":
        await delete_secret_message(message)
        try:
            value = vultr.parse_api_key(value)
        except ValueError:
            await message.reply_text(
                "مقدار کامل API Key را در یک خط بفرست. نام‌هایی مثل mybot که در فهرست کلیدها می‌بینی، مقدار کلید نیستند."
            )
            return
        try:
            await vultr.verify_api_key(value)
        except vultr.APIError as exc:
            if exc.ip_restricted:
                reason = "Vultr دسترسی IP را رد کرد. IP عمومی خروجی VPS ربات را در Access Control List مجاز کن."
            elif exc.status in {401, 403}:
                reason = (
                    "Vultr دسترسی را رد کرد. مقدار کامل کلید، مجوز دسترسی به Instances و "
                    "مجاز بودن IP عمومی خروجی VPS ربات در Access Control List را بررسی کن."
                )
            elif exc.status == 429:
                reason = "Vultr تعداد درخواست‌ها را محدود کرده است. کمی بعد دوباره تلاش کن."
            elif exc.status is None or exc.status >= 500:
                reason = "ارتباط با API ولتر ناموفق بود. بعداً دوباره تلاش کن."
            else:
                reason = "Vultr درخواست بررسی کلید را نپذیرفت."
            if exc.status:
                reason += f" (HTTP {exc.status})"
            await message.reply_text(reason)
            return
        with ADMIN_DB:
            ADMIN_DB.execute(
                "INSERT INTO vultr_accounts VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET token=excluded.token",
                (update.effective_user.id, SERVER_CIPHER.encrypt(value.encode())),
            )
        clear(context)
        await message.reply_text("کلید Vultr تأیید و رمزگذاری شد.", reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("منوی Vultr", callback_data="vultr")],
        ]))
    elif step == "name":
        if len(value) > 63 or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", value):
            await message.reply_text("نام را با حروف انگلیسی، عدد و خط تیره بفرست. با خط تیره شروع یا تمام نشود.")
            return
        form = state["form"]
        form.update(label=value, hostname=value)
        state["step"] = "create_confirm"
        await message.reply_text(
            f"نام: {value}\nمنطقه: {form['region']}\nسیستم‌عامل: {state['image']}\n"
            f"پلن: {form['plan']}\nقیمت اعلام‌شدهٔ پلن: ${state['price']:g} در ماه (USD)\n"
            f"شبکه: {'فقط IPv6' if form['plan'].endswith('-v6') else 'IPv4 عمومی'}",
            reply_markup=vultr_keyboard(state, [[(replacement_confirm_label(context), "confirm")],
                                                  [("انصراف", "list")]]),
        )
    else:
        await message.reply_text("از دکمه‌های همین مرحله استفاده کن یا /cancel را بزن.")


HOST_CHECKS_ACTIVE = set()


async def host_check_button(update, context):
    query = update.callback_query
    await query.answer()
    if not private_admin(update):
        return
    clear(context)
    if query.data == "host_checks":
        await query.message.reply_text("پینگ و اطلاعات IP", reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🇮🇷 پینگ از ایران", callback_data="hc:ping"),
             InlineKeyboardButton("ℹ️ اطلاعات IP", callback_data="hc:info")],
            [InlineKeyboardButton("🕒 پایش دوره‌ای", callback_data="hc:monitor")],
            [InlineKeyboardButton("بازگشت", callback_data="cancel")],
        ]))
        return
    context.user_data["host_check"] = query.data.split(":")[1]
    await query.message.reply_text("یک IP عمومی یا نام دامنه بفرست. برای لغو /cancel را بزن.")


async def host_check_text(update, context):
    message = update.message
    try:
        host = host_checks.parse_host(message.text)
    except ValueError:
        await message.reply_text("فقط یک IP عمومی یا نام دامنه بفرست، بدون پورت یا آدرس کامل URL.")
        return
    user_id = update.effective_user.id
    if user_id in HOST_CHECKS_ACTIVE:
        await message.reply_text("هنوز درخواست قبلی‌ات در حال اجراست.")
        return
    action = context.user_data["host_check"]
    await message.reply_text("در حال بررسی…")
    clear(context)
    HOST_CHECKS_ACTIVE.add(user_id)
    context.application.create_task(run_host_check(message, user_id, action, host), update=update)


async def run_host_check(message, user_id, action, host):
    try:
        if action == "ping":
            nodes, results = await host_checks.ping_iran(host)
            if not nodes:
                text = "در حال حاضر هیچ نود ایرانی برای پینگ در دسترس نیست."
            else:
                lines = [f"🇮🇷 پینگ {host} از ایران"]
                for node, city in sorted(nodes.items()):
                    summary = host_checks.ping_summary(results.get(node))
                    lines.append(f"{city} ({node.split('.')[0]}): {summary}")
                text = "\n".join(lines)
        else:
            rows = await host_checks.ip_information(host)
            if not rows:
                text = "برای این مقصد IP عمومی پیدا نشد."
            else:
                sections = [f"ℹ️ اطلاعات IP · {host}"]
                for ip, info in rows:
                    if not info:
                        sections.append(f"IP: {ip}\nاطلاعات موقعیت و شبکه در دسترس نیست.")
                        continue
                    connection = info.get("connection") or {}
                    location = "، ".join(str(info[key])[:100] for key in ("country", "region", "city") if info.get(key))
                    asn = connection.get("asn")
                    organization = str(connection.get("org") or connection.get("isp") or "—")[:180]
                    sections.append(
                        f"IP: {ip}\nموقعیت تقریبی: {location or '—'}\n"
                        f"شبکه: {('AS' + str(asn)) if asn else '—'} · {organization}"
                    )
                text = "\n\n".join(sections) + "\n\nمنبع اطلاعات IP: ipwho.is"
        await message.reply_text(text, reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("بررسی دوباره", callback_data=f"hc:{action}"),
             InlineKeyboardButton("بازگشت", callback_data="host_checks")],
        ]))
    except host_checks.CheckError:
        await message.reply_text("دریافت نتیجه ناموفق بود. کمی بعد دوباره امتحان کن.")
    finally:
        HOST_CHECKS_ACTIVE.discard(user_id)


HOST_MONITORS_ACTIVE = set()


async def host_monitor_menu(message, state, user_id, page=0):
    hosts, next_at = host_monitor.get(ADMIN_DB, user_id)
    state.update(step="list", hosts=hosts)
    offset = page * 8
    rows = [[("➕ افزودن ساب‌دامنه", "add"), ("⚡ تست درجا", "test")], [("⏱ فاصلهٔ پایش", "interval")]]
    rows.extend([(f"🗑 {host[:60]}", f"remove:{index}")] for index, host in enumerate(hosts[offset:offset + 8], offset))
    nav = []
    if page:
        nav.append(("قبلی", f"page:{page - 1}"))
    if offset + 8 < len(hosts):
        nav.append(("بعدی", f"page:{page + 1}"))
    if nav:
        rows.append(nav)
    keyboard = nonce_keyboard(state, rows, "hm")
    text = f"پایش از ایران هر {host_monitor.interval(ADMIN_DB, user_id) / 3600:g} ساعت · {len(hosts)} مقصد"
    if next_at:
        date = datetime.fromtimestamp(next_at, ZoneInfo("Asia/Tehran"))
        text += f"\nبررسی بعدی: {date:%Y-%m-%d %H:%M} به وقت تهران"
    if hosts:
        text += "\nبرای حذف یک مقصد، دکمهٔ 🗑 کنار نام آن را بزن."
    await message.reply_text(text, reply_markup=InlineKeyboardMarkup([
        *keyboard.inline_keyboard,
        [InlineKeyboardButton("🔁 برنامه‌های جایگزینی نود", callback_data="replacement_list")],
        [InlineKeyboardButton("بازگشت", callback_data="host_checks")],
    ]))


async def host_monitor_button(update, context):
    query = update.callback_query
    if not private_admin(update):
        await query.answer()
        return
    user_id = update.effective_user.id
    message = query.message
    if query.data == "hc:monitor":
        await query.answer()
        clear(context)
        state = context.user_data["host_monitor"] = {}
        await host_monitor_menu(message, state, user_id)
        return
    state = context.user_data.get("host_monitor", {})
    _, nonce, action = query.data.split(":", 2)
    if nonce != state.get("nonce"):
        await query.answer("این منو بسته شده است.")
        return
    await query.answer()
    if action == "add":
        state.pop("nonce", None)
        state["step"] = "add"
        await message.reply_text("ساب‌دامنه‌ها را یک‌به‌یک در خط‌های جداگانه بفرست. برای لغو /cancel را بزن.")
    elif action == "interval":
        state.pop("nonce", None)
        state["step"] = "interval"
        await message.reply_text("فاصلهٔ پایش را به ساعت بفرست، مثلاً ۱.۵. حداقل ۰.۲۵ و حداکثر ۷۲۰ ساعت.")
    elif action == "test":
        hosts, _ = host_monitor.get(ADMIN_DB, user_id)
        if not hosts:
            await message.reply_text("اول یک ساب‌دامنه به فهرست پایش اضافه کن.")
            return
        if user_id in HOST_MONITORS_ACTIVE:
            await message.reply_text("یک بررسی در حال اجراست.")
            return
        await message.reply_text("تست درجا شروع شد. گزارش در همین چت ارسال می‌شود.")
        HOST_MONITORS_ACTIVE.add(user_id)
        context.application.create_task(run_host_monitor(context.bot, user_id, hosts), update=update)
    else:
        verb, value = action.split(":")
        index = int(value)
        if verb == "page":
            await host_monitor_menu(message, state, user_id, index)
        elif index < len(state["hosts"]):
            host = state["hosts"][index]
            hosts, _ = host_monitor.get(ADMIN_DB, user_id)
            host_monitor.save(ADMIN_DB, user_id, [item for item in hosts if item != host])
            await host_monitor_menu(message, state, user_id)


async def host_monitor_text(update, context):
    state = context.user_data["host_monitor"]
    message = update.message
    if state.get("step") == "interval":
        try:
            value = message.text.strip().replace("٫", ".")
            if not re.fullmatch(r"\d{1,3}(?:\.\d{1,4})?", value):
                raise ValueError
            seconds = int(Decimal(value) * 3600)
            host_monitor.set_interval(ADMIN_DB, update.effective_user.id, seconds)
        except (ValueError, InvalidOperation):
            await message.reply_text("یک عدد بین ۰.۲۵ و ۷۲۰ ساعت بفرست.")
            return
        await host_monitor_menu(message, state, update.effective_user.id)
        return
    if state.get("step") != "add":
        await message.reply_text("برای مدیریت پایش از دکمه‌ها استفاده کن.")
        return
    try:
        targets = [host_checks.parse_host(item) for item in message.text.split()]
        if not targets:
            raise ValueError
    except ValueError:
        await message.reply_text("یک یا چند ساب‌دامنه یا IP عمومی معتبر بفرست، بدون URL یا پورت.")
        return
    user_id = update.effective_user.id
    existing, _ = host_monitor.get(ADMIN_DB, user_id)
    host_monitor.save(ADMIN_DB, user_id, list(dict.fromkeys(existing + targets)))
    await host_monitor_menu(message, state, user_id)


async def send_monitor_report(bot, user_id, text):
    chunk = ""
    for line in text.splitlines(keepends=True):
        if len(chunk) + len(line) > 3500:
            await bot.send_message(chat_id=user_id, text=chunk.rstrip())
            chunk = ""
        chunk += line
    if chunk:
        await bot.send_message(chat_id=user_id, text=chunk.rstrip())


async def run_host_monitor(bot, user_id, hosts, due_at=None):
    try:
        result = await host_monitor.run(hosts)
        if not user_has_access(user_id):
            return
        current, current_due = host_monitor.get(ADMIN_DB, user_id)
        if current != hosts or (due_at is not None and current_due != due_at):
            return
        title = "📡 گزارش پایش دوره‌ای" if due_at is not None else "⚡ نتیجهٔ تست درجا"
        await send_monitor_report(bot, user_id, f"{title}\n\n{host_monitor.report(result)}")
        if due_at is not None:
            host_monitor.move_due(ADMIN_DB, user_id, due_at)
    except TelegramError:
        if due_at is not None:
            host_monitor.move_due(ADMIN_DB, user_id, due_at, retry=True)
        else:
            raise
    finally:
        HOST_MONITORS_ACTIVE.discard(user_id)


async def host_monitor_job(context):
    runs = []
    for (user_id,) in host_monitor.due(ADMIN_DB):
        if user_id in HOST_MONITORS_ACTIVE:
            continue
        hosts, due_at = host_monitor.get(ADMIN_DB, user_id)
        if not user_has_access(user_id):
            host_monitor.move_due(ADMIN_DB, user_id, due_at)
            continue
        HOST_MONITORS_ACTIVE.add(user_id)
        runs.append(run_host_monitor(context.bot, user_id, hosts, due_at))
    await asyncio.gather(*runs)


CHERRY_PROMPTS = {
    "team": "تیم Cherry Servers را انتخاب کن.",
    "project": "پروژه را انتخاب کن.",
    "region": "دیتاسنتر را انتخاب کن.",
    "plan": "یک پلن مجازی موجود را انتخاب کن.",
    "image": "سیستم‌عامل را انتخاب کن.",
    "cycle": "دورهٔ پرداخت را انتخاب کن.",
    "servers": "سرور پروژه را انتخاب کن.",
}
CHERRY_OPERATIONS = {**cherry.POWER, "delete": "حذف دائمی"}


def cherry_token(user_id):
    row = ADMIN_DB.execute("SELECT token FROM cherry_accounts WHERE user_id = ?", (user_id,)).fetchone()
    return SERVER_CIPHER.decrypt(row[0]).decode() if row else None


def cherry_keyboard(state, rows):
    return nonce_keyboard(state, rows, "chp")


async def cherry_picker(message, state, page=0):
    await show_cloud_picker(message, state, page, CHERRY_PROMPTS[state["step"]], "chp", "منوی Cherry Servers", "cherry")


def cherry_price_label(cycle, price):
    period = "ساعتی" if cycle == "hourly" else "ماهانه"
    tax = "با مالیات" if price.get("taxed") else "بدون مالیات"
    return f"{period}: {price['price']:g} {price['currency']} · {tax}"


async def show_cherry_server(message, state, token):
    server = await cherry.details(token, state["instance"])
    state.update(step="instance", label=str(server.get("hostname") or server.get("name") or server["id"])[:120])
    addresses = [
        entry["address"] for entry in server.get("ip_addresses") or []
        if isinstance(entry, dict) and isinstance(entry.get("address"), str)
    ]
    region = server.get("region") or {}
    await message.reply_text(
        f"سرور: {state['label']}\nوضعیت: {server.get('status') or server.get('state') or '—'}\n"
        f"دیتاسنتر: {region.get('location') or region.get('slug') or '—'}\nIP: {', '.join(addresses)[:1500] or '—'}",
        reply_markup=cherry_keyboard(state, [
            [(caption, action) for action, caption in cherry.POWER.items()],
            [("🔑 رمز اولیه", "password"), ("🗑 حذف سرور", "delete")],
            [("🔄 تازه‌سازی", "refresh"), ("بازگشت به فهرست", "list")],
        ]),
    )


async def show_cherry_password(message, state, server, title):
    password = server.get("password")
    keyboard = list(cherry_keyboard(state, [[("جزئیات سرور", "refresh"), ("سرورهای پروژه", "list")]]).inline_keyboard)
    if isinstance(password, str) and password:
        title += f"\n\nکاربر: {server.get('username') or 'root'}\nرمز اولیه:\n{password}"
        if len(password) <= 256:
            keyboard.insert(0, [InlineKeyboardButton("کپی رمز", copy_text=CopyTextButton(password))])
    else:
        title += "\nAPI هنوز رمز اولیه‌ای برنگردانده است. بعد از آماده‌شدن سرور می‌توانی دوباره بررسی کنی."
    await message.reply_text(title, protect_content=bool(password), reply_markup=InlineKeyboardMarkup(keyboard))


async def show_cherry_balance(message, state, token):
    name, balances = await cherry.team_balance(token, state["team"])
    state["step"] = "balance"
    lines = [
        f"💳 موجودی Cherry Servers · {name}",
        f"اعتبار حساب: {balances.get('account', 'اعلام نشده')}",
    ]
    if "promo" in balances:
        lines.append(f"اعتبار تشویقی: {balances['promo']}")
    await message.reply_text(
        "\n".join(lines),
        reply_markup=InlineKeyboardMarkup([
            *cherry_keyboard(state, [[("🔄 تازه‌سازی موجودی", "balance")]]).inline_keyboard,
            [InlineKeyboardButton("انتخاب تیم", callback_data="ch:balance")],
        ]),
    )


async def cherry_button(update, context):
    query = update.callback_query
    if not private_admin(update):
        await query.answer()
        return
    user_id = update.effective_user.id
    message = query.message
    state = context.user_data.get("cherry", {})
    action = query.data
    if action.startswith("chp:"):
        _, nonce, action = action.split(":", 2)
        if nonce != state.get("nonce"):
            await query.answer("این منو بسته شده است.")
            return
    else:
        if action == "ch:new":
            clear_for_creation(context, "cherry")
        else:
            clear(context)
        state = context.user_data["cherry"] = {}
    await query.answer()
    if action == "cherry":
        await message.reply_text("مدیریت Cherry Servers", reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔑 ثبت یا تعویض توکن API", callback_data="ch:key")],
            [InlineKeyboardButton("💳 موجودی حساب", callback_data="ch:balance")],
            [InlineKeyboardButton("➕ ساخت VPS", callback_data="ch:new"),
             InlineKeyboardButton("🖥 سرورهای موجود", callback_data="ch:servers")],
        ]))
        return
    if action == "ch:key":
        state["step"] = "key"
        await message.reply_text("توکن API پنل Cherry Servers را بفرست. ربات تلاش می‌کند پیام توکن را حذف کند.")
        return
    try:
        token = cherry_token(user_id)
    except InvalidToken:
        token = None
    if not token:
        await message.reply_text("ابتدا توکن Cherry Servers را ثبت کن.")
        return
    try:
        if action in {"ch:new", "ch:servers", "ch:balance"}:
            teams = await cherry.catalog("/teams", token)
            state.update(step="team", mode=action, form={}, choices=[
                (row["id"], str(row.get("name") or row["id"])) for row in teams
            ])
            await cherry_picker(message, state)
        elif action.startswith(("pick:", "page:")):
            verb, raw = action.split(":")
            index = int(raw)
            if verb == "page":
                if index * 8 < len(state["choices"]):
                    await cherry_picker(message, state, index)
            elif index < len(state["choices"]):
                await cherry_pick(message, state, token, index)
        elif action == "balance":
            await show_cherry_balance(message, state, token)
        elif action == "list":
            await cherry_list_servers(message, state, token)
        elif action == "refresh":
            await show_cherry_server(message, state, token)
        elif action == "password":
            server = await cherry.details(token, state["instance"])
            await show_cherry_password(message, state, server, f"سرور: {state['label']}")
        elif action in CHERRY_OPERATIONS and state["step"] == "instance":
            state.update(step="operation_confirm", operation=action)
            text = f"«{CHERRY_OPERATIONS[action]}» برای سرور «{state['label']}» با شناسهٔ {state['instance']} انجام شود؟"
            if action == "delete":
                text += "\nسرور و داده‌های روی دیسک آن برای همیشه حذف می‌شوند."
            await message.reply_text(text, reply_markup=cherry_keyboard(state, [[("تأیید", "confirm"), ("انصراف", "refresh")]]))
        elif action == "confirm":
            await cherry_confirm(message, context, state, token, user_id)
    except cherry.APIError as exc:
        text = "درخواست Cherry Servers ناموفق بود."
        if action == "confirm" and (exc.status is None or exc.status >= 500):
            text = "نتیجهٔ درخواست مشخص نیست. قبل از تکرار، فهرست سرورها یا پنل Cherry Servers را بررسی کن."
        elif exc.status:
            text += f" HTTP {exc.status}"
        await message.reply_text(text)


async def cherry_list_servers(message, state, token):
    rows = await cherry.catalog(f"/projects/{state['project']}/servers", token)
    state.update(step="servers", choices=[
        (row["id"], f"{row.get('hostname') or row.get('name') or row['id']} · {row.get('status', '—')}") for row in rows
    ])
    await cherry_picker(message, state)


async def cherry_pick(message, state, token, index):
    value, label = state["choices"][index]
    step = state["step"]
    form = state["form"]
    if step == "team":
        if state["mode"] == "ch:balance":
            state["team"] = int(value)
            await show_cherry_balance(message, state, token)
            return
        projects = await cherry.catalog(f"/teams/{int(value)}/projects", token)
        state.update(team=int(value), step="project", choices=[
            (row["id"], str(row.get("name") or row["id"])) for row in projects
        ])
    elif step == "project":
        state.update(project=int(value), project_name=label)
        if state["mode"] == "ch:servers":
            await cherry_list_servers(message, state, token)
            return
        regions = await cherry.catalog("/regions", token)
        state.update(step="region", choices=[
            (row["slug"], f"{row.get('location') or row.get('name') or row['slug']} · {row['slug']}") for row in regions
        ])
    elif step == "region":
        plans = await cherry.plans(token, state["team"], value)
        if not plans:
            await message.reply_text("این دیتاسنتر پلن مجازی با قیمت قابل نمایش ندارد. منطقهٔ دیگری را انتخاب کن.")
            return
        form["region"] = value
        state.update(step="plan", choices=[(row, str(row.get("name") or row["slug"])) for row in plans])
    elif step == "plan":
        images = await cherry.images(token, state["team"], value["slug"])
        if not images:
            await message.reply_text("ایمیج لینوکسی بدون هزینهٔ جداگانه پیدا نشد. پلن دیگری را انتخاب کن.")
            return
        form["plan"] = value["slug"]
        state.update(step="image", plan_prices=cherry.prices(value), plan_label=label, choices=[
            (row["slug"], str(row.get("name") or row["slug"])) for row in images
        ])
    elif step == "image":
        form["image"] = value
        state.update(step="cycle", image_label=label, choices=[
            (cycle, cherry_price_label(cycle, price)) for cycle, price in state["plan_prices"].items()
        ])
    elif step == "cycle":
        form["cycle"] = value
        state.update(step="name", price_label=label)
        state.pop("nonce", None)
        await message.reply_text("نام VPS را بفرست. برای لغو /cancel را بزن.")
        return
    elif step == "servers":
        state["instance"] = value
        await show_cherry_server(message, state, token)
        return
    await cherry_picker(message, state)


async def cherry_confirm(message, context, state, token, user_id):
    state.pop("nonce", None)
    if state["step"] == "create_confirm":
        form = state["form"]
        if await offer_replacement(message, context, user_id, "cherry", form, token, project=state["project"], image=state["image_label"]):
            return
        server = await cherry.create(token, state["project"], form)
        storage = store_created_server(
            user_id, "cherry", server["id"], form["region"], form["hostname"], instance=server,
            password=server.get("password"), username=server.get("username") or "root",
        )
        state.update(step="instance", instance=server["id"], label=form["hostname"])
        await show_cherry_password(message, state, server, f"درخواست ساخت VPS ثبت شد. شناسه: {server['id']}\n{storage}")
        return
    operation = state["operation"]
    await cherry.change_server(token, state["instance"], operation)
    if operation == "delete":
        rows = [[("بازگشت به فهرست", "list")]]
        title = "درخواست حذف VPS ثبت شد."
    else:
        rows = [[("🔄 تازه‌سازی وضعیت", "refresh"), ("بازگشت به فهرست", "list")]]
        title = "درخواست تغییر وضعیت ثبت شد."
    await message.reply_text(title, reply_markup=cherry_keyboard(state, rows))


async def cherry_text(update, context):
    message = update.message
    state = context.user_data["cherry"]
    value = message.text.strip()
    if state.get("step") == "key":
        await delete_secret_message(message)
        value = re.sub(r"^Bearer\s+", "", value, flags=re.IGNORECASE)
        if not re.fullmatch(r"[A-Za-z0-9._~+/=\-]{16,4096}", value):
            await message.reply_text("مقدار کامل توکن را در یک خط بفرست.")
            return
        try:
            result = await cherry.request("GET", "/teams", value, params={"limit": 1})
            if not isinstance(result, list):
                raise cherry.APIError()
        except cherry.APIError as exc:
            suffix = f" (HTTP {exc.status})" if exc.status else ""
            await message.reply_text(f"توکن تأیید نشد. دسترسی توکن به تیم‌ها را بررسی کن.{suffix}")
            return
        with ADMIN_DB:
            ADMIN_DB.execute(
                "INSERT INTO cherry_accounts VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET token=excluded.token",
                (update.effective_user.id, SERVER_CIPHER.encrypt(value.encode())),
            )
        clear(context)
        await message.reply_text("توکن Cherry Servers تأیید و رمزگذاری شد.", reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("منوی Cherry Servers", callback_data="cherry")],
        ]))
    elif state.get("step") == "name":
        if len(value) > 63 or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", value):
            await message.reply_text("نام VPS را با حروف انگلیسی، عدد و خط تیره بفرست. با خط تیره شروع یا تمام نشود.")
            return
        form = state["form"]
        form["hostname"] = value
        state["step"] = "create_confirm"
        await message.reply_text(
            f"نام: {value}\nپروژه: {state['project_name']}\nدیتاسنتر: {form['region']}\n"
            f"سیستم‌عامل: {state['image_label']}\nپلن: {state['plan_label']}\nقیمت پلن: {state['price_label']}",
            reply_markup=cherry_keyboard(state, [[(replacement_confirm_label(context), "confirm")]]),
        )
    else:
        await message.reply_text("از دکمه‌های همین مرحله استفاده کن یا /cancel را بزن.")


def replacement_confirm_label(context):
    if context.user_data.get("replacement", {}).get("provider"):
        return "ادامهٔ تنظیم جایگزینی"
    return "تأیید ساخت و هزینه"


REPLACEMENT_CHECKS = set()
REPLACEMENT_ERRORS = (
    kamatera.APIError, linode.APIError, hetzner.APIError, vultr.APIError, cherry.APIError,
    cloudflare.APIError, InvalidToken,
)
REPLACEMENT_START = {
    "hetzner": "hetzner", "linode": "li:new", "kamatera": "km:new", "vultr": "vu:new", "cherry": "ch:new",
}
REPLACEMENT_STATUS = {
    "watching": "منتظر پایش", "creating": "در حال ثبت ساخت", "provisioning": "در انتظار VPS",
    "installing": "در حال نصب نود", "deleting": "در حال درخواست حذف", "done": "انجام شد",
    "failed": "متوقف با خطا", "cancelled": "لغوشده",
}


def clear_for_creation(context, provider):
    draft = context.user_data.get("replacement")
    clear(context)
    if draft and draft.get("provider") == provider:
        context.user_data["replacement"] = draft


async def replacement_token(rule):
    if rule.provider == "kamatera":
        return await kamatera_token(rule.user_id)
    if rule.provider == "hetzner":
        return hetzner_token(rule.user_id, rule.account_id)
    return {"linode": linode_token, "vultr": vultr_token, "cherry": cherry_token}[rule.provider](rule.user_id)


async def replacement_servers(rule, token):
    if rule.provider == "hetzner":
        return await hetzner.catalog(token, "servers")
    if rule.provider == "kamatera":
        return await kamatera.list_servers(token)
    if rule.provider == "linode":
        return await linode.catalog("/linode/instances", token)
    if rule.provider == "vultr":
        return await vultr.catalog("/instances", "instances", token)
    return await cherry.catalog(f"/projects/{rule.project_id}/servers", token)


async def replacement_details(rule, token, remote_id):
    if rule.provider in {"linode", "hetzner", "cherry"}:
        remote_id = int(remote_id)
    if rule.provider == "hetzner":
        return await hetzner.server_details(token, remote_id)
    if rule.provider == "kamatera":
        return await kamatera.server_details(token, remote_id)
    return await {"linode": linode.details, "vultr": vultr.details, "cherry": cherry.details}[rule.provider](token, remote_id)


def replacement_region(provider, row):
    value = row.get("datacenter") if provider == "kamatera" else row.get("region")
    if provider == "hetzner":
        value = row.get("location") or (row.get("datacenter") or {}).get("location")
    if isinstance(value, dict):
        return value.get("slug") or value.get("name")
    return value


def replacement_ips(provider, row):
    if provider == "linode":
        values = [*(row.get("ipv4") or []), row.get("ipv6")]
    elif provider == "hetzner":
        net = row.get("public_net") or {}
        values = [(net.get(key) or {}).get("ip") for key in ("ipv4", "ipv6")]
    elif provider == "kamatera":
        values = [ip for entry in row.get("networks") or [] for ip in entry.get("ips") or []]
    elif provider == "cherry":
        values = [entry.get("address") for entry in row.get("ip_addresses") or []]
    else:
        values = [row.get("main_ip"), row.get("v6_main_ip")]
    return {address for value in values if (address := cloud_saved.public_address([value]))}


async def replacement_find_old(rule, token, region):
    candidates = []
    for row in await replacement_servers(rule, token):
        if str(replacement_region(rule.provider, row)).casefold() != region.casefold():
            continue
        if rule.provider == "kamatera":
            row = await replacement_details(rule, token, row["id"])
        if rule.target in replacement_ips(rule.provider, row):
            candidates.append(str(row["id"]))
    return candidates[0] if len(candidates) == 1 else None


async def offer_replacement(message, context, user_id, provider, form, token, *, account=None, project=None, image=""):
    draft = context.user_data.get("replacement")
    if not draft or draft.get("provider") != provider:
        return False
    if "windows" in image.casefold() or (provider == "cherry" and "bsd" in image.casefold()):
        await message.reply_text("برای نصب خودکار نود، یک ایمیج لینوکسی سازگار با نصب‌کنندهٔ پاسارگارد انتخاب کن.")
        return True
    region = form[replacement.REGION_KEY.get(provider, "region")]
    probe = replacement.Rule(0, user_id, draft["rotation_id"], draft["target"], provider,
                             account, project, None, None, "", 0, None, 0, 0, "")
    try:
        old_id = await replacement_find_old(probe, token, region)
    except REPLACEMENT_ERRORS:
        old_id = None
    draft.update(account=account, project=project, form=dict(form), old_id=old_id)
    rows = [[("سرور قبلی را نگه دار", "keep")]]
    text = (
        f"IP مورد پایش: {draft['target']}\nسرویس: {replacement.PROVIDERS[provider]} · دیتاسنتر: {region}\n"
        "تأیید، یک برنامهٔ یک‌بارمصرف ثبت می‌کند. پس از بی‌پاسخ‌ماندن پینگ و تأیید دوبارهٔ آن، "
        "حداکثر یک VPS هزینه‌دار ساخته می‌شود و نصب نود شروع می‌شود. رکورد Cloudflare عوض نمی‌شود."
    )
    if old_id:
        rows.append([("بعد از آماده‌شدن نود، حذف کن", "auto")])
        text += f"\nشناسهٔ سرور قبلی: {old_id}. حذف خودکار می‌تواند DNS را روی IP قدیمی و غیرفعال بگذارد."
    else:
        text += "\nسرور قبلی در این حساب و دیتاسنتر به‌صورت یکتا پیدا نشد. حذف آن دستی خواهد بود."
    await message.reply_text(text, reply_markup=nonce_keyboard(draft, rows, "rp"))
    return True


async def replacement_menu(message, state, user_id, page=0):
    state.update(mode="list", choices=[
        (rule_id, f"{target} · {replacement.PROVIDERS.get(provider, provider)} · {REPLACEMENT_STATUS.get(status, status)}")
        for rule_id, target, provider, status in replacement.for_user(ADMIN_DB, user_id)
    ])
    await show_cloud_picker(
        message, state, page, "برنامه‌های جایگزینی نود", "rp", "پایش IP", "hc:monitor",
        extra_buttons=([InlineKeyboardButton("➕ افزودن IP", callback_data="replacement_add")],),
        empty_prompt="هنوز برنامه‌ای ثبت نشده است. با «افزودن IP» شروع کن.",
    )


async def replacement_choose_provider(message, draft, target):
    draft.update(target=target, mode="provider")
    await message.reply_text(
        f"IP مورد پایش: {target}\nسرویس ساخت VPS جایگزین را انتخاب کن.",
        reply_markup=nonce_keyboard(
            draft, [[(caption, f"provider:{provider}")] for provider, caption in replacement.PROVIDERS.items()], "rp",
        ),
    )


async def replacement_ip_text(update, context):
    message = update.message
    target = cloud_saved.public_address([message.text.strip()])
    if target is None or "/" in message.text or "%" in message.text:
        await message.reply_text("یک آدرس IPv4 یا IPv6 عمومی بفرست، بدون دامنه یا پورت.")
        return
    await replacement_choose_provider(message, context.user_data["replacement"], target)


async def replacement_button(update, context):
    query = update.callback_query
    if not private_admin(update):
        await query.answer()
        return
    message = query.message
    user_id = update.effective_user.id
    if query.data == "replacement_list":
        await query.answer()
        clear(context)
        await replacement_menu(message, context.user_data.setdefault("replacement", {}), user_id)
        return
    if query.data == "replacement_add":
        await query.answer()
        clear(context)
        context.user_data["replacement"] = {"mode": "enter_ip", "rotation_id": replacement.DIRECT}
        await message.reply_text("IP عمومی سروری را که می‌خواهی پایش شود بفرست. برای لغو /cancel را بزن.")
        return
    draft = context.user_data.get("replacement", {})
    _, nonce, action = query.data.split(":", 2)
    if nonce != draft.get("nonce"):
        await query.answer("این منو بسته شده است.")
        return
    await query.answer()
    if action.startswith("page:"):
        page = int(action.split(":")[1])
        if page * 8 < len(draft["choices"]):
            if draft.get("mode") == "list":
                await replacement_menu(message, draft, user_id, page)
            else:
                await show_cloud_picker(message, draft, page, "IP مورد پایش را انتخاب کن.", "rp", "منوی Cloudflare", "cloudflare")
        return
    if action.startswith("pick:"):
        index = int(action.split(":")[1])
        if index >= len(draft["choices"]):
            return
        value = draft["choices"][index][0]
        if draft.get("mode") == "list":
            row = replacement.get(ADMIN_DB, user_id, value)
            if not row:
                return
            draft["rule_id"] = row.id
            buttons = [[("بازگشت به فهرست", "list")]]
            if row.state == "watching":
                buttons[:0] = [[("📡 پینگ دستی", "ping")], [("لغو برنامه", "cancel")]]
            await message.reply_text(
                f"{row.target} · {replacement.PROVIDERS[row.provider]}\n{REPLACEMENT_STATUS[row.state]}"
                + (f"\nشناسهٔ VPS جدید: {row.remote_id}" if row.remote_id else "") + (f"\n{row.note}" if row.note else ""),
                reply_markup=nonce_keyboard(draft, buttons, "rp"),
            )
        else:
            await replacement_choose_provider(message, draft, value)
        return
    if action.startswith("provider:"):
        provider = action.split(":")[1]
        draft.update(provider=provider)
        draft.pop("nonce", None)
        await message.reply_text(
            "مشخصات VPS جایگزین را انتخاب کن. در این مسیر دکمهٔ تأیید فقط برنامه را ثبت می‌کند.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("انتخاب مشخصات", callback_data=REPLACEMENT_START[provider])]]),
        )
    elif action == "list":
        await replacement_menu(message, draft, user_id)
    elif action == "ping":
        row = replacement.get(ADMIN_DB, user_id, draft["rule_id"])
        if not row or row.state != "watching":
            await message.reply_text("این برنامه دیگر در انتظار پایش نیست.")
        elif row.id in REPLACEMENT_CHECKS:
            await message.reply_text("پایش این برنامه در حال اجراست. کمی بعد دوباره بزن.")
        else:
            await run_replacement(context.bot, row, manual=(message, draft))
    elif action == "cancel":
        row = replacement.get(ADMIN_DB, user_id, draft["rule_id"])
        if row and row.state == "watching":
            replacement.update(ADMIN_DB, row, state="cancelled", recipe=None)
        await replacement_menu(message, draft, user_id)
    elif action in {"keep", "auto"}:
        if action == "auto" and not draft.get("old_id"):
            return
        rotation_id = draft["rotation_id"]
        if rotation_id != replacement.DIRECT:
            row = dns_rotation.get(ADMIN_DB, user_id, rotation_id)
            if not row or row.status not in {"active", "done"}:
                await message.reply_text("برنامهٔ تعویض IP دیگر فعال یا قابل استفاده نیست.")
                return
            if draft["target"] != row.expected and (
                row.status != "active" or all(ip != draft["target"] for _, ip in dns_rotation.read_steps(row))
            ):
                await message.reply_text("این IP دیگر در برنامه نیست. دوباره از برنامهٔ تعویض IP انتخاب کن.")
                return
        secret = SERVER_CIPHER.encrypt(json.dumps(draft["form"]).encode())
        try:
            replacement.add(
                ADMIN_DB, user_id, rotation_id, draft["target"], draft["provider"], draft["account"], draft["project"],
                secret, draft["old_id"] if action == "auto" else None, host_monitor.interval(ADMIN_DB, user_id),
            )
        except sqlite3.IntegrityError:
            await message.reply_text("برای این IP در این برنامه از قبل یک جایگزینی ثبت شده است.")
            return
        clear(context)
        await message.reply_text("برنامهٔ جایگزینی ثبت شد.", reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("برنامه‌های جایگزینی", callback_data="replacement_list")],
        ]))


def replacement_private_key(recipe):
    return paramiko.RSAKey.from_private_key(StringIO(recipe["_ssh_key"]))


def prepare_replacement(rule, recipe):
    form = {key: value for key, value in recipe.items() if not key.startswith("_")}
    name_key = replacement.NAME_KEY.get(rule.provider, "label")
    suffix = f"-r{rule.id}-{secrets.token_hex(3)}"
    form[name_key] = form[name_key][:63 - len(suffix)].rstrip("-_.") + suffix
    if rule.provider == "vultr":
        form["hostname"] = form[name_key]
    if rule.provider == "hetzner":
        key = paramiko.RSAKey.generate(2048)
        raw = StringIO()
        key.write_private_key(raw)
        recipe["_ssh_key"] = raw.getvalue()
        marker = f"telegram-vps-replacement-{rule.id}"
        form["user_data"] = (
            "#!/bin/sh\nset -e\ninstall -d -m 700 /root/.ssh\n"
            f"printf '%s\\n' 'ssh-rsa {key.get_base64()} {marker}' >> /root/.ssh/authorized_keys\n"
            "chmod 600 /root/.ssh/authorized_keys\n"
        )
    return form


async def create_replacement(rule, token, form):
    if rule.provider == "kamatera":
        return await kamatera.create_server(token, form), None
    if rule.provider == "hetzner":
        result = await hetzner.create(token, form)
        return str(result["server"]["id"]), result.get("root_password")
    if rule.provider == "cherry":
        result = await cherry.create(token, rule.project_id, form)
        return str(result["id"]), result.get("password")
    create = linode.create if rule.provider == "linode" else vultr.create
    result = await create(token, form)
    return str(result["id"]), result.get("default_password")


async def delete_replacement_origin(rule, token):
    if rule.provider == "hetzner":
        await hetzner.change_server(token, int(rule.old_id), "delete")
    elif rule.provider == "linode":
        await linode.delete_instance(token, int(rule.old_id))
    elif rule.provider == "kamatera":
        await kamatera.terminate_server(token, rule.old_id)
    elif rule.provider == "vultr":
        await vultr.change_instance(token, rule.old_id, "delete")
    else:
        await cherry.change_server(token, int(rule.old_id), "delete")


async def replacement_active(rule):
    if rule.rotation_id == replacement.DIRECT:
        return True, True
    rotation = dns_rotation.get(ADMIN_DB, rule.user_id, rule.rotation_id)
    if not rotation or rotation.status not in {"active", "done"}:
        return False, False
    if rotation.expected != rule.target:
        upcoming = rotation.status == "active" and any(step[1] == rule.target for step in dns_rotation.read_steps(rotation))
        return False, upcoming
    token = cf_token(rule.user_id, rotation.account_id)
    if not token:
        return False, True
    record = await cloudflare.record(token, rotation.zone_id, rotation.record_id)
    active = (
        record.get("name") == rotation.name and record.get("type") == rotation.kind
        and cloudflare.destination(record.get("content") or "", rotation.kind) == rule.target
    )
    return active, True


async def replacement_notify(bot, rule, text):
    if user_has_access(rule.user_id):
        try:
            await bot.send_message(chat_id=rule.user_id, text=f"🔁 جایگزینی {rule.target}\n{text}")
        except TelegramError:
            pass


async def replacement_fail(bot, rule, text):
    if replacement.update(ADMIN_DB, rule, state="failed", note=text, recipe=None):
        await replacement_notify(bot, rule, text)


async def replacement_watch(bot, rule, recipe, now, *, manual=None):
    if manual:
        message, draft = manual
        previous = draft.get("manual_down")
        first = previous[1] if previous and previous[0] == rule.id else None
        if first is not None and now < first + 120:
            await message.reply_text(f"برای پینگ دوم حدود {first + 120 - now} ثانیه صبر کن.")
            return
    delay = host_monitor.interval(ADMIN_DB, rule.user_id)
    try:
        active, upcoming = await replacement_active(rule)
        if not upcoming:
            replacement.update(ADMIN_DB, rule, state="cancelled", recipe=None, note="این IP دیگر در برنامه نیست.")
            if manual:
                await message.reply_text("این IP دیگر در برنامهٔ تعویض نیست.")
            return
        if not active:
            if manual:
                draft.pop("manual_down", None)
                await message.reply_text("این IP هنوز مقصد فعال برنامهٔ تعویض نیست.")
            else:
                replacement.update(ADMIN_DB, rule, next_at=now + delay, evidence=0)
            return
        async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
            networks = await host_monitor.aws_networks(client)
            status = await host_monitor.check_ip(client, rule.target, networks, minimum_timeout_nodes=2)
    except (*REPLACEMENT_ERRORS, ValueError):
        status = "unknown"
    notes = {
        "down": "حداقل دو نود ایران تایم‌اوت دادند. بررسی تأییدی حدود دو دقیقه دیگر انجام می‌شود.",
        "ok": "در آخرین پایش دست‌کم یک نود ایران پاسخ گرفت.",
        "aws": "IP متعلق به Amazon/AWS است و از پایش کنار گذاشته شد.",
        "provider_unknown": "در آخرین بررسی، سرویس تشخیص ISP نتیجه نداد.",
    }
    inconclusive = "آخرین پایش نتیجهٔ قطعی نداشت. برای جایگزینی حداقل دو تایم‌اوت لازم است."
    if manual:
        draft.pop("manual_down", None)
        if status != "down":
            await message.reply_text(notes.get(status, inconclusive))
            return
        if first is None or now - first > delay:
            draft["manual_down"] = (rule.id, int(time.time()))
            await message.reply_text(
                "قطع پینگ یک‌بار تأیید شد. دو دقیقه بعد دوباره «پینگ دستی» را بزن. "
                "اگر بار دوم هم قطع پینگ تأیید شود، ساخت VPS هزینه‌دار شروع می‌شود."
            )
            return
    elif status != "down" or not rule.evidence:
        replacement.update(
            ADMIN_DB, rule, evidence=int(status == "down"),
            next_at=now + (120 if status == "down" else delay),
            note=notes.get(status, inconclusive),
        )
        return
    try:
        token = await replacement_token(rule)
    except REPLACEMENT_ERRORS:
        token = None
    if not token:
        await replacement_fail(bot, rule, "توکن سرویس برای ساخت VPS در دسترس نیست.")
        return
    form = await asyncio.to_thread(prepare_replacement, rule, recipe)
    recipe["_name"] = form[replacement.NAME_KEY.get(rule.provider, "label")]
    encoded = SERVER_CIPHER.encrypt(json.dumps(recipe).encode())
    try:
        still_active, _ = await replacement_active(rule)
    except (*REPLACEMENT_ERRORS, ValueError):
        still_active = False
    if not still_active or not user_has_access(rule.user_id):
        replacement.update(ADMIN_DB, rule, next_at=now + delay, evidence=0)
        return
    claim = replacement.update(ADMIN_DB, rule, state="creating", recipe=encoded, next_at=now + 180)
    if not claim:
        return
    try:
        remote_id, initial_password = await create_replacement(claim, token, form)
    except REPLACEMENT_ERRORS:
        await replacement_fail(bot, claim, "ساخت VPS تأیید نشد. برای جلوگیری از ساخت تکراری، پنل سرویس را بررسی کن.")
        return
    if isinstance(initial_password, str) and initial_password:
        recipe["_initial_password"] = initial_password
        encoded = SERVER_CIPHER.encrypt(json.dumps(recipe).encode())
    if replacement.update(ADMIN_DB, claim, state="provisioning", remote_id=remote_id, recipe=encoded,
                          next_at=int(time.time()) + 30, deadline=int(time.time()) + 3600):
        await replacement_notify(bot, claim, f"درخواست VPS جایگزین ثبت شد. شناسه: {remote_id}")


async def replacement_instance(rule, token, recipe):
    if rule.provider != "kamatera":
        return await replacement_details(rule, token, rule.remote_id)
    pending = SimpleNamespace(user_id=rule.user_id, remote_id=rule.remote_id,
                              region=recipe["datacenter"], name=recipe["_name"])
    instance, failed = await kamatera_created_instance(pending)
    if failed:
        raise kamatera.APIError(409)
    return instance


async def replacement_install(bot, rule, recipe, now):
    if now >= rule.deadline:
        await replacement_fail(bot, rule, "VPS یا دسترسی SSH در مهلت بررسی آماده نشد. سرور قبلی حفظ شد.")
        return
    client = None
    try:
        token = await replacement_token(rule)
        instance = await replacement_instance(rule, token, recipe) if token else None
        ip = cloud_saved.instance_address(rule.provider, instance) if instance else None
        if not ip:
            replacement.update(ADMIN_DB, rule, next_at=now + replacement.POLL)
            return
        password = (recipe.get("root_pass") or recipe.get("password") or recipe.get("_initial_password")
                    or instance.get("default_password") or instance.get("password"))
        key = replacement_private_key(recipe) if rule.provider == "hetzner" else None
        if key or password:
            client = await asyncio.to_thread(connect, ip, 22, "root", None if key else password, key)
    except (OSError, ValueError, paramiko.SSHException, *REPLACEMENT_ERRORS):
        pass
    if client is None:
        replacement.update(ADMIN_DB, rule, next_at=now + replacement.POLL)
        return
    claim = None
    try:
        if user_has_access(rule.user_id):
            claim = replacement.update(ADMIN_DB, rule, state="installing", next_at=now + 1900)
        if not claim:
            return
        status, node = await asyncio.to_thread(install_node, client, "")
        if status or not node or not all(node):
            await replacement_fail(bot, claim, "نصب یا استخراج اطلاعات نود ناموفق بود. سرور قبلی حفظ شد.")
            return
        if key:
            marker = f"telegram-vps-replacement-{rule.id}"
            cleanup, _ = await asyncio.to_thread(run, client, f"sed -i '/ {marker}$/d' /root/.ssh/authorized_keys")
            if cleanup:
                await replacement_fail(bot, claim, "نود نصب شد، اما پاک‌کردن کلید موقت SSH تأیید نشد. سرور قبلی حفظ شد.")
                return
    except (OSError, paramiko.SSHException):
        if claim:
            await replacement_fail(bot, claim, "ارتباط در زمان نصب یا آماده‌سازی نود قطع شد. سرور قبلی حفظ شد.")
        return
    finally:
        client.close()
    if not user_has_access(rule.user_id) or replacement.get(ADMIN_DB, claim.user_id, claim.id) != claim:
        return
    region = recipe[replacement.REGION_KEY.get(rule.provider, "region")]
    store_created_server(
        rule.user_id, rule.provider, rule.remote_id, region, recipe["_name"], instance=instance,
        password=password, account_id=rule.account_id,
    )
    try:
        await bot.send_message(chat_id=rule.user_id, text=f"✅ نود جایگزین آماده شد.\nIP: {ip}\nAPI Key: {node[0]}")
        await bot.send_message(chat_id=rule.user_id, text=node[1])
    except TelegramError:
        await replacement_fail(bot, claim, "نود نصب شد، اما ارسال اطلاعات نود تأیید نشد. سرور قبلی حفظ شد.")
        return
    if not rule.old_id:
        replacement.update(ADMIN_DB, claim, state="done", recipe=None, note=f"نود جایگزین: {ip} · سرور قبلی حفظ شد.")
        return
    try:
        nodes, results = await host_checks.ping_iran(ip)
        old = await replacement_details(rule, token, rule.old_id)
        active, _ = await replacement_active(rule)
    except (host_checks.CheckError, *REPLACEMENT_ERRORS, ValueError):
        nodes, results, old, active = {}, {}, {}, False
    if (
        not user_has_access(rule.user_id) or not active or host_monitor.ping_status(nodes, results) != "ok"
        or rule.target not in replacement_ips(rule.provider, old)
        or str(replacement_region(rule.provider, old)).casefold() != region.casefold()
        or str(instance.get("id")) == rule.old_id
    ):
        replacement.update(ADMIN_DB, claim, state="done", recipe=None, note=f"نود جایگزین: {ip} · حذف خودکار تأیید نشد.")
        await replacement_notify(bot, claim, "شرایط حذف خودکار تأیید نشد. سرور قبلی حفظ شد.")
        return
    deleting = replacement.update(ADMIN_DB, claim, state="deleting", recipe=None, next_at=int(time.time()) + 180)
    if not deleting:
        return
    try:
        await delete_replacement_origin(deleting, token)
    except REPLACEMENT_ERRORS:
        await replacement_fail(bot, deleting, "نتیجهٔ درخواست حذف مشخص نیست. وضعیت VPS قبلی را در پنل بررسی کن.")
        return
    replacement.update(ADMIN_DB, deleting, state="done", note=f"نود جایگزین: {ip} · درخواست حذف VPS قبلی ثبت شد.")
    await replacement_notify(bot, deleting, "درخواست حذف VPS قبلی ثبت شد. رکورد Cloudflare تغییر نکرد.")


async def run_replacement(bot, rule, *, manual=None):
    if rule.id in REPLACEMENT_CHECKS:
        return
    REPLACEMENT_CHECKS.add(rule.id)
    try:
        if not user_has_access(rule.user_id):
            replacement.update(ADMIN_DB, rule, state="cancelled", recipe=None, note="دسترسی کاربر فعال نیست.")
            return
        if rule.state not in {"watching", "provisioning"}:
            await replacement_fail(bot, rule, "اجرای قبلی کامل ثبت نشد. وضعیت VPSها را در پنل بررسی کن.")
            return
        recipe = json.loads(SERVER_CIPHER.decrypt(rule.recipe))
        now = int(time.time())
        if rule.state == "watching":
            await replacement_watch(bot, rule, recipe, now, manual=manual)
        else:
            await replacement_install(bot, rule, recipe, now)
    except (TypeError, ValueError, InvalidToken):
        current = replacement.get(ADMIN_DB, rule.user_id, rule.id)
        if current and current.state not in replacement.TERMINAL:
            await replacement_fail(bot, current, "برنامه یا اطلاعات ذخیره‌شده قابل خواندن نبود.")
    finally:
        REPLACEMENT_CHECKS.discard(rule.id)


async def replacement_job(context):
    for rule in replacement.due(ADMIN_DB):
        if rule.id not in REPLACEMENT_CHECKS:
            task = context.application.create_task(run_replacement(context.bot, rule))
            # Start the task so it reserves the rule before a subsequent job tick.
            if not task.done():
                await asyncio.sleep(0)


async def handle_text(update, context):
    if not private_admin(update):
        return
    state = context.user_data
    message = update.message
    if state.get("panel_install_step") in {"domain", "email", "confirm"}:
        await panel_install_text(update, context)
        return
    if "pasarguard" in state and state["pasarguard"]["step"] == "credentials":
        await panel_credentials_text(update, context)
        return
    if state.get("action") == "ssl" and "ssl_domain" not in state:
        await ssl_request_text(update, context)
        return
    if state.get("replacement", {}).get("mode") == "enter_ip":
        await replacement_ip_text(update, context)
        return
    if "host_monitor" in state:
        await host_monitor_text(update, context)
        return
    if "host_check" in state:
        await host_check_text(update, context)
        return
    if state.get("folder_pending"):
        await create_server_folder(update, context)
        return
    if "cherry" in state:
        await cherry_text(update, context)
        return
    if "vultr" in state:
        await vultr_text(update, context)
        return
    if private_operator(update) and "backup" in state:
        await backup_text(update, context)
        return
    if "cloudflare" in state:
        await cloudflare_text(update, context)
        return
    if "hetzner" in state:
        await hetzner_text(update, context)
        return
    if "linode" in state:
        await linode_text(update, context)
        return
    if "kamatera" in state:
        await kamatera_text(update, context)
        return
    if private_operator(update) and state.get("license", {}).get("enter_id"):
        await activate_license(update, context)
        return
    if "action" not in state or "servers_token" in state:
        return
    if "client" in state and time.monotonic() >= state["expires"]:
        clear(context)
        await message.reply_text("مهلت اتصال تمام شد.", reply_markup=menu(private_operator(update)))
        return
    if "address" not in state:
        try:
            state["address"] = parse_address(message.text)
        except ValueError:
            await message.reply_text("آدرس معتبر نیست. آی‌پی، نام میزبان یا آدرس به‌همراه پورت را بفرست.")
            return
        await message.reply_text("نام کاربری SSH را بفرست. مثلاً root یا ubuntu.")
        return
    if "username" not in state:
        username = message.text.strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", username):
            await message.reply_text("نام کاربری معتبر نیست. دوباره بفرست.")
            return
        state["username"] = username
        await ask_password(message, private_owner(update))
        return
    if "client" not in state:
        use_key = (
            not state.get("password_only") and private_owner(update)
            and message.text == "." and os.getenv("SSH_KEY_PATH")
        )
        password = None if use_key else message.text
        if password is not None:
            try:
                await message.delete()
            except TelegramError:
                await message.reply_text("حذف پیام رمز ناموفق بود. پیام را دستی حذف کن.")
        state.pop("servers_token", None)
        if not await login_server(update, context, password) and "saved_server_id" in state:
            await show_saved_password_retry(message, state)
        return
    try:
        await operate(message, state, state["client"], message.text)
    except (OSError, paramiko.SSHException):
        await cancel(update, context)


async def login_server(update, context, password, remember=True):
    state = context.user_data
    message = update.effective_message
    try:
        client = await asyncio.to_thread(
            connect, *state["address"], state["username"], password,
        )
    except paramiko.BadHostKeyException:
        await message.reply_text("کلید SSH این سرور تغییر کرده است. کلید جدید را روی میزبان ربات بررسی کن.")
        return False
    except (OSError, paramiko.SSHException, ValueError):
        await message.reply_text("اتصال برقرار نشد. دسترسی و اطلاعات ورود را بررسی کن. برای تغییر سرور /cancel را بزن.")
        return False
    if remember:
        try:
            save_server(update.effective_user.id, state["address"], state["username"], password)
        except sqlite3.Error:
            await message.reply_text("اتصال برقرار شد، اما ذخیرهٔ سرور ناموفق بود.")
    if state["action"] == "ssh":
        state["client"] = client
        state["expires"] = time.monotonic() + 600
        state["expiry_job"] = context.application.job_queue.run_once(
            expire, 600, data=client, user_id=update.effective_user.id,
        )
        await message.reply_text("متصل شدی. هر پیام یک دستور جداگانه است. برای بستن اتصال /cancel را بزن.")
        return True
    action = state["action"]
    try:
        await operate(message, state, client)
    except (OSError, paramiko.SSHException):
        await message.reply_text("ارتباط قطع شد یا مهلت عملیات تمام شد.")
    finally:
        client.close()
        clear(context)
    if action == "panel_install":
        await message.reply_text("پنل پاسارگارد", reply_markup=panel_menu())
    elif action != "ssl":
        await message.reply_text("عملیات بعدی را انتخاب کن.", reply_markup=menu(private_operator(update)))
    return True


async def expire(context):
    client = context.job.data
    if context.user_data.get("client") is client:
        context.user_data.pop("expiry_job", None)
        clear(context)


async def report_error(update, context):
    # Exception messages and update bodies can include credentials.
    logging.error("Bot handler failed (%s)", type(context.error).__name__)
    if getattr(update, "effective_message", None) and private_admin(update):
        try:
            await update.effective_message.reply_text("ادامهٔ این مرحله ناموفق بود. از مرحلهٔ قبل یا منوی اصلی دوباره شروع کن.")
        except TelegramError:
            pass


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    configured_owners = [int(value) for value in os.environ["TELEGRAM_ADMIN_IDS"].split(",")]
    MAIN_OWNER_ID = configured_owners[0]
    OWNER_IDS = set(configured_owners)
    ADMIN_DB, ADDED_ADMINS = load_admins()
    SERVER_CIPHER = init_servers(ADMIN_DB)
    telegram_bot = navigation.NavigationBot(os.environ["TELEGRAM_BOT_TOKEN"], user_has_access)
    application = Application.builder().bot(telegram_bot).build()

    def add(handler):
        handler.callback = navigation.track(handler.callback, user_has_access)
        application.add_handler(handler)

    application.add_handler(CallbackQueryHandler(navigation_button, pattern=r"^nav:(?:back|main)$"))
    add(CommandHandler(["start", "menu"], start))
    add(CommandHandler("cancel", cancel))
    add(CommandHandler("update", update_command))
    add(CallbackQueryHandler(cancel, pattern=r"^cancel$"))
    add(CallbackQueryHandler(
        replacement_button,
        pattern=r"^(?:replacement_(?:list|add)|rp:[a-f0-9]{16}:(?:(?:pick|page):[0-9]{1,8}|provider:(?:hetzner|linode|kamatera|vultr|cherry)|keep|auto|list|cancel|ping))$",
    ))
    add(CallbackQueryHandler(
        host_monitor_button, pattern=r"^(?:hc:monitor|hm:[a-f0-9]{16}:(?:add|test|interval|(?:remove|page):[0-9]{1,8}))$",
    ))
    add(CallbackQueryHandler(
        host_check_button, pattern=r"^(?:host_checks|hc:(?:ping|info))$",
    ))
    add(CallbackQueryHandler(panel_install_button, pattern=r"^pg:install(?::confirm:[a-f0-9]{16})?$"))
    add(CallbackQueryHandler(select, pattern=r"^(ssh|node|ssl|on|off|update)$"))
    add(CallbackQueryHandler(
        panel_button,
        pattern=r"^(?:pg|pg:(?:key|default|hosts|(?:add|confirm):[a-f0-9]{24})|pgp:[a-f0-9]{16}:(?:(?:pick|page):[0-9]{1,8}|confirm))$",
    ))
    add(CallbackQueryHandler(
        cherry_button,
        pattern=r"^(?:cherry|ch:(?:key|new|servers|balance)|chp:[a-f0-9]{16}:(?:(?:pick|page):[0-9]{1,8}|power-on|power-off|reboot|delete|password|refresh|list|balance|confirm))$",
    ))
    add(CallbackQueryHandler(
        vultr_button,
        pattern=r"^(?:vultr|vu:(?:key|new|list)|vp:[a-f0-9]{16}:(?:(?:pick|page):[0-9]{1,8}|start|halt|reboot|delete|password|refresh|list|confirm))$",
    ))
    add(CallbackQueryHandler(
        backup_button, pattern=r"^(?:backup|db:(?:export|import|apply:[a-f0-9]{16}))$",
    ))
    add(CallbackQueryHandler(
        cloudflare_button,
        pattern=r"^(?:cloudflare|cf:(?:key|zones|add)|cp:[a-f0-9]{16}:(?:(?:pick|page):[0-9]{1,8}|accounts|replace|zones|list|edit_list|search|dns|add|type:(?:A|AAAA|CNAME)|field:(?:name|content|proxied|ttl)|proxy:(?:on|off)|ttl:(?:1|60|300|600|1800|3600)|delete|confirm|rotate|rot_(?:next|review|confirm|list|refresh|now|cancel|delete|remove|replace|page:[0-9]{1,8})))$",
    ))
    add(CallbackQueryHandler(
        hetzner_button,
        pattern=r"^(?:hetzner|he:add|hp:[a-f0-9]{16}:(?:(?:pick|page):[0-9]{1,8}|new|replace|accounts|poweron|shutdown|reboot|refresh|list|delete|password|reset_status|confirm))$",
    ))
    add(CallbackQueryHandler(
        linode_button, pattern=r"^(?:linode|li:(?:key|new|servers)|lp:[a-f0-9]{16}:(?:(?:pick|page):[0-9]{1,8}|boot|shutdown|reboot|refresh|list|delete|confirm))$",
    ))
    add(CallbackQueryHandler(kamatera_button, pattern=r"^(kamatera|km:(key|new|servers|status|make:[a-f0-9]{16}))$"))
    add(CallbackQueryHandler(
        kamatera_create_button,
        pattern=r"^kmc:[a-f0-9]{16}:(?:pick|page|back):[0-9]{1,8}$",
    ))
    add(CallbackQueryHandler(
        kamatera_server_button,
        pattern=r"^kms:[a-f0-9]{16}:(?:(?:page|detail):[0-9]+|power:(?:on|off|restart)|(?:confirm|status|delete):0|confirm:delete)$",
    ))
    add(CallbackQueryHandler(my_servers, pattern=r"^my_servers$"))
    add(CallbackQueryHandler(
        server_button,
        pattern=r"^s:[0-9a-f]{12}:(?:pick|page|new|connect|delete|folder_new|folders_page|folder|move|move_page|move_to|new_password):[0-9]{1,19}$",
    ))
    add(CallbackQueryHandler(
        license_button,
        pattern=r"^(?:license_panel|lic:(?:add|list)|licp:[a-f0-9]{16}:(?:(?:page|pick):[0-9]{1,8}|back|revoke))$",
    ))
    add(MessageHandler(filters.Document.ALL, backup_document))
    add(MessageHandler(filters.TEXT, handle_text))
    application.add_error_handler(report_error)
    application.job_queue.run_repeating(dns_rotation_job, interval=15, first=1)
    application.job_queue.run_repeating(host_monitor_job, interval=60, first=5)
    application.job_queue.run_repeating(cloud_saved_job, interval=60, first=10)
    application.job_queue.run_repeating(replacement_job, interval=30, first=15)
    application.run_polling(drop_pending_updates=True, allowed_updates=["message", "callback_query"])
