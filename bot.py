import asyncio
from datetime import datetime
from decimal import Decimal, InvalidOperation
from html import escape
from ipaddress import IPv6Address
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
from urllib.parse import quote
from zoneinfo import ZoneInfo

import paramiko
from cryptography.fernet import Fernet, InvalidToken
from telegram import (
    CopyTextButton, InlineKeyboardButton, InlineKeyboardMarkup, KeyboardButton,
    KeyboardButtonRequestUsers, ReplyKeyboardMarkup, ReplyKeyboardRemove,
)
from telegram.error import TelegramError
from telegram.ext import (
    Application, CallbackQueryHandler, CommandHandler, MessageHandler, filters,
)

import cloudflare
import database_backup
import dns_rotation
import hetzner
import host_checks
import kamatera
import linode
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



def connect(host, port, username, password=None):
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
            host, port=port, username=username, password=password,
            key_filename=os.getenv("SSH_KEY_PATH") if password is None else None,
            look_for_keys=False, allow_agent=False, timeout=15,
            banner_timeout=15, auth_timeout=15,
        )
        if len(host_keys) != known_count:
            save_host_keys(host_keys, path)
    except BaseException:
        client.close()
        raise
    return client


def run(client, command, timeout=90):
    transport = client.get_transport()
    deadline = time.monotonic() + timeout
    with transport.open_session(timeout=15) as channel:
        channel.settimeout(15)
        channel.set_combine_stderr(True)
        channel.exec_command(command)
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
    dns_rotation.init(db)
    has_saved_secrets = db.execute("""
        SELECT 1 FROM servers WHERE secret IS NOT NULL
        UNION ALL SELECT 1 FROM kamatera_accounts
        UNION ALL SELECT 1 FROM linode_accounts
        UNION ALL SELECT 1 FROM hetzner_projects
        UNION ALL SELECT 1 FROM cloudflare_accounts
        UNION ALL SELECT 1 FROM vultr_accounts LIMIT 1
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


def private_admin(update):
    return (
        update.effective_chat.type == "private"
        and (update.effective_user.id in OWNER_IDS or update.effective_user.id in ADDED_ADMINS)
    )


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
    rows = [[InlineKeyboardButton(LABELS[name], callback_data=name)] for name in ("ssh", "node")]
    rows.append([InlineKeyboardButton(LABELS[name], callback_data=name) for name in ("on", "off")])
    rows.append([
        InlineKeyboardButton("🖥 سرورهای من", callback_data="my_servers"),
        InlineKeyboardButton("📡 پینگ و اطلاعات IP", callback_data="host_checks"),
    ])
    if owner:
        rows.append([
            InlineKeyboardButton("☁️ سرور کاماترا", callback_data="kamatera"),
            InlineKeyboardButton("☁️ سرور Linode", callback_data="linode"),
        ])
        rows.append([
            InlineKeyboardButton("☁️ سرور هتزنر", callback_data="hetzner"),
            InlineKeyboardButton("🌐 Cloudflare", callback_data="cloudflare"),
        ])
        rows.append([
            InlineKeyboardButton("➕ افزودن ادمین", callback_data="add_admin"),
            InlineKeyboardButton(LABELS["update"], callback_data="update"),
        ])
        rows.append([
            InlineKeyboardButton("☁️ سرور Vultr", callback_data="vultr"),
            InlineKeyboardButton("💾 پشتیبان‌گیری و بازیابی", callback_data="backup"),
        ])
    return InlineKeyboardMarkup(rows)


async def start(update, context):
    if private_admin(update):
        clear(context)
        await update.message.reply_text("عملیات سرور را انتخاب کن.", reply_markup=menu(private_owner(update)))


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
    if private_owner(update):
        await update_bot(update.message, context)


async def select(update, context):
    query = update.callback_query
    await query.answer()
    if not private_admin(update) or query.data not in LABELS:
        return
    if query.data == "update":
        if private_owner(update):
            await update_bot(query.message, context)
        return
    clear(context)
    context.user_data["action"] = query.data
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
            "SELECT id, host, port, username FROM servers WHERE user_id = ? ORDER BY id DESC LIMIT 9 OFFSET ?",
            (user_id, page * 8),
        ).fetchall()
    else:
        rows = ADMIN_DB.execute("""
            SELECT s.id, s.host, s.port, s.username FROM servers s
            LEFT JOIN server_folder_members m ON m.server_id = s.id
            WHERE s.user_id = ? AND COALESCE(m.folder_id, 0) = ?
            ORDER BY s.id DESC LIMIT 9 OFFSET ?
        """, (user_id, folder_id, page * 8)).fetchall()
    if not rows and page:
        return await show_servers(update, context, page - 1)
    if not rows and state.get("action"):
        await ask_address(message)
        return
    token = server_list_token(state)
    keyboard = [
        [InlineKeyboardButton(server_label(host, port, username)[:64], callback_data=f"s:{token}:pick:{row_id}")]
        for row_id, host, port, username in rows[:8]
    ]
    navigation = []
    if page:
        navigation.append(InlineKeyboardButton("قبلی", callback_data=f"s:{token}:page:{page - 1}"))
    if len(rows) > 8:
        navigation.append(InlineKeyboardButton("بعدی", callback_data=f"s:{token}:page:{page + 1}"))
    if navigation:
        keyboard.append(navigation)
    if state.get("action"):
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
    await message.reply_text(
        title,
        reply_markup=InlineKeyboardMarkup(keyboard),
    )


async def my_servers(update, context):
    await update.callback_query.answer()
    if private_admin(update):
        clear(context)
        await show_server_folders(update, context)


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
    if verb == "connect" or (verb == "pick" and action):
        state.pop("servers_token")
        state.update(action=action or "ssh", address=(host, port), username=username)
        if secret is None and not (private_owner(update) and os.getenv("SSH_KEY_PATH")):
            await ask_password(query.message, private_owner(update))
            return
        try:
            password = SERVER_CIPHER.decrypt(secret).decode() if secret is not None else None
        except InvalidToken:
            await query.message.reply_text("رمز ذخیره‌شده خوانده نشد. رمز SSH را دوباره بفرست.")
            await ask_password(query.message, private_owner(update))
            return
        if not await login_server(update, context, password, remember=False):
            await ask_password(query.message, private_owner(update))


async def add_admin(update, context):
    query = update.callback_query
    await query.answer()
    if not private_owner(update):
        return
    clear(context)
    request_id = secrets.randbelow(2**31)
    context.user_data["admin_request"] = request_id
    chooser = KeyboardButton(
        "انتخاب کاربر در تلگرام",
        request_users=KeyboardButtonRequestUsers(request_id, user_is_bot=False, request_username=True),
    )
    await query.message.reply_text(
        "آیدی عددی کاربر را بفرست یا با دکمهٔ پایین، کاربر را با نام کاربری پیدا و انتخاب کن. "
        "برای برگشت /cancel را بزن.",
        reply_markup=ReplyKeyboardMarkup([[chooser]], resize_keyboard=True, one_time_keyboard=True),
    )


async def grant_admin(update, context, user_id):
    try:
        with ADMIN_DB:
            if user_id not in OWNER_IDS:
                ADMIN_DB.execute("INSERT OR IGNORE INTO admins VALUES (?)", (user_id,))
    except sqlite3.Error:
        await update.message.reply_text("ذخیرهٔ ادمین ناموفق بود. دوباره تلاش کن.")
        return
    ADDED_ADMINS.add(user_id)
    clear(context)
    await update.message.reply_text(
        f"دسترسی آیدی {user_id} فعال است. کاربر می‌تواند /start را در چت خصوصی ربات بزند.",
        reply_markup=ReplyKeyboardRemove(),
    )
    await update.message.reply_text("عملیات بعدی را انتخاب کن.", reply_markup=menu(True))


async def shared_admin(update, context):
    if not private_owner(update):
        return
    shared = update.message.users_shared
    state = context.user_data
    if shared.request_id != state.get("admin_request") or len(shared.users) != 1:
        return
    user = shared.users[0]
    if "admin_username" in state and (user.username or "").lower() != state["admin_username"]:
        await update.message.reply_text("نام کاربری انتخاب‌شده مطابقت ندارد. کاربر درست را انتخاب کن.")
        return
    await grant_admin(update, context, user.user_id)


async def cancel(update, context):
    if not private_admin(update):
        return
    if update.callback_query:
        await update.callback_query.answer()
    if "admin_request" in context.user_data:
        await update.effective_message.reply_text("افزودن ادمین لغو شد.", reply_markup=ReplyKeyboardRemove())
    clear(context)
    await update.effective_message.reply_text("اتصال بسته شد. عملیات بعدی را انتخاب کن.", reply_markup=menu(private_owner(update)))


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


async def operate(message, state, client, command=None):
    action = state["action"]
    sudo = "" if state["username"] == "root" else "sudo -n "
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


async def kamatera_button(update, context):
    query = update.callback_query
    await query.answer()
    if not private_owner(update):
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
        clear(context)
        try:
            token = await kamatera_token(user_id)
        except (kamatera.APIError, InvalidToken):
            await message.reply_text("ورود به API ناموفق بود. کلید کاماترا را بررسی کن.")
            return
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
        await message.reply_text(
            f"درخواست ساخت ثبت شد. شناسهٔ عملیات: {command_id}",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("بررسی وضعیت", callback_data="km:status")]]),
        )
        return

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
    if not private_owner(update):
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
    if not private_owner(update):
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
                [InlineKeyboardButton("تأیید ساخت و هزینه", callback_data=confirmation)],
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


async def show_cloud_picker(message, state, page, prompt, prefix, menu_label, menu_action):
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
    keyboard = [*markup.inline_keyboard, [InlineKeyboardButton(menu_label, callback_data=menu_action)]]
    await message.reply_text(
        prompt if choices else "گزینه‌ای برای نمایش پیدا نشد.",
        reply_markup=InlineKeyboardMarkup(keyboard),
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
    if not private_owner(update):
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
            form = state.pop("form")
            clear(context)
            result = await linode.create(token, form)
            await message.reply_text(
                f"درخواست ساخت Linode ثبت شد. شناسه: {result.get('id', '—')}. "
                "برای دیدن IP و وضعیت به «سرورهای موجود» برو."
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
            reply_markup=linode_keyboard(state, [[("تأیید ساخت و هزینه", "confirm")]]),
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
    if not private_owner(update):
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
            await hetzner_confirm(message, context, state, token)
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


async def hetzner_confirm(message, context, state, token):
    state.pop("nonce", None)
    account = {key: state[key] for key in ("account_id", "account_name")}
    if state["step"] == "create_confirm":
        form = state["form"]
        clear(context)
        result = await hetzner.create(token, form)
        instance_id = result["server"]["id"]
        password = result.get("root_password")
        if password:
            instance_state = {**account, "step": "instance", "instance": instance_id, "name": form["name"]}
            context.user_data["hetzner"] = instance_state
            controls = hetzner_keyboard(instance_state, [[("🔑 بازنشانی رمز root", "password")]])
            await message.reply_text(
                f"درخواست ساخت سرور {instance_id} ثبت شد. رمز اولیهٔ root را ذخیره کن:\n{password}",
                protect_content=True,
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("کپی رمز", copy_text=CopyTextButton(password))],
                    *controls.inline_keyboard,
                ]),
            )
        else:
            context.user_data["hetzner"] = account
            await message.reply_text(
                f"درخواست ساخت سرور {instance_id} ثبت شد.",
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
            reply_markup=hetzner_keyboard(state, [[("تأیید ساخت و هزینه", "confirm")]]),
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
                token = cf_token(user_id) if user_id in OWNER_IDS else None
            except InvalidToken:
                token = None
            await dns_rotation.apply_step(ADMIN_DB, row, token)


async def cf_rotation_list(message, state, user_id, page=0):
    if page == 0:
        entries = dns_rotation.for_zone(ADMIN_DB, user_id, state["zone"]["id"])
        state.update(step="rotation_list", choices=[
            (rotation_id, f"{name} · {ROTATION_STATUS.get(status, status)}") for rotation_id, name, status in entries
        ])
    await show_cloud_picker(
        message, state, page, f"برنامه‌های تعویض IP · {state['zone']['name']}", "cp",
        "منوی Cloudflare", "cloudflare",
    )


async def cf_rotation_details(message, state, user_id, rotation_id):
    row = dns_rotation.get(ADMIN_DB, user_id, rotation_id)
    if not row or row.zone_id != state["zone"]["id"]:
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


async def cf_rotation_button(message, state, token, user_id, action):
    if action == "rot_list":
        await cf_rotation_list(message, state, user_id)
    elif action == "rot_refresh":
        await cf_rotation_details(message, state, user_id, state["rotation_id"])
    elif action == "rot_now":
        state.pop("nonce", None)
        rotation_id = state["rotation_id"]
        async with ROTATION_LOCK:
            row = dns_rotation.get(ADMIN_DB, user_id, rotation_id)
            same_step = (
                row and row.zone_id == state["zone"]["id"] and row.status == "active"
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
        if not row or row.zone_id != state["zone"]["id"]:
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
            removed = dns_rotation.delete(ADMIN_DB, user_id, state["zone"]["id"], state["rotation_id"])
        if removed:
            await message.reply_text("برنامهٔ تعویض IP حذف شد.")
        await cf_rotation_list(message, state, user_id)
    elif action == "rot_cancel":
        async with ROTATION_LOCK:
            row = dns_rotation.get(ADMIN_DB, user_id, state["rotation_id"])
            if row and row.zone_id == state["zone"]["id"]:
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
                rotation_id = dns_rotation.schedule(ADMIN_DB, user_id, state["zone"]["id"], latest, state["rotation_steps"])
        except sqlite3.IntegrityError:
            await message.reply_text("برای این رکورد از قبل برنامهٔ فعال وجود دارد.")
            await cf_rotation_list(message, state, user_id)
            return
        await cf_rotation_details(message, state, user_id, rotation_id)


CF_FIELDS = {"name": "نام ساب‌دامنه", "content": "مقصد", "proxied": "Proxy", "ttl": "TTL"}


def cf_token(user_id):
    row = ADMIN_DB.execute("SELECT token FROM cloudflare_accounts WHERE user_id = ?", (user_id,)).fetchone()
    return SERVER_CIPHER.decrypt(row[0]).decode() if row else None


def cf_keyboard(state, rows):
    return nonce_keyboard(state, rows, "cp")


async def cf_picker(message, state, page=0):
    prompt = "دامنه را انتخاب کن." if state["step"] == "zones" else f"ساب‌دامنه‌های {state['zone']['name']} را انتخاب کن."
    await show_cloud_picker(message, state, page, prompt, "cp", "منوی Cloudflare", "cloudflare")


async def cf_dns_menu(message, state):
    state["step"] = "dns"
    await message.reply_text(
        f"مدیریت DNS · {state['zone']['name']}",
        reply_markup=cf_keyboard(state, [
            [("➕ افزودن ساب‌دامنه", "add"), ("✏️ تغییر ساب‌دامنه", "edit_list")],
            [("🔍 جست‌وجوی ساب‌دامنه", "search"), ("📋 نمایش ساب‌دامنه‌ها", "list")],
            [("🕒 برنامه‌های تعویض IP", "rot_list"), ("تغییر دامنه", "zones")],
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
    text = f"دامنه: {state['zone']['name']}\nعملیات: {labels[mode]} رکورد\nنام: {row['name']} · {row['type']}"
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
    if not private_owner(update):
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
    if action == "cloudflare":
        await message.reply_text("مدیریت Cloudflare", reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("مدیریت DNS", callback_data="cf:zones")],
            [InlineKeyboardButton("ثبت یا تعویض API Token", callback_data="cf:key")],
            [InlineKeyboardButton("بازگشت", callback_data="cancel")],
        ]))
        return
    if action == "cf:key":
        state["step"] = "key"
        await message.reply_text(
            "API Token کلادفلر با دسترسی Zone Read و DNS Edit را بفرست. "
            "ربات تلاش می‌کند پیام حاوی توکن را حذف کند."
        )
        return
    try:
        token = cf_token(update.effective_user.id)
    except InvalidToken:
        token = None
    if not token:
        await message.reply_text("ابتدا API Token را ثبت کن.")
        return
    try:
        if action in {"cf:zones", "zones"}:
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
            await cf_rotation_button(message, state, token, update.effective_user.id, action)
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
        with ADMIN_DB:
            ADMIN_DB.execute(
                "INSERT INTO cloudflare_accounts VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET token=excluded.token",
                (user_id, SERVER_CIPHER.encrypt(value.encode())),
            )
        clear(context)
        await message.reply_text("توکن رمزگذاری و ذخیره شد.", reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("مدیریت DNS", callback_data="cf:zones")],
        ]))
        return
    if step in {"rotation_delay", "rotation_ip"}:
        await cf_rotation_text(message, state, value)
        return
    if step == "search":
        if not value or len(value) > 253 or not value.isprintable():
            await message.reply_text("بخشی از نام ساب‌دامنه را در یک خط بفرست.")
            return
        try:
            token = cf_token(user_id)
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
    if not private_owner(update):
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
    if not private_owner(update):
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
        f"{sum(len(rows[name]) for name in ('kamatera_accounts', 'linode_accounts', 'hetzner_projects', 'cloudflare_accounts', 'vultr_accounts'))} حساب سرویس.\n"
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
    if not private_owner(update):
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
            await vultr_confirm(message, context, state, token)
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


async def vultr_confirm(message, context, state, token):
    state.pop("nonce", None)
    if state["step"] == "create_confirm":
        form = state["form"]
        clear(context)
        instance = await vultr.create(token, form)
        state = {"step": "instance", "instance": instance["id"], "label": form["label"]}
        context.user_data["vultr"] = state
        await show_vultr_password(message, state, instance.get("default_password"),
                                  f"درخواست ساخت VPS ثبت شد. شناسه: {instance['id']}")
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
            reply_markup=vultr_keyboard(state, [[("✅ تأیید ساخت و هزینه", "confirm")],
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


async def handle_text(update, context):
    if not private_admin(update):
        return
    state = context.user_data
    message = update.message
    if "host_check" in state:
        await host_check_text(update, context)
        return
    if state.get("folder_pending"):
        await create_server_folder(update, context)
        return
    if private_owner(update) and "vultr" in state:
        await vultr_text(update, context)
        return
    if private_owner(update) and "backup" in state:
        await backup_text(update, context)
        return
    if private_owner(update) and "cloudflare" in state:
        await cloudflare_text(update, context)
        return
    if private_owner(update) and "hetzner" in state:
        await hetzner_text(update, context)
        return
    if private_owner(update) and "linode" in state:
        await linode_text(update, context)
        return
    if private_owner(update) and "kamatera" in state:
        await kamatera_text(update, context)
        return
    if private_owner(update) and "admin_request" in state:
        value = message.text.strip()
        if re.fullmatch(r"[0-9]{1,16}", value) and 0 < int(value) < 2**52:
            await grant_admin(update, context, int(value))
        elif re.fullmatch(r"@?[A-Za-z0-9_]{1,32}", value):
            state["admin_username"] = value.lstrip("@").lower()
            await message.reply_text("همین نام کاربری را با دکمهٔ «انتخاب کاربر در تلگرام» پیدا و تأیید کن.")
        else:
            await message.reply_text("آیدی عددی یا نام کاربری معتبر بفرست.")
        return
    if "action" not in state or "servers_token" in state:
        return
    if "client" in state and time.monotonic() >= state["expires"]:
        clear(context)
        await message.reply_text("مهلت اتصال تمام شد.", reply_markup=menu(private_owner(update)))
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
        use_key = private_owner(update) and message.text == "." and os.getenv("SSH_KEY_PATH")
        password = None if use_key else message.text
        if password is not None:
            try:
                await message.delete()
            except TelegramError:
                await message.reply_text("حذف پیام رمز ناموفق بود. پیام را دستی حذف کن.")
        state.pop("servers_token", None)
        await login_server(update, context, password)
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
    try:
        await operate(message, state, client)
    except (OSError, paramiko.SSHException):
        await message.reply_text("ارتباط قطع شد یا مهلت عملیات تمام شد.")
    finally:
        client.close()
        clear(context)
    await message.reply_text("عملیات بعدی را انتخاب کن.", reply_markup=menu(private_owner(update)))
    return True


async def expire(context):
    client = context.job.data
    if context.user_data.get("client") is client:
        context.user_data.pop("expiry_job", None)
        clear(context)


async def report_error(update, context):
    # Exception messages and update bodies can include credentials.
    logging.error("Bot handler failed (%s)", type(context.error).__name__)


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    OWNER_IDS = {int(value) for value in os.environ["TELEGRAM_ADMIN_IDS"].split(",")}
    ADMIN_DB, ADDED_ADMINS = load_admins()
    SERVER_CIPHER = init_servers(ADMIN_DB)
    application = Application.builder().token(os.environ["TELEGRAM_BOT_TOKEN"]).build()
    application.add_handler(CommandHandler(["start", "menu"], start))
    application.add_handler(CommandHandler("cancel", cancel))
    application.add_handler(CommandHandler("update", update_command))
    application.add_handler(CallbackQueryHandler(cancel, pattern=r"^cancel$"))
    application.add_handler(CallbackQueryHandler(
        host_check_button, pattern=r"^(?:host_checks|hc:(?:ping|info))$",
    ))
    application.add_handler(CallbackQueryHandler(select, pattern=r"^(ssh|node|on|off|update)$"))
    application.add_handler(CallbackQueryHandler(
        vultr_button,
        pattern=r"^(?:vultr|vu:(?:key|new|list)|vp:[a-f0-9]{16}:(?:(?:pick|page):[0-9]{1,8}|start|halt|reboot|delete|password|refresh|list|confirm))$",
    ))
    application.add_handler(CallbackQueryHandler(
        backup_button, pattern=r"^(?:backup|db:(?:export|import|apply:[a-f0-9]{16}))$",
    ))
    application.add_handler(CallbackQueryHandler(
        cloudflare_button,
        pattern=r"^(?:cloudflare|cf:(?:key|zones)|cp:[a-f0-9]{16}:(?:(?:pick|page):[0-9]{1,8}|zones|list|edit_list|search|dns|add|type:(?:A|AAAA|CNAME)|field:(?:name|content|proxied|ttl)|proxy:(?:on|off)|ttl:(?:1|60|300|600|1800|3600)|delete|confirm|rotate|rot_(?:next|review|confirm|list|refresh|now|cancel|delete|remove|page:[0-9]{1,8})))$",
    ))
    application.add_handler(CallbackQueryHandler(
        hetzner_button,
        pattern=r"^(?:hetzner|he:add|hp:[a-f0-9]{16}:(?:(?:pick|page):[0-9]{1,8}|new|replace|accounts|poweron|shutdown|reboot|refresh|list|delete|password|reset_status|confirm))$",
    ))
    application.add_handler(CallbackQueryHandler(
        linode_button, pattern=r"^(?:linode|li:(?:key|new|servers)|lp:[a-f0-9]{16}:(?:(?:pick|page):[0-9]{1,8}|boot|shutdown|reboot|refresh|list|delete|confirm))$",
    ))
    application.add_handler(CallbackQueryHandler(kamatera_button, pattern=r"^(kamatera|km:(key|new|servers|status|make:[a-f0-9]{16}))$"))
    application.add_handler(CallbackQueryHandler(
        kamatera_create_button,
        pattern=r"^kmc:[a-f0-9]{16}:(?:pick|page|back):[0-9]{1,8}$",
    ))
    application.add_handler(CallbackQueryHandler(
        kamatera_server_button,
        pattern=r"^kms:[a-f0-9]{16}:(?:(?:page|detail):[0-9]+|power:(?:on|off|restart)|(?:confirm|status|delete):0|confirm:delete)$",
    ))
    application.add_handler(CallbackQueryHandler(my_servers, pattern=r"^my_servers$"))
    application.add_handler(CallbackQueryHandler(
        server_button,
        pattern=r"^s:[0-9a-f]{12}:(?:pick|page|new|connect|delete|folder_new|folders_page|folder|move|move_page|move_to):[0-9]{1,19}$",
    ))
    application.add_handler(CallbackQueryHandler(add_admin, pattern=r"^add_admin$"))
    application.add_handler(MessageHandler(filters.StatusUpdate.USERS_SHARED, shared_admin))
    application.add_handler(MessageHandler(filters.Document.ALL, backup_document))
    application.add_handler(MessageHandler(filters.TEXT, handle_text))
    application.add_error_handler(report_error)
    application.job_queue.run_repeating(dns_rotation_job, interval=15, first=1)
    application.run_polling(drop_pending_updates=True, allowed_updates=["message", "callback_query"])
