import asyncio
from html import escape
from ipaddress import IPv6Address, ip_address
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

import hetzner
import kamatera
import linode

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
        db.execute("CREATE TABLE IF NOT EXISTS hetzner_accounts (user_id INTEGER PRIMARY KEY, token BLOB NOT NULL)")
    has_saved_secrets = db.execute(
        "SELECT 1 FROM servers WHERE secret IS NOT NULL UNION ALL SELECT 1 FROM kamatera_accounts UNION ALL SELECT 1 FROM linode_accounts UNION ALL SELECT 1 FROM hetzner_accounts LIMIT 1"
    ).fetchone()
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
    job = context.user_data.pop("expiry_job", None)
    if job:
        job.schedule_removal()
    client = context.user_data.pop("client", None)
    if client:
        client.close()
    context.user_data.clear()


def menu(owner):
    rows = [[InlineKeyboardButton(LABELS[name], callback_data=name)] for name in ("ssh", "node")]
    rows.append([InlineKeyboardButton(LABELS[name], callback_data=name) for name in ("on", "off")])
    rows.append([InlineKeyboardButton("🖥 سرورهای من", callback_data="my_servers")])
    if owner:
        rows.append([
            InlineKeyboardButton("☁️ سرور کاماترا", callback_data="kamatera"),
            InlineKeyboardButton("☁️ سرور Linode", callback_data="linode"),
        ])
        rows.append([InlineKeyboardButton("☁️ سرور هتزنر", callback_data="hetzner")])
        rows.append([
            InlineKeyboardButton("➕ افزودن ادمین", callback_data="add_admin"),
            InlineKeyboardButton(LABELS["update"], callback_data="update"),
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


async def show_servers(update, context, page=0):
    message = update.effective_message
    user_id = update.effective_user.id
    state = context.user_data
    rows = ADMIN_DB.execute(
        "SELECT id, host, port, username FROM servers WHERE user_id = ? ORDER BY id DESC LIMIT 9 OFFSET ?",
        (user_id, page * 8),
    ).fetchall()
    if not rows and page:
        return await show_servers(update, context, page - 1)
    if not rows and state.get("action"):
        await ask_address(message)
        return
    token = secrets.token_hex(6)
    state["servers_token"] = token
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
    keyboard.append([InlineKeyboardButton("بازگشت", callback_data="cancel")])
    await message.reply_text(
        "یک سرور انتخاب کن." if rows else "هنوز سروری ذخیره نشده است. با اولین ورود موفق، سرور به این فهرست اضافه می‌شود.",
        reply_markup=InlineKeyboardMarkup(keyboard),
    )


async def my_servers(update, context):
    await update.callback_query.answer()
    if private_admin(update):
        clear(context)
        await show_servers(update, context)


async def server_button(update, context):
    query = update.callback_query
    state = context.user_data
    _, token, verb, value = query.data.split(":")
    if not private_admin(update) or token != state.get("servers_token"):
        await query.answer("این منو بسته شده است.")
        return
    await query.answer()
    if verb == "page":
        await show_servers(update, context, int(value))
        return
    if verb == "new":
        state.pop("servers_token")
        await ask_address(query.message)
        return
    user_id = update.effective_user.id
    server_id = int(value)
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
    if verb == "pick" and not action:
        state["servers_token"] = secrets.token_hex(6)
        token = state["servers_token"]
        await query.message.reply_text(
            server_label(host, port, username),
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("اتصال SSH", callback_data=f"s:{token}:connect:{server_id}")],
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
    if action == "confirm":
        power = state.pop("power")
        state["token"] = None
    try:
        bearer = await kamatera_token(update.effective_user.id)
        if action == "confirm":
            command_id = await kamatera.set_power(bearer, server_id, power)
            state["command_id"] = command_id
            await message.reply_text(
                f"درخواست ثبت شد. شناسهٔ عملیات: {command_id}",
                reply_markup=kamatera_controls(state, [
                    [("وضعیت عملیات", "status:0"), ("وضعیت سرور", f"detail:{index}")],
                ]),
            )
            return
        if action == "status":
            result = await kamatera.command_status(bearer, state["command_id"])
            status = {"complete": "انجام شد", "error": "ناموفق بود"}.get(result["status"], "در صف یا در حال انجام")
            await message.reply_text(
                f"عملیات {state['command_id']} — {status}",
                reply_markup=kamatera_controls(state, [
                    [("بررسی دوباره", "status:0"), ("وضعیت سرور", f"detail:{index}")],
                ]),
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
    "location": "لوکیشن را انتخاب کن.",
    "type": "پلن را انتخاب کن.",
    "image": "سیستم‌عامل را انتخاب کن.",
    "ssh": "کلید SSH پروژه را انتخاب کن. برای دریافت رمز اولیهٔ root، گزینهٔ بدون کلید را بزن.",
    "servers": "یک VPS هتزنر را انتخاب کن.",
}
HETZNER_OPERATIONS = {**hetzner.POWER, "delete": "حذف دائمی"}


def hetzner_token(user_id):
    row = ADMIN_DB.execute("SELECT token FROM hetzner_accounts WHERE user_id = ?", (user_id,)).fetchone()
    return SERVER_CIPHER.decrypt(row[0]).decode() if row else None


def hetzner_keyboard(state, rows):
    return nonce_keyboard(state, rows, "hp")


async def show_hetzner_picker(message, state, page=0):
    await show_cloud_picker(
        message, state, page, HETZNER_PROMPTS[state["step"]], "hp", "منوی هتزنر", "hetzner",
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
    rows.append([("🔑 تغییر رمز root", "password")])
    rows.append([("تازه‌سازی", "refresh"), ("بازگشت به فهرست", "list")])
    await message.reply_text(
        f"سرور: {state['name']}\nوضعیت: {server.get('status') or '—'}\n"
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
    if action == "hetzner":
        await message.reply_text("مدیریت Hetzner Cloud", reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("ثبت یا تعویض توکن", callback_data="he:key")],
            [InlineKeyboardButton("ساخت VPS", callback_data="he:new"),
             InlineKeyboardButton("سرورهای موجود", callback_data="he:servers")],
            [InlineKeyboardButton("بازگشت", callback_data="cancel")],
        ]))
        return
    if action == "he:key":
        context.user_data["hetzner"] = {"step": "key"}
        await message.reply_text(
            "توکن API پروژهٔ هتزنر با دسترسی Read & Write را بفرست. ربات تلاش می‌کند پیام را حذف کند. "
            "چت ربات رمزنگاری سرتاسری ندارد."
        )
        return
    try:
        token = hetzner_token(user_id)
    except InvalidToken:
        token = None
    if not token:
        await message.reply_text("اول توکن هتزنر را ثبت کن.")
        return
    try:
        if action == "he:new":
            locations, plans = await asyncio.gather(
                hetzner.catalog(token, "locations"), hetzner.catalog(token, "server_types"),
            )
            state.update(step="location", form={}, plans=plans, choices=[
                (loc["name"], f"{loc.get('city') or loc['name']} · {loc['name']}")
                for loc in locations if any(hetzner.regional_price(plan, loc["name"]) for plan in plans)
            ])
        elif action in {"he:servers", "list"}:
            servers = await hetzner.catalog(token, "servers")
            state.update(step="servers", choices=[
                (row["id"], f"{row.get('name') or row['id']} · {row.get('status', '—')}") for row in servers
            ])
        elif action.startswith("page:"):
            page = int(action.split(":")[1])
            if page * 8 < len(state["choices"]):
                await show_hetzner_picker(message, state, page)
            return
        elif action.startswith("pick:"):
            await hetzner_pick(message, state, token, int(action.split(":")[1]))
            return
        elif action == "refresh":
            await show_hetzner_server(message, state, token)
            return
        elif action == "password" and state["step"] == "instance":
            state.pop("nonce", None)
            state["step"] = "password"
            await message.reply_text(
                "رمز فعلی یا رمز اولیهٔ root همین سرور را بفرست. ربات یک رمز جدید می‌سازد "
                "و آن را همین‌جا به‌صورت قابل کپی می‌فرستد. برای لغو /cancel را بزن."
            )
            return
        elif action in HETZNER_OPERATIONS and state["step"] == "instance":
            state.update(step="operation_confirm", operation=action)
            prompt = f"عملیات «{HETZNER_OPERATIONS[action]}» روی «{state['name']}» با شناسهٔ {state['instance']} انجام شود؟"
            if action == "delete":
                prompt += "\nسرور و داده‌های روی دیسک آن برای همیشه حذف می‌شوند."
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
    if state["step"] == "create_confirm":
        form = state["form"]
        clear(context)
        result = await hetzner.create(token, form)
        instance_id = result["server"]["id"]
        password = result.get("root_password")
        if password:
            instance_state = {"step": "instance", "instance": instance_id}
            context.user_data["hetzner"] = instance_state
            controls = hetzner_keyboard(instance_state, [[("🔑 تغییر رمز root", "password")]])
            await message.reply_text(
                f"درخواست ساخت سرور {instance_id} ثبت شد. رمز اولیهٔ root را ذخیره کن:\n{password}",
                protect_content=True,
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("کپی رمز", copy_text=CopyTextButton(password))],
                    *controls.inline_keyboard,
                ]),
            )
        else:
            await message.reply_text(f"درخواست ساخت سرور {instance_id} ثبت شد. وضعیت را از فهرست سرورها ببین.")
        return
    operation = state["operation"]
    instance = state["instance"]
    await hetzner.change_server(token, instance, operation)
    if operation == "delete":
        clear(context)
        await message.reply_text(
            f"درخواست حذف سرور {instance} ثبت شد.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("سرورهای موجود", callback_data="he:servers")]]),
        )
    else:
        await message.reply_text(
            "درخواست تغییر وضعیت ثبت شد.",
            reply_markup=hetzner_keyboard(state, [[("تازه‌سازی وضعیت", "refresh")]]),
        )


async def hetzner_text(update, context):
    message = update.message
    state = context.user_data["hetzner"]
    value = message.text.strip()
    if state["step"] == "password":
        await hetzner_change_password(update, context, state, message.text)
        return
    if state["step"] == "key":
        await delete_secret_message(message)
        if not re.fullmatch(r"[A-Za-z0-9_-]{16,256}", value):
            await message.reply_text("توکن هتزنر را در یک خط بفرست.")
            return
        try:
            await hetzner.request("GET", "/servers", value, params={"per_page": 1})
        except hetzner.APIError:
            await message.reply_text("توکن تأیید نشد. توکن پروژه و دسترسی آن را بررسی کن.")
            return
        with ADMIN_DB:
            ADMIN_DB.execute(
                "INSERT INTO hetzner_accounts VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET token=excluded.token",
                (update.effective_user.id, SERVER_CIPHER.encrypt(value.encode())),
            )
        clear(context)
        await message.reply_text(
            "توکن هتزنر تأیید و رمزگذاری شد.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("منوی هتزنر", callback_data="hetzner")]]),
        )
    elif state["step"] == "name":
        if len(value) > 63 or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", value):
            await message.reply_text("نام را با حروف انگلیسی، عدد و خط تیره بفرست. با خط تیره شروع یا تمام نشود.")
            return
        state["form"]["name"] = value
        state["step"] = "create_confirm"
        form = state["form"]
        hourly, monthly = state["price"]
        await message.reply_text(
            f"سرور: {value}\nلوکیشن: {form['location']}\nپلن: {form['server_type']}\n"
            f"ایمیج: {state['image']}\nورود: {state['ssh_label']}\n"
            f"قیمت پلن با مالیات: €{hourly}/ساعت، €{monthly}/ماه\n"
            "IPv4 عمومی فعال است و جداگانه طبق تعرفهٔ هتزنر حساب می‌شود.",
            reply_markup=hetzner_keyboard(state, [[("تأیید ساخت و هزینه", "confirm")]]),
        )
    else:
        await message.reply_text("از دکمه‌های همین مرحله استفاده کن یا /cancel را بزن.")


PASSWORD_PROMPT = re.compile(
    rb"(?:^|[\r\n])[ \t]*(?:(?:\(current\)|current|old)[ \t]+(?:unix[ \t]+)?password|"
    rb"new(?:[ \t]+unix)?[ \t]+password|(?:retype|repeat|confirm)[ \t]+(?:new[ \t]+)?"
    rb"(?:unix[ \t]+)?password(?:[ \t]+again)?):[ \t]*$",
    re.IGNORECASE,
)


def change_root_password(host, current, replacement):
    """Return whether SSH verified the change and whether the new password was submitted twice."""
    phase = "current"
    submitted = False
    try:
        with connect(host, 22, "root", current) as client:
            with client.get_transport().open_session(timeout=10) as channel:
                channel.settimeout(10)
                channel.get_pty(term="dumb")
                channel.set_combine_stderr(True)
                channel.exec_command("LC_ALL=C passwd")
                deadline = time.monotonic() + 30
                pending = b""
                while time.monotonic() < deadline:
                    if not channel.recv_ready():
                        if channel.exit_status_ready():
                            break
                        time.sleep(0.05)
                        continue
                    received = channel.recv(4096)
                    if not received:
                        break
                    pending = (pending + received)[-4096:]
                    match = PASSWORD_PROMPT.search(pending)
                    if not match:
                        continue
                    prompt = match.group().strip().lower()
                    pending = b""
                    if phase == "current" and prompt.startswith((b"current", b"(current)", b"old")):
                        channel.sendall(current.encode() + b"\n")
                        phase = "new"
                    elif phase in {"current", "new"} and prompt.startswith(b"new"):
                        channel.sendall(replacement.encode() + b"\n")
                        phase = "repeat"
                    elif phase == "repeat" and prompt.startswith((b"retype", b"repeat", b"confirm")):
                        submitted = True
                        phase = "done"
                        channel.sendall(replacement.encode() + b"\n")
    except (OSError, EOFError, paramiko.SSHException):
        pass

    if submitted:
        try:
            # Expired accounts cannot execute a command without a PTY.
            with connect(host, 22, "root", replacement) as client:
                status, _ = run(client, "true", timeout=10)
                return status == 0, True
        except (OSError, EOFError, paramiko.SSHException):
            pass
    return False, submitted


async def hetzner_change_password(update, context, state, current):
    message = update.message
    await delete_secret_message(message)
    if not current or any(char in current for char in "\r\n\x00"):
        await message.reply_text("رمز فعلی root را در یک خط بفرست.")
        return
    instance = state["instance"]
    state["step"] = "password_running"
    try:
        token = hetzner_token(update.effective_user.id)
        if not token:
            raise hetzner.APIError()
        server = await hetzner.server_details(token, instance)
    except (hetzner.APIError, InvalidToken):
        state["step"] = "password"
        await message.reply_text("دریافت اطلاعات سرور ناموفق بود.")
        return
    public = server.get("public_net") or {}
    hosts = []
    for version in ("ipv4", "ipv6"):
        value = (public.get(version) or {}).get("ip")
        if value:
            try:
                hosts.append(str(ip_address(value)))
            except ValueError:
                continue
    if not hosts:
        clear(context)
        await message.reply_text("سرور هنوز IP عمومی ندارد. پس از آماده‌شدن دوباره تلاش کن.")
        return

    replacement = "Aa9!" + secrets.token_urlsafe(21)
    await message.reply_text("در حال تغییر و بررسی رمز root از طریق SSH…")
    verified, submitted = await asyncio.to_thread(change_root_password, hosts[0], current, replacement)
    if not submitted:
        state["step"] = "password"
        await message.reply_text(
            "تغییر رمز انجام نشد. آماده‌بودن VPS، باز بودن پورت ۲۲ و درستی رمز فعلی را بررسی کن و دوباره بفرست."
        )
        return
    clear(context)
    title = (
        "رمز جدید root تنظیم شد و ورود با آن تأیید شد."
        if verified else "رمز زیر به سرور ارسال شد، اما ورود با آن تأیید نشد. پیش از تکرار، این رمز را امتحان کن."
    )
    await message.reply_text(
        f"{title}\n\n{replacement}",
        protect_content=True,
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("کپی رمز", copy_text=CopyTextButton(replacement))],
            [InlineKeyboardButton("سرورهای موجود", callback_data="he:servers")],
        ]),
    )


async def handle_text(update, context):
    if not private_admin(update):
        return
    state = context.user_data
    message = update.message
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
    application.add_handler(CallbackQueryHandler(select, pattern=r"^(ssh|node|on|off|update)$"))
    application.add_handler(CallbackQueryHandler(
        hetzner_button,
        pattern=r"^(?:hetzner|he:(?:key|new|servers)|hp:[a-f0-9]{16}:(?:(?:pick|page):[0-9]{1,8}|poweron|shutdown|reboot|refresh|list|delete|password|confirm))$",
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
        pattern=r"^kms:[a-f0-9]{16}:(?:(?:page|detail):[0-9]+|power:(?:on|off|restart)|(?:confirm|status):0)$",
    ))
    application.add_handler(CallbackQueryHandler(my_servers, pattern=r"^my_servers$"))
    application.add_handler(CallbackQueryHandler(server_button, pattern=r"^s:[0-9a-f]{12}:(pick|page|new|connect|delete):[0-9]+$"))
    application.add_handler(CallbackQueryHandler(add_admin, pattern=r"^add_admin$"))
    application.add_handler(MessageHandler(filters.StatusUpdate.USERS_SHARED, shared_admin))
    application.add_handler(MessageHandler(filters.TEXT, handle_text))
    application.add_error_handler(report_error)
    application.run_polling(drop_pending_updates=True, allowed_updates=["message", "callback_query"])
