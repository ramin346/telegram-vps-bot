import asyncio
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

import paramiko
from telegram import (
    CopyTextButton, InlineKeyboardButton, InlineKeyboardMarkup, KeyboardButton,
    KeyboardButtonRequestUsers, ReplyKeyboardMarkup, ReplyKeyboardRemove,
)
from telegram.error import TelegramError
from telegram.ext import (
    Application, CallbackQueryHandler, CommandHandler, MessageHandler, filters,
)

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
    if owner:
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
    await query.message.reply_text(
        "آی‌پی یا آدرس سرور را بفرست. "
        "برای پورت سفارشی از host:port یا [IPv6]:port استفاده کن.",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("بازگشت", callback_data="cancel")]]),
    )


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
    prompt = "رمز SSH را بفرست. ربات تلاش می‌کند پیام رمز را پس از دریافت حذف کند."
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


async def handle_text(update, context):
    if not private_admin(update):
        return
    state = context.user_data
    message = update.message
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
    if "action" not in state:
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
        try:
            client = await asyncio.to_thread(
                connect, *state["address"], state["username"], password,
            )
        except paramiko.BadHostKeyException:
            await message.reply_text("کلید SSH این سرور تغییر کرده است. کلید جدید را روی میزبان ربات بررسی کن.")
            return
        except (OSError, paramiko.SSHException, ValueError):
            await message.reply_text("اتصال برقرار نشد. دسترسی و اطلاعات ورود را بررسی کن. برای تغییر سرور /cancel را بزن.")
            return
        if state["action"] == "ssh":
            state["client"] = client
            state["expires"] = time.monotonic() + 600
            state["expiry_job"] = context.application.job_queue.run_once(
                expire, 600, data=client, user_id=update.effective_user.id,
            )
            await message.reply_text("متصل شدی. هر پیام یک دستور جداگانه است. برای بستن اتصال /cancel را بزن.")
            return
        try:
            await operate(message, state, client)
        except (OSError, paramiko.SSHException):
            await message.reply_text("ارتباط قطع شد یا مهلت عملیات تمام شد.")
        finally:
            client.close()
            clear(context)
        await message.reply_text("عملیات بعدی را انتخاب کن.", reply_markup=menu(private_owner(update)))
        return
    try:
        await operate(message, state, state["client"], message.text)
    except (OSError, paramiko.SSHException):
        await cancel(update, context)


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
    application = Application.builder().token(os.environ["TELEGRAM_BOT_TOKEN"]).build()
    application.add_handler(CommandHandler(["start", "menu"], start))
    application.add_handler(CommandHandler("cancel", cancel))
    application.add_handler(CommandHandler("update", update_command))
    application.add_handler(CallbackQueryHandler(cancel, pattern=r"^cancel$"))
    application.add_handler(CallbackQueryHandler(select, pattern=r"^(ssh|node|on|off|update)$"))
    application.add_handler(CallbackQueryHandler(add_admin, pattern=r"^add_admin$"))
    application.add_handler(MessageHandler(filters.StatusUpdate.USERS_SHARED, shared_admin))
    application.add_handler(MessageHandler(filters.TEXT, handle_text))
    application.add_error_handler(report_error)
    application.run_polling(drop_pending_updates=True, allowed_updates=["message", "callback_query"])
