"""Install a fresh PasarGuard panel and bootstrap its owner over verified TLS."""

import json
from ipaddress import ip_address
import re
import secrets
import shlex
import socket
import string
from urllib.parse import urlencode

# The installer is pinned because its interactive log-following step is removed below.
SCRIPT = "https://raw.githubusercontent.com/PasarGuard/scripts/95845c7638dd02f59cbc88443424cf56f428c071/pasarguard.sh"
INSTALL = r"""
set -eu
umask 077
export APP_NAME=pasarguard APP_DIR=/opt/pasarguard DATA_DIR=/var/lib/pasarguard
export ACCOUNT_EMAIL="$1" DEBIAN_FRONTEND=noninteractive TERM=dumb
domain="$2"
exec 9>/run/lock/telegram-pasarguard-install.lock
flock -n 9 || exit 76
if [ -e "$APP_DIR" ] || [ -L "$APP_DIR" ] || [ -e "$DATA_DIR" ] || [ -L "$DATA_DIR" ]; then
    exit 73
fi
command -v ss >/dev/null
listeners=$(ss -H -ltn '( sport = :80 or sport = :8000 )')
[ -z "$listeners" ] || exit 74
script=$(mktemp)
trap 'rm -f -- "$script"' EXIT
curl -fsSL --connect-timeout 15 --max-time 90 "$3" -o "$script"
test -s "$script"
# Keep the official install procedure, skipping only its final indefinite log stream.
sed -i '/^install_command() {/,/^}/s/^    follow_pasarguard_logs$/    : # non-interactive install/' "$script"
grep -Fq ': # non-interactive install' "$script"
sed -i '/^install_command() {/,/^}/s/^    read .* install_node_choice$/    install_node_choice=n/' "$script"
grep -Fq '    install_node_choice=n' "$script"
bash "$script" install --ssl-domain "$domain" </dev/null
test -s "$DATA_DIR/certs/$domain/fullchain.pem" && test -s "$DATA_DIR/certs/$domain/privkey.pem" || exit 75
"""

TEMP_KEY = r"""
set -eu
if docker compose version >/dev/null 2>&1; then
    set -- docker compose
else
    set -- docker-compose
fi
"$@" -f /opt/pasarguard/docker-compose.yml -p pasarguard exec -T pasarguard pasarguard-cli generate-temp-key
"""


class InstallError(Exception):
    pass


def make_password():
    # The panel requires two digits, two letters of each case, and a symbol.
    random = secrets.SystemRandom()
    chars = [secrets.choice(group) for group in (
        string.ascii_uppercase, string.ascii_uppercase,
        string.ascii_lowercase, string.ascii_lowercase, string.digits, string.digits,
    )]
    chars += [secrets.choice(string.ascii_letters + string.digits) for _ in range(21)]
    chars.append("!")
    random.shuffle(chars)
    return "".join(chars)


def install(run, client, sudo, domain, email):
    try:
        peer = ip_address(client.get_transport().sock.getpeername()[0])
        addresses = {ip_address(item[4][0]) for item in socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)}
    except OSError:
        raise InstallError("DNS ساب‌دامنهٔ پنل قابل بررسی نبود.") from None
    if peer not in addresses:
        raise InstallError("DNS ساب‌دامنه به IP سرور انتخابی اشاره نمی‌کند. رکورد DNS را بررسی کن.")
    code, _ = run(client, sudo + shlex.join(["bash", "-c", INSTALL, "install", email, domain, SCRIPT]), timeout=900)
    failures = {
        73: "فایل یا دادهٔ پنل قبلی پیدا شد. نصب روی آن انجام نشد.",
        74: "پورت ۸۰ یا ۸۰۰۰ اشغال است. نصب شروع نشد.",
        75: "گواهی SSL صادر یا نصب نشد. DNS و دسترسی ورودی پورت ۸۰ را بررسی کن.",
        76: "یک نصب دیگر روی این سرور در حال اجراست.",
    }
    if code:
        raise InstallError(failures.get(code, f"نصب پنل با کد {code} متوقف شد. وضعیت نصب را در سرور بررسی کن."))

    base = f"https://{domain}:8000"
    curl = ["curl", "--silent", "--show-error", "--fail", "--noproxy", "*", "--max-time", "8",
            "--resolve", f"{domain}:8000:127.0.0.1"]
    health = [*curl, "--retry", "15", "--retry-connrefused", "--retry-delay", "3",
              "--retry-max-time", "65", "--output", "/dev/null", base + "/dashboard/"]
    code, _ = run(client, shlex.join(health), timeout=80)
    if code:
        raise InstallError("پنل نصب شد، اما داشبورد با گواهی معتبر HTTPS پاسخ نداد.")

    code, output = run(client, sudo + shlex.join(["bash", "-c", TEMP_KEY]))
    key = re.search(r"Temp key:\s*([0-9a-f-]{36})\b", output, flags=re.I) if not code else None
    if not key:
        raise InstallError("پنل آماده است، اما ساخت کلید یک‌بارمصرف حساب مدیر ناموفق بود.")

    username = "admin"
    password = make_password()
    setup = [*curl, "--output", "/dev/null", "--write-out", "%{http_code}",
             "--header", "Content-Type: application/json",
             "--data-binary", "@-", base + "/api/setup/owner"]
    body = json.dumps({"key": key[1], "username": username, "password": password}).encode()
    code, output = run(client, shlex.join(setup), input_data=body)
    if code or output.strip() != "201":
        # A lost response can follow a successful write. Try login with the generated credentials.
        login = [*curl, "--output", "/dev/null", "--write-out", "%{http_code}",
                 "--data-binary", "@-", base + "/api/admin/token"]
        form = urlencode({"username": username, "password": password}).encode()
        code, output = run(client, shlex.join(login), input_data=form)
        if code or output.strip() != "200":
            raise InstallError("پنل آماده است، اما ساخت حساب مدیر تأیید نشد. آدرس پنل: " + base + "/dashboard/")
    return base + "/dashboard/", username, password
