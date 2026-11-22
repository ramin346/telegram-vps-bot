# ربات تلگرام مدیریت VPS

با `/start` منوی دکمه‌های شیشه‌ای باز می‌شود. دسترسی به گفت‌وگوی خصوصی و شناسه‌های عددی ادمین محدود است.

- **SSH** یک اتصال باز می‌کند و هر پیام را به‌عنوان یک دستور مستقل، بدون ترمینال تعاملی، اجرا می‌کند. برای بستن اتصال از `/cancel` استفاده کن. اتصال بعد از ۱۰ دقیقه منقضی می‌شود.
- **نصب نود پاسارگارد** نصب‌کنندهٔ رسمی را با `install -y` و پیش‌فرض‌های آن اجرا می‌کند. پس از موفقیت، کلید API و گواهی عمومی PEM را جداگانه به‌شکل متن کپی‌شونده می‌فرستد. اگر مسیر نصب یا دادهٔ قبلی وجود داشته باشد، عملیات را متوقف می‌کند.
- **UFW** در حالت روشن‌کردن ابتدا دسترسی TCP به پورت SSH همین اتصال را مجاز می‌کند. هر دو دکمه وضعیت نهایی UFW را نشان می‌دهند.
- **`/update`** از شاخهٔ پیگیری‌شده در `origin` نسخه می‌گیرد، فقط fast-forward را می‌پذیرد و پس از تغییر کد به systemd اجازه می‌دهد فرایند را دوباره اجرا کند.

## راه‌اندازی روی Debian یا Ubuntu

روی میزبان ربات Python 3.10 یا جدیدتر، Git و systemd لازم است. اگر مخزن را خصوصی کردی، برای حساب سرویس یک کلید deploy فقط‌خواندنی در GitHub تنظیم کن و در دستور clone از آدرس SSH مخزن استفاده کن. کلید میزبان GitHub باید در `known_hosts` حساب سرویس تأیید شده باشد. این کلید با کلید اتصال به VPSها جداست.

```bash
sudo apt update
sudo apt install -y git python3 python3-venv
sudo useradd --system --create-home --home-dir /var/lib/telegram-vps --shell /usr/sbin/nologin telegram-vps
sudo install -d -o telegram-vps -g telegram-vps /opt/telegram-vps-bot
sudo -u telegram-vps -H git clone https://github.com/ramin346/telegram-vps-bot.git /opt/telegram-vps-bot
sudo -u telegram-vps -H python3 -m venv /opt/telegram-vps-bot/.venv
sudo install -m 600 /dev/null /etc/telegram-vps-bot.env
sudoedit /etc/telegram-vps-bot.env
```

در فایل تنظیمات توکن BotFather و شناسهٔ عددی تلگرام خودت را بگذار. برای چند ادمین شناسه‌ها را با کاما جدا کن. خط `SSH_KEY_PATH` اختیاری است. اگر آن را می‌گذاری، کلید خصوصی مخصوص VPS باید برای کاربر سرویس خواندنی باشد و کلید عمومی آن روی سرورهای مقصد ثبت شده باشد.

```ini
TELEGRAM_BOT_TOKEN=botfather-token
TELEGRAM_ADMIN_IDS=123456789
ENABLE_UPDATE=1
SSH_KEY_PATH=/var/lib/telegram-vps/.ssh/id_vps
```

```bash
sudo install -m 644 /opt/telegram-vps-bot/telegram-vps-bot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now telegram-vps-bot
sudo journalctl -u telegram-vps-bot -n 30
```

## اتصال به VPS

بعد از انتخاب دکمه، ربات به‌ترتیب **آی‌پی یا آدرس سرور**، **نام کاربری** و **رمز SSH** را در سه پیام جداگانه می‌پرسد. پورت پیش‌فرض ۲۲ است. برای پورت سفارشی از `vps.example.com:2222` یا `[IPv6]:2222` استفاده کن. اگر کلید ورود SSH را تنظیم کرده‌ای، در مرحلهٔ رمز می‌توانی یک نقطه بفرستی.

ربات کلیدهای ثبت‌شده در `~/.ssh/known_hosts` کاربر سرویس را بررسی می‌کند. برای سرور جدید، کلید اعلام‌شده از طرف سرور را در اولین اتصال موفق، بدون سؤال، در `~/.ssh/telegram-vps-known-hosts` ثبت می‌کند. اگر کلید ثبت‌شده تغییر کند، اتصال رد می‌شود. برای بررسی هویت سرور از همان اتصال اول، کلید تأییدشدهٔ آن را از قبل در `known_hosts` قرار بده.

ربات تلاش می‌کند پیام رمز را حذف کند. چت ربات تلگرام رمزنگاری سرتاسری ندارد و کلید API در تاریخچهٔ چت می‌ماند. نصب و عملیات UFW نیاز به دسترسی root یا sudo بدون سؤال رمز دارند. نصب‌کننده روی مقصد به Bash، curl، flock و دسترسی اینترنت نیاز دارد.

توکن ربات و دسترسی حساب ادمین را مثل دسترسی مدیریت سرورها محافظت کن. هر ادمین مجاز می‌تواند از اعتبار SSH راه‌اندازی‌شده روی میزبان ربات استفاده کند.
