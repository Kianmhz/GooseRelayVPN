# GooseRelayVPN

[![GitHub](https://img.shields.io/badge/GitHub-GooseRelayVPN-blue?logo=github)](https://github.com/kianmhz/GooseRelayVPN)

**[English README](README.md)**

یک VPN مبتنی بر SOCKS5 که **ترافیک خام TCP** را از طریق یک وب اپ Google Apps Script به سرور خروجی VPS کوچک خودتان تونل می‌کند. هر چیزی که در مسیر شبکه قرار دارد فقط TLS به یک IP گوگل با یکی از SNIهای گوگل که در کانفیگ تنظیم کرده‌اید می‌بیند. همه چیز در مسیر به‌صورت سرتاسری با AES-256-GCM رمز می‌شود — گوگل هرگز متن خام را نمی‌بیند و کلید را نگه نمی‌دارد.

> **توضیح ساده:** مرورگر/اپ شما از طریق SOCKS5 به این ابزار روی کامپیوترتان وصل می‌شود. ابزار هر بایت TCP را در فریم‌های AES-GCM می‌پیچد و از طریق یک ارتباط HTTPS رو‌به‌گوگل به وب اپ Apps Script شما می‌فرستد. Apps Script آن بایت‌ها را بدون تغییر به VPS شما فوروارد می‌کند، VPS رمزگشایی کرده و اتصال واقعی را باز می‌کند. برای فایروال/فیلتر انگار فقط دارید با گوگل حرف می‌زنید.

> ⚠️ **برای سرور خروجی به یک VPS کوچک نیاز دارید.** برخلاف پراکسی‌های صرفاً Apps Script، این پروژه TCP خام را تونل می‌کند — هر چیزی که SOCKS5 حمل می‌کند — پس یک `net.Dial` واقعی باید جایی انجام شود. یک VPS ارزان حدود ۴ دلار در ماه کافی است. در عوض می‌توانید SSH، IMAP و هر پروتکل دلخواه را تونل کنید — نه فقط HTTP.

## حمایت از پروژه

اگر این پروژه را دوست دارید، لطفاً با ستاره دادن در GitHub (⭐) از آن حمایت کنید. این کار باعث دیده شدن پروژه می‌شود.

اگر تمایل دارید، می‌توانید به صورت مالی هم حمایت کنید:

- TRX / USDT TRC20:
  `TSxg2WAXYnkoR2UiUTzCxbmqNARAt91aqB`
- BNB / USDT BEP20:
  `0xe7b48d8fd5fbbb4e3fa9a06723a62a88585139ea`
- TON:
  `UQDBzJqzJ5e7uZFPrmarTRSGGbD1UoFK2q5_jWh4D2nnNdUB`

## نکات مهم

- هرگز `tunnel_key` را با کسی به اشتراک نگذارید. هر کسی این کلید را داشته باشد می‌تواند مثل شما از تونل/VPS استفاده کند.
- داشتن یک سرور با دسترسی اینترنت عمومی الزامی است. سرور خروجی باید از سمت Google Apps Script قابل دسترسی باشد.
- گوگل سهمیه URL Fetch در Apps Script را به‌صورت per-user/account مستند کرده است. برای اکانت‌های مصرفی حدود ۲۰٬۰۰۰ فراخوانی در روز است و پنجره سهمیه ۲۴ ساعت بعد از اولین درخواست ریست می‌شود. deploymentهای زیر یک اکانت را یک quota pool مشترک فرض کنید.
- در این پروژه نیازی به نصب گواهی MITM محلی ندارید. تنظیمات گواهی در `MasterHttpRelayVPN` مخصوص معماری همان پروژه است و اینجا لازم نیست.
- این پروژه از ایده مخزن اصلی الهام گرفته است: https://github.com/masterking32/MasterHttpRelayVPN

---

## سلب مسئولیت

GooseRelayVPN فقط برای اهداف آموزشی، تست و پژوهش ارائه شده است.

- **بدون ضمانت:** این نرم‌افزار به‌صورت "همان‌گونه که هست" ارائه می‌شود و هیچ ضمانت صریح یا ضمنی، از جمله قابلیت فروش، مناسب بودن برای هدف خاص یا عدم نقض حقوق دیگران، برای آن وجود ندارد.
- **محدودیت مسئولیت:** توسعه‌دهندگان و مشارکت‌کنندگان مسئول هیچ خسارت مستقیم، غیرمستقیم، اتفاقی، تبعی یا هر نوع خسارت ناشی از استفاده از این پروژه نیستند.
- **مسئولیت کاربر:** اجرای این پروژه خارج از محیط‌های کنترل‌شده ممکن است بر شبکه‌ها، حساب‌ها یا سیستم‌های متصل اثر بگذارد. تمام مسئولیت نصب، پیکربندی و استفاده بر عهده کاربر است.
- **رعایت قوانین:** پیش از استفاده، رعایت تمام قوانین محلی، کشوری و بین‌المللی بر عهده کاربر است.
- **رعایت قوانین گوگل:** اگر از Google Apps Script در این پروژه استفاده می‌کنید، رعایت Terms of Service گوگل، قوانین استفاده مجاز، سهمیه‌ها و سیاست‌های پلتفرم بر عهده شماست. سوءاستفاده ممکن است باعث تعلیق حساب گوگل یا deployment شما شود.
- **شرایط مجوز:** استفاده، کپی، توزیع و تغییر فقط تحت شرایط مجوز مخزن مجاز است. هر استفاده خارج از آن شرایط ممنوع است.

---

## نحوه کار

```
Browser/App
  -> SOCKS5  (127.0.0.1:1080)
  -> Zstd-compressed + AES-256-GCM frame batches
  -> HTTPS to a Google edge IP   (configured Google SNI, Host=script.google.com)
  -> Apps Script doPost()        (dumb forwarder, never sees plaintext)
  -> Your VPS :8443/tunnel       (decrypts, demuxes by session_id, dials target)
  <- Same path in reverse via long-polling
```

اپلیکیشن شما بایت‌های TCP را از طریق شنونده SOCKS5 روی کامپیوترتان به این ابزار می‌فرستد. کلاینت هر تکه را با AES-256-GCM رمز می‌کند و batchها را روی یک ارتباط HTTPS با domain fronting برای وب اپ Apps Script شما POST می‌کند. Apps Script یک اسکریپت ~۳۰ خطی است که بدنه را بدون تغییر به VPS شما فوروارد می‌کند — هرگز رمزگشایی نمی‌کند و کلید AES هرگز به گوگل نمی‌رسد. VPS رمزگشایی می‌کند، مقصد واقعی را دایل می‌کند و بایت‌ها را در همان مسیر برمی‌گرداند. فیلتر فقط TLS به گوگل می‌بیند.

---

## راهنمای راه‌اندازی مرحله‌به‌مرحله

### مرحله ۱: گرفتن یک VPS

به یک VPS لینوکسی با IP عمومی نیاز دارید. هر ارائه‌دهنده‌ای کار می‌کند.

### مرحله ۲: دریافت باینری‌ها

شما به دو برنامه جداگانه نیاز دارید:
- **`goose-client`** — روی **کامپیوتر خودتان** اجرا می‌شود. این همان چیزی است که هر روز اجرا می‌کنید.
- **`goose-server`** — روی **VPS** اجرا می‌شود. یک‌بار راه‌اندازی می‌کنید و همان‌جا می‌ماند.

**گزینه A — دانلود نسخه آماده (پیشنهادی):**

1. به [صفحه Releases](https://github.com/kianmhz/GooseRelayVPN/releases) بروید.
2. آرشیو مناسب سیستم‌عامل خود را دانلود کنید:
   - Windows x86_64: `GooseRelayVPN-client-vX.Y.Z-windows-amd64.zip`
   - Windows ARM64: `GooseRelayVPN-client-vX.Y.Z-windows-arm64.zip`
   - macOS (Intel): `GooseRelayVPN-client-vX.Y.Z-darwin-amd64.tar.gz`
   - macOS (M1/M2/M3): `GooseRelayVPN-client-vX.Y.Z-darwin-arm64.tar.gz`
   - Linux x86_64: `GooseRelayVPN-client-vX.Y.Z-linux-amd64.tar.gz`
   - Linux ARM64: `GooseRelayVPN-client-vX.Y.Z-linux-arm64.tar.gz`
   - Linux ARMv7: `GooseRelayVPN-client-vX.Y.Z-linux-armv7.tar.gz`
   - Android / Termux (arm64): `GooseRelayVPN-client-vX.Y.Z-android-arm64.tar.gz`
3. برای **سرور**، باینری مناسب سیستم‌عامل VPS خود را دانلود کنید:
   - **لینوکس x86_64 / amd64 (رایج‌ترین):**
     ```bash
     VERSION=vX.Y.Z
     wget https://github.com/kianmhz/GooseRelayVPN/releases/download/$VERSION/GooseRelayVPN-server-$VERSION-linux-amd64.tar.gz
     tar -xzf GooseRelayVPN-server-$VERSION-linux-amd64.tar.gz
     ```
     اگر VPS شما ARM است، به‌جای آن از `linux-arm64` یا `linux-armv7` استفاده کنید.
   - **ویندوز سرور:** فایل `GooseRelayVPN-server-vX.Y.Z-windows-amd64.zip` را از صفحه Releases دانلود کنید و آن را در پوشه‌ای مثل `C:\goose-relay\` اکسترکت کنید. برای راه‌اندازی سرویس، مرحله ۸ (ویندوز) را ببینید.

   (عدد `vX.Y.Z` را با آخرین نسخه در صفحه Releases جایگزین کنید.)

> 💡 **اگر صفحه Releases باز نمی‌شود**، می‌توانید مستقیماً با لینک‌های زیر دانلود کنید (`vX.Y.Z` را با آخرین نسخه جایگزین کنید):
> - **کلاینت — ویندوز:** `https://github.com/Kianmhz/GooseRelayVPN/releases/download/vX.Y.Z/GooseRelayVPN-client-vX.Y.Z-windows-amd64.zip`
> - **کلاینت — macOS (Apple Silicon):** `https://github.com/Kianmhz/GooseRelayVPN/releases/download/vX.Y.Z/GooseRelayVPN-client-vX.Y.Z-darwin-arm64.tar.gz`
> - **کلاینت — macOS (Intel):** `https://github.com/Kianmhz/GooseRelayVPN/releases/download/vX.Y.Z/GooseRelayVPN-client-vX.Y.Z-darwin-amd64.tar.gz`
> - **کلاینت — لینوکس x86_64:** `https://github.com/Kianmhz/GooseRelayVPN/releases/download/vX.Y.Z/GooseRelayVPN-client-vX.Y.Z-linux-amd64.tar.gz`
> - **کلاینت — لینوکس ARM64:** `https://github.com/Kianmhz/GooseRelayVPN/releases/download/vX.Y.Z/GooseRelayVPN-client-vX.Y.Z-linux-arm64.tar.gz`
> - **کلاینت — اندروید/Termux:** `https://github.com/Kianmhz/GooseRelayVPN/releases/download/vX.Y.Z/GooseRelayVPN-client-vX.Y.Z-android-arm64.tar.gz`
> - **سرور — لینوکس:** `https://github.com/Kianmhz/GooseRelayVPN/releases/download/vX.Y.Z/GooseRelayVPN-server-vX.Y.Z-linux-amd64.tar.gz`

**گزینه B — ساخت از سورس (Go 1.25+؛ Go 1.26.3 توصیه می‌شود) — توصیه نمی‌شود، ممکن است ناپایدار باشد:**

```bash
git clone https://github.com/kianmhz/GooseRelayVPN.git
cd GooseRelayVPN
go build -o goose-client ./cmd/client
go build -o goose-server ./cmd/server
```

**گزینه C — اجرای فقط سرور با Docker (GHCR):**

اگر روی VPS استفاده از کانتینر را ترجیح می‌دهید، می‌توانید `goose-server` را مستقیم از GHCR اجرا کنید:

```bash
docker pull ghcr.io/kianmhz/gooserelayvpn-server:latest
```

### مرحله ۳: ساخت یک کلید مخفی

این دستور را یک‌بار اجرا کنید:

```bash
openssl rand -hex 32
```

رشته ۶۴ کاراکتری خروجی را کپی کنید. **همان مقدار** را هم در کانفیگ کلاینت و هم سرور می‌گذارید. محرمانه نگه دارید — هر کسی این کلید را داشته باشد می‌تواند از تونل شما استفاده کند.

### مرحله ۴: پیکربندی

فایل‌های نمونه را کپی کنید:

```bash
cp client_config.example.json client_config.json
cp server_config.example.json server_config.json
```

هر دو فایل را باز کنید و کلید را در فیلد `tunnel_key` بگذارید. فعلاً `script_keys` را خالی بگذارید.

`client_config.json`:

```json
{
  "socks_host":  "127.0.0.1",
  "socks_port":  1080,
  "google_host": "216.239.38.120",
  "sni":         ["www.google.com", "mail.google.com", "accounts.google.com"],
  "script_keys": [],
  "tunnel_key":  "PASTE_OUTPUT_OF_GEN_KEY"
}
```

`server_config.json`:

```json
{
  "server_host": "0.0.0.0",
  "server_port": 8443,
  "tunnel_key":  "SAME_VALUE_AS_CLIENT"
}
```

### مرحله ۵: راه‌اندازی Google Apps Script

این بخش رایگانِ سمت گوگل است که ترافیک شما را پنهان می‌کند.

1. وارد [Google Apps Script](https://script.google.com/) شوید و لاگین کنید.
2. روی **New project** کلیک کنید.
3. کد پیش‌فرض را حذف کنید و همه محتوای [`apps_script/Code.gs`](apps_script/Code.gs) را جایگزین کنید.
4. این خط را با IP VPS خودتان جایگزین کنید:
   ```javascript
   const RELAY_URLS = ['http://YOUR.VPS.IP:8443/tunnel'];
   ```
5. روی **Deploy → New deployment** کلیک کنید و نوع را **Web app** بگذارید.
6. **Execute as:** Me و **Who has access:** Anyone را انتخاب کنید.
7. روی **Deploy** بزنید. یک پنجره باز می‌شود که **Deployment ID** را نشان می‌دهد. آن را کپی و در `script_keys` قرار دهید.
8. آن Deployment ID را در `script_keys` داخل `client_config.json` هم وارد کنید.

> ⚠️ هر بار که `Code.gs` را ویرایش می‌کنید، صرفاً ذخیره کردن کد کافی نیست. یا یک deployment جدید بسازید و `script_keys` را به‌روزرسانی کنید، یا یک نسخه جدید بسازید و همان deployment وب‌اپ موجود را به آن نسخه وصل کنید تا Deployment ID قبلی حفظ شود.

نسخهٔ جدید `Code.gs` در `doGet` متادیتای نسخه/پروتکل را هم برمی‌گرداند تا بررسی pre-flight بتواند ناسازگاری نسخه را تشخیص دهد. اگر deployment قدیمی باشد، باید یک‌بار دوباره deploy کنید تا هشدار ناسازگاری نگیرید.

### مرحله ۶: باز کردن پورت 8443 روی فایروال VPS

سرور باید از اینترنت روی پورت 8443 قابل دسترسی باشد. روی VPS اجرا کنید:

```bash
sudo ufw allow 8443/tcp
```

سپس از کامپیوتر خودتان تست کنید (IP واقعی VPS را جایگزین کنید):

```bash
curl http://YOUR.VPS.IP:8443/healthz
```

باید یک JSON مثل `{ "ok": true, "version": "vX.Y.Z", "protocol": 1 }` با HTTP 200 بگیرید. اگر `curl` تایم‌اوت شد یا خطا داد، **فایروال ارائه‌دهنده ابری** را هم بررسی کنید (در AWS/Hetzner به نام "Security Groups"، در DigitalOcean/Vultr به نام "Firewall Rules") و یک قانون ورودی برای TCP پورت 8443 اضافه کنید.

### مرحله ۷: اجرای سرور روی VPS

روی VPS این دستور را اجرا کنید:

**لینوکس:**
```bash
./goose-server -config server_config.json
```

**ویندوز سرور:**
```cmd
.\goose-server.exe -config server_config.json
```

باید آدرس listening و آدرس‌های healthz/tunnel را ببینید. این ترمینال را باز بگذارید، یا مرحله ۸ را انجام دهید تا بعد از ریبوت هم بالا بماند.

**Docker (ایمیج GHCR):**

> ⚠️ **مهم:** کانتینر فایل `server_config.json` را به‌صورت خودکار نمی‌سازد. باید قبل از اجرا، `server_config.json` را خودتان بسازید و با `tunnel_key` خودتان پر کنید.

```bash
docker run -d \
  --name goose-server \
  --restart unless-stopped \
  -p 8443:8443 \
  -v $(pwd)/server_config.json:/app/server_config.json:ro \
  ghcr.io/kianmhz/gooserelayvpn-server:latest
```

**Docker Compose (پیشنهادی برای راه‌اندازی کانتینری):**

```bash
cp server_config.example.json server_config.json
nano server_config.json
docker compose up -d
```

فایل [`docker-compose.yml`](docker-compose.yml) داخل مخزن آماده است. به‌صورت پیش‌فرض از `ghcr.io/kianmhz/gooserelayvpn-server:latest` استفاده می‌کند و برای پین کردن نسخه می‌توانید override کنید:

```bash
GOOSE_SERVER_IMAGE=ghcr.io/kianmhz/gooserelayvpn-server:vX.Y.Z docker compose up -d
```

تست از روی کامپیوتر خودتان:

```bash
curl http://YOUR.VPS.IP:8443/healthz
```

### مرحله ۸: اجرای خودکار سرور بعد از ریبوت (systemd)

اگر می‌خواهید سرور بعد از ریبوت VPS خودکار بالا بیاید، یک سرویس systemd بسازید.

روی VPS اجرا کنید:

```bash
sudo nano /etc/systemd/system/goose-relay.service
```

این را قرار دهید (اگر مسیر باینری شما فرق دارد، اصلاح کنید):

```ini
[Unit]
Description=GooseRelayVPN exit server
After=network.target

[Service]
Type=simple
WorkingDirectory=/root
ExecStart=/root/goose-server -config /root/server_config.json
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal
LimitNOFILE=1048576
OOMScoreAdjust=-500
Nice=-10
Environment="GOGC=200"
Environment="GOMEMLIMIT=400MiB"

[Install]
WantedBy=multi-user.target
```

بعد اجرا کنید:

```bash
sudo systemctl daemon-reload
sudo systemctl enable goose-relay
sudo systemctl start goose-relay
sudo systemctl status goose-relay --no-pager
```

### مرحله ۸ (ویندوز): اجرای خودکار سرور بعد از ریبوت (NSSM)

اگر VPS شما **ویندوز سرور** دارد، به جای systemd از [NSSM](https://nssm.cc) (Non-Sucking Service Manager) استفاده کنید تا `goose-server` را به عنوان یک سرویس ویندوز ثبت کنید. فایل `goose-server.exe` یک باینری ساده Go است و نیازی به نصب ندارد.

**۱. باز کردن پورت ۸۴۴۳ در فایروال ویندوز** (با دسترسی Administrator در Command Prompt):
```cmd
netsh advfirewall firewall add rule name="GooseRelayVPN" protocol=TCP dir=in localport=8443 action=allow
```
همچنین یک قانون ورودی TCP/8443 در پنل فایروال ارائه‌دهنده ابری خود اضافه کنید (Security Groups / Firewall Rules).

**۲. دانلود NSSM** از آدرس https://nssm.cc/download، آن را اکسترکت کنید و مسیر `nssm.exe` را یادداشت کنید (مثلاً `C:\nssm\win64\nssm.exe`).

**۳. ثبت و شروع سرویس** (با دسترسی Administrator):
```cmd
C:\nssm\win64\nssm.exe install GooseRelayVPN "C:\goose-relay\goose-server.exe"
C:\nssm\win64\nssm.exe set GooseRelayVPN AppParameters "-config C:\goose-relay\server_config.json"
C:\nssm\win64\nssm.exe set GooseRelayVPN AppDirectory "C:\goose-relay"
C:\nssm\win64\nssm.exe set GooseRelayVPN Start SERVICE_AUTO_START
C:\nssm\win64\nssm.exe start GooseRelayVPN
```

**۴. بررسی اجرا بودن سرویس:**
```cmd
C:\nssm\win64\nssm.exe status GooseRelayVPN
curl http://YOUR.VPS.IP:8443/healthz
```

برای توقف یا حذف سرویس:
```cmd
C:\nssm\win64\nssm.exe stop GooseRelayVPN
C:\nssm\win64\nssm.exe remove GooseRelayVPN confirm
```

### مرحله ۹: اجرای کلاینت روی کامپیوتر

**Linux/macOS:**
```bash
./goose-client -config client_config.json
```

**Windows (cmd.exe or PowerShell):**
```cmd
.\goose-client.exe -config client_config.json
```

Use the backslash form (`.\...`) on Windows. `cmd.exe` does not understand the Unix-style `./goose-client.exe` form.

باید خروجی‌ای شبیه این ببینید:

```
CLIENT  INFO    GooseRelayVPN client starting
CLIENT  INFO    SOCKS5 proxy: socks5://127.0.0.1:1080
CLIENT  INFO    pre-flight OK: relay healthy, AES key matches end-to-end
CLIENT  INFO    ready: local SOCKS5 is listening on 127.0.0.1:1080
```

**بررسی pre-flight** در شروع اجرا خودکار انجام می‌شود و مطمئن می‌شود Apps Script قابل دسترسی است، VPS بالا است و کلید AES یکسان است. اگر fail شود، پیام خطا می‌گوید مشکل از کجاست.

حالا مرورگرتان را روی پراکسی SOCKS5 آدرس `127.0.0.1:1080` تنظیم کنید:

- **Firefox:** Settings → Network Settings → Manual proxy → SOCKS5 host `127.0.0.1` port `1080`. گزینه **Proxy DNS when using SOCKS v5** را فعال کنید.
- **Chrome/Edge:** از افزونه‌هایی مثل FoxyProxy یا SwitchyOmega استفاده کنید.
- **System-wide on macOS/Linux:** SOCKS5 را در تنظیمات شبکه ست کنید.

---

## راه‌اندازی macOS

همان باینری `goose-client` که در Linux استفاده می‌شود روی macOS هم کار می‌کند، اما فایل‌های دانلودشده ممکن است پرچم quarantine مربوط به Gatekeeper داشته باشند. معماری درست را انتخاب کنید: **Apple Silicon (M1/M2/M3/M4)** → `darwin-arm64`؛ **Intel Mac** → `darwin-amd64`.

**۱. دانلود و استخراج:**
```bash
cd ~/Downloads
tar -xzf GooseRelayVPN-client-vX.Y.Z-darwin-arm64.tar.gz
cd GooseRelayVPN-client-vX.Y.Z-darwin-arm64/
```

**۲. پاک کردن پرچم quarantine:**
```bash
xattr -d com.apple.quarantine goose-client 2>/dev/null || true
chmod +x goose-client
```

**۳. ساخت فایل config:**
```bash
cp client_config.example.json client_config.json
open -e client_config.json
```
`script_keys` و `tunnel_key` را پر کنید و ذخیره کنید.

**۴. اجرای کلاینت:**
```bash
./goose-client -config client_config.json
```

اگر خطای `cannot execute binary file: Exec format error` دیدید، معماری اشتباه را دانلود کرده‌اید.

---

## راه‌اندازی اندروید (Termux)

کلاینت اندروید داخل [Termux](https://termux.dev) اجرا می‌شود — فایل APK وجود ندارد. مراحل زیر را دنبال کنید:

**۱. نصب و آماده‌سازی Termux:**
```bash
apt update && apt upgrade -y
pkg install wget tar -y
```

**۲. دانلود و استخراج کلاینت:**
```bash
VERSION=vX.Y.Z
wget https://github.com/Kianmhz/GooseRelayVPN/releases/download/$VERSION/GooseRelayVPN-client-$VERSION-android-arm64.tar.gz
tar -xzvf GooseRelayVPN-client-$VERSION-android-arm64.tar.gz
cd GooseRelayVPN-client-$VERSION-android-arm64/
chmod +x goose-client
```

**۳. ساخت کانفیگ:**
```bash
cp client_config.example.json client_config.json
nano client_config.json
```
`script_keys` و `tunnel_key` را پر کنید و با Ctrl+X ذخیره کنید.

**۴. اجرای کلاینت:**
```bash
./goose-client -config client_config.json
```

وقتی `ready: local SOCKS5 is listening on 127.0.0.1:1080` را دیدید یعنی همه چیز درست است.

**۵. اتصال اپ‌ها:**

از یک اپ با پشتیبانی SOCKS5 برای روت کردن ترافیک از طریق `127.0.0.1:1080` استفاده کنید. [NekoBox](https://github.com/MatsuriDayo/NekoBoxForAndroid) و [v2rayNG](https://github.com/2dust/v2rayNG) هر دو خوب کار می‌کنند:
- یک پروکسی SOCKS5 به آدرس `127.0.0.1:1080` اضافه کنید
- در **per-app settings**، پروکسی را برای اپ‌های دلخواه فعال کنید و **Termux را از VPN خارج کنید** تا تونل قطع نشود

---

## اشتراک‌گذاری LAN (اختیاری)

به‌صورت پیش‌فرض کلاینت روی `127.0.0.1:1080` گوش می‌دهد، پس فقط کامپیوتر شما می‌تواند استفاده کند. برای اشتراک در شبکه محلی، `socks_host` را در `client_config.json` به `0.0.0.0` تغییر دهید و کلاینت را ری‌استارت کنید. اگر این کار را می‌کنید، حتماً `socks_user` و `socks_pass` را هم تنظیم کنید؛ وگرنه هر کسی در همان شبکه می‌تواند از تونل شما استفاده کند.

> ⚠️ **نکته امنیتی:** در این حالت هر کسی در شبکه محلی می‌تواند از تونل شما استفاده کند و سهمیه Apps Script شما را مصرف کند. فقط روی شبکه‌های قابل اعتماد انجام دهید.

---

## افزایش ظرفیت با چند deployment (پیشنهاد می‌شود)

گوگل سهمیه URL Fetch در Apps Script را به‌صورت per-user/account مستند کرده است؛ برای اکانت‌های مصرفی حدود **۲۰٬۰۰۰ فراخوانی در روز** است. deploymentهای زیر یک اکانت گوگل را یک quota pool مشترک فرض کنید و انتظار نداشته باشید هر deployment یا پروژه سهمیه جدا بگیرد. کلاینت در حالت بی‌کار حدود یک بار در ثانیه poll می‌کند، اما اپ‌های real-time مثل **تلگرام یا X می‌توانند quota را ظرف چند ساعت تمام کنند**. برای عبور از این محدودیت، `Code.gs` را روی **اکانت‌های مختلف گوگل** deploy کنید و همه Deployment IDها را در `script_keys` بگذارید.

> ⚠️ **هر deployment را با اکانت گوگلی که زیرش است برچسب (`account`) بزنید.** workerهای POST فعال بر اساس تعداد deploymentها scale می‌شوند، اما long-pollهای بیکار با bucket محدود می‌شوند. دو deployment برچسب‌خورده زیر یک اکانت یک bucket بیکار مشترک دارند؛ deploymentهای بدون برچسب برای سازگاری با configهای قدیمی جدا فرض می‌شوند، چون کلاینت نمی‌تواند ثابت کند زیر یک اکانت هستند.

```json
{
  "script_keys": [
    {"id": "FIRST_DEPLOYMENT_ID",  "account": "acct-a"},
    {"id": "SECOND_DEPLOYMENT_ID", "account": "acct-a"},
    {"id": "THIRD_DEPLOYMENT_ID",  "account": "acct-b"},
    {"id": "FOURTH_DEPLOYMENT_ID", "account": "acct-b"}
  ]
}
```

مثال بالا ۴ deployment روی ۲ اکانت = **۴ deployment فعال و ۲ bucket بیکار** — یعنی throughput فعال از همه deploymentها استفاده می‌کند، ولی long-pollهای ایستاده همچنان per-account محدود می‌مانند.

اگر برچسب نزنید (`["ID1", "ID2", ...]` به‌صورت رشته خالی)، هر deployment یک bucket ضمنی جدا می‌گیرد تا configهای قدیمی multi-endpoint کند نشوند. اگر چند deployment واقعاً زیر یک اکانت هستند، آن‌ها را با یک `account` مشترک برچسب بزنید تا idle long-poll بیش از حد روی همان اکانت باز نشود.

کلاینت به‌صورت خودکار این کارها را انجام می‌دهد:

- **Round-robin** بین deploymentهای فعال داخل هر bucket.
- **بلک‌لیست سلامت‌محور** — اگر یکی خراب شود، کلاینت با backoff (۳، ۶، ۱۲، … تا حدود ۴۸ ثانیه) از بقیه استفاده می‌کند.
- **Failover در همان poll** — اگر یک poll روی یک deployment fail شود، همان payload در همان چرخه روی deployment دیگر retry می‌شود، پس خطاهای موقتی quota یا 5xx ترافیک را از دست نمی‌دهند.
- **آمار per-account** — خط دوره‌ای `[stats]` تعداد درخواست‌ها را به ازای هر برچسب اکانت جمع می‌بندد تا ببینید سهمیه روزانه هر اکانت چقدر مصرف شده.

> 💡 همه deploymentها باید از **همان `tunnel_key`** استفاده کنند چون همگی به یک VPS فوروارد می‌شوند که فقط یک کلید AES دارد. وقتی deployment جدید اضافه می‌کنید، روی VPS تغییری لازم نیست.

> 💡 می‌توانید فقط Deployment ID (بخش بین `/s/` و `/exec`) یا کل URL `/exec` را paste کنید — کلاینت در هر دو حالت ID را استخراج می‌کند.

> 💡 **سقف عملی ۲ تا ۳ اکانت است.** افزودن deploymentهای بیشتر زیر اکانت‌هایی که از قبل دارید فقط quota را پخش می‌کند و معمولاً throughput را بهبود نمی‌دهد؛ چیزی که کمک می‌کند *یک اکانت مجزای دیگر* است.

---

## حالت Direct Stream

برای کمترین latency در مسیر مستقیم به VPS، `direct_stream_urls` را به `client_config.json` اضافه کنید و `transport_mode` را روی `auto` بگذارید:

```json
{
  "transport_mode": "auto",
  "direct_stream_urls": ["ws://YOUR.VPS.IP:8443/stream"],
  "script_keys": ["APPS_SCRIPT_FALLBACK_DEPLOYMENT_ID"]
}
```

فقط وقتی `goose-server` را پشت reverse proxy دارای TLS گذاشته‌اید از `wss://` استفاده کنید؛ سرور داخلی خودش `ws://` ساده گوش می‌دهد. حالت `auto` اگر `direct_stream_urls` تنظیم شده باشد اول WebSocket `/stream` را امتحان می‌کند. برای fallback نوع POST فقط **یک** مسیر POST استفاده می‌شود: اگر `relay_urls` تنظیم شده باشد direct POST، وگرنه Apps Script از روی `script_keys`. در نسخه فعلی اگر `relay_urls` را تنظیم کنید، Apps Script همزمان به‌عنوان fallback دوم POST استفاده نمی‌شود. برای اجبار یک مسیر از `direct_stream`، `direct_post` یا `apps_script` استفاده کنید. Apps Script نمی‌تواند WebSocket حمل کند و وقتی دسترسی مستقیم به VPS مسدود است امن‌ترین مسیر سازگار است.

---

## پیکربندی

### کلاینت (`client_config.json`)

| فیلد | مقدار پیش‌فرض | توضیح |
|---|---|---|
| `socks_host` | `127.0.0.1` | میزبان/IP برای شنونده SOCKS5 محلی. برای اشتراک LAN آن را `0.0.0.0` بگذارید، ولی `socks_user` و `socks_pass` را هم تنظیم کنید. |
| `socks_port` | `1080` | پورت SOCKS5 محلی. |
| `google_host` | `216.239.38.120` | میزبان/IP لبه گوگل برای اتصال (پورت همیشه `443` است). |
| `sni` | `["www.google.com", "mail.google.com", "accounts.google.com"]` | مقدار SNI در TLS. یک رشته یا آرایه می‌پذیرد. هر SNI connection pool و TLS session جدا دارد و ممکن است در شبکه‌هایی که با frontهای گوگل متفاوت رفتار می‌کنند کمک کند، اما bucket/throttle جداگانه برای هر SNI چیزی نیست که گوگل به‌صورت رسمی تضمین کرده باشد. |
| `transport_mode` | `apps_script` | پیش‌فرض مسیر fronted Apps Script است، چون در هدف اصلی این پروژه دسترسی مستقیم به VPS معمولاً بسته است. فقط وقتی عمداً `direct_stream_urls` یا `relay_urls` را تنظیم کرده‌اید و می‌خواهید مسیر مستقیم هم تست شود مقدار را `auto` بگذارید. `direct_post` و `direct_stream` هم یک مسیر مستقیم را اجبار می‌کنند. |
| `direct_stream_urls` | `[]` | endpointهای مستقیم WebSocket مثل `ws://YOUR.VPS.IP:8443/stream`. فقط وقتی استفاده می‌شود که `transport_mode` برابر `auto` یا `direct_stream` باشد. برای VPS پشت reverse proxy TLS از `wss://` استفاده کنید. اگر دسترسی مستقیم به VPS مسدود یا ناپایدار است خالی بگذارید. |
| `relay_urls` | `[]` | endpointهای مستقیم POST مثل `http://YOUR.VPS.IP:8443/tunnel`. فقط وقتی استفاده می‌شود که `transport_mode` برابر `auto` یا `direct_post` باشد؛ برای استفاده معمول Apps Script/fronting خالی بگذارید. |
| `downstream_replay_mode` | `auto` | بازیابی پاسخ‌های downstream از دست‌رفته برای Apps Script/direct POST. مقدار `auto` فقط وقتی فعال می‌شود که سرور `downstream_replay_v1` را advertise کند. direct stream تغییر نمی‌کند. |
| `script_keys` | — | آرایه deploymentهای Apps Script. هر entry می‌تواند یک رشته ساده Deployment ID یا یک آبجکت `{ "id": "...", "account": "..." }` با برچسب اکانت گوگل باشد. **برچسب `account` برای idle cap و تشخیص quota مهم است**: deploymentهای با برچسب یکسان یک bucket بیکار مشترک دارند؛ deploymentهای بدون برچسب برای سازگاری قدیمی جدا فرض می‌شوند. اگر چند deployment زیر یک اکانت هستند، آن‌ها را یکسان برچسب بزنید تا روی آن اکانت long-poll بیش از حد باز نشود. به [افزایش ظرفیت با چند deployment](#افزایش-ظرفیت-با-چند-deployment-پیشنهاد-میشود) مراجعه کنید. |
| `tunnel_key` | — | کلید AES-256 به‌صورت hex (۶۴ کاراکتر). باید با سرور یکسان باشد. |
| `socks_user` | *(اختیاری)* | نام کاربری SOCKS5 (RFC 1929). وقتی تنظیم شود، کلاینت‌ها باید احراز هویت کنند وگرنه اتصال رد می‌شود. باید همراه با `socks_pass` تنظیم شود — هر دو با هم یا هیچ‌کدام. |
| `socks_pass` | *(اختیاری)* | رمز SOCKS5 متناظر با `socks_user`. |
| `max_local_sessions` | `0` | سقف اضافه برای اتصال‌های همزمان SOCKS5 محلی. مقدار `0` یعنی خود listener سقف اضافه نمی‌گذارد، اما محافظ داخلی carrier هنوز از طوفان sessionها جلوگیری می‌کند. اگر می‌خواهید سقف قابل‌مشاهده داشته باشید، مثلاً `512` بگذارید. |
| `poll_timeout_ms` | `300000` | timeout هر درخواست relay به میلی‌ثانیه. باید از پنجره long-poll سرور و زمان دریافت پاسخ‌های بزرگ Apps Script بیشتر باشد. |
| `endpoint_outage_grace_ms` | `300000` | وقتی همه endpointها موقتاً قطع هستند، کلاینت sessionهای فعال را تا این مدت نگه می‌دارد تا شبکه یا گوگل برگردد. |
| `write_startup_diagnostics` | `false` | اگر `true` شود، هنگام شروع یک zip عیب‌یابی redacted می‌نویسد تا بدون لو دادن کلید بتوانید وضعیت سیستم و config را بررسی کنید. |
| `debug_pprof_addr` | *(خالی)* | آدرس pprof فقط برای localhost مثل `127.0.0.1:6060`. برای تست عمیق CPU/heap استفاده کنید؛ روی `0.0.0.0` نگذارید. |
| `stats_json` | `false` | اگر `true` باشد، stats دوره‌ای به شکل JSON لاگ می‌شود تا با analyzer یا ابزارهای لاگ راحت‌تر بررسی شود. |
| `save_terminal_log` | `false` | گزینه کمکی برای تست میدانی. وقتی `true` باشد، لاگ‌ها مثل قبل در ترمینال چاپ می‌شوند و همزمان در یک فایل `.log` ذخیره می‌شوند. این لاگ‌ها redacted نیستند و ممکن است دامنه/IP مقصد و URL کامل direct یا tokenها را نشان بدهند؛ قبل از ارسال مرورشان کنید. |
| `terminal_log_file` | *(خالی)* | نام/پیشوند اختیاری برای `save_terminal_log`. اگر خالی باشد، فایل `logs/goose-client-YYYYMMDD-HHMMSS.log` کنار باینری کلاینت ساخته می‌شود. اگر مسیر بدهید هم هر اجرا یک فایل timestamped تازه می‌سازد. |
| `coalesce_step_ms` | `0` (خاموش) | کوآلِسسِ تطبیقی برای آپلینک. وقتی مقدارش را `> 0` بگذارید، اولین kick یک burst کمی برای عملیات‌های بعدی صبر می‌کند؛ هر عملیات جدید تایمر را ریست می‌کند. این کار با کمی تأخیر، تعداد فراخوانی‌های Apps Script را کمتر می‌کند. بازهٔ شروع خوب ۲۰ تا ۴۰ میلی‌ثانیه است. مقدار `0` یعنی خاموش. سقف ایمنی داخلی به‌صورت خودکار از همین مقدار ساخته می‌شود و در config دیده نمی‌شود. |
| `idle_slots_per_bucket` | `1` | تنظیم throughput دانلود. کلاینت به ازای هر «bucket» اکانت این تعداد long-poll بی‌کار همزمان باز نگه می‌دارد تا push دانلود را دریافت کند. پیش‌فرض `1` همان baseline ایمنِ fix شدهٔ issue #۵۶ است. اگر هر اکانت گوگل ۲ یا بیشتر deployment دارد، روی `2` بگذارید — این کار ممکن است throughput دانلود را افزایش دهد؛ اگر هر اکانت فقط یک deployment دارد روی `1` بگذارید (افزایش معنی‌اش این است که ۲ poll همزمان روی یک URL deployment می‌رود که احتمال برخورد با concurrency cap هر اکانت در Apps Script را بالا می‌برد). حداکثر `3`؛ بیشتر از این رد می‌شود. |
| `idle_poll_mode` | `always` | حالت صرفه‌جویی quota. `adaptive` بعد از idle طولانی pollها را کم/متوقف می‌کند؛ `off` وقتی session فعالی نیست idle poll نمی‌زند. |
| `idle_poll_max_buckets` | `2` | حداکثر bucketهایی که وقتی هیچ session فعالی نیست idle poll می‌گیرند. |
| `workers_per_endpoint` | `3` | تعداد workerهای POST فعال به ازای هر deployment/endpoint. مقدار بیشتر latency را در مسیرهای پایدار کم می‌کند ولی quota و فشار simultaneous execution را بالا می‌برد. |
| `tx_buffer_budget_bytes` | `67108864` | بودجه کلی صف آپلود روی کل sessionهای local. پیش‌فرض ۶۴MiB از مصرف RAM زیاد در Android/Termux جلوگیری می‌کند. |

### سرور (`server_config.json`)

| فیلد | مقدار پیش‌فرض | توضیح |
|---|---|---|
| `server_host` | `0.0.0.0` | میزبان/IP که سرور خروجی روی آن bind می‌شود. |
| `server_port` | `8443` | پورتی که سرور خروجی روی آن گوش می‌دهد. باید از شبکه گوگل قابل دسترسی باشد. |
| `tunnel_key` | — | کلید AES-256 به‌صورت hex. باید با کلاینت یکسان باشد. |
| `upstream_proxy` | *(اختیاری)* | مسیردهی تمام اتصالات خروجی از طریق پروکسی SOCKS5. برای دور زدن محدودیت‌های سایت‌هایی که آی‌پی دیتاسنتر را بلاک می‌کنند. برای Cloudflare WARP محلی مقدار `socks5://127.0.0.1:40000` بگذارید؛ اگر پروکسی auth می‌خواهد از `socks5://user:pass@host:port` استفاده کنید. در این حالت DNS هم از طریق پروکسی حل می‌شود. خالی بگذارید یا حذف کنید برای اتصال مستقیم. |
| `debug_timing` | `false` | وقتی `true` است، زمان DNS و TCP برای هر session لاگ می‌شود. |
| `max_sessions` | `4096` | سقف sessionهای همزمان روی VPS. این گزینه جلوی مصرف RAM/FD بی‌رویه را می‌گیرد و هنگام فشار زیاد سریع RST می‌دهد تا برنامه‌ها سریع‌تر retry کنند و معطل نمانند. |
| `max_drain_frames_per_session` | `8` | گزینه server-only برای تعادل بین دانلود سنگین و وب‌گردی/ویدیو. هر frame downstream حداکثر `256 KiB` است؛ مقدار `8` یعنی یک session داغ حدود `2 MiB` plaintext از هر پاسخ سرور می‌گیرد و برای استفاده ترکیبی امن‌تر است. برای تست دانلود bulk اول `16` را امتحان کنید؛ `24` و `32` تهاجمی‌تر هستند و ممکن است سرعت دانلود Google Play را بهتر کنند، ولی tabها/ویدیوهای دیگر ممکن است بیشتر منتظر بمانند و پاسخ‌های Apps Script بزرگ‌تر شوند. |
| `auto_tune` | `false` | اگر `true` شود، فقط cadenceهای امن داخلی را داخل سقف‌های ثابت تنظیم می‌کند. برای شروع بهتر است خاموش بماند تا با log واقعی دلیل روشنی برای روشن کردنش داشته باشید. |
| `performance_mode` | `latency` | پروفایل پیش‌فرض برای وب‌گردی و شروع سریع ویدیو. اگر فقط throughput bulk می‌خواهید می‌توانید profile را در آینده تغییر دهید. |
| `active_drain_window_ms` | `0` (خودکار) | پنجره کوتاه drain وقتی session فعال است. مقدار کم یعنی پاسخ سریع‌تر برای browse/video start. |
| `long_poll_window_ms` | `6000` پیش‌فرض، `8000` در مثال | مدت نگه‌داشتن هر POST روی VPS. عدد بزرگ‌تر idle request کمتر می‌سوزاند؛ عدد خیلی بزرگ می‌تواند بازیابی خطا را کندتر کند. |
| `coalesce_window_ms` | `0` | مکث اختیاری برای جمع کردن چند frame در یک پاسخ. `0` کمترین latency را می‌دهد. |
| `coalesce_window_busy_ms` | `0` | پنجره coalesce جدا برای حالت شلوغ. اگر `0` باشد از رفتار latency-safe استفاده می‌شود. |
| `write_startup_diagnostics` | `false` | اگر `true` شود، هنگام شروع سرور zip عیب‌یابی redacted می‌نویسد. مسیرهای relative کنار باینری ساخته می‌شوند؛ برای systemd اگر پوشه نصب read-only است مسیر writable مطلق بدهید. |
| `debug_pprof_addr` | *(خالی)* | pprof سرور فقط روی localhost مثل `127.0.0.1:6061`. برای بررسی CPU/heap در تست زنده استفاده کنید. |
| `stats_json` | `false` | اگر `true` باشد، آمار دوره‌ای سرور به شکل JSON لاگ می‌شود و برای `cmd/analyze` مناسب‌تر است. |
| `save_terminal_log` | `false` | گزینه کمکی برای تست میدانی. وقتی `true` باشد، لاگ‌ها مثل قبل در ترمینال یا journal چاپ می‌شوند و همزمان در یک فایل `.log` ذخیره می‌شوند. این لاگ‌ها redacted نیستند و ممکن است دامنه/IP مقصد و URL کامل direct یا tokenها را نشان بدهند؛ قبل از ارسال مرورشان کنید. |
| `terminal_log_file` | *(خالی)* | نام/پیشوند اختیاری برای `save_terminal_log`. اگر خالی باشد، فایل `logs/goose-server-YYYYMMDD-HHMMSS.log` کنار باینری سرور ساخته می‌شود. اگر مسیر بدهید هم هر اجرا یک فایل timestamped تازه می‌سازد. |
| `max_request_body_bytes` | `12582912` | سقف body درخواست HTTP روی VPS. این مقدار برای batch آپلود ۸MiB کلاینت بعد از افزایش حجم base64/App Script کافی است و مصرف memory درخواست‌های احرازنشده را محدود نگه می‌دارد. فقط وقتی batch آپلود را عمداً بزرگ‌تر می‌کنید، cap کلاینت و سرور را با هم بالا ببرید. |
| `max_response_bytes_pre_encode` | `6291456` | سقف batch پاسخ server-to-client قبل از رمزنگاری/base64، بعد از ramp شروع session. مقدار `2097152` برای لینک موبایل ناپایدار امن‌تر است؛ `4194304` محافظه‌کارانه است؛ و `6291456` پیش‌فرض متعادل برای دانلود بهتر است. وقتی replay روشن است این مقدار را حداکثر `8388608` نگه دارید. |
| `initial_response_cap_enabled` | `true` | روشن/خاموش کردن cap اولین پاسخ. برای تست حداکثر سرعت دانلود bulk مقدار را `false` بگذارید تا `initial_response_bytes_pre_encode` بدون نیاز به تغییر عدد نادیده گرفته شود. |
| `initial_response_bytes_pre_encode` | `524288` | سقف اولین پاسخ downstream برای هر session وقتی `initial_response_cap_enabled` برابر `true` است. کمک می‌کند اولین بایت‌های صفحه/ویدیو پشت یک پاسخ دانلود بزرگ گیر نکنند. |
| `second_response_cap_enabled` | `true` | روشن/خاموش کردن cap دومین پاسخ. اگر `false` باشد، `second_response_bytes_pre_encode` بدون نیاز به تغییر عدد نادیده گرفته می‌شود. |
| `second_response_bytes_pre_encode` | `1048576` | سقف دومین پاسخ downstream برای هر session وقتی `second_response_cap_enabled` برابر `true` است. مقدار `1048576` برای شروع ویدیو/وب‌گردی روی Apps Script و موبایل نرم‌تر است؛ فقط وقتی دانلودها پایدارند و quota سالم است `2097152` را تست کنید. پاسخ‌های بعدی از `max_response_bytes_pre_encode` استفاده می‌کنند. |
| `downstream_replay_enabled` | `false` اگر حذف شود، `true` در مثال‌ها | replay buffer محدود برای پاسخ‌های downstream در Apps Script/direct POST. همراه با `downstream_replay_mode: "auto"` در کلاینت استفاده کنید. |

---

## به‌روزرسانی

فایل‌های config forward-compatible هستند: فیلدهای جدید در `client_config.json` / `server_config.json` مقدار پیش‌فرض منطقی دارند و فیلدهای قدیمی همچنان کار می‌کنند. معمولاً لازم نیست از اول نصب کنید.

یک نکته مهم برای configهای قدیمی مسیر مستقیم: اگر قبلاً `transport_mode` را حذف کرده بودید ولی از `relay_urls` یا `direct_stream_urls` استفاده می‌کردید، حالا صریحاً `"transport_mode": "auto"`، `"direct_post"` یا `"direct_stream"` را اضافه کنید. پیش‌فرض فعلی `"apps_script"` است تا مسیر معمول و سازگار Apps Script قابل‌پیش‌بینی بماند.

### سرور

۱. سرور در حال اجرا را متوقف کنید (`sudo systemctl stop goose-relay` در Linux systemd، یا پردازش tmux/manual خودتان را ببندید).
۲. `goose-server` / `goose-server.exe` را با باینری جدید جایگزین کنید.
۳. `server_config.json` را نگه دارید مگر اینکه release note صراحتاً بگوید فیلدی اضافه کنید.
۴. سرور را دوباره اجرا کنید.

### کلاینت

۱. `goose-client` در حال اجرا را متوقف کنید.
۲. `goose-client` / `goose-client.exe` را با باینری جدید جایگزین کنید.
۳. `client_config.json` فعلی را نگه دارید.
۴. فقط در macOS، پرچم quarantine را دوباره پاک کنید:
   ```bash
   xattr -d com.apple.quarantine goose-client 2>/dev/null || true
   chmod +x goose-client
   ```
۵. کلاینت را دوباره اجرا کنید.

اگر `Code.gs` تغییر نکرده، نیازی به redeploy کردن Apps Script نیست.

### forwarder در Apps Script

اگر `Code.gs` را تغییر دادید — مثلاً برای تغییر IP VPS — صرفاً ذخیره کردن کد چیزی را عوض نمی‌کند؛ URL زنده `/exec` نسخه deploy شده را سرو می‌کند. یا یک **deployment جدید** بسازید و `script_keys` را به‌روزرسانی کنید، یا یک نسخه جدید بسازید و همان deployment وب‌اپ موجود را به آن نسخه وصل کنید تا Deployment ID قبلی حفظ شود.

نسخهٔ فعلی `Code.gs` از طریق `doGet` متادیتای forwarder/protocol را برای pre-flight کلاینت نمایش می‌دهد. اگر `ENABLE_INVOCATION_COUNTING` را `true` کنید، یک شمارنده تقریبی از درخواست‌های web-app هر deployment هم نمایش داده می‌شود؛ این عدد را سیگنال فشار محلی بدانید، نه شمارنده دقیق quota مربوط به Google URL Fetch. این گزینه به‌صورت پیش‌فرض خاموش است چون نوشتن در Apps Script properties روی هر درخواست latency اضافه می‌کند.

---

## معماری

```
┌─────────┐   ┌──────────────┐   ┌──────────────┐   ┌─────────────┐   ┌──────────┐
│ Browser │──►│ goose-client │──►│ Google edge  │──►│ Apps Script │──►│  Your    │──► Internet
│  / App  │◄──│  (SOCKS5)    │◄──│ TLS, fronted │◄──│  doPost()   │◄──│  VPS     │◄──
└─────────┘   └──────────────┘   └──────────────┘   └─────────────┘   └──────────┘
              AES-256-GCM         Google SNI         dumb forwarder    decrypt +
              session multiplex   Host=script.…      no plaintext      net.Dial
```

اصول کلیدی:

- **احراز هویت = تگ AES-GCM.** هیچ رمز عبور یا گواهی مشترکی نیست. فریم‌هایی که `Open()` آن‌ها fail شود بی‌صدا drop می‌شوند.
- **Apps Script هرگز متن خام را نمی‌بیند.** اسکریپت یک forwarder ~۳۰ خطی است؛ کلید AES فقط روی کامپیوتر شما و VPS شماست.
- **DNS از تونل عبور می‌کند.** سرور SOCKS5 از یک resolver خنثی استفاده می‌کند؛ از `socks5h://` استفاده کنید تا DNS در نقطه خروج resolve شود نه محلی.
- **Long-poll تمام‌دوطرفه.** VPS هر درخواست را به اندازه `long_poll_window_ms` باز نگه می‌دارد (پیش‌فرض ۶ ثانیه؛ کانفیگ نمونه ۸ ثانیه استفاده می‌کند). کلاینت workerهای POST فعال را بر اساس تعداد deploymentها اجرا می‌کند، اما idle long-pollها را با bucketهای اکانت محدود می‌کند. deploymentهای برچسب‌خورده زیر یک اکانت یک bucket مشترک دارند؛ deploymentهای بدون برچسب جدا فرض می‌شوند. مدل bucket به این دلیل وجود دارد که محدودیت‌های simultaneous-execution و short-time invocation در Apps Script per-account هستند. coalescing پاسخ قابل تنظیم است و در حالت latency پیش‌فرض ۰ میلی‌ثانیه دارد.
- **چند deployment سلامت‌محور.** وقتی `script_keys` بیش از یک deployment دارد، کلاینت endpointها را با توجه به سلامت، RTT و فشار quota انتخاب می‌کند. batchهای TX روی endpointهای سالم retry می‌شوند تا یک deployment خراب یا تمام‌شده ترافیک را drop نکند وقتی deployment سالم دیگری وجود دارد.

### فرمت wire

- **Frame** (plaintext، داخل batch مهر و موم‌شده): `session_id (16) || seq (u64 BE) || flags (u8) || target_len (u8) || target || payload_len (u32 BE) || payload`
- **Batch seal** (AES-GCM): کل batch یک‌بار seal می‌شود — `nonce (12 bytes) || AES-GCM(flags (u8) || client_id (16) || u16 frame_count || [u32 frame_len || frame_bytes] …)` — یک nonce و auth-tag به ازای هر HTTP body، نه به ازای هر frame.
- **HTTP body**: در مسیر Apps Script از `base64(nonce || ciphertext+tag)` استفاده می‌شود تا round-trip متنی `ContentService` سالم بماند. direct POST و direct stream چون از Apps Script عبور نمی‌کنند می‌توانند بدنه باینری خام `nonce || ciphertext+tag` را مذاکره/ارسال کنند.

---

## فایل‌های پروژه

```
GooseRelayVPN/
├── cmd/
│   ├── client/main.go              # Entry point: SOCKS5 listener + carrier loop
│   └── server/main.go              # Entry point: VPS HTTP handler
├── internal/
│   ├── frame/                      # Wire format, AES-GCM seal/open, batch packer
│   ├── session/                    # Per-connection state, seq counters, rx/tx queues
│   ├── socks/                      # SOCKS5 server + VirtualConn (net.Conn adapter)
│   ├── carrier/                    # Long-poll loop + domain-fronted HTTPS client
│   ├── exit/                       # VPS HTTP handler: decrypt, demux, dial upstream
│   └── config/                     # JSON config loaders
├── bench/
│   ├── harness/main.go             # E2E benchmark: real binaries, loopback sink
│   ├── sink/main.go                # TCP sink (echo / sized / source / quick modes)
│   ├── diff/main.go                # JSON result comparator with noise-floor logic
│   ├── baselines/                  # Committed baseline JSON files
│   └── bench.sh                   # Build + run + compare orchestrator
├── apps_script/
│   └── Code.gs                     # Apps Script forwarder
├── scripts/
│   └── goose-relay.service         # systemd unit template
├── client_config.example.json
└── server_config.example.json
```

---

## رفع مشکل

| مشکل | راه‌حل |
|---|---|
| موقع اجرای `goose-server` یا `goose-client` خطای `cannot execute binary file: Exec format error` می‌گیرید | آرشیو اشتباهی برای OS/معماری خود دانلود کرده‌اید. اسم پوشه نشان می‌دهد چه چیزی گرفته‌اید — مثلاً `…-darwin-amd64` باینری **macOS** است و روی لینوکس اجرا نمی‌شود. آرشیو مناسب را دوباره دانلود کنید (VPS لینوکسی → `linux-amd64`؛ مک Apple Silicon → `darwin-arm64`؛ Termux → `android-arm64`). |
| Pre-flight fails: `cannot reach Apps Script` | اینترنت شما به گوگل دسترسی ندارد. `google_host` را چک کنید — یک IP edge فعلی متعلق به گوگل را امتحان کنید و اجازه دهید startup probe فقط SNIهای سالم را نگه دارد. |
| Pre-flight fails: `HTTP 204 — key mismatch` | `tunnel_key` در `client_config.json` با `server_config.json` روی VPS یکسان نیست. باید بایت‌به‌بایت برابر باشند. |
| Pre-flight fails: `Apps Script cannot reach your VPS` | پورت 8443 روی VPS قابل دسترسی نیست. `sudo ufw allow 8443/tcp` را اجرا کنید و فایروال ارائه‌دهنده ابری را هم بررسی کنید. |
| Log says `relay returned non-batch payload` | Apps Script returned HTML/JSON/text instead of an encrypted batch. Common causes: stale deployment/access settings, old pre-v2 `Code.gs` still returning upstream error text with HTTP 200, wrong Deployment ID, or per-account Apps Script quota/rate limits. Current `Code.gs` throws HTTP 500 when all VPS `RELAY_URLS` fail, so check HTTP 500 rows too. |
| Log says `relay returned HTTP 404 via …` | Deployment ID در کانفیگ شما با `/exec` زنده‌ای مطابقت ندارد. دوباره deploy کنید و کانفیگ را به‌روزرسانی کنید. |
| Log says `relay returned HTTP 500 via ...` | Apps Script/Google returned a wrapper-level error, or current `Code.gs` threw because every `RELAY_URLS` target failed. Check the response body in the logs: quota text points to Apps Script/UrlFetch quota, while upstream fetch/status text points to VPS reachability, `/tunnel`, tunnel key, firewall, or upstream proxy trouble. |
| Log says `relay request failed via …: timeout` | اتصال fronted به گوگل fail می‌شود. یک IP edge فعلی متعلق به گوگل را در `google_host` امتحان کنید؛ رنج‌های IP گوگل تغییر می‌کنند، پس به startup probe اعتماد کنید نه اینکه فرض کنید هر `216.239.x.120` همیشه کار می‌کند. |
| Browser hangs on every request | مطمئن شوید افزونه مرورگر روی SOCKS5 با **DNS through proxy** تنظیم شده است (نه SOCKS5 معمولی). در Firefox گزینه **Proxy DNS when using SOCKS v5** را فعال کنید. |
| `[exit] dial X: ... timeout` در لاگ VPS | مقصد، IPهای دیتاسنتر را بلاک می‌کند یا VPS شما برای آن پورت اتصال خروجی ندارد. |
| Cloudflare-protected sites show captchas | طبیعی است. IP VPS شما روی ASN دیتاسنتری است و bot scoring کلودفلر آن را علامت می‌زند. مشکل از تونل نیست. |
| YouTube buffers a lot at 1080p | طبیعی است. تونل به دلیل overhead Apps Script حدود ۳۰۰ تا ۸۰۰ میلی‌ثانیه به هر round trip اضافه می‌کند. 480p راحت‌تر است. چند `script_keys` به throughput پایدار کمک می‌کند. |
| One deployment hits quota mid-session | اگر `script_keys` بیش از یک عضو دارد، کلاینت به‌صورت خودکار چند ثانیه آن را blacklist می‌کند و ادامه می‌دهد. اگر فقط یک اکانت دارید، مرور تا ریست پنجره سهمیه گوگل متوقف می‌شود. |
| Mismatched AES keys | علامت: کلاینت خطایی نشان نمی‌دهد اما ترافیک رد نمی‌شود؛ لاگ VPS خطوط `dial ...` ندارد. مطمئن شوید `tunnel_key` در دو کانفیگ بایت‌به‌بایت برابر است. |

### جمع‌آوری شواهد قبل از تنظیم بیشتر

قبل از اینکه حدس بزنید کدام گزینه را تغییر دهید، یک تست کوتاه واقعی بگیرید و شواهد را نگه دارید:

```bash
./goose-client -config client_config.json -dump-diag
./goose-server -config server_config.json -dump-diag
```

فایل‌های `goose-diagnostics-*.zip` و `goose-server-diagnostics-*.zip` کلید تونل را redacted می‌کنند و برای بررسی کندی، goroutine، heap، config و وضعیت runtime مفید هستند. برای پروفایل عمیق‌تر، باینری را با `-debug-pprof 127.0.0.1:6060` اجرا کنید و با `go tool pprof` بررسی کنید؛ pprof فقط روی localhost مجاز است. اگر `-stats-json` را روشن کنید، لاگ‌های دوره‌ای قابل پردازش‌تر می‌شوند. برای تست میدانی، `save_terminal_log: true` را در config بگذارید تا خروجی ترمینال مثل قبل دیده شود و یک فایل `.log` زمان‌دار هم داخل پوشه `logs/` ذخیره شود. مسیرهای relative کنار باینری اجراشده ساخته می‌شوند؛ مثلاً سروری که در `/root/23goosecodex` است، فایل‌ها را در `/root/23goosecodex/diagnostics/` و `/root/23goosecodex/logs/` می‌نویسد. هر restart فایل جدید می‌سازد و به فایل قبلی append نمی‌کند.

برای خلاصه کردن لاگ‌های طولانی کلاینت/سرور بعد از تست زنده:

```bash
go run ./cmd/analyze client.log server.log
```

چک‌لیست تست Android/mobile و پروفایل امن موبایل در [`docs/TESTING_REAL_WORLD.md`](docs/TESTING_REAL_WORLD.md) است. آن فایل مشخص می‌کند چه لاگ‌ها، diagnostic zipها، replay settingها و اندازه response را قبل از tuning بیشتر ذخیره کنید.

---

## نکات امنیتی

- **هرگز `client_config.json` یا `server_config.json` را با کسی به اشتراک نگذارید** — کلید AES داخل آن‌هاست و لو رفتن آن یعنی هر کسی می‌تواند از طریق VPS شما تونل بزند.
- **برای هر گروه VPS/کلاینت یک کلید تازه با `openssl rand -hex 32` بسازید.** همه deploymentهای Apps Script که به همان VPS فوروارد می‌شوند باید همان کلید را داشته باشند. کلید را بین میزبان‌های جداگانه reuse نکنید.
- **AES-GCM تنها احراز هویت است.** هیچ رمز عبور، rate-limiting یا حسابداری per-user وجود ندارد. کلید را مثل پسورد ادمین سرور نگه دارید.
- **Apps Script هر `doPost` را در داشبورد گوگل لاگ می‌کند** (فقط تعداد و مدت — Apps Script هرگز متن خام را نمی‌بیند).
- **`socks_host` کلاینت را روی `127.0.0.1` نگه دارید** مگر اینکه واقعاً قصد اشتراک LAN داشته باشید. اگر روی `0.0.0.0` bind می‌کنید، `socks_user` و `socks_pass` را تنظیم کنید.
- **سهمیه Apps Script URL Fetch به‌صورت per-user/account مستند شده است**: حدود ۲۰٬۰۰۰ فراخوانی در روز برای اکانت‌های مصرفی. deploymentهای زیر یک اکانت را یک pool مشترک فرض کنید.

---

## مشارکت در توسعه

Pull request خوش‌آمد است. برای هر تغییری که به carrier loop، session layer یا poll behavior مربوط می‌شود، لطفاً نتایج benchmark را هم ضمیمه کنید تا بازبینی‌کنندگان بتوانند تأثیر عملکردی را ارزیابی کنند.

پوشه `bench/` یک harness end-to-end دارد که باینری‌های واقعی `goose-client` و `goose-server` را در حالت loopback راه‌اندازی می‌کند و throughput، TTFB، session rate و idle CPU را اندازه می‌گیرد.

```bash
# ساخت باینری‌ها و اجرای کامل benchmark
bash bench/bench.sh
```

harness نتایج working tree شما را با baseline ذخیره‌شده در `bench/baselines/` مقایسه می‌کند و یک جدول مقایسه‌ای چاپ می‌کند. رگرسیون‌های بالاتر از noise floor اسکریپت را با exit code 1 خاتمه می‌دهند. نتیجه را در توضیحات PR قرار دهید.

برای ذخیره یک baseline جدید از یک git ref مشخص:

```bash
bash bench/bench.sh --update <ref>   # مثلاً --update v1.6.0 یا --update HEAD
```

---

## Special Thanks

Special thanks to [@abolix](https://github.com/abolix) for making this project possible.

## License

MIT
