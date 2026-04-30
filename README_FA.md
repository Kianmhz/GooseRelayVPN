# GooseRelayVPN

[![GitHub](https://img.shields.io/badge/GitHub-GooseRelayVPN-blue?logo=github)](https://github.com/kianmhz/GooseRelayVPN)

**[English README](README.md)**

یک VPN مبتنی بر SOCKS5 که **ترافیک خام TCP** را از طریق یک وب اپ Google Apps Script به سرور خروجی VPS کوچک خودتان تونل می‌کند. هر چیزی که در مسیر شبکه قرار دارد فقط TLS به یک IP گوگل با `SNI=www.google.com` می‌بیند. همه چیز در مسیر به‌صورت سرتاسری با AES-256-GCM رمز می‌شود — گوگل هرگز متن خام را نمی‌بیند و کلید را نگه نمی‌دارد.

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
- هر Deployment ID در Google Apps Script حدود ۲۰٬۰۰۰ اجرا در روز سهمیه دارد و این سهمیه حدود ساعت ۱۰:۳۰ صبح به وقت ایران (GMT+3:30) ریست می‌شود.
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
  -> AES-256-GCM raw-TCP frames
  -> HTTPS to a Google edge IP   (SNI=www.google.com, Host=script.google.com)
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
   - Windows: `GooseRelayVPN-client-vX.Y.Z-windows-amd64.zip`
   - macOS (Intel): `GooseRelayVPN-client-vX.Y.Z-darwin-amd64.tar.gz`
   - macOS (M1/M2/M3): `GooseRelayVPN-client-vX.Y.Z-darwin-arm64.tar.gz`
   - Linux: `GooseRelayVPN-client-vX.Y.Z-linux-amd64.tar.gz`
   - Android / Termux (arm64): `GooseRelayVPN-client-vX.Y.Z-android-arm64.tar.gz`
3. برای **سرور**، باینری مناسب سیستم‌عامل VPS خود را دانلود کنید:
   - **لینوکس (رایج‌ترین):**
     ```bash
     wget https://github.com/kianmhz/GooseRelayVPN/releases/latest/download/GooseRelayVPN-server-vX.Y.Z-linux-amd64.tar.gz
     tar -xzf GooseRelayVPN-server-vX.Y.Z-linux-amd64.tar.gz
     ```
   - **ویندوز سرور:** فایل `GooseRelayVPN-server-vX.Y.Z-windows-amd64.zip` را از صفحه Releases دانلود کنید و آن را در پوشه‌ای مثل `C:\goose-relay\` اکسترکت کنید. برای راه‌اندازی سرویس، مرحله ۸ (ویندوز) را ببینید.

   (عدد `vX.Y.Z` را با آخرین نسخه در صفحه Releases جایگزین کنید.)

**گزینه B — ساخت از سورس (Go 1.22+):**

```bash
git clone https://github.com/kianmhz/GooseRelayVPN.git
cd GooseRelayVPN
go build -o goose-client ./cmd/client
go build -o goose-server ./cmd/server
```

### مرحله ۳: ساخت یک کلید مخفی

این دستور را یک‌بار اجرا کنید:

```bash
bash scripts/gen-key.sh
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
  "sni":         "www.google.com",
  "script_keys": ["PASTE_DEPLOYMENT_ID"],
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
   const VPS_URL = 'http://YOUR.VPS.IP:8443/tunnel';
   ```
5. روی **Deploy → New deployment** کلیک کنید و نوع را **Web app** بگذارید.
6. **Execute as:** Me و **Who has access:** Anyone را انتخاب کنید.
7. روی **Deploy** بزنید. یک پنجره باز می‌شود که **Deployment ID** را نشان می‌دهد. آن را کپی و در `script_keys` قرار دهید.
8. آن Deployment ID را در `script_keys` داخل `client_config.json` هم وارد کنید.

> ⚠️ هر بار که `Code.gs` را ویرایش می‌کنید باید **یک deployment جدید** بسازید (Deploy → **New deployment**) و `script_keys` را به‌روزرسانی کنید. صرفاً ذخیره کردن کد کافی نیست.

### مرحله ۶: باز کردن پورت 8443 روی فایروال VPS

سرور باید از اینترنت روی پورت 8443 قابل دسترسی باشد. روی VPS اجرا کنید:

```bash
sudo ufw allow 8443/tcp
```

سپس از کامپیوتر خودتان تست کنید (IP واقعی VPS را جایگزین کنید):

```bash
curl http://YOUR.VPS.IP:8443/healthz
```

باید یک پاسخ خالی با HTTP 200 بگیرید. اگر `curl` تایم‌اوت شد یا خطا داد، **فایروال ارائه‌دهنده ابری** را هم بررسی کنید (در AWS/Hetzner به نام "Security Groups"، در DigitalOcean/Vultr به نام "Firewall Rules") و یک قانون ورودی برای TCP پورت 8443 اضافه کنید.

### مرحله ۷: اجرای سرور روی VPS

روی VPS این دستور را اجرا کنید:

```bash
./goose-server -config server_config.json
```

باید آدرس listening و آدرس‌های healthz/tunnel را ببینید. این ترمینال را باز بگذارید، یا مرحله ۸ را انجام دهید تا بعد از ریبوت هم بالا بماند.

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

```bash
./goose-client -config client_config.json
```

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

## اشتراک‌گذاری LAN (اختیاری)

به‌صورت پیش‌فرض کلاینت روی `127.0.0.1:1080` گوش می‌دهد، پس فقط کامپیوتر شما می‌تواند استفاده کند. برای اشتراک در شبکه محلی، `socks_host` را در `client_config.json` به `0.0.0.0` تغییر دهید و کلاینت را ری‌استارت کنید.

> ⚠️ **نکته امنیتی:** در این حالت هر کسی در شبکه محلی می‌تواند از تونل شما استفاده کند و سهمیه Apps Script شما را مصرف کند. فقط روی شبکه‌های قابل اعتماد انجام دهید.

---

## افزایش ظرفیت با چند deployment (پیشنهاد می‌شود)

هر اکانت گوگل برای هر deployment در Apps Script سهمیه روزانه **~۲۰٬۰۰۰ فراخوانی** دارد. کلاینت در حالت بی‌کار حدود یک بار در ثانیه poll می‌کند، پس یک deployment برای استفاده پایدار کافی است، اما روزهای پرترافیک به سقف می‌رسند. برای عبور از این محدودیت، `Code.gs` را چندبار deploy کنید — با همان اکانت یا چند اکانت — و همه Deployment IDها را در `script_keys` بگذارید:

```json
{
  "script_keys": [
    "FIRST_DEPLOYMENT_ID",
    "SECOND_DEPLOYMENT_ID",
    "THIRD_DEPLOYMENT_ID"
  ]
}
```

کلاینت به‌صورت خودکار این کارها را انجام می‌دهد:

- **Round-robin** بین همه deploymentهای پیکربندی‌شده.
- **بلک‌لیست سلامت‌محور** — اگر یکی خراب شود، کلاینت با backoff (۳، ۶، ۱۲، … تا حدود ۴۸ ثانیه) از بقیه استفاده می‌کند.
- **Failover در همان poll** — اگر یک poll روی یک deployment fail شود، همان payload در همان چرخه روی deployment دیگر retry می‌شود، پس خطاهای موقتی quota یا 5xx ترافیک را از دست نمی‌دهند.

> 💡 همه deploymentها باید از **همان `tunnel_key`** استفاده کنند چون همگی به یک VPS فوروارد می‌شوند که فقط یک کلید AES دارد. وقتی deployment جدید اضافه می‌کنید، روی VPS تغییری لازم نیست.

> 💡 می‌توانید فقط Deployment ID (بخش بین `/s/` و `/exec`) یا کل URL `/exec` را paste کنید — کلاینت در هر دو حالت ID را استخراج می‌کند.

> ⚠️ **تعداد پیشنهادی: ۳ تا ۴ Deployment ID.** بیشتر لزوماً بهتر نیست — هر کلید ۳ worker موازی اضافه می‌کند و تعداد زیاد بار غیرضروری روی سرویس گوگل ایجاد می‌کند بدون اینکه سرعت محسوسی اضافه شود. برای عملکرد پایدار، به ۳ تا ۴ عدد پایبند باشید.

---

## پیکربندی

### کلاینت (`client_config.json`)

| فیلد | مقدار پیش‌فرض | توضیح |
|---|---|---|
| `socks_host` | `127.0.0.1` | میزبان/IP برای شنونده SOCKS5 محلی. برای اشتراک LAN آن را `0.0.0.0` بگذارید. |
| `socks_port` | `1080` | پورت SOCKS5 محلی. |
| `google_host` | `216.239.38.120` | میزبان/IP لبه گوگل برای اتصال (پورت همیشه `443` است). |
| `sni` | `www.google.com` | مقدار SNI در TLS. یک رشته یا آرایه می‌پذیرد — `["www.google.com", "mail.google.com", "accounts.google.com"]` — هر SNI اتصال و bucket جداگانه دارد که می‌تواند پهنای باند را در مناطقی که per-domain throttle دارند چند برابر کند. |
| `script_keys` | — | آرایه Deployment IDهای Apps Script (بدون URL کامل). حداقل یک ID لازم است؛ هر ID اضافه ۳ worker موازی و ~۲۰٬۰۰۰ درخواست روزانه quota اضافه می‌کند. **پیشنهاد: ۳ تا ۴ ID.** تعداد بیشتر بار اضافی ایجاد می‌کند بدون بهبود محسوس. |
| `tunnel_key` | — | کلید AES-256 به‌صورت hex (۶۴ کاراکتر). باید با سرور یکسان باشد. |
| `socks_user` | *(اختیاری)* | نام کاربری SOCKS5 (RFC 1929). وقتی تنظیم شود، کلاینت‌ها باید احراز هویت کنند وگرنه اتصال رد می‌شود. باید همراه با `socks_pass` تنظیم شود — هر دو با هم یا هیچ‌کدام. |
| `socks_pass` | *(اختیاری)* | رمز SOCKS5 متناظر با `socks_user`. |

### سرور (`server_config.json`)

| فیلد | مقدار پیش‌فرض | توضیح |
|---|---|---|
| `server_host` | `0.0.0.0` | میزبان/IP که سرور خروجی روی آن bind می‌شود. |
| `server_port` | `8443` | پورتی که سرور خروجی روی آن گوش می‌دهد. باید از شبکه گوگل قابل دسترسی باشد. |
| `tunnel_key` | — | کلید AES-256 به‌صورت hex. باید با کلاینت یکسان باشد. |
| `upstream_proxy` | *(اختیاری)* | مسیردهی تمام اتصالات خروجی از طریق یک پروکسی SOCKS5 محلی. برای دور زدن محدودیت‌های سایت‌هایی که آی‌پی دیتاسنتر را بلاک می‌کنند. برای استفاده با Cloudflare WARP مقدار `socks5://127.0.0.1:40000` بگذارید. در این حالت DNS هم از طریق پروکسی حل می‌شود. خالی بگذارید یا حذف کنید برای اتصال مستقیم. |
| `debug_timing` | `false` | وقتی `true` است، زمان DNS و TCP برای هر session لاگ می‌شود. |

---

## به‌روزرسانی forwarder در Apps Script

اگر `Code.gs` را تغییر دادید — مثلاً برای تغییر IP VPS — باید در ویرایشگر Apps Script یک **deployment جدید** بسازید (Deploy → **New deployment**، نه فقط "Manage deployments"). صرفاً ذخیره کردن کد چیزی را عوض نمی‌کند؛ URL زنده `/exec` نسخه منتشرشده قبلی را سرو می‌کند. بعد از deploy جدید، `script_keys` را در `client_config.json` به‌روزرسانی کنید.

---

## معماری

```
┌─────────┐   ┌──────────────┐   ┌──────────────┐   ┌─────────────┐   ┌──────────┐
│ Browser │──►│ goose-client │──►│ Google edge  │──►│ Apps Script │──►│  Your    │──► Internet
│  / App  │◄──│  (SOCKS5)    │◄──│ TLS, fronted │◄──│  doPost()   │◄──│  VPS     │◄──
└─────────┘   └──────────────┘   └──────────────┘   └─────────────┘   └──────────┘
              AES-256-GCM         SNI=www.google     dumb forwarder    decrypt +
              session multiplex   Host=script.…      no plaintext      net.Dial
```

اصول کلیدی:

- **احراز هویت = تگ AES-GCM.** هیچ رمز عبور یا گواهی مشترکی نیست. فریم‌هایی که `Open()` آن‌ها fail شود بی‌صدا drop می‌شوند.
- **Apps Script هرگز متن خام را نمی‌بیند.** اسکریپت یک forwarder ~۳۰ خطی است؛ کلید AES فقط روی کامپیوتر شما و VPS شماست.
- **DNS از تونل عبور می‌کند.** سرور SOCKS5 از یک resolver خنثی استفاده می‌کند؛ از `socks5h://` استفاده کنید تا DNS در نقطه خروج resolve شود نه محلی.
- **Long-poll تمام‌دوطرفه.** VPS هر درخواست را تا ۸ ثانیه باز نگه می‌دارد؛ کلاینت **۳ worker موازی به ازای هر deployment ID** اجرا می‌کند — یعنی ۳ کلید = ۹ worker، ۶ کلید = ۱۸ worker. اضافه کردن script key بیشتر هم موازی‌کاری را بالا می‌برد هم سهمیه را. فریم‌های downstream در یک پنجره کوچک (~۲۵ میلی‌ثانیه) coalesce می‌شوند تا برای استریم‌ها HTTP پاسخ‌های کمتر و بزرگ‌تر ساخته شود.
- **چند deployment سلامت‌محور.** وقتی `script_keys` بیش از یک deployment دارد، کلاینت endpointها را round-robin انتخاب می‌کند و هر کدام که بد رفتار کند به‌صورت نمایی blacklist می‌کند؛ یک retry در همان poll روی deployment سالم انجام می‌شود تا خطاهای موقتی ترافیک را drop نکنند.

### فرمت wire

- **Frame** (plaintext، داخل batch مهر و موم‌شده): `session_id (16) || seq (u64 BE) || flags (u8) || target_len (u8) || target || payload_len (u32 BE) || payload`
- **Batch seal** (AES-GCM): کل batch یک‌بار seal می‌شود — `nonce (12 bytes) || AES-GCM(u16 frame_count || [u32 frame_len || frame_bytes] …)` — یک nonce و auth-tag به ازای هر HTTP body، نه به ازای هر frame.
- **HTTP body**: `base64(nonce || ciphertext+tag)`، base64 برای اینکه round-trip متنی `ContentService` را سالم عبور دهد.

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
│   └── Code.gs                     # ~30-line dumb forwarder
├── scripts/
│   ├── gen-key.sh                  # openssl rand -hex 32
│   └── goose-relay.service         # systemd unit template
├── client_config.example.json
└── server_config.example.json
```

---

## مشکلات شناخته‌شده

- **استفاده از تعداد زیاد Deployment ID می‌تواند باعث ناپایداری شود.** در حال حاضر یک مشکل شناخته‌شده وجود دارد که تنظیم تعداد زیادی `script_keys` عملکرد را کاهش داده یا مشکلات اتصال ایجاد می‌کند. تا رفع این مشکل، **به ۳ تا ۴ Deployment ID پایبند باشید**.

---

## رفع مشکل

| مشکل | راه‌حل |
|---|---|
| Pre-flight fails: `cannot reach Apps Script` | اینترنت شما به گوگل دسترسی ندارد. `google_host` را چک کنید — یک IP دیگر از رنج 216.239.x.120 امتحان کنید. |
| Pre-flight fails: `HTTP 204 — key mismatch` | `tunnel_key` در `client_config.json` با `server_config.json` روی VPS یکسان نیست. باید بایت‌به‌بایت برابر باشند. |
| Pre-flight fails: `Apps Script cannot reach your VPS` | پورت 8443 روی VPS قابل دسترسی نیست. `sudo ufw allow 8443/tcp` را اجرا کنید و فایروال ارائه‌دهنده ابری را هم بررسی کنید. |
| Log says `relay returned non-batch payload` | Apps Script به جای batch رمزشده، HTML برگردانده. یا deployment داخل `script_keys` زنده نیست، یا **Who has access** روی `Anyone` نیست. دوباره deploy کنید و `script_keys` را به‌روزرسانی کنید. |
| Log says `relay returned HTTP 404 via …` | Deployment ID در کانفیگ شما با `/exec` زنده‌ای مطابقت ندارد. دوباره deploy کنید و کانفیگ را به‌روزرسانی کنید. |
| Log says `relay returned HTTP 500 via …` | Apps Script نمی‌تواند به `VPS_URL` برسد. آدرس سرور در `Code.gs` را چک کنید، مطمئن شوید VPS بالا است و TCP/8443 ورودی باز است. `curl http://your.vps.ip:8443/healthz` باید 200 برگرداند. |
| Log says `relay request failed via …: timeout` | اتصال fronted به گوگل fail می‌شود. یک `google_host` دیگر امتحان کنید — هر 216.239.x.120 که گوگل سرویس می‌دهد کار می‌کند. |
| Browser hangs on every request | مطمئن شوید افزونه مرورگر روی SOCKS5 با **DNS through proxy** تنظیم شده است (نه SOCKS5 معمولی). در Firefox گزینه **Proxy DNS when using SOCKS v5** را فعال کنید. |
| `[exit] dial X: ... timeout` در لاگ VPS | مقصد، IPهای دیتاسنتر را بلاک می‌کند یا VPS شما برای آن پورت اتصال خروجی ندارد. |
| Cloudflare-protected sites show captchas | طبیعی است. IP VPS شما روی ASN دیتاسنتری است و bot scoring کلودفلر آن را علامت می‌زند. مشکل از تونل نیست. |
| YouTube buffers a lot at 1080p | طبیعی است. تونل به دلیل overhead Apps Script حدود ۳۰۰ تا ۸۰۰ میلی‌ثانیه به هر round trip اضافه می‌کند. 480p راحت‌تر است. چند `script_keys` به throughput پایدار کمک می‌کند. |
| One deployment hits quota mid-session | اگر `script_keys` بیش از یک عضو دارد، کلاینت به‌صورت خودکار چند ثانیه آن را blacklist می‌کند و ادامه می‌دهد. اگر فقط یک عضو دارید، مرور تا ریست سهمیه (~۱۰:۳۰ صبح به وقت ایران / نیمه‌شب Pacific) متوقف می‌شود. |
| Mismatched AES keys | علامت: کلاینت خطایی نشان نمی‌دهد اما ترافیک رد نمی‌شود؛ لاگ VPS خطوط `dial ...` ندارد. مطمئن شوید `tunnel_key` در دو کانفیگ بایت‌به‌بایت برابر است. |

---

## نکات امنیتی

- **هرگز `client_config.json` یا `server_config.json` را با کسی به اشتراک نگذارید** — کلید AES داخل آن‌هاست و لو رفتن آن یعنی هر کسی می‌تواند از طریق VPS شما تونل بزند.
- **برای هر deployment یک کلید تازه با `scripts/gen-key.sh` بسازید.** کلید را بین چند میزبان reuse نکنید.
- **AES-GCM تنها احراز هویت است.** هیچ رمز عبور، rate-limiting یا حسابداری per-user وجود ندارد. کلید را مثل پسورد ادمین سرور نگه دارید.
- **Apps Script هر `doPost` را در داشبورد گوگل لاگ می‌کند** (فقط تعداد و مدت — Apps Script هرگز متن خام را نمی‌بیند).
- **`socks_host` کلاینت را روی `127.0.0.1` نگه دارید** مگر اینکه واقعاً قصد اشتراک LAN داشته باشید.
- **هر deployment در Apps Script محدودیت ~۲۰٬۰۰۰ فراخوانی در روز** روی حساب رایگان گوگل دارد.

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
bash bench/bench.sh --update <ref>   # مثلاً --update v1.3.0 یا --update HEAD
```

---

## Special Thanks

Special thanks to [@abolix](https://github.com/abolix) for making this project possible.

## License

MIT
