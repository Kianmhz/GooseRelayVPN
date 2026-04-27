# GooseRelayVPN

[![GitHub](https://img.shields.io/badge/GitHub-GooseRelayVPN-blue?logo=github)](https://github.com/kianmhz/GooseRelayVPN)

**[English README](README.md)**

یک VPN مبتنی بر SOCKS5 که **ترافیک خام TCP** را از طریق یک Google Apps Script رایگان به سرور اختصاصی شما تونل می‌کند. هر چیزی که در مسیر شبکه قرار دارد فقط یک ارتباط TLS به IP گوگل با `SNI=www.google.com` می‌بیند. تمام بایت‌ها به‌صورت سرتاسری با AES-256-GCM رمز می‌شوند — گوگل هرگز محتوای خام را نمی‌بیند و کلید رمز هیچ‌وقت به دست گوگل نمی‌رسد.

> **توضیح ساده:** مرورگر یا اپلیکیشن شما با این ابزار روی کامپیوتر خودتان از طریق SOCKS5 صحبت می‌کند. این ابزار هر بایت TCP را در فریم‌های AES-GCM می‌بسته‌بندی و از طریق یک ارتباط HTTPS به Apps Script شما می‌فرستد. اسکریپت آن بایت‌ها را بدون تغییر به VPS شما هدایت می‌کند، VPS رمزگشایی کرده و اتصال واقعی را برقرار می‌کند. برای فیلتر، شما فقط در حال صحبت با گوگل هستید.

> ⚠️ **شما به یک VPS کوچک برای سرور خروجی نیاز دارید.** برخلاف پراکسی‌های صرفاً Apps Script محور، این پروژه ترافیک خام TCP را تونل می‌کند — هر چیزی که SOCKS5 می‌تواند حمل کند — پس یک `net.Dial` واقعی باید جایی انجام شود. یک VPS ارزان کافی است. در مقابل می‌توانید SSH، IMAP، پروتکل‌های دلخواه و هر چیزی را تونل کنید — نه فقط HTTP.

## نکات مهم

- کلید `tunnel_key` را هرگز با کسی به اشتراک نگذارید. هر کسی این کلید را داشته باشد می‌تواند مثل شما از تونل/VPS استفاده کند.
- داشتن یک سرور با دسترسی اینترنت عمومی الزامی است. سرور خروجی شما باید از سمت Google Apps Script قابل دسترسی باشد.
- هر Deployment ID در Google Apps Script حدود ۲۰٬۰۰۰ اجرا در روز سهمیه دارد و این سهمیه حدود ساعت ۱۰:۳۰ صبح به وقت ایران (GMT+3:30) ریست می‌شود.
- در این پروژه نیازی به نصب گواهی (certificate) مثل `MasterHttpRelayVPN` ندارید. مدل فنی آن پروژه متفاوت است و اینجا لازم نیست.
- ایده‌ی اصلی این پروژه از مخزن اصلی الهام گرفته شده است: https://github.com/masterking32/MasterHttpRelayVPN

---

## سلب مسئولیت

پروژه GooseRelayVPN فقط برای اهداف آموزشی، تست و پژوهش ارائه شده است.

- **بدون ضمانت:** این نرم‌افزار به‌صورت «همان‌گونه که هست» ارائه می‌شود و هیچ ضمانت صریح یا ضمنی، از جمله قابلیت فروش، مناسب بودن برای هدف خاص یا عدم نقض حقوق دیگران، برای آن وجود ندارد.
- **محدودیت مسئولیت:** توسعه‌دهندگان و مشارکت‌کنندگان این پروژه هیچ مسئولیتی در قبال خسارت‌های مستقیم، غیرمستقیم، اتفاقی، تبعی یا هر نوع خسارت دیگر ناشی از استفاده از این پروژه ندارند.
- **مسئولیت کاربر:** اجرای این پروژه خارج از محیط‌های کنترل‌شده ممکن است بر شبکه، حساب‌ها یا سیستم‌های متصل اثر بگذارد. تمام مسئولیت نصب، پیکربندی و استفاده بر عهده‌ی کاربر است.
- **رعایت قوانین:** پیش از استفاده، رعایت تمام قوانین محلی، کشوری و بین‌المللی بر عهده‌ی کاربر است.
- **رعایت قوانین گوگل:** اگر از Google Apps Script در این پروژه استفاده می‌کنید، رعایت Terms of Service گوگل، قوانین استفاده‌ی مجاز، سهمیه‌ها و سیاست‌های پلتفرم بر عهده‌ی شماست. استفاده‌ی نادرست ممکن است باعث تعلیق حساب گوگل یا deployment شما شود.
- **شرایط مجوز:** استفاده، کپی، توزیع و تغییر این نرم‌افزار فقط تحت شرایط مجوز موجود در مخزن مجاز است.

---

## نحوه‌ی کار

```
مرورگر/اپ
  -> SOCKS5  (127.0.0.1:1080)
  -> فریم‌های TCP رمز‌شده با AES-256-GCM
  -> HTTPS به IP گوگل   (SNI=www.google.com, Host=script.google.com)
  -> Apps Script doPost()        (فقط یک پل ساده، محتوای خام را نمی‌بیند)
  -> VPS شما :8443/tunnel        (رمزگشایی، demux بر اساس session_id، dial به مقصد واقعی)
  <- مسیر برگشت از طریق long-polling
```

اپلیکیشن شما بایت‌های TCP را از طریق SOCKS5 به این ابزار می‌فرستد. کلاینت هر تکه را با AES-256-GCM رمز کرده و در قالب batch روی یک ارتباط HTTPS که از طریق گوگل fronted شده برای Apps Script شما POST می‌کند. اسکریپت Apps Script یک کد حدوداً ۳۰ خطی است که body را بدون تغییر برای VPS شما می‌فرستد — هرگز رمزگشایی نمی‌کند و کلید AES هیچ‌وقت روی گوگل قرار نمی‌گیرد. VPS رمزگشایی، dial به مقصد واقعی و pump بایت‌ها را در مسیر برگشت انجام می‌دهد. فیلتر فقط TLS به گوگل می‌بیند.

---

## راه‌اندازی مرحله‌به‌مرحله

### مرحله ۱: تهیه‌ی یک VPS خارج از ایران

به یک سرور لینوکسی با IP عمومی نیاز دارید. هر پروایدری کار می‌کند.

### مرحله ۲: تهیه‌ی باینری‌ها

**گزینه‌ی الف — دانلود نسخه‌ی آماده (پیشنهادی):**

۱. به [صفحه‌ی Releases](https://github.com/kianmhz/GooseRelayVPN/releases) بروید.
۲. فایل مناسب سیستم‌عامل خودتان را دانلود کنید:
   - ویندوز: `GooseRelayVPN-client-vX.Y.Z-windows-amd64.zip`
   - مک (Intel): `GooseRelayVPN-client-vX.Y.Z-darwin-amd64.tar.gz`
   - مک (M1/M2/M3): `GooseRelayVPN-client-vX.Y.Z-darwin-arm64.tar.gz`
   - لینوکس: `GooseRelayVPN-client-vX.Y.Z-linux-amd64.tar.gz`
  - اندروید / Termux (arm64): `GooseRelayVPN-client-vX.Y.Z-android-arm64.tar.gz`
۳. فایل را extract کنید. داخلش `goose-client` و یک فایل نمونه‌ی کانفیگ هست.

**گزینه‌ی ب — ساخت از سورس (Go 1.22+):**

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

رشته‌ی ۶۴ کاراکتری که چاپ می‌شود را کپی کنید. همین مقدار را در **هر دو** کانفیگ (کلاینت و سرور) باید بگذارید. این کلید را محرمانه نگه دارید — هر کسی آن را داشته باشد می‌تواند از تونل شما استفاده کند.

### مرحله ۴: تنظیم کانفیگ

فایل‌های نمونه را کپی کنید:

```bash
cp client_config.example.json client_config.json
cp server_config.example.json server_config.json
```

هر دو را باز کنید و کلید خود را در فیلد `tunnel_key` قرار دهید. فعلاً `script_keys` را خالی بگذارید.

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

این بخش رایگان است و ترافیک شما را از طریق سرورهای گوگل عبور می‌دهد.

1. وارد [Google Apps Script](https://script.google.com/) شوید.
2. روی **New project** کلیک کنید.
3. کد پیش‌فرض را حذف کنید و محتوای فایل [`apps_script/Code.gs`](apps_script/Code.gs) را paste کنید.
4. این خط را به IP سرور خودتان تغییر دهید:
   ```javascript
    const VPS_URL = 'http://YOUR.VPS.IP:8443/tunnel';
   ```
5. روی **Deploy → New deployment** کلیک کنید و نوع را **Web app** انتخاب کنید.
6. **Execute as:** Me و **Who has access:** Anyone را انتخاب کنید.
7. روی **Deploy** بزنید و Deployment ID را از URL بردارید (رشته‌ی طولانی بین `/s/` و `/exec`).
8. آن را در `script_keys` داخل `client_config.json` قرار دهید.

> ⚠️ هر بار که `Code.gs` را ویرایش کنید باید **یک deployment جدید** بسازید و `script_keys` را آپدیت کنید.

### مرحله ۶: اجرای خودکار سرور بعد از ریبوت (systemd)

اگر می‌خواهید سرور خروجی بعد از ریبوت VPS به‌صورت خودکار بالا بیاید، یک سرویس systemd بسازید.

این دستور را اجرا کنید:

```bash
sudo nano /etc/systemd/system/goose-relay.service
```

این محتوا را قرار دهید (اگر مسیر باینری/کانفیگ شما فرق دارد، اصلاح کنید):

```ini
[Unit]
Description=GooseRelayVPN exit server
After=network.target

[Service]
Type=simple
WorkingDirectory=/root
ExecStart=/root/goose-server-linux -config /root/server_config.json
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

بعد این دستورات را اجرا کنید:

```bash
sudo systemctl daemon-reload
sudo systemctl enable goose-relay
sudo systemctl start goose-relay
sudo systemctl status goose-relay --no-pager
```

### مرحله ۷: اجرای کلاینت

```bash
./goose-client -config client_config.json
```

باید این پیام را ببینید:

```
[client] SOCKS5 listening on 127.0.0.1:1080
```

این باید **IP سرور شما** را نشان دهد، نه IP خودتان.

حالا مرورگرتان را روی پراکسی SOCKS5 آدرس `127.0.0.1:1080` تنظیم کنید:

- **Firefox:** Settings → Network Settings → Manual proxy → SOCKS5 host `127.0.0.1` port `1080`. گزینه‌ی **Proxy DNS when using SOCKS v5** را فعال کنید.
- **Chrome/Edge:** از افزونه‌ای مثل FoxyProxy یا SwitchyOmega استفاده کنید.
- **macOS / Linux:** پراکسی SOCKS5 در تنظیمات شبکه.

---

## اشتراک‌گذاری در شبکه‌ی محلی (اختیاری)

به‌طور پیش‌فرض، کلاینت روی `127.0.0.1:1080` گوش می‌دهد، یعنی فقط همین کامپیوتر می‌تواند از آن استفاده کند. برای اشتراک‌گذاری با سایر دستگاه‌های شبکه‌ی محلی، مقدار `socks_host` در `client_config.json` را به `0.0.0.0` تغییر دهید و کلاینت را restart کنید.

> ⚠️ **نکته‌ی امنیتی:** در این حالت هر کسی در شبکه‌ی محلی می‌تواند از تونل شما استفاده کند و سهمیه‌ی Apps Script شما را مصرف کند. فقط روی شبکه‌های قابل اعتماد این کار را انجام دهید.

---

## افزایش ظرفیت با چند Deployment (پیشنهاد می‌شود)

هر اکانت گوگل برای هر deployment آپس‌اسکریپت سهمیه‌ی روزانه‌ی **~۲۰٬۰۰۰ فراخوانی** دارد. کلاینت در حالت بی‌کار حدود یک poll در ثانیه می‌فرستد، پس یک deployment برای استفاده‌ی پیوسته کافی است ولی روزهای پرترافیک می‌توانند به سقف سهمیه برسند. برای عبور از این محدودیت، `Code.gs` را چند بار deploy کنید — زیر یک اکانت گوگل یا چند اکانت — و همه‌ی Deployment IDها را در `script_keys` بگذارید:

```json
{
  "script_keys": [
    "FIRST_DEPLOYMENT_ID",
    "SECOND_DEPLOYMENT_ID",
    "THIRD_DEPLOYMENT_ID"
  ]
}
```

کاری که کلاینت به‌صورت خودکار برای شما انجام می‌دهد:

- **round-robin** بین همه‌ی deploymentهای پیکربندی‌شده.
- **بلک‌لیست سلامت‌محور** — اگر یکی شروع به fail کند، کلاینت backoff می‌کند (۳، ۶، ۱۲، … تا حدود ۴۸ ثانیه) و از بقیه استفاده می‌کند.
- **failover در همان poll** — اگر یک poll روی یک deployment fail شود، همان payload در همان چرخه روی deployment دیگری retry می‌شود، پس در حین خطاهای موقتی quota یا 5xx ترافیکی از دست نمی‌رود.

> 💡 همه‌ی deploymentها باید از **همان `tunnel_key`** استفاده کنند چون همگی به یک VPS forward می‌کنند که فقط یک کلید AES دارد. وقتی deployment جدیدی اضافه می‌کنید، روی VPS هیچ تغییری لازم نیست.

> 💡 می‌توانید فقط Deployment ID (بخشی که بین `/s/` و `/exec` است) یا کل آدرس `/exec` را paste کنید — کلاینت در هر دو حالت ID را استخراج می‌کند.

---

## تنظیمات

### کلاینت (`client_config.json`)

| فیلد | مقدار پیش‌فرض | توضیح |
|---|---|---|
| `socks_host` | `127.0.0.1` | میزبان/IP برای SOCKS5 محلی. برای اشتراک LAN آن را `0.0.0.0` بگذارید. |
| `socks_port` | `1080` | پورت SOCKS5 محلی. |
| `google_host` | `216.239.38.120` | میزبان/IP لبه‌ی گوگل برای اتصال (پورت همیشه `443` است). |
| `sni` | `www.google.com` | مقدار SNI در handshake TLS. |
| `script_keys` | — | آرایه‌ای از Deployment IDهای Apps Script (بدون URL کامل). حداقل یک ID لازم است؛ افزودن چند ID برای load balancing سلامت‌محور و پخش quota بین چند deployment. |
| `tunnel_key` | — | کلید AES-256 به‌صورت hex (۶۴ کاراکتر) که باید با سرور یکسان باشد. |

### سرور (`server_config.json`)

| فیلد | مقدار پیش‌فرض | توضیح |
|---|---|---|
| `server_host` | `0.0.0.0` | میزبان/IP که سرور خروجی روی آن bind می‌شود. |
| `server_port` | `8443` | پورتی که سرور خروجی روی آن گوش می‌دهد. باید از شبکه‌ی گوگل قابل دسترسی باشد. |
| `tunnel_key` | — | کلید AES-256 به‌صورت hex. باید با کلاینت یکسان باشد. |

---

## به‌روزرسانی forwarder روی Apps Script

اگر `Code.gs` را تغییر دادید — مثلاً برای تغییر IP دراپلت — باید در ویرایشگر Apps Script یک **deployment جدید** بسازید (Deploy → **New deployment**، نه فقط "Manage deployments"). صرفاً ذخیره کردن کد، نسخه‌ی فعال را عوض نمی‌کند؛ آدرس `/exec` همچنان نسخه‌ی منتشرشده‌ی قبلی را سرو می‌کند. بعد از deploy جدید، `script_keys` را در `client_config.json` به‌روزرسانی کنید.

---

## معماری

```
┌─────────┐   ┌──────────────┐   ┌──────────────┐   ┌─────────────┐   ┌──────────┐
│ مرورگر  │──►│ goose-client │──►│ لبه‌ی گوگل   │──►│ Apps Script │──►│  VPS     │──► اینترنت
│  / اپ   │◄──│  (SOCKS5)    │◄──│ TLS, fronted │◄──│  doPost()   │◄──│  شما     │◄──
└─────────┘   └──────────────┘   └──────────────┘   └─────────────┘   └──────────┘
              AES-256-GCM         SNI=www.google     پل ساده          رمزگشایی +
              مالتی‌پلکس session   Host=script.…      بدون plaintext   net.Dial
```

اصول کلیدی:

- **احراز هویت = تگ AES-GCM.** هیچ رمز عبور یا گواهی مشترکی نیست. فریم‌هایی که `Open()` آن‌ها fail می‌شود به‌صورت بی‌صدا drop می‌شوند.
- **Apps Script هرگز محتوای خام را نمی‌بیند.** اسکریپت یک forwarder ~۳۰ خطی است؛ کلید AES فقط روی کامپیوتر شما و VPS شما قرار دارد.
- **DNS از تونل عبور می‌کند.** سرور SOCKS5 از یک resolver خنثی استفاده می‌کند؛ از `socks5h://` استفاده کنید تا DNS در نقطه‌ی خروج resolve شود نه به‌صورت محلی.
- **Long-poll دو طرفه.** VPS هر درخواست را تا ۸ ثانیه باز نگه می‌دارد و منتظر بایت‌های downstream می‌ماند؛ کلاینت بلافاصله بعد از پاسخ، درخواست بعدی را می‌فرستد. دو HTTP exchange همزمان، یک مسیر full-duplex می‌سازد. فریم‌های downstream در یک پنجره‌ی کوچک (~۲۵ میلی‌ثانیه) coalesce می‌شوند تا برای استریم‌ها HTTP responseهای کم‌تر و بزرگ‌تر فرستاده شود.
- **چند Deployment با آگاهی از سلامت.** اگر `script_keys` بیش از یک deployment داشته باشد، کلاینت endpointها را round-robin انتخاب می‌کند و هر کدام را که خطا بدهد به‌صورت توانی blacklist می‌کند؛ یک retry در همان poll روی یک deployment سالم انجام می‌شود تا خطاهای موقتی ترافیکی را drop نکنند.

### قالب wire

- **Frame** (plaintext، قبل از AES-GCM): `session_id (16) || seq (u64 BE) || flags (u8) || target_len (u8) || target || payload_len (u32 BE) || payload`
- **Envelope** (AES-GCM): `nonce (12) || ciphertext+tag`. Nonce برای هر فریم، AAD خالی.
- **Body HTTP**: `[u16 frame_count] [u32 frame_len][envelope] ...`، سپس base64 می‌شود تا از round-trip متنی `ContentService` گوگل سالم رد شود.

---

## فایل‌های پروژه

```
GooseRelayVPN/
├── cmd/
│   ├── client/main.go              # نقطه‌ی شروع: SOCKS5 listener + carrier loop
│   └── server/main.go              # نقطه‌ی شروع: VPS HTTP handler
├── internal/
│   ├── frame/                      # قالب wire، AES-GCM seal/open، batch packer
│   ├── session/                    # state هر اتصال، شمارنده‌ی seq، صف rx/tx
│   ├── socks/                      # SOCKS5 server + VirtualConn (آداپتور net.Conn)
│   ├── carrier/                    # حلقه‌ی long-poll + کلاینت HTTPS با domain fronting
│   ├── exit/                       # VPS HTTP handler: رمزگشایی، demux، dial به مقصد
│   └── config/                     # بارگذاری کانفیگ JSON
├── apps_script/
│   └── Code.gs                     # forwarder ساده‌ی ~۳۰ خطی
├── scripts/
│   ├── gen-key.sh                  # openssl rand -hex 32
│   ├── deploy.sh                   # build + scp + نصب systemd روی VPS
│   └── goose-relay.service        # template برای systemd unit
├── client_config.example.json
└── server_config.example.json
```

---

## رفع مشکل

| مشکل | راه‌حل |
|---|---|
| لاگ می‌گوید `decode batch: ... base64 ...` | Apps Script به‌جای batch رمزشده یک صفحه‌ی HTML برگردانده. یا deployment داخل `script_keys` زنده نیست، یا گزینه‌ی **Who has access** روی `Anyone` تنظیم نشده. یک **deployment جدید** بسازید و `script_keys` را در `client_config.json` به‌روزرسانی کنید. |
| لاگ می‌گوید `relay returned HTTP 404 via …` | همان مشکل بالا — Deployment ID داخل کانفیگ شما با `/exec` زنده‌ای مطابقت ندارد. دوباره deploy کنید و کانفیگ را به‌روزرسانی کنید. |
| لاگ می‌گوید `relay returned HTTP 500 via …` | Apps Script نمی‌تواند به `VPS_URL` برسد. آدرس سرور داخل `Code.gs` را چک کنید، اطمینان حاصل کنید VPS بالا است و TCP/8443 ورودی باز است. `curl http://your.vps.ip:8443/healthz` باید 200 برگرداند. |
| لاگ می‌گوید `relay request failed via …: timeout` | اتصال fronted به گوگل fail می‌شود. یک `google_host` دیگر امتحان کنید — هر 216.239.x.120 که گوگل سرویس می‌دهد کار می‌کند. |
| مرورگر روی هر درخواست hang می‌کند | از `socks5://` به‌جای `socks5h://` استفاده می‌کنید. حالت بدون `h` نام‌ها را به‌صورت محلی resolve می‌کند و پراکسی فقط IP خام دریافت می‌کند. |
| `[exit] dial X: ... timeout` در لاگ VPS | مقصد، IPهای دیتاسنتر را بلاک می‌کند یا VPS شما برای آن پورت اتصال خروجی ندارد. |
| سایت‌های پشت Cloudflare کپچا می‌خواهند | طبیعی است. IP سرور شما روی یک ASN دیتاسنتری است و bot scoring کلودفلر آن را علامت می‌زند. این مشکل تونل نیست. |
| یوتیوب در ۱۰۸۰p بافر می‌کند | طبیعی است. تونل به‌خاطر overhead فراخوانی Apps Script حدود ۳۰۰–۸۰۰ میلی‌ثانیه به هر round trip اضافه می‌کند. کیفیت ۴۸۰p روان است. اضافه کردن چند Deployment ID در `script_keys` (بخش بالا) به throughput پایدار کمک می‌کند. |
| یک deployment وسط کار به سهمیه می‌رسد | اگر `script_keys` بیش از یک عضو دارد، کلاینت به‌صورت خودکار چند ثانیه بلک‌لیستش می‌کند و از بقیه ادامه می‌دهد. اگر فقط یک عضو دارید، browsing تا reset سهمیه (~۱۰:۳۰ صبح به وقت ایران / نیمه‌شب Pacific) متوقف می‌ماند. |
| کلیدهای AES (`tunnel_key`) ناهمسان | علامت: کلاینت خطا نمی‌دهد ولی هیچ ترافیکی رد نمی‌شود؛ خطوط `dial ...` در لاگ سرور ظاهر نمی‌شوند. مطمئن شوید مقدار `tunnel_key` در دو کانفیگ بایت‌به‌بایت یکسان است. |

---

## نکات امنیتی

- **هرگز `client_config.json` یا `server_config.json` را با کسی به اشتراک نگذارید** — کلید AES داخل آن‌ها است و leak شدن آن یعنی هر کسی می‌تواند از طریق VPS شما تونل بزند.
- **برای هر deployment کلید جدید با `scripts/gen-key.sh` بسازید.** کلید را بین چند سرور به اشتراک نگذارید.
- **AES-GCM تنها مکانیزم احراز هویت است.** هیچ رمز عبور، rate-limiting یا حسابداری per-user وجود ندارد. کلید را مثل پسورد ادمین سرور حفظ کنید.
- **Apps Script هر فراخوانی `doPost` را در داشبورد گوگل لاگ می‌کند** (فقط تعداد و duration — Apps Script هرگز محتوای خام را نمی‌بیند).
- **مقدار `socks_host` کلاینت را روی `127.0.0.1` نگه دارید** مگر اینکه واقعاً قصد اشتراک LAN داشته باشید.
- **هر deployment روی Apps Script محدودیت ~۲۰٬۰۰۰ فراخوانی در روز** روی حساب رایگان گوگل دارد.

---

## Special Thanks

Special thanks to [@abolix](https://github.com/abolix) for making this project possible.

## License

MIT
