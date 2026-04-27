# relay-tunnel

[![GitHub](https://img.shields.io/badge/GitHub-relay--tunnel-blue?logo=github)](https://github.com/kianmhz/relay-tunnel)

**[English README](README.md)**

یک VPN مبتنی بر SOCKS5 که **ترافیک خام TCP** را از طریق یک Google Apps Script رایگان به سرور اختصاصی شما تونل می‌کند. هر چیزی که در مسیر شبکه قرار دارد فقط یک ارتباط TLS به IP گوگل با `SNI=www.google.com` می‌بیند. تمام بایت‌ها به‌صورت سرتاسری با AES-256-GCM رمز می‌شوند — گوگل هرگز محتوای خام را نمی‌بیند و کلید رمز هیچ‌وقت به دست گوگل نمی‌رسد.

> **توضیح ساده:** مرورگر یا اپلیکیشن شما با این ابزار روی کامپیوتر خودتان از طریق SOCKS5 صحبت می‌کند. این ابزار هر بایت TCP را در فریم‌های AES-GCM می‌بسته‌بندی و از طریق یک ارتباط HTTPS به Apps Script شما می‌فرستد. اسکریپت آن بایت‌ها را بدون تغییر به VPS شما هدایت می‌کند، VPS رمزگشایی کرده و اتصال واقعی را برقرار می‌کند. برای فیلتر، شما فقط در حال صحبت با گوگل هستید.

> ⚠️ **شما به یک VPS کوچک برای سرور خروجی نیاز دارید.** برخلاف پراکسی‌های صرفاً Apps Script محور، این پروژه ترافیک خام TCP را تونل می‌کند — هر چیزی که SOCKS5 می‌تواند حمل کند — پس یک `net.Dial` واقعی باید جایی انجام شود. یک دراپلت ۴ دلاری در ماه از DigitalOcean کافی است. در مقابل می‌توانید SSH، IMAP، پروتکل‌های دلخواه و هر چیزی را تونل کنید — نه فقط HTTP.

## نکات مهم

- کلید `tunnel_key` را هرگز با کسی به اشتراک نگذارید. هر کسی این کلید را داشته باشد می‌تواند مثل شما از تونل/VPS استفاده کند.
- داشتن یک سرور با دسترسی اینترنت عمومی الزامی است. سرور خروجی شما باید از سمت Google Apps Script قابل دسترسی باشد.
- هر Deployment ID در Google Apps Script حدود ۲۰٬۰۰۰ اجرا در روز سهمیه دارد و این سهمیه حدود ساعت ۱۰:۳۰ صبح به وقت ایران (GMT+3:30) ریست می‌شود.
- در این پروژه نیازی به نصب گواهی (certificate) مثل `MasterHttpRelayVPN` ندارید. مدل فنی آن پروژه متفاوت است و اینجا لازم نیست.
- ایده‌ی اصلی این پروژه از مخزن اصلی الهام گرفته شده است: https://github.com/masterking32/MasterHttpRelayVPN

---

## سلب مسئولیت

پروژه relay-tunnel فقط برای اهداف آموزشی، تست و پژوهش ارائه شده است.

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

### مرحله ۱: تهیه‌ی VPS برای سرور خروجی

به یک VPS لینوکسی کوچک نیاز دارید که `UrlFetchApp` در Apps Script بتواند از طریق TCP/8443 به آن برسد. هر ارائه‌دهنده‌ای کار می‌کند؛ یک دراپلت ~۴ دلاری در ماه از DigitalOcean کافی است.

- یک دراپلت Ubuntu بسازید و IP عمومی آن را یادداشت کنید.
- پورت TCP/8443 را در فایروال دراپلت برای ورودی باز کنید.
- اطمینان حاصل کنید که می‌توانید با `ssh user@droplet-ip` متصل شوید و کاربر شما `sudo` دارد.

### مرحله ۲: تهیه‌ی باینری‌ها

یکی از دو روش زیر را انتخاب کنید.

**گزینه‌ی الف — دانلود باینری آماده (پیشنهاد می‌شود اگر نمی‌خواهید Go نصب کنید):**

۱. به [صفحه‌ی Releases](https://github.com/kianmhz/relay-tunnel/releases) بروید.
۲. آرشیو متناسب با کامپیوترتان را دانلود کنید:
   - ویندوز: `relay-tunnel-vX.Y.Z-windows-amd64.zip`
   - مک (Intel): `relay-tunnel-vX.Y.Z-darwin-amd64.tar.gz`
   - مک (Apple Silicon / M1/M2/M3): `relay-tunnel-vX.Y.Z-darwin-arm64.tar.gz`
   - لینوکس: `relay-tunnel-vX.Y.Z-linux-amd64.tar.gz`
۳. آن را extract کنید. داخلش `relay-client`، `relay-server`، فایل‌های نمونه‌ی کانفیگ و سورس Apps Script را می‌بینید.

می‌توانید وارد همان پوشه شوید و بقیه‌ی مراحل را از آنجا ادامه دهید — همه‌ی دستورهای پایین به‌همان شکل کار می‌کنند.

**گزینه‌ی ب — ساخت از سورس (Go نسخه‌ی ۱.۲۲ یا بالاتر):**

```bash
git clone https://github.com/kianmhz/relay-tunnel.git
cd relay-tunnel
go build -o relay-client ./cmd/client
go build -o relay-server ./cmd/server
```

یا با Makefile همراه پروژه: `make build` (باینری‌ها در پوشه‌ی `bin/` ساخته می‌شوند).

### مرحله ۳: ساخت کلید AES-256

```bash
bash scripts/gen-key.sh
```

رشته‌ی hex با ۶۴ کاراکتر را کپی کنید. در مرحله‌ی بعد همین مقدار را در **هر دو** فایل کانفیگ paste می‌کنید. این تنها مکانیزم احراز هویت بین کلاینت و سرور است — مراقب آن باشید.

### مرحله ۴: تنظیم کانفیگ

ابتدا فایل‌های نمونه را کپی کنید:

```bash
cp client_config.example.json client_config.json
cp server_config.example.json   server_config.json
```

هر دو را باز کنید و رشته‌ی hex را در فیلد `tunnel_key` (در کلاینت) و `tunnel_key` (در سرور) قرار دهید. مقدار `script_key` را فعلاً خالی بگذارید — بعد از مرحله‌ی ۵ آن را پر می‌کنید.

`client_config.json`:

```json
{
  "socks_host":  "127.0.0.1",
  "socks_port":  1080,
  "google_host": "216.239.38.120",
  "sni":         "www.google.com",
  "script_key":  "PASTE_DEPLOYMENT_ID_ONLY",
  "script_keys": ["OPTIONAL_SECOND_DEPLOYMENT_ID", "OPTIONAL_THIRD_DEPLOYMENT_ID"],
  "tunnel_key":  "PASTE_OUTPUT_OF_GEN_KEY"
}
```

`server_config.json`:

```json
{
  "server_host": "0.0.0.0",
  "server_port": 8443,
  "tunnel_key": "SAME_VALUE_AS_CLIENT"
}
```

### مرحله ۵: deploy کردن forwarder روی Apps Script

این بخش همان پل ساده‌ای است که ترافیک شما را شبیه ترافیک گوگل نشان می‌دهد.

1. وارد [Google Apps Script](https://script.google.com/) شوید.
2. روی **New project** کلیک کنید.
3. کد پیش‌فرض را کاملاً حذف کنید.
4. فایل [`apps_script/Code.gs`](apps_script/Code.gs) همین پروژه را باز کنید، همه‌ی محتوای آن را کپی کنید و در ویرایشگر Apps Script paste کنید.
5. این خط را به IP دراپلت خودتان تغییر دهید:
   ```javascript
   const DO_URL = 'http://YOUR.DROPLET.IP:8443/tunnel';
   ```
6. روی **Deploy → New deployment** کلیک کنید (آیکون چرخ‌دنده → **Web app**).
7. این تنظیمات را انتخاب کنید:
   - **Execute as:** Me
   - **Who has access:** Anyone
8. روی **Deploy** بزنید و Deployment ID را از آدرس `/exec` بردارید (بخشی که بین `/s/` و `/exec` است).
9. این مقدار را در فیلد `script_key` فایل `client_config.json` paste کنید. اگر چند deployment دارید، بقیه را در `script_keys` قرار دهید.

> ⚠️ **ویرایش اسکریپت، نسخه‌ی فعال را به‌روزرسانی نمی‌کند.** هر بار که `Code.gs` را تغییر می‌دهید باید **یک deployment جدید** بسازید و `script_key`/`script_keys` را در کانفیگ کلاینت به‌روزرسانی کنید.

تست deployment:

```bash
curl "$YOUR_SCRIPT_URL"
# باید چاپ کند: relay-tunnel forwarder OK
```

### مرحله ۶: deploy کردن سرور خروجی

یک اسکریپت کمکی، باینری لینوکس را می‌سازد، روی دراپلت کپی می‌کند و یک systemd unit نصب می‌کند:

```bash
bash scripts/deploy.sh user@your.droplet.ip
```

تأیید کنید که سرور بالا است:

```bash
curl http://your.droplet.ip:8443/healthz   # HTTP 200، body خالی
```

### مرحله ۷: اجرای کلاینت روی کامپیوتر محلی

```bash
./relay-client -config client_config.json
```

باید این پیام را ببینید:

```
[client] SOCKS5 listening on 127.0.0.1:1080
```

### مرحله ۸: استفاده

تست سریع:

```bash
curl -x socks5h://127.0.0.1:1080 https://api.ipify.org
```

این دستور باید **IP دراپلت شما** را چاپ کند، نه IP خانگی‌تان.

مرورگر/سیستم خود را روی پراکسی SOCKS5 آدرس `127.0.0.1:1080` تنظیم کنید. **حتماً از `socks5h://` استفاده کنید** (نه `socks5://`) تا DNS هم از تونل عبور کند — در غیر این صورت نام دامنه‌ها در شبکه‌ی محلی شما resolve می‌شود و پراکسی هرگز آن‌ها را نمی‌بیند.

- **Firefox:** Settings → Network Settings → Manual proxy → SOCKS5 host `127.0.0.1` port `1080`. گزینه‌ی **Proxy DNS when using SOCKS v5** را فعال کنید.
- **Chrome/Edge:** از یک افزونه‌ی proxy-switcher استفاده کنید (FoxyProxy، SwitchyOmega). تنظیمات پراکسی پیش‌فرض سیستم‌عامل به‌خوبی با SOCKS5h و remote DNS کار نمی‌کنند.
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
  "script_key":  "PRIMARY_DEPLOYMENT_ID",
  "script_keys": [
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
| `script_key` | — | Deployment ID اصلی Apps Script (بدون URL کامل). |
| `script_keys` | — | Deployment IDهای اضافه برای load balancing سلامت‌محور و پخش quota. |
| `tunnel_key` | — | کلید AES-256 به‌صورت hex (۶۴ کاراکتر) که باید با سرور یکسان باشد. |

### سرور (`server_config.json`)

| فیلد | مقدار پیش‌فرض | توضیح |
|---|---|---|
| `server_host` | `0.0.0.0` | میزبان/IP که سرور خروجی روی آن bind می‌شود. |
| `server_port` | `8443` | پورتی که سرور خروجی روی آن گوش می‌دهد. باید از شبکه‌ی گوگل قابل دسترسی باشد. |
| `tunnel_key` | — | کلید AES-256 به‌صورت hex. باید با کلاینت یکسان باشد. |

---

## به‌روزرسانی forwarder روی Apps Script

اگر `Code.gs` را تغییر دادید — مثلاً برای تغییر IP دراپلت — باید در ویرایشگر Apps Script یک **deployment جدید** بسازید (Deploy → **New deployment**، نه فقط "Manage deployments"). صرفاً ذخیره کردن کد، نسخه‌ی فعال را عوض نمی‌کند؛ آدرس `/exec` همچنان نسخه‌ی منتشرشده‌ی قبلی را سرو می‌کند. بعد از deploy جدید، `script_key`/`script_keys` را در `client_config.json` به‌روزرسانی کنید.

---

## معماری

```
┌─────────┐   ┌──────────────┐   ┌──────────────┐   ┌─────────────┐   ┌──────────┐
│ مرورگر  │──►│ relay-client │──►│ لبه‌ی گوگل   │──►│ Apps Script │──►│  VPS     │──► اینترنت
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
relay-tunnel/
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
│   └── relay-tunnel.service        # template برای systemd unit
├── client_config.example.json
└── server_config.example.json
```

---

## رفع مشکل

| مشکل | راه‌حل |
|---|---|
| لاگ می‌گوید `decode batch: ... base64 ...` | Apps Script به‌جای batch رمزشده یک صفحه‌ی HTML برگردانده. یا deployment داخل `script_key`/`script_keys` زنده نیست، یا گزینه‌ی **Who has access** روی `Anyone` تنظیم نشده. یک **deployment جدید** بسازید و `script_key`/`script_keys` را در `client_config.json` به‌روزرسانی کنید. |
| لاگ می‌گوید `relay returned HTTP 404 via …` | همان مشکل بالا — Deployment ID داخل کانفیگ شما با `/exec` زنده‌ای مطابقت ندارد. دوباره deploy کنید و کانفیگ را به‌روزرسانی کنید. |
| لاگ می‌گوید `relay returned HTTP 500 via …` | Apps Script نمی‌تواند به `DO_URL` برسد. IP داخل `Code.gs` را چک کنید، اطمینان حاصل کنید VPS بالا است و TCP/8443 ورودی باز است. `curl http://your.vps.ip:8443/healthz` باید 200 برگرداند. |
| لاگ می‌گوید `relay request failed via …: timeout` | اتصال fronted به گوگل fail می‌شود. یک `google_host` دیگر امتحان کنید — هر 216.239.x.120 که گوگل سرویس می‌دهد کار می‌کند. |
| مرورگر روی هر درخواست hang می‌کند | از `socks5://` به‌جای `socks5h://` استفاده می‌کنید. حالت بدون `h` نام‌ها را به‌صورت محلی resolve می‌کند و پراکسی فقط IP خام دریافت می‌کند. |
| `[exit] dial X: ... timeout` در لاگ VPS | مقصد، IPهای دیتاسنتر را بلاک می‌کند یا VPS شما برای آن پورت اتصال خروجی ندارد. |
| سایت‌های پشت Cloudflare کپچا می‌خواهند | طبیعی است. IP دراپلت شما روی ASN دیتاسنتر است (DigitalOcean = AS14061) و bot scoring کلودفلر آن را علامت می‌زند. این مشکل تونل نیست. |
| یوتیوب در ۱۰۸۰p بافر می‌کند | طبیعی است. تونل به‌خاطر overhead فراخوانی Apps Script حدود ۳۰۰–۸۰۰ میلی‌ثانیه به هر round trip اضافه می‌کند. کیفیت ۴۸۰p روان است. اضافه کردن چند Deployment ID در `script_keys` (بخش بالا) به throughput پایدار کمک می‌کند. |
| یک deployment وسط کار به سهمیه می‌رسد | اگر در `script_keys` deploymentهای دیگری دارید، کلاینت به‌صورت خودکار چند ثانیه بلک‌لیستش می‌کند و از بقیه ادامه می‌دهد. اگر فقط یک `script_key` دارید، browsing تا reset سهمیه (~۱۰:۳۰ صبح به وقت ایران / نیمه‌شب Pacific) متوقف می‌ماند. |
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

## License

MIT
