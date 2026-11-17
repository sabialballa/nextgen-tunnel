# Nextgen Tunnel

مدیر تانل با Go برای چند سرویس TCP/UDP، با TLS 1.3 دوطرفه و دو مسیر QUIC و TLS/TCP. این نسخهٔ محلی هنوز آمادهٔ انتشار Production اعلام نشده است؛ محدودیت‌ها و آزمون‌های باقی‌مانده در [وضعیت پروژه](docs/STATUS.md) ثبت می‌شوند.

## ساخت و تست

```sh
go mod download
go test ./...
go vet ./...
go build -trimpath -o dist/nextgen-tunnel ./cmd/nextgen-tunnel
python3 -m unittest discover -s tests -v
python3 scripts/local_lab.py --binary ./dist/nextgen-tunnel --output docs/evidence/local-lab.json
```

Go 1.26 حداقل زبان است؛ آزمایش محلی نهایی با Go 1.27.4 انجام می‌شود. برای تولید باید اسکن امنیتی پاس شود. آزمایشگاه محلی baseline مستقیم، پروسه‌های واقعی، TCP/UDP، چند اتصال و قطع پروسهٔ اصلی دارد. نتیجهٔ loopback معادل کارایی یا عبور از DPI ایران نیست.

## اتصال

```sh
nextgen-tunnel pki -dir ./private-pki -server-name tunnel.internal -client-name entry
```

CA خصوصی را آفلاین نگه دارید. به سرور فقط `ca.crt`، `server.crt` و `server.key`؛ به کلاینت فقط `ca.crt`، `client.crt` و `client.key` بدهید. کلیدها را با کانال امن منتقل کنید. مسیرهای مطلق و مقصد سرویس‌ها را در [نمونهٔ سرور](configs/examples/server.json) و [نمونهٔ کلاینت](configs/examples/client.json) اصلاح کنید. IP نمونه متعلق به شبکهٔ مستنداتی است.

```sh
nextgen-tunnel check -config /absolute/path/server.json
nextgen-tunnel run -config /absolute/path/server.json
nextgen-tunnel run -config /absolute/path/client.json
nextgen-tunnel probe -config /absolute/path/client.json
nextgen-tunnel status -config /absolute/path/client.json
nextgen-tunnel menu -config /absolute/path/client.json
```

فرمان‌های `run` را در ترمینال‌های جدا یا با systemd اجرا کنید. `check` فقط تنظیمات و فایل‌های TLS را بارگذاری می‌کند و معادل تست اتصال نیست. فقط سرویس‌های allowlist سرور قابل دسترسی‌اند. ورودی‌های کلاینت فقط روی loopback باز می‌شوند. چند سرویس روی یک manager پشتیبانی می‌شود؛ هر flow اتصال حامل مستقل دارد. برای انتخاب دستی فقط یک endpoint بگذارید. ترتیب endpointها ترجیح اولیه است؛ مسیر سالم خودکار به مسیر اول برنمی‌گردد.

UDP حداکثر payload برابر **1150 بایت** دارد؛ بستهٔ بزرگ‌تر شمارش و حذف می‌شود. مسیر TLS/TCP دچار head-of-line blocking می‌شود. sessionهای موجود هنگام تغییر حامل مهاجرت نمی‌کنند. ALPN و framing اختصاصی قابل شناسایی‌اند؛ شبیه‌سازی مرورگر و مقاومت اثبات‌شده در برابر DPI/active probing ادعا نمی‌شود.

## نصب آفلاین روی Linux

```sh
sh scripts/install.sh --binary ./dist/nextgen-tunnel-linux-amd64 --sha256 TRUSTED_SHA256 --config ./server.json
sudo sh scripts/install.sh --binary ./dist/nextgen-tunnel-linux-amd64 --sha256 TRUSTED_SHA256 --config ./server.json --apply
```

دستور اول فقط preflight است. نصب‌کننده route، firewall، sysctl و VPNهای دیگر را تغییر نمی‌دهد. پورت انتخابی TCP/UDP را در فایروال فعلی جداگانه بررسی کنید. نصب واقعی، rollback، recover و reboot روی Debian 12 آزمایش شده‌اند؛ نتیجه به تمام توزیع‌ها تعمیم داده نمی‌شود.

در بستهٔ آفلاینِ استخراج‌شده، باینری در `bin/nextgen-tunnel` است؛ مسیر `dist/` بالا مربوط به پوشهٔ توسعه است. ابتدا checksum آرشیو را با مقدار مورد اعتماد تطبیق دهید و سپس داخل بسته `sha256sum -c SHA256SUMS` را اجرا کنید. SHA256 باینری در همان manifest درج شده است. نصب از بسته:

```sh
sudo sh scripts/install.sh --binary ./bin/nextgen-tunnel --sha256 BINARY_SHA256_FROM_MANIFEST --config /absolute/path/server.json --apply
```

در Windows، باینری `bin/nextgen-tunnel.exe` برای CLI و آزمایشگاه محلی است؛ نصب‌کنندهٔ systemd فقط روی Linux اجرا می‌شود.

- [معماری](docs/architecture.md)
- [تحقیق پروتکل‌ها](docs/research.md)
- [نصب و بازیابی](docs/installation.md)
- [امنیت](docs/security.md)
- [Benchmark](docs/benchmark.md)
- [رفع اشکال](docs/troubleshooting.md)

TUN دوپشته، DNS، Hysteria2/REALITY و Site-to-Site مبتنی بر WireGuard در Linux محلی تست شدند؛ [راهنمای engine و site](docs/engine-site.md) را بخوانید. پذیرش میدانی ایران–ترکیه پاس نشده و نصب دائمی یکپارچهٔ engine/site و مقایسهٔ همهٔ پروتکل‌های درخواست اولیه تکمیل نیستند. [وضعیت دقیق](docs/STATUS.md) ملاک اعتبار نسخهٔ `0.2.0-dev` است. ابزار قبلی مسیر مستقلی دارد و [راهنمایش](docs/legacy-deployment.md) حفظ شده است.
