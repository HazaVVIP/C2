# 🔍 GitHunt — GitHub Credential Exposure Crawler

Tools untuk **authorized security research** — menelusuri GitHub dan mendeteksi kredensial yang tidak sengaja ter-expose.

## Cara Pakai

```bash
# Install dependencies
pip install -r requirements.txt

# Basic scan (input token sekali di awal)
python githunt.py --keyword "komdigi.go.id" --token ghp_YOUR_TOKEN

# Setelah token tersimpan, cukup jalankan:
python githunt.py --keyword "komdigi.go.id"

# Deep scan (termasuk commit history)
python githunt.py --keyword "komdigi.go.id" --token ghp_YOUR_TOKEN --deep

# Output HTML report ke folder tertentu
python githunt.py --keyword "komdigi.go.id" --output html --output-dir ./reports

# Tingkatkan konkurensi untuk scan lebih cepat
python githunt.py --keyword "komdigi.go.id" --concurrency 20

# Mode verbose (debug logging)
python githunt.py --keyword "komdigi.go.id" --verbose
```

## Opsi

| Flag | Deskripsi | Default |
|------|-----------|---------|
| `--keyword` | Kata kunci pencarian | *required* |
| `--token` | GitHub Personal Access Token (wajib saat pertama kali) | *opsional setelah tersimpan* |
| `--output` | Format output: json, csv, html | json |
| `--output-dir` | Direktori untuk menyimpan report | `.` (current dir) |
| `--max-repos` | Maks repo yang di-crawl | 50 |
| `--concurrency` | Jumlah async HTTP request paralel | 10 |
| `--deep` | Scan commit history juga | off |
| `--validate` | Cek apakah credential masih aktif | off |
| `--verbose` | Tampilkan debug log | off |

## Flow

```
keyword input
    │
    ├─→ GitHub Search API (repositories)  ─┐
    ├─→ GitHub Code Search API (files)    ─┤ asyncio.gather (parallel)
    │                                       ┘
    ▼
Crawl tiap repo (aiohttp + asyncio)
    ├─→ List file tree (rekursif, concurrent)
    ├─→ Fetch semua file menarik secara paralel (asyncio.gather)
    └─→ [--deep] Commit history diff (paralel per commit)
    │
    ▼
Scan tiap file (CredentialScanner)
    ├─→ 45+ regex patterns (AWS, GCP, Stripe, JWT, dll.)
    ├─→ Shannon entropy filter (kurangi false positive)
    ├─→ Indonesia-specific (Midtrans, Xendit, DOKU)
    ├─→ False-positive filter (placeholder, comment lines)
    └─→ Redact nilai sensitif untuk logging aman
    │
    ▼
Report (JSON / CSV / HTML)
    └─→ HTML: semua field di-escape (mencegah XSS)
```

## Pattern yang Dideteksi

- **Cloud**: AWS Keys, GCP Service Account, Azure Storage
- **Payment**: Stripe, PayPal/Braintree, Midtrans, Xendit, DOKU
- **Communication**: Twilio, SendGrid, Mailgun, Slack, Discord, Telegram
- **Git & CI/CD**: GitHub PAT/OAuth/App, GitLab Token, npm Auth Token, CircleCI
- **Cloud Platforms**: Heroku, DigitalOcean, Cloudflare, Firebase, Shopify
- **Database**: MySQL/Postgres/MongoDB connection strings
- **Keys**: RSA, EC, PGP, OpenSSH, PKCS8 private keys
- **Generic**: API keys, passwords, tokens, JWT

## Shannon Entropy Filter

Setiap pattern dengan `min_entropy > 0` akan menolak match yang nilai entropynya
terlalu rendah (nilai berulang / template seperti `AAAAAAAAAAAAAAAA`), sehingga
false positive berkurang secara signifikan.

## Teknologi

| Library | Kegunaan |
|---------|---------|
| `aiohttp` | Async HTTP client — semua request ke GitHub API |
| `asyncio` | Event loop untuk konkurensi penuh |
| `rich` | Progress bar, colored output, summary table |
| `re` + `math` | Regex pattern matching + Shannon entropy |

## GitHub Token

Buat token di: https://github.com/settings/tokens
Scope yang dibutuhkan: `public_repo` (read-only cukup)

Token akan disimpan otomatis di `~/.githunt_token` setelah input pertama,
sehingga penggunaan berikutnya tidak perlu `--token`. Jika ingin mengganti token,
hapus file tersebut lalu jalankan ulang dengan `--token`.

## ⚠️ Disclaimer

Tools ini hanya untuk **authorized security research** dan **responsible disclosure**.
Penggunaan terhadap sistem tanpa izin melanggar hukum.
