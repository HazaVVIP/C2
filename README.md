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

# Output HTML report
python githunt.py --keyword "komdigi.go.id" --token ghp_YOUR_TOKEN --output html
```

## Opsi

| Flag | Deskripsi | Default |
|------|-----------|---------|
| `--keyword` | Kata kunci pencarian | *required* |
| `--token` | GitHub Personal Access Token (wajib saat pertama kali) | *opsional setelah tersimpan* |
| `--output` | Format output: json, csv, html | json |
| `--max-repos` | Maks repo yang di-crawl | 50 |
| `--deep` | Scan commit history juga | off |
| `--validate` | Cek apakah credential masih aktif | off |

## Flow

```
keyword input
    │
    ├─→ GitHub Search API (repositories)
    ├─→ GitHub Code Search API (file-level)
    │
    ▼
Crawl tiap repo
    ├─→ List file tree (rekursif)
    ├─→ Filter file menarik (.env, .config, .py, dll.)
    └─→ [--deep] Commit history diff
    │
    ▼
Scan tiap file
    ├─→ 30+ regex patterns (AWS, GCP, Stripe, JWT, dll.)
    ├─→ Indonesia-specific (Midtrans, Xendit, DOKU)
    ├─→ False-positive filter
    └─→ Redact nilai sensitif untuk logging aman
    │
    ▼
Report (JSON / CSV / HTML)
```

## Pattern yang Dideteksi

- **Cloud**: AWS Keys, GCP Service Account, Azure Storage
- **Payment**: Stripe, PayPal/Braintree, Midtrans, Xendit, DOKU
- **Communication**: Twilio, SendGrid, Mailgun
- **Git**: GitHub PAT, GitHub OAuth, GitLab Token
- **Database**: MySQL/Postgres/MongoDB connection strings
- **Keys**: RSA, EC, PGP, OpenSSH private keys
- **Generic**: API keys, passwords, tokens, JWT

## GitHub Token

Buat token di: https://github.com/settings/tokens
Scope yang dibutuhkan: `public_repo` (read-only cukup)

Token akan disimpan otomatis di `~/.githunt_token` setelah input pertama,
sehingga penggunaan berikutnya tidak perlu `--token`. Jika ingin mengganti token,
hapus file tersebut lalu jalankan ulang dengan `--token`.

## ⚠️ Disclaimer

Tools ini hanya untuk **authorized security research** dan **responsible disclosure**.
Penggunaan terhadap sistem tanpa izin melanggar hukum.
