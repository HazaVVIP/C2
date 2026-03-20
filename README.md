# 🔍 GitHunt — GitHub Credential Exposure Crawler

Tools untuk **authorized security research** — menelusuri GitHub dan mendeteksi kredensial yang tidak sengaja ter-expose.

> 📖 **Panduan lengkap, rekomendasi dork, dan tips penggunaan ada di [USAGE.md](USAGE.md).**

## Cara Pakai

```bash
# Install dependencies
pip install -r requirements.txt

# Basic scan (input token sekali di awal)
python githunt.py --keyword "komdigi.go.id" --token ghp_YOUR_TOKEN

# Setelah token tersimpan, cukup jalankan:
python githunt.py --keyword "komdigi.go.id"

# Deep scan (termasuk commit history DAN gists publik)
python githunt.py --keyword "komdigi.go.id" --token ghp_YOUR_TOKEN --deep

# Validasi apakah credential yang ditemukan masih aktif
python githunt.py --keyword "komdigi.go.id" --validate

# Multi-keyword dari file (satu keyword per baris, # untuk komentar)
python githunt.py --keywords-file targets.txt

# Output HTML report ke folder tertentu
python githunt.py --keyword "komdigi.go.id" --output html --output-dir ./reports

# Output SARIF (untuk GitHub Advanced Security / CI/CD integration)
python githunt.py --keyword "komdigi.go.id" --output sarif --output-dir ./reports

# Output Markdown (untuk GitHub Issues / Slack)
python githunt.py --keyword "komdigi.go.id" --output markdown

# Tingkatkan konkurensi untuk scan lebih cepat
python githunt.py --keyword "komdigi.go.id" --concurrency 20

# Mode verbose (debug logging)
python githunt.py --keyword "komdigi.go.id" --verbose
```

## Opsi

| Flag | Deskripsi | Default |
|------|-----------|---------|
| `--keyword` | Kata kunci pencarian (mutual exclusive dengan `--keywords-file`) | *required* |
| `--keywords-file` | File teks berisi daftar keyword (satu per baris, `#` = komentar) | *opsional* |
| `--token` | GitHub Personal Access Token (wajib saat pertama kali) | *opsional setelah tersimpan* |
| `--output` | Format output: `json`, `csv`, `html`, `sarif`, `markdown` | json |
| `--output-dir` | Direktori untuk menyimpan report | `.` (current dir) |
| `--max-repos` | Maks repo yang di-crawl | 50 |
| `--concurrency` | Jumlah async HTTP request paralel | 10 |
| `--deep` | Scan commit history + gists publik (semua teknik) | off |
| `--validate` | Validasi apakah credential masih aktif | off |
| `--verbose` | Tampilkan debug log | off |

## Flow

```
keyword input (tunggal atau file)
    │
    ├─→ GitHub Search API (repositories)  ─┐
    ├─→ GitHub Code Search API (files)    ─┤ asyncio.gather (parallel)
    └─→ [--deep] Gist Search              ─┘
    │
    ▼
Crawl tiap repo (aiohttp + asyncio)
    ├─→ List file tree (rekursif, concurrent)
    ├─→ Fetch semua file menarik secara paralel (asyncio.gather)
    └─→ [--deep] Commit history diff (paralel per commit)
    │
    ▼
Scan tiap file (CredentialScanner)
    ├─→ 63+ regex patterns (AWS, GCP, Stripe, OpenAI, dll.)
    ├─→ Shannon entropy filter (kurangi false positive)
    ├─→ Indonesia-specific (Midtrans, Xendit, DOKU)
    ├─→ False-positive filter (placeholder, comment lines)
    └─→ Redact nilai sensitif untuk logging aman
    │
    ▼
[--validate] Credential Validation (CredentialValidator)
    ├─→ GitHub tokens → GET /user
    ├─→ Stripe keys   → GET /v1/account
    ├─→ Slack tokens  → POST /api/auth.test
    ├─→ SendGrid keys → GET /v3/scopes
    └─→ GitLab tokens → GET /api/v4/user
    │
    ▼
Report (JSON / CSV / HTML / SARIF / Markdown)
    ├─→ HTML: semua field di-escape (mencegah XSS)
    └─→ SARIF: kompatibel dengan GitHub Advanced Security & Code Scanning
```

## Pattern yang Dideteksi (63+)

- **Cloud**: AWS Keys, GCP Service Account, Azure Storage, Azure Client Secret, Alibaba Cloud
- **Payment**: Stripe, PayPal/Braintree, Midtrans, Xendit, DOKU
- **Communication**: Twilio, SendGrid, Mailgun, Slack, Discord, Telegram
- **Git & CI/CD**: GitHub PAT/OAuth/App, GitLab Token, npm Auth Token, CircleCI
- **Cloud Platforms**: Heroku, DigitalOcean, Cloudflare, Firebase, Shopify, LaunchDarkly
- **Database**: MySQL/Postgres/MongoDB connection strings
- **Keys**: RSA, EC, PGP, OpenSSH, PKCS8 private keys
- **AI/ML**: OpenAI, Anthropic, Hugging Face
- **Observability**: Datadog, New Relic, Grafana, PagerDuty
- **Identity/Access**: Okta, Atlassian, HashiCorp Vault
- **Project Mgmt**: Linear
- **Generic**: API keys, passwords, tokens, JWT

## Shannon Entropy Filter

Setiap pattern dengan `min_entropy > 0` akan menolak match yang nilai entropynya
terlalu rendah (nilai berulang / template seperti `AAAAAAAAAAAAAAAA`), sehingga
false positive berkurang secara signifikan.

## SARIF Output (Enterprise CI/CD)

Format SARIF 2.1.0 digunakan untuk integrasi dengan:
- **GitHub Advanced Security / Code Scanning** — upload via `github/codeql-action/upload-sarif`
- **Azure DevOps** — compatible dengan SARIF viewer
- **IDE plugins** — VS Code, IntelliJ SARIF viewers
- **Custom SAST pipelines**

```yaml
# Contoh GitHub Actions workflow
- name: Run GitHunt
  run: python githunt.py --keyword "${{ env.TARGET }}" --output sarif --output-dir ./results

- name: Upload SARIF results
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ./results/
```

## Credential Validation (`--validate`)

Saat flag `--validate` aktif, setiap finding akan diverifikasi langsung ke API
provider-nya untuk mengonfirmasi apakah credential masih aktif:

| Provider | Metode Validasi | Status Mungkin |
|----------|----------------|----------------|
| GitHub | `GET /user` dengan token | VALID, INVALID, RATE_LIMITED |
| GitLab | `GET /api/v4/user` | VALID, INVALID, RATE_LIMITED |
| Stripe | `GET /v1/account` | VALID, INVALID |
| Slack  | `POST /api/auth.test` | VALID, INVALID |
| SendGrid | `GET /v3/scopes` | VALID, INVALID |
| Others | — | UNKNOWN |

Status validasi akan tampil di semua format report.

## Multi-Keyword Scan (`--keywords-file`)

```
# targets.txt
# scan multiple targets in one run

komdigi.go.id
bumn.go.id
kemenkes.go.id
```

```bash
python githunt.py --keywords-file targets.txt --output sarif --output-dir ./results
```

## Teknologi

| Library | Kegunaan |
|---------|---------|
| `aiohttp` | Async HTTP client — semua request ke GitHub API & validasi |
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

