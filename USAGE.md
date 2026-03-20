# 📖 GitHunt — Panduan Penggunaan & Rekomendasi Dork

Dokumen ini menjelaskan cara menggunakan GitHunt secara optimal, termasuk
rekomendasi dork, skenario nyata, dan tips untuk meminimalkan false-positive
sekaligus memaksimalkan hasil temuan.

---

## Daftar Isi

1. [Persiapan Awal](#1-persiapan-awal)
2. [Konsep Dasar Dork](#2-konsep-dasar-dork)
3. [Rekomendasi Dork per Kategori Target](#3-rekomendasi-dork-per-kategori-target)
   - [Pemerintah & Instansi Publik Indonesia](#31-pemerintah--instansi-publik-indonesia)
   - [Perusahaan Swasta & Startup](#32-perusahaan-swasta--startup)
   - [Platform Payment & Fintech](#33-platform-payment--fintech)
   - [Cloud & Infrastruktur](#34-cloud--infrastruktur)
   - [Database & Connection String](#35-database--connection-string)
4. [Strategi Scan Bertingkat](#4-strategi-scan-bertingkat)
5. [Multi-Keyword Scan (`--keywords-file`)](#5-multi-keyword-scan---keywords-file)
6. [Mode Deep Scan (`--deep`)](#6-mode-deep-scan---deep)
7. [Validasi Credential (`--validate`)](#7-validasi-credential---validate)
8. [Format Output & Integrasi](#8-format-output--integrasi)
9. [Tips Memaksimalkan Kinerja](#9-tips-memaksimalkan-kinerja)
10. [Mengurangi False-Positive](#10-mengurangi-false-positive)
11. [Contoh Skenario End-to-End](#11-contoh-skenario-end-to-end)
12. [Pengelolaan Token](#12-pengelolaan-token)

---

## 1. Persiapan Awal

```bash
# 1. Clone repo & masuk ke direktori
git clone https://github.com/HazaVVIP/C2.git && cd C2  # tools GitHunt ada di repo ini

# 2. Install dependencies
pip install -r requirements.txt

# 3. Buat GitHub Personal Access Token (PAT)
#    Kunjungi: https://github.com/settings/tokens
#    Pilih scope: public_repo  (read-only sudah cukup)

# 4. Jalankan pertama kali — token akan disimpan otomatis
python githunt.py --keyword "example.com" --token ghp_YOUR_TOKEN
```

Setelah token tersimpan di `~/.githunt_token`, flag `--token` tidak perlu
diulang lagi pada run berikutnya.

---

## 2. Konsep Dasar Dork

GitHunt menggunakan **GitHub Code Search** dan **Repository Search** API.
Pilihan keyword (dork) yang tepat menentukan kualitas hasil temuan.

| Prinsip | Penjelasan |
|---------|-----------|
| **Spesifik domain** | Gunakan domain lengkap (`bpjs.go.id`) — lebih sedikit noise |
| **Substring unik** | Bagian unik dari nama perusahaan/sistem (`bpjsketenagakerjaan`) |
| **Nama env-var internal** | Variabel env yang khas (`PROD_DB_HOST`, `STAGING_KEY`) jika diketahui |
| **Nama layanan internal** | Nama microservice / produk internal (`payment-service-prod`) |
| **Kombinasi keyword** | Jalankan beberapa keyword berbeda untuk satu target |

---

## 3. Rekomendasi Dork per Kategori Target

### 3.1 Pemerintah & Instansi Publik Indonesia

```
komdigi.go.id
kominfo.go.id
kemenkes.go.id
kemenkeu.go.id
kemendikbud.go.id
bpk.go.id
bpjs.go.id
bpjsketenagakerjaan
ojk.go.id
bi.go.id
kpu.go.id
lapan.go.id
bssn.go.id
ppatk.go.id
kemenkumham.go.id
bkn.go.id
lkpp.go.id
bnpb.go.id
basarnas.go.id
polri.go.id
```

> **Catatan:** Gunakan subdomain jika diketahui (`api.kemenkes.go.id`) untuk
> hasil yang lebih tertarget.

### 3.2 Perusahaan Swasta & Startup

```
tokopedia.com
bukalapak.com
gojek.com
grab.com
traveloka.com
tiket.com
blibli.com
shopee.co.id
lazada.co.id
ovo.id
dana.id
linkaja.id
kredivo.com
akulaku.com
bibit.id
stockbit.com
```

### 3.3 Platform Payment & Fintech

Keyword ini berguna untuk menemukan integrasi payment gateway yang tidak
sengaja ter-commit:

```
midtrans
midtrans_server_key
midtrans_client_key
xendit
xendit_secret_key
DOKU
DOKU_MERCHANT
flip.id
nicepay
iPaymu
veritrans
```

### 3.4 Cloud & Infrastruktur

```
AKIAIOSFODNN7EXAMPLE
aws_access_key_id
aws_secret_access_key
GOOGLE_APPLICATION_CREDENTIALS
gcp_service_account
AZURE_CLIENT_SECRET
AZURE_STORAGE_CONNECTION_STRING
DO_AUTH_TOKEN
digitalocean_token
heroku_api_key
cloudflare_api_token
cloudflare_global_api_key
firebase_api_key
FIREBASE_SERVICE_ACCOUNT
```

### 3.5 Database & Connection String

```
mongodb+srv://
postgresql://
mysql://
redis://
DATABASE_URL
DB_PASSWORD
MONGO_URI
REDIS_URL
```

---

## 4. Strategi Scan Bertingkat

Lakukan scan secara bertahap untuk efisiensi:

```bash
# Tahap 1 — Quick scan (default): 50 repo, 10 concurrency
python githunt.py --keyword "komdigi.go.id"

# Tahap 2 — Perluas jangkauan: naikkan max-repos
python githunt.py --keyword "komdigi.go.id" --max-repos 200

# Tahap 3 — Deep scan: commit history + gists
python githunt.py --keyword "komdigi.go.id" --max-repos 200 --deep

# Tahap 4 — Validasi semua temuan
python githunt.py --keyword "komdigi.go.id" --max-repos 200 --deep --validate
```

---

## 5. Multi-Keyword Scan (`--keywords-file`)

Buat file teks dengan satu keyword per baris. Baris yang diawali `#` diabaikan.

```
# targets.txt

# Instansi pemerintah
komdigi.go.id
kemenkes.go.id
bpjs.go.id

# Fintech
ovo.id
dana.id
linkaja.id

# Payment gateway
midtrans
xendit
```

```bash
# Jalankan semua keyword sekaligus
python githunt.py --keywords-file targets.txt --output html --output-dir ./reports

# Deep scan + validasi untuk semua keyword
python githunt.py --keywords-file targets.txt --deep --validate --output sarif --output-dir ./results
```

---

## 6. Mode Deep Scan (`--deep`)

Flag `--deep` mengaktifkan dua teknik tambahan:

| Teknik | Keterangan |
|--------|-----------|
| **Commit history** | Menelusuri diff setiap commit — menemukan credential yang sudah dihapus dari kode tetapi masih ada di riwayat |
| **Gist publik** | Mencari di Gist milik user yang terkait keyword |

```bash
# Contoh: scan history & gist untuk target payment
python githunt.py --keyword "midtrans_server_key" --deep --max-repos 100
```

> ⚠️ Mode `--deep` secara signifikan meningkatkan jumlah API request.
> Gunakan `--concurrency` yang wajar (10–20) untuk menghindari rate-limit.

---

## 7. Validasi Credential (`--validate`)

Setelah menemukan credential, gunakan `--validate` untuk mengonfirmasi apakah
masih aktif sebelum melaporkan ke pemilik sistem.

```bash
python githunt.py --keyword "komdigi.go.id" --validate
```

Credential yang sudah tidak aktif akan ditandai `INVALID`, sehingga laporan
lebih fokus pada risiko nyata.

---

## 8. Format Output & Integrasi

### HTML Report (untuk presentasi / pentest report)

```bash
python githunt.py --keyword "target.go.id" --output html --output-dir ./reports
# Hasilkan: ./reports/githunt_report_<timestamp>.html
```

### CSV (untuk analisis di spreadsheet)

```bash
python githunt.py --keyword "target.go.id" --output csv --output-dir ./reports
```

### Markdown (untuk GitHub Issues / Slack)

```bash
python githunt.py --keyword "target.go.id" --output markdown
```

### SARIF (untuk CI/CD & GitHub Advanced Security)

```bash
python githunt.py --keyword "target.go.id" --output sarif --output-dir ./results
```

Contoh integrasi GitHub Actions:

```yaml
- name: Run GitHunt
  run: python githunt.py --keyword "${{ env.TARGET }}" --output sarif --output-dir ./results

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ./results/
```

---

## 9. Tips Memaksimalkan Kinerja

| Tips | Perintah |
|------|---------|
| Naikkan konkurensi (jaringan cepat) | `--concurrency 20` |
| Perluas cakupan repo | `--max-repos 500` |
| Kombinasikan multiple keyword sekaligus | `--keywords-file` |
| Jalankan di background (Linux/macOS) | `nohup python githunt.py ... &` |
| Pisahkan report per target | `--output-dir ./reports/<target>` |
| Gunakan verbose untuk debug | `--verbose` |

```bash
# Scan cepat skala besar
python githunt.py \
  --keywords-file big_targets.txt \
  --max-repos 500 \
  --concurrency 20 \
  --output html \
  --output-dir ./reports
```

---

## 10. Mengurangi False-Positive

GitHunt sudah memiliki Shannon Entropy filter dan filter placeholder bawaan.
Namun, beberapa tips tambahan:

- **Gunakan keyword spesifik** — domain lengkap lebih baik daripada kata umum
  (`password`, `secret`) yang menghasilkan terlalu banyak noise.
- **Hindari kata terlalu generik** seperti `token`, `key`, `api` — hasilkan
  noise tinggi.
- **Gabungkan dengan `--validate`** — langsung saring credential yang sudah
  tidak aktif.
- **Review output HTML** — lebih mudah dibaca dan di-filter dibanding JSON/CSV.

---

## 11. Contoh Skenario End-to-End

### Skenario A — Bug Bounty / Responsible Disclosure pada instansi pemerintah

```bash
# 1. Buat daftar target
cat > gov_targets.txt <<EOF
# Kemendikbud
kemendikbud.go.id

# Kemenkes
kemenkes.go.id

# BSSN
bssn.go.id
EOF

# 2. Scan dengan deep mode dan validasi
python githunt.py \
  --keywords-file gov_targets.txt \
  --deep \
  --validate \
  --max-repos 200 \
  --output html \
  --output-dir ./gov_reports

# 3. Review report HTML di browser
open ./gov_reports/githunt_report_*.html
```

### Skenario B — Internal audit platform fintech

```bash
# 1. Scan keyword payment gateway
python githunt.py \
  --keyword "midtrans_server_key" \
  --deep \
  --validate \
  --max-repos 100 \
  --concurrency 15 \
  --output sarif \
  --output-dir ./audit

# 2. Scan keyword tambahan
python githunt.py \
  --keyword "xendit_secret_key" \
  --deep \
  --validate \
  --max-repos 100 \
  --output sarif \
  --output-dir ./audit
```

### Skenario C — Continuous monitoring (cron job)

```bash
# Tambahkan ke crontab (jalankan setiap hari pukul 02.00)
# Di dalam crontab, karakter % harus di-escape menjadi \%
# crontab -e
0 2 * * * cd /opt/githunt && python githunt.py \
  --keywords-file /opt/githunt/targets.txt \
  --output sarif \
  --output-dir /var/reports/githunt/$(date +%Y-%m-%d) >> /var/log/githunt.log 2>&1
```

> **Catatan crontab:** Jika memasukkan perintah di atas langsung ke `crontab -e`,
> ganti `%` dengan `\%` (escape yang dibutuhkan oleh parser crontab):
> `$(date +\%Y-\%m-\%d)`. Jika perintah dipanggil melalui shell script, gunakan
> `%` biasa seperti contoh di atas.

---

## 12. Pengelolaan Token

Token GitHub disimpan di `~/.githunt_token` dengan permission `600` (hanya
bisa dibaca oleh pemilik).

```bash
# Lihat token yang tersimpan
cat ~/.githunt_token

# Ganti token
rm ~/.githunt_token
python githunt.py --keyword "test" --token ghp_NEW_TOKEN

# Hapus token (untuk keamanan setelah selesai)
rm ~/.githunt_token
```

> **Scope minimum yang dibutuhkan:** `public_repo` (read-only).
> Jangan gunakan token dengan scope lebih luas dari yang dibutuhkan.

---

## ⚠️ Disclaimer

Tools ini hanya untuk **authorized security research** dan **responsible
disclosure**. Selalu pastikan kamu memiliki izin sebelum melakukan scanning
terhadap target tertentu. Penggunaan tanpa izin melanggar hukum yang berlaku.
