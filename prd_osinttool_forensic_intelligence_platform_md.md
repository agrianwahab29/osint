# PRD — OSINTTool Forensic Intelligence Platform

## 1. Ringkasan Produk

**Nama Produk:** OSINTTool  
**Versi Target:** v6.0 Forensic Intelligence Edition  
**Jenis Produk:** Web-based OSINT, digital footprint intelligence, domain forensic, breach intelligence, dan report generator.  
**Target Pengguna:** Tim forensik digital, analis keamanan, auditor IT, bug bounty hunter legal, mahasiswa cybersecurity, dan pengguna yang ingin mengecek jejak digital sendiri.

OSINTTool saat ini sudah memiliki fondasi yang cukup baik, seperti dashboard scan, history, report, modul social media, email intelligence, people search, breach check, dark web intel, domain, Hunter.io, Telegram, WHOIS, Shodan, VirusTotal, dan beberapa modul intelijen lainnya.

Namun agar sistem ini lebih **powerful**, lebih **dipercaya**, dan lebih layak digunakan sebagai referensi oleh tim forensik, OSINTTool perlu naik kelas dari sekadar alat pencari banyak data menjadi **evidence-based forensic intelligence platform**.

Setiap hasil harus memiliki:

```text
Sumber bukti
Timestamp
Confidence score
Kategori temuan
Status validasi
Batasan klaim
Rekomendasi mitigasi
Export report yang rapi
```

---

## 2. Latar Belakang Masalah

Berdasarkan tampilan sistem saat ini, beberapa modul sudah berjalan, tetapi masih ada beberapa kekurangan yang membuat hasil kurang kuat secara forensik.

Contoh dari hasil scan:

```text
Email Intelligence
70 permutations, 70 valid, 0 breached
No breached emails detected.
```

Masalah dari tampilan tersebut adalah istilah **70 valid** dapat disalahpahami sebagai 70 email yang benar-benar aktif atau benar-benar milik target. Padahal dalam konteks OSINT, email hasil kombinasi pola nama seharusnya disebut **candidate email**, bukan email valid.

Contoh lain:

```text
People Search Aggregator
Phones: 0-1779811249, 15913852, -1779811249, 1779811249
```

Nomor seperti ini berisiko false positive, apalagi jika sumbernya berasal dari people search engine yang cenderung US-centric. Untuk target Indonesia, hasil seperti ini harus diberi confidence rendah dan label unverified.

Pada bagian Dark Web Intel terlihat:

```text
Dark Web Intel
0 matches
```

Jika sistem tidak benar-benar terhubung ke sumber dark web yang kredibel, maka klaim “0 matches” bisa berbahaya karena memberi kesan seolah-olah seluruh dark web telah diperiksa. Lebih baik fitur ini diposisikan sebagai **Exposure Intelligence** atau **Breach Advisory**.

---

## 3. Visi Produk

OSINTTool v6.0 harus menjadi:

```text
Free-first Digital Footprint & Forensic Intelligence Platform
```

Produk ini bukan sekadar tool untuk mencari data seseorang, tetapi platform untuk menganalisis jejak digital publik secara transparan, terukur, dan dapat dipertanggungjawabkan.

---

## 4. Tujuan Produk

Tujuan utama pengembangan OSINTTool v6.0 adalah:

1. Membuat hasil OSINT lebih akurat, transparan, dan tidak overclaim.
2. Menjadikan setiap hasil memiliki sumber bukti, timestamp, dan confidence score.
3. Mengurangi false positive dari modul email, phone, people search, social media, dan breach.
4. Membuat report yang layak dibaca oleh tim forensik digital.
5. Memastikan sistem tetap berjalan tanpa API berbayar.
6. Meningkatkan UI/UX agar lebih profesional dan mudah dipercaya.
7. Menyediakan mode investigasi yang aman seperti self-check, authorized investigation, dan forensic reference.
8. Menjadikan OSINTTool sebagai alat edukasi, audit, dan referensi forensik yang legal dan defensif.

---

## 5. Target Pengguna

### 5.1 Digital Forensic Analyst

Kebutuhan:

```text
Evidence URL
Timestamp
Hash bukti
Report formal
Confidence score
Metodologi investigasi
Chain-of-custody log
```

### 5.2 Security Researcher / Bug Bounty Hunter Legal

Kebutuhan:

```text
Domain footprint
Email exposure
GitHub exposure
Subdomain hint
Security header check
SPF/DMARC check
Public leak reference
```

### 5.3 Auditor IT

Kebutuhan:

```text
Domain security posture
Mail security posture
Evidence-based report
Risk score
Recommendation checklist
```

### 5.4 Mahasiswa / Pembelajar Cybersecurity

Kebutuhan:

```text
Hasil mudah dipahami
Penjelasan risiko
Rekomendasi mitigasi
Export PDF/HTML
Contoh edukatif
```

### 5.5 Pengguna Umum

Kebutuhan:

```text
Cek jejak digital saya
Exposure score
Akun sosial yang ditemukan
Rekomendasi privasi
Password exposure check
```

---

## 6. Scope Produk

### 6.1 In Scope

Fitur yang masuk ke ruang lingkup pengembangan:

```text
Name intelligence
Username intelligence
Public email discovery
Email pattern generator
Domain forensic
GitHub intelligence
Social media discovery
Breach catalogue
Password exposure check
Report generator
Evidence locker
Confidence scoring
Risk scoring
Free-first API mode
Region-aware OSINT
```

### 6.2 Out of Scope

Fitur yang tidak boleh dijadikan bagian inti produk:

```text
Credential dump ilegal
Combo list checker
Login checking
SMTP brute force
Account enumeration agresif
Private data scraping
Doxxing workflow
Bypass login
Eksploitasi akun
Malware
DDoS
```

Produk harus diposisikan sebagai alat OSINT legal, edukatif, defensif, dan forensik.

---

## 7. Prinsip Produk

### 7.1 Evidence-first

Setiap temuan harus menjawab:

```text
Data ini ditemukan dari mana?
Kapan ditemukan?
Seberapa yakin sistem terhadap data ini?
Apakah data ini ditemukan langsung atau hanya kandidat?
Apa batasan klaimnya?
```

### 7.2 No Overclaim

Hindari istilah yang terlalu kuat seperti:

```text
Email valid
Nomor valid
Akun pasti milik target
Breach pasti
Dark web clean
```

Gunakan istilah yang lebih tepat:

```text
Candidate
Publicly observed
Format valid
Source matched
Unverified
Low confidence
High confidence
```

### 7.3 Free-first

Sistem harus tetap berguna walaupun tidak ada API key berbayar.

### 7.4 Forensic-ready Reporting

Report harus dapat diekspor dan dipakai sebagai referensi investigasi.

Format minimal:

```text
HTML
PDF
JSON
CSV
Markdown
```

### 7.5 Modular

Setiap modul harus dapat aktif/nonaktif tanpa membuat scan utama gagal.

---

## 8. Kondisi Saat Ini

### 8.1 Kelebihan Saat Ini

```text
UI sudah modern
Input sederhana
Progress scanning cukup jelas
Modul cukup banyak
Ada summary score
Ada collapsible result panel
Ada menu Scan, History, dan Report
Ada module badge di bagian atas
```

### 8.2 Masalah Saat Ini

```text
Versi tidak konsisten antara badge logo dan kanan atas
Email candidate masih ditampilkan sebagai valid
Hasil email tidak menampilkan daftar kandidat secara transparan
Risk masih NONE walaupun ada social/github exposure
People Search menampilkan phone yang berisiko false positive
Tidak ada confidence score per item
Tidak ada evidence URL per temuan
Tidak ada timestamp per temuan
Tidak ada evidence hash
Tidak ada scan mode
Tidak ada region awareness
Dark Web Intel berpotensi overclaim jika tidak memakai sumber kredibel
Report belum cukup forensik
```

---

## 9. Requirement Fungsional

## 9.1 Scan Mode

Tambahkan pilihan mode scan:

```text
Quick Scan
Standard Scan
Forensic Scan
Self-Check Mode
Domain Audit Mode
```

### 9.1.1 Quick Scan

Digunakan untuk scan cepat.

Modul aktif:

```text
Name search
Social media
GitHub
Email pattern
```

Target waktu:

```text
< 30 detik
```

### 9.1.2 Standard Scan

Digunakan untuk investigasi umum.

Modul aktif:

```text
Name intelligence
Username intelligence
Email intelligence
Social media
GitHub intelligence
Breach catalogue
Domain basic check
```

Target waktu:

```text
< 90 detik
```

### 9.1.3 Forensic Scan

Digunakan untuk report serius.

Syarat:

```text
Semua hasil wajib punya evidence URL jika tersedia
Timestamp wajib
Confidence score wajib
Evidence hash wajib
Chain-of-custody log wajib
Limitations wajib
```

### 9.1.4 Self-Check Mode

Digunakan untuk fitur viral “Cek Jejak Digital Saya”.

Output utama:

```text
Digital Footprint Score
Public Profile Found
Public Email Found
Candidate Email Found
Privacy Recommendation
Password Exposure Check
```

### 9.1.5 Domain Audit Mode

Digunakan untuk audit domain secara pasif.

Modul aktif:

```text
DNS records
WHOIS/RDAP
SPF
DMARC
MX
TLS certificate
HTTP security headers
robots.txt
sitemap.xml
technology fingerprint
```

---

## 9.2 Input Form Baru

Form saat ini:

```text
Name
Email
Domain
Phone
```

Form baru yang direkomendasikan:

```text
Full Name
Known Username
Email Optional
Domain Optional
Phone Optional
Country/Region Optional
Scan Mode
Purpose
```

### 9.2.1 Purpose Dropdown

Tambahkan dropdown:

```text
Self-check
Authorized investigation
Bug bounty
Academic research
Forensic reference
```

### 9.2.2 Country/Region

Country/Region penting agar sumber seperti People Search tidak salah konteks.

Contoh:

```text
Indonesia
United States
Malaysia
Singapore
Global
```

Jika target adalah Indonesia, sumber people search US harus diberi confidence rendah atau dinonaktifkan secara default.

---

## 9.3 Name Intelligence

### Tujuan

Mencari footprint publik berdasarkan nama.

### Sumber

```text
DuckDuckGo
Bing
Google News
GitHub Search
Wikipedia
PDF indexed pages
Public CV/resume
Portfolio pages
Public document pages
```

### Peningkatan

Tambahkan:

```text
Deduplication URL lebih kuat
Domain clustering
Language detection
Indonesia-aware query
PDF discovery
Email extraction from public pages
Profile correlation
Confidence score
Evidence URL
```

### Output Baru

```json
{
  "query": "agrian wahab",
  "results": [
    {
      "title": "GitHub Profile",
      "url": "https://github.com/example",
      "source": "github",
      "confidence": 82,
      "evidence_type": "profile",
      "matched_terms": ["agrian", "wahab"],
      "timestamp": "2026-05-27T10:00:00+08:00"
    }
  ]
}
```

---

## 9.4 Username Intelligence

### Tujuan

Mengecek keberadaan username di berbagai platform publik.

### Input

```text
agrianwahab29
agriakultur
```

### Platform Gratis

```text
GitHub
GitLab
Reddit
Medium
Dev.to
npm
PyPI
Docker Hub
Telegram public username
YouTube handle
Linktree
About.me
Kaggle
Hugging Face
CodePen
Replit
StackOverflow
```

### Output

```text
Platform
Username
URL
Status
Confidence
Category
Evidence
```

### Scoring

```text
95 = profile ditemukan dan nama/bio cocok
80 = profile ditemukan, username cocok
60 = profile ditemukan, nama belum cocok
40 = platform merespons ambigu
0  = tidak ditemukan
```

---

## 9.5 Public Email Discovery

### Tujuan

Mencari email dari sumber publik, bukan sekadar membuat tebakan dari nama.

### Pembagian Hasil

Wajib pisahkan:

```text
Publicly Found Emails
Candidate Emails
Format Valid Candidates
Breached Emails
Disposable Emails
Role-based Emails
```

### Sumber

```text
Halaman web publik
PDF publik
GitHub profile public email
GitHub README
GitHub commit metadata publik
Portfolio
CV publik
Contact page
Domain page
```

### Output

```json
{
  "publicly_found_emails": [
    {
      "email": "name@example.com",
      "source_url": "https://example.com/profile",
      "confidence": 92,
      "reason": "Email ditemukan pada halaman yang juga memuat nama target",
      "timestamp": "2026-05-27T10:00:00+08:00"
    }
  ],
  "candidate_emails": [
    {
      "email": "agrian.wahab@example.com",
      "confidence": 45,
      "reason": "Generated from name + domain pattern, not publicly observed"
    }
  ]
}
```

### UI Wajib

Jangan tampilkan:

```text
70 permutations, 70 valid
```

Ubah menjadi:

```text
0 publicly found
70 candidate patterns
70 format-valid candidates
0 breached via configured provider
```

### Empty State

Jika tidak ada email publik:

```text
No public email found.
Possible reasons:
- Email is not publicly exposed
- Name is too common
- Domain was not provided
- API key is not configured
- Source was blocked or rate-limited
```

---

## 9.6 Email Pattern Generator

### Tujuan

Membantu investigasi dengan kandidat pola email.

### Input

```text
Full Name
Domain
```

### Output

```text
agrian.wahab@domain.com
agrianwahab@domain.com
a.wahab@domain.com
awahab@domain.com
wahab.agrian@domain.com
```

### Label Wajib

```text
Status: Candidate only — not verified
```

### Catatan

Candidate email tidak boleh diklaim sebagai email valid, email aktif, atau email milik target.

---

## 9.7 Email Validation

### Validasi Aman

```text
Syntax validation
Domain MX check
SPF/DMARC domain context
Disposable domain check
Role-based email check
```

### Validasi yang Harus Dihindari

```text
SMTP probing agresif
Login checking
Account enumeration
Brute force validation
Credential stuffing
```

### Perbaikan Bug

Jika saat ini terdapat logika seperti:

```python
"is_free_provider": domain.lower() in [d.split('.')[0] for d in COMMON_DOMAINS]
```

Ubah menjadi:

```python
"is_free_provider": domain.lower() in COMMON_DOMAINS
```

Karena `gmail.com` tidak sama dengan `gmail`.

---

## 9.8 Breach Intelligence

### Mode Gratis

Gunakan:

```text
HIBP breach catalogue
HIBP latest breach metadata
Pwned Passwords range API
Local breach knowledge base
```

### Mode Opsional Berbayar

```text
HIBP breached account email lookup
```

### UI Jika API Key Tidak Ada

```text
HIBP Email Breach Check: Disabled
Reason: API key not configured
Free alternatives enabled:
- Breach catalogue
- Password exposure check
- Public exposure analysis
```

### Password Exposure Check

Fitur ini harus:

```text
Hash SHA-1 dilakukan lokal
Kirim hanya 5 karakter pertama hash
Cocokkan suffix secara lokal
Jangan simpan password
Jangan log password plaintext
```

### Output Password Exposure

```json
{
  "status": "found",
  "seen_count": 18230,
  "recommendation": "Password ini pernah muncul di breach publik. Jangan digunakan kembali."
}
```

---

## 9.9 GitHub Intelligence

### Tujuan

Menemukan footprint developer secara publik.

### Fitur

```text
Public profile analysis
Public email if available
Blog/website extraction
Bio keyword extraction
Repository list
README scan
Commit metadata public email scan
Noreply email detection
Secret exposure warning
Technology stack
Activity timeline
```

### Catatan UI

Jika email GitHub kosong, tampilkan:

```text
Public GitHub email not exposed.
This does not mean the user has no email.
```

### Output

```json
{
  "username": "agrianwahab29",
  "profile_url": "https://github.com/agrianwahab29",
  "public_email": null,
  "public_email_status": "not_exposed",
  "repos_scanned": 12,
  "emails_from_commits": [],
  "technology_stack": ["Python", "JavaScript"],
  "confidence": 85
}
```

---

## 9.10 Domain Forensic

### Tujuan

Memberi gambaran keamanan domain secara pasif.

### Fitur

```text
WHOIS/RDAP
DNS A record
DNS AAAA record
MX record
TXT record
SPF record
DMARC record
DKIM selector hints
NS record
CAA record
TLS certificate
HTTP headers
Security headers
robots.txt
sitemap.xml
Technology fingerprint
Subdomain hints from public sources
```

### Output

```text
Domain Risk Score
Mail Security Score
Web Security Score
Evidence URLs
Recommended Fixes
```

### Contoh Temuan

```text
DMARC missing
SPF too permissive
No HSTS
No X-Content-Type-Options
No security.txt
TLS certificate valid
MX configured
```

---

## 9.11 People Search

### Masalah

People Search aggregator sering mengambil data dari sumber yang relevansinya rendah untuk target non-US.

### Perbaikan

Tambahkan region awareness:

```text
Country: Indonesia
Disable US people-search by default
Enable generic web search
Enable public document search
Enable social correlation
```

### UI Warning

```text
This source is US-centric. Confidence lowered for non-US target.
```

### Output

```json
{
  "phones": [
    {
      "value": "1779811249",
      "source": "FastPeopleSearch",
      "region_bias": "US",
      "confidence": 15,
      "status": "unverified"
    }
  ]
}
```

---

## 9.12 Dark Web Intel

### Reposisi Fitur

Jika tidak ada sumber dark web yang benar-benar kredibel, jangan klaim sebagai dark web check penuh.

Ubah nama menjadi:

```text
Exposure Intelligence
Leak Reference
Breach Advisory
Credential Hygiene Recommendation
```

### Output Jika Tidak Ada API/Sumber Kredibel

```text
No verified dark web source configured.
Showing defensive recommendations only.
```

### Rekomendasi yang Boleh Ditampilkan

```text
Gunakan password unik per layanan
Aktifkan 2FA
Gunakan password manager
Cek password exposure dengan Pwned Passwords
Pantau breach catalogue
```

---

## 9.13 Hunter.io

### Masalah

Hunter.io membutuhkan data yang lebih spesifik. Jika hanya domain atau nama tanpa konteks, hasil bisa kosong.

### Form Baru

```text
Domain
First Name
Last Name
Company Optional
```

### Jika API Key Tidak Ada

```text
Hunter.io disabled — API key not configured.
Use local email pattern generator instead.
```

---

## 9.14 Telegram OSINT

### Tujuan

Mengecek public username atau public channel/group metadata.

### Batasan

Tidak boleh melakukan scraping privat, bypass, atau akses grup tertutup.

### Output

```json
{
  "username": "exampleuser",
  "public_url": "https://t.me/exampleuser",
  "status": "public_link_checked",
  "confidence": 60,
  "note": "Public username format exists, ownership not verified"
}
```

---

## 9.15 Report Generator

### Format Report

Report harus memiliki struktur:

```text
Executive Summary
Scope
Input Data
Scan Mode
Methodology
Source Inventory
Findings
Evidence Table
Confidence Scoring
Risk Matrix
Timeline
Limitations
Recommendations
Appendix JSON
```

### Evidence Table

```text
Finding ID
Category
Value
Source URL
Timestamp
Confidence
Risk
Evidence Hash
Screenshot Path
Notes
```

### Export Format

```text
HTML
PDF
JSON
CSV
Markdown
```

---

## 10. Confidence Scoring System

### 10.1 Skala Umum

```text
90–100 = Very High
75–89  = High
50–74  = Medium
25–49  = Low
0–24   = Very Low
```

---

### 10.2 Email Scoring

```text
95 = email ditemukan langsung di halaman resmi/profil publik yang memuat nama target
85 = email ditemukan di GitHub/profile publik yang cocok
75 = email ditemukan di PDF/CV publik yang cocok
60 = email ditemukan di domain terkait tapi nama tidak kuat
45 = kandidat dari nama + domain
25 = kandidat dari nama + provider umum
0  = tidak ada bukti
```

---

### 10.3 Social Profile Scoring

```text
95 = username + nama + foto/bio cocok
80 = username + nama cocok
60 = username cocok, nama tidak tersedia
40 = nama mirip tapi username berbeda
20 = hasil pencarian ambigu
0  = tidak ditemukan
```

---

### 10.4 Phone Scoring

```text
95 = nomor ditemukan pada halaman resmi milik target
75 = nomor ditemukan di dokumen publik yang memuat nama target
40 = nomor ditemukan di aggregator tapi region cocok
15 = nomor ditemukan di aggregator US untuk target non-US
0  = tidak ada sumber valid
```

---

### 10.5 Domain Scoring

```text
90 = semua record utama lengkap dan security header kuat
75 = konfigurasi cukup baik, ada sedikit kekurangan
50 = beberapa konfigurasi penting hilang
25 = banyak konfigurasi keamanan tidak ada
0  = domain tidak dapat dianalisis
```

---

## 11. Risk Scoring System

### 11.1 Kategori Risiko

```text
NONE
LOW
MEDIUM
HIGH
CRITICAL
```

### 11.2 Faktor Risiko

```text
Public email ditemukan
Password exposure ditemukan
SPF/DMARC lemah
GitHub commit email exposed
Social media banyak dan saling terhubung
Phone/address ditemukan dengan confidence tinggi
Domain security header lemah
Credential breach confirmed via configured API
```

### 11.3 Contoh Bobot Risiko

```text
Public email found: +15
GitHub email exposed: +10
Phone found high confidence: +20
Password found in Pwned Passwords: +30
DMARC missing: +10
SPF weak: +10
Social footprint high: +10
```

### 11.4 Contoh Output Risk

```json
{
  "risk_score": 45,
  "risk_level": "MEDIUM",
  "risk_reasons": [
    "Public social profiles found",
    "Candidate email patterns generated",
    "DMARC missing on domain"
  ]
}
```

---

## 12. UI/UX Requirement

### 12.1 Dashboard Summary Baru

Ganti summary card menjadi:

```text
Public Findings
Candidate Findings
Verified Sources
Risk Score
Evidence Items
Report Ready
```

Jangan hanya:

```text
Web
Social
Email
Breach
GitHub
Risk
```

---

### 12.2 Panel Result

Setiap panel harus memiliki:

```text
Status
Jumlah hasil
Confidence tertinggi
Source count
Last scanned
Expand/collapse
Export per module
```

---

### 12.3 Badge Warna

```text
Green  = verified/public source
Blue   = informational
Yellow = candidate/unverified
Orange = medium risk
Red    = high risk
Gray   = disabled/no API
```

---

### 12.4 Empty State

Jangan hanya tampilkan:

```text
0 results
```

Tampilkan alasan:

```text
No public email found.
Possible reasons:
- Email is not public
- Name too common
- Domain not provided
- API key not configured
- Source blocked/rate-limited
```

---

### 12.5 Version Consistency

Saat ini terlihat ada potensi ketidakkonsistenan versi.

Contoh:

```text
Logo badge: v5.0
Header kanan: v4.0.0 — 15 modules
```

Perbaikan:

```text
Gunakan satu sumber versi dari config
Tampilkan build number
Tampilkan module count aktual
```

Contoh:

```text
OSINTTool v6.0.0 — 18 modules — Free Mode
```

---

## 13. Data Model Baru

### 13.1 Finding Object

```json
{
  "finding_id": "FND-0001",
  "category": "email",
  "type": "publicly_found_email",
  "value": "name@example.com",
  "source_url": "https://example.com/profile",
  "source_name": "Public Web Page",
  "confidence": 92,
  "risk": "MEDIUM",
  "status": "publicly_observed",
  "timestamp": "2026-05-27T10:00:00+08:00",
  "evidence_hash": "sha256...",
  "notes": "Email found on page containing target name"
}
```

---

### 13.2 Scan Object

```json
{
  "scan_id": "SCAN-20260527-001",
  "scan_mode": "forensic",
  "target": {
    "name": "Agrian Wahab",
    "username": "agrianwahab29",
    "email": null,
    "domain": null,
    "country": "Indonesia"
  },
  "modules_enabled": [],
  "started_at": "2026-05-27T10:00:00+08:00",
  "finished_at": "2026-05-27T10:01:20+08:00",
  "findings": [],
  "errors": [],
  "risk_score": 0
}
```

---

### 13.3 Evidence Object

```json
{
  "evidence_id": "EVD-0001",
  "finding_id": "FND-0001",
  "source_url": "https://example.com/profile",
  "captured_at": "2026-05-27T10:00:00+08:00",
  "content_hash_sha256": "sha256...",
  "screenshot_path": "evidence/screenshots/EVD-0001.png",
  "html_snapshot_path": "evidence/html/EVD-0001.html",
  "notes": "Captured from public page"
}
```

---

## 14. Non-Functional Requirement

### 14.1 Performance

```text
Quick scan selesai < 30 detik
Standard scan selesai < 90 detik
Forensic scan boleh lebih lama, tetapi progress harus jelas
Timeout per source maksimal 10–15 detik
```

### 14.2 Reliability

```text
Jika satu modul error, modul lain tetap jalan
Semua error masuk report
API rate limit ditangani
Retry maksimal 2 kali
Timeout tidak membuat scan utama gagal
```

### 14.3 Privacy

```text
Jangan simpan password plaintext
Jangan log email sensitif secara berlebihan
Masking untuk report publik
Tambah pilihan delete scan history
Tambah local-only mode
```

### 14.4 Security

```text
Jangan hardcode secret key Flask
Jangan hardcode API key
Gunakan .env
Matikan debug di production
Sanitasi input
Escape output HTML
Rate limit endpoint API
Tambahkan CSRF protection untuk form sensitif
Tambahkan security headers
```

### 14.5 Auditability

```text
Setiap scan punya scan_id
Setiap finding punya finding_id
Setiap evidence punya evidence_id
Setiap modul mencatat error dan warning
Report menyimpan metodologi dan batasan
```

---

## 15. API Key Strategy

### 15.1 Free-first Mode

Sistem harus tetap berjalan tanpa API key.

Contoh `.env`:

```env
ENABLE_FREE_MODE=true
HIBP_API_KEY=
HUNTER_API_KEY=
SHODAN_API_KEY=
VIRUSTOTAL_API_KEY=
```

---

### 15.2 Feature Flags

```env
ENABLE_HIBP_EMAIL_CHECK=false
ENABLE_HIBP_PASSWORD_CHECK=true
ENABLE_BREACH_CATALOG=true
ENABLE_HUNTER=false
ENABLE_SHODAN=false
ENABLE_VIRUSTOTAL=false
ENABLE_GITHUB_INTEL=true
ENABLE_PUBLIC_EMAIL_DISCOVERY=true
ENABLE_DOMAIN_FORENSIC=true
```

---

### 15.3 API Status UI

Tambahkan panel status:

```text
HIBP Email: Disabled
Pwned Passwords: Enabled
Hunter.io: Disabled
Shodan: Disabled
VirusTotal: Disabled
GitHub Public API: Enabled
Public Web Search: Enabled
```

---

## 16. Modul yang Perlu Ditambahkan

### 16.1 Evidence Locker

Fungsi:

```text
Simpan HTML snippet
Simpan screenshot optional
Hitung SHA-256
Simpan source URL
Simpan timestamp
Hubungkan evidence dengan finding_id
```

---

### 16.2 Public Email Extractor

Fungsi:

```text
Ambil URL dari name_search
Fetch halaman publik
Extract email dengan regex
Filter asset palsu
Korelasikan dengan nama
Beri confidence
Simpan evidence URL
```

---

### 16.3 GitHub Intelligence

Fungsi:

```text
Profile public email
Repo README scan
Commit metadata scan
Noreply detection
Technology stack
Repository exposure warning
```

---

### 16.4 Breach Catalogue

Fungsi:

```text
Search breach by company/domain
Latest breach
Data class explorer
Breach timeline
Educational breach summary
```

---

### 16.5 Password Exposure Check

Fungsi:

```text
SHA-1 lokal
Range API
Suffix matching lokal
No password logging
No password storage
```

---

### 16.6 Indonesia-aware OSINT

Fungsi:

```text
Query Indonesia
Domain .id
Kampus/sekolah/instansi
PDF publik
GitHub/LinkedIn/public web
Local language keyword expansion
```

---

## 17. Modul yang Perlu Diperbarui

### 17.1 `email_finder.py`

Perubahan:

```text
Ubah valid_emails menjadi candidate_emails
Tambahkan publicly_found_emails
Tambahkan custom domain dari input
Perbaiki is_free_provider
Matikan HIBP email check jika API kosong
Tambahkan confidence score
Tambahkan source URL
Tambahkan reason per result
```

---

### 17.2 `app.py`

Perubahan:

```text
Kirim domain ke find_emails(name, custom_domains=[domain])
Tambahkan scan_mode
Tambahkan country/region
Tambahkan username input
Tambahkan feature flags
Jangan hardcode secret_key
Tambahkan API status endpoint
Tambahkan consistent version source
```

---

### 17.3 `people_search.py`

Perubahan:

```text
Tambahkan region bias
Disable US source jika country bukan US
Confidence rendah untuk aggregator
Jangan tampilkan phone sebagai verified
Tambahkan source warning
```

---

### 17.4 `main.js`

Perubahan:

```text
Render publicly_found_emails
Render candidate_emails
Render confidence
Render source URL
Render disabled API explanation
Render risk reason
Render evidence table
Render empty state explanation
```

---

### 17.5 `report_generator.py`

Perubahan:

```text
Tambahkan forensic report format
Tambahkan evidence table
Tambahkan confidence scoring
Tambahkan limitations
Tambahkan JSON appendix
Tambahkan executive summary
Tambahkan risk matrix
```

---

### 17.6 `domain_checker.py`

Perubahan:

```text
Tambahkan DMARC check
Tambahkan SPF quality check
Tambahkan CAA check
Tambahkan TLS certificate summary
Tambahkan security headers
Tambahkan robots.txt dan sitemap.xml check
```

---

## 18. Roadmap

## Phase 1 — Trust Fix

Target: 1–2 minggu

```text
Ubah label email valid menjadi candidate
Tampilkan daftar candidate email
Tambahkan confidence score sederhana
Tambahkan API status
Matikan HIBP email jika API kosong
Perbaiki secret key
Perbaiki version mismatch
Tambahkan empty state explanation
Tambahkan status disabled untuk API berbayar
```

---

## Phase 2 — Forensic Evidence

Target: 2–4 minggu

```text
Evidence locker
Source URL per finding
Timestamp per finding
Hash evidence
Report forensic HTML/PDF
Limitations section
Risk scoring v1
Finding ID
Evidence ID
```

---

## Phase 3 — Free Intelligence Expansion

Target: 4–6 minggu

```text
Public email extractor
GitHub intelligence
Password exposure check
Breach catalogue
Indonesia-aware source mode
Domain forensic upgrade
Username intelligence expansion
```

---

## Phase 4 — Viral Self-Check

Target: 6–8 minggu

```text
Digital Footprint Score
Shareable privacy report
User-friendly recommendations
Before/after privacy tips
Export clean PDF
Simple public-facing mode
```

---

## Phase 5 — Professional Edition

Target: 2–3 bulan

```text
Case management
Multi-target investigation
Team notes
Evidence tagging
API integration optional
Audit log
Role-based access
Advanced report templates
```

---

## 19. Acceptance Criteria

Produk dianggap berhasil jika:

```text
Email candidate tidak lagi diklaim sebagai email valid
Setiap temuan punya confidence score
Setiap temuan penting punya source URL
HIBP email check tidak error saat API key kosong
Report bisa dipakai sebagai ringkasan forensik
People Search tidak overclaim nomor telepon
Risk score punya alasan yang jelas
UI menjelaskan kenapa hasil kosong
Tool tetap berjalan tanpa API berbayar
Setiap modul error tidak mematikan scan utama
```

---

## 20. Success Metrics

### 20.1 Product Metrics

```text
Scan completion rate > 90%
False positive complaint turun
Report export usage naik
Average scan result clarity naik
User kembali memakai self-check mode
```

### 20.2 Technical Metrics

```text
Error rate per module < 5%
Timeout terkendali
API failure tidak mematikan scan
Quick scan < 30 detik
Standard scan < 90 detik
```

### 20.3 Trust Metrics

```text
100% finding penting punya confidence
100% report punya methodology
100% report punya limitation
100% candidate data diberi label unverified
100% API berbayar punya fallback gratis
```

---

## 21. Prioritas Implementasi Teknis

### Prioritas P0 — Wajib Segera

```text
Ubah istilah valid_emails menjadi candidate_emails
Tambahkan publicly_found_emails
Tambahkan confidence score
Tambahkan source_url
Tambahkan API disabled state
Perbaiki secret key hardcoded
Perbaiki version mismatch
```

### Prioritas P1 — Penting

```text
Public email extractor
GitHub intelligence
Domain forensic upgrade
Report forensic format
Risk scoring v1
Region-aware people search
```

### Prioritas P2 — Pengembangan Lanjutan

```text
Evidence locker
Password exposure check
Breach catalogue UI
Digital footprint score
Case management
Advanced report export
```

---

## 22. Rekomendasi Struktur Folder Baru

```text
osint_tool/
├── app.py
├── config.py
├── requirements.txt
├── modules/
│   ├── name_search.py
│   ├── username_intel.py
│   ├── email_finder.py
│   ├── public_email_extractor.py
│   ├── github_intel.py
│   ├── domain_forensic.py
│   ├── breach_catalogue.py
│   ├── password_exposure.py
│   ├── people_search.py
│   ├── social_media.py
│   └── report_generator.py
├── services/
│   ├── evidence_locker.py
│   ├── confidence_scoring.py
│   ├── risk_scoring.py
│   ├── api_status.py
│   └── export_service.py
├── templates/
│   ├── index.html
│   ├── report.html
│   └── history.html
├── static/
│   ├── js/
│   │   └── main.js
│   └── css/
│       └── style.css
├── reports/
├── evidence/
│   ├── html/
│   ├── screenshots/
│   └── metadata/
└── data/
    └── scans.db
```

---

## 23. Contoh Tampilan Hasil Baru

### 23.1 Email Intelligence

```text
Email Intelligence
0 publicly found
70 candidate patterns
70 format-valid candidates
0 breached via configured provider

Publicly Found Emails:
- No public email found

Candidate Emails:
- agrian.wahab@example.com | Confidence: 45 | Candidate only
- agrianwahab@example.com  | Confidence: 40 | Candidate only

Notes:
Candidate emails are generated from name patterns and are not verified ownership.
```

---

### 23.2 People Search

```text
People Search Aggregator
4 possible phone-like values found

Warning:
Sources are US-centric. Confidence lowered for non-US target.

Results:
- 1779811249 | Source: FastPeopleSearch | Confidence: 15 | Status: Unverified
```

---

### 23.3 Dark Web / Exposure Intelligence

```text
Exposure Intelligence
No verified dark web provider configured.
Showing defensive recommendations only.

Recommendations:
- Enable 2FA
- Use unique passwords
- Use password manager
- Check password exposure
- Monitor breach catalogue
```

---

### 23.4 GitHub Intelligence

```text
GitHub Intelligence
Profile found: github.com/agrianwahab29
Public email: Not exposed
Repositories scanned: 12
Commit emails found: 0
Noreply emails found: 3
Technology stack: Python, JavaScript, Flask
Confidence: 85
```

---

## 24. Kesimpulan

Agar OSINTTool menjadi lebih kuat dan dipercaya oleh tim forensik, hal paling penting adalah mengubah pendekatannya dari:

```text
Banyak hasil cepat
```

menjadi:

```text
Hasil berbasis bukti, confidence, dan report yang bisa dipertanggungjawabkan
```

Prioritas utama:

1. Jangan klaim hasil tebakan sebagai data valid.
2. Pisahkan `publicly found`, `candidate`, dan `verified`.
3. Tambahkan confidence score di semua hasil.
4. Tambahkan source URL, timestamp, dan evidence hash.
5. Jadikan HIBP, Hunter, Shodan, dan VirusTotal sebagai fitur opsional.
6. Fokus pada fitur gratis: public email discovery, GitHub intelligence, domain forensic, breach catalogue, dan password exposure check.
7. Buat report forensik yang rapi.
8. Tambahkan region awareness untuk mengurangi false positive.
9. Perbaiki UI agar hasil kosong tetap informatif.
10. Posisikan produk sebagai:

```text
OSINTTool — Free-first Digital Footprint & Forensic Intelligence Platform
```

Dengan arah ini, OSINTTool akan terlihat lebih profesional, lebih aman secara reputasi, lebih dipercaya, dan lebih layak digunakan sebagai referensi oleh tim forensik digital.

