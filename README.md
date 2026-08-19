# ⚡ VOID-RECON (v4.0 Overpowered Edition)

> **Advanced OSINT, Infrastructure Fingerprinting & Attack Surface Intelligence Engine**

**VoidRecon** adalah *tool reconnaissance* cepat dan modern yang dirancang untuk kebutuhan Red Teaming, Bug Bounty Hunting, dan Cybersecurity Auditing. Alat ini secara otomatis melakukan analisis passive & active OSINT, mengekstraksi data SSL, mendeteksi header keamanan, memindai port, mencari endpoint sensitif, hingga menghubungkan target dengan database ancaman **Shodan InternetDB**.

---

## 🔥 Fitur Utama (v4.0 OP Engine)

- 🌐 **Flexible Target Input & URL Sanitizer:** Bebas memasukkan target berupa nama domain (`example.com`), URL lengkap (`https://example.com/path`), atau subdomain.
- 📍 **IP Geolocation & Infrastructure OSINT:** Identifikasi lokasi fisik server (Negara, Kota) serta penyedia layanan jaringan (ISP/ASN).
- 💥 **Shodan Threat Intelligence (Free/No API Key):** Menarik tag infrastruktur, CPEs, dan kerentanan publik (**CVEs**) yang terdaftar di Shodan secara instan.
- 🔐 **SSL/TLS Certificate Intelligence:** Mengekstraksi informasi penerbit (*Issuer*), masa berlaku sertifikat, dan daftar *Subject Alternative Names (SANs)*.
- 🛡️ **Web Stack & Security Headers Audit:**
  - Audit otomatis header keamanan utama (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`).
  - Fingerprinting teknologi web (PHP, Node.js/Express, Laravel, WordPress, dll.).
  - Deteksi Web Application Firewall (Cloudflare, Fastly, Akamai).
- 🔍 **Sensitive Endpoints Discovery:** Pemindaian file sensitif secara *asynchronous* (`/robots.txt`, `/.env`, `/.git/config`, `/admin`, dll.).
- 📡 **Passive Subdomain Enumeration:** Mengakses Certificate Transparency Logs (`crt.sh`) untuk menemukan puluhan subdomain aktif.
- 🔓 **Async Port Scanner:** Pemindaian port kritis berkecepatan tinggi menggunakan `asyncio`.
- 📊 **Rich Terminal Dashboard & JSON Export:** Tampilan CLI yang interaktif berbasis `rich` serta ekspor hasil lengkap ke file `void_report.json`.

---

## 🛠️ Instalasi

### 1. Clone Repositori
```bash
git clone [https://github.com/Izzatiin/Portofolio-NawfalArfa.git](https://github.com/Izzatiin/Portofolio-NawfalArfa.git)
cd Portofolio-NawfalArfa

# Pemindaian domain standar:
python void_recon.py -t github.com

# Menggunakan URL lengkap (otomatis dibersihkan oleh program):
python void_recon.py -t [https://github.com/](https://github.com/)
python void_recon.py -t [http://scanme.nmap.org](http://scanme.nmap.org)

⚡ VOID-RECON v4.0 (OVERPOWERED ENGINE)
Attack Surface Intelligence & Shodan Threat Profiler
Calculated Risk Score: 0 / 100

🎯 Target Asset: github.com (Input: [https://github.com](https://github.com))
├── 🌐 Resolved IPv4: 20.205.243.166
├── 📍 Infrastructure & Geolocation
│   ├── Location: Singapore, Singapore
│   └── Provider: Microsoft Corporation (Microsoft Azure Cloud (southeastasia))
├── 💥 Shodan Threat & CVE Intelligence
│   └── Infrastructure Tags: cloud
└── 🌐 Web Fingerprint & Stack
    ├── Title: No Title Found
    ├── Server: github.com
    └── WAF Shield: None / Direct Server

🔍 Discovered Sensitive Endpoints
┌──────────────────┬─────────────┐
│ Path / Endpoint  │ HTTP Status │
├──────────────────┼─────────────┤
│ /robots.txt      │     200     │
└──────────────────┴─────────────┘

🛡️ Security Headers Audit
┌──────────────────────────────────┬──────────────┐
│ Security Header Policy           │ Audit Status │
├──────────────────────────────────┼──────────────┤
│ Strict-Transport-Security (HSTS) │ PASS (PRESENT)│
│ Content-Security-Policy (CSP)    │ PASS (PRESENT)│
│ X-Frame-Options                  │ PASS (PRESENT)│
│ X-Content-Type-Options           │ PASS (PRESENT)│
└──────────────────────────────────┴──────────────┘

🔓 Open Attack Surface Ports
┌──────┬────────────────┐
│ Port │ Active Service │
├──────┼────────────────┤
│  22  │ SSH            │
│  80  │ HTTP           │
│ 443  │ HTTPS          │
└──────┴────────────────┘

✅ OVERPOWERED Recon complete! Report saved to void_report.json