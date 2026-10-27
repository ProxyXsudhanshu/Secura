# Secura – Web Security Posture Scanner

Secura is an automated web security posture scanner designed to inspect target domains for SSL/TLS certificate validity, HTTP security headers, open port exposure, and SPF/DMARC/DKIM email authorization to generate an overall security gauge score.

---

## 🛠️ Tech Stack

* **Language:** Python
* **Framework:** Flask
* **Key Modules & Tools:** `socket`, `ssl`, `dnspython`, `python-nmap`
* **Version Control:** Git & GitHub

---

## ✨ Features

* 🔒 **SSL/TLS Certificate Inspection:** Checks SSL certificate validity, issuer details, and expiration status.
* 🛡️ **HTTP Security Headers Analysis:** Detects missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).
* 🌐 **Open Port Exposure Scanning:** Scans for exposed ports and identifies active domain services.
* 📧 **Email Authorization Verification:** Inspects SPF, DMARC, and DKIM DNS records to prevent email spoofing.
* 📊 **Security Gauge Score:** Computes and displays an overall security posture score based on scan findings.

---
