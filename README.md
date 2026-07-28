# 🔒 HackProof - From Vulnerable to Unbreakable

A dual-version banking platform demonstrating OWASP Top 10 vulnerabilities and their complete remediation.

## 🎯 Versions

| Version | Port | Security |
|---------|------|----------|
| **HackProof v1** (Vulnerable) | 5000 | SQL Injection, XSS, IDOR |
| **HackProof v2** (Secure) | 5001 | Argon2, CSRF tokens, Input Validation |

## 🚀 Quick Start

### Vulnerable Version
```bash
cd vulnerable
pip install -r requirements.txt
python app.py
# Visit http://localhost:5000