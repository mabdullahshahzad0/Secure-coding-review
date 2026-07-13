## Secure Coding Review — Task 3 (Cybersecurity Internship)

A hands-on secure coding review of a small **Python/Flask** web
application. This project demonstrates the full workflow of a security
code audit: writing/selecting sample code, scanning it with a static
analysis tool, identifying vulnerabilities, and shipping a remediated,
production-safer version.

## Project Structure

```
├── vulnerable_app.py     # Original app with 6 intentional vulnerabilities
├── secure_app.py         # Remediated version (0 findings after fix)
├── bandit_report.txt     # Raw static analysis tool output
├── SECURITY_REVIEW.md    # Full audit report: findings + fixes + best practices
└── README.md
```

##  Tools Used

- **Manual code review** — line-by-line inspection
- **[Bandit](https://bandit.readthedocs.io/)** — static analysis (SAST) for Python

##  Vulnerabilities Found

| Vulnerability | Severity | CWE |
|---|---|---|
| Hardcoded secret key | Low | CWE-259 |
| Plaintext password storage | High | CWE-256 |
| SQL Injection (`/login`) | Critical | CWE-89 |
| Reflected XSS | High | CWE-79 |
| SQL Injection (`/search`) | Critical | CWE-89 |
| Debug mode + insecure bind | High | CWE-94 / CWE-605 |

Full details, root cause, and fix for each issue are in
[`SECURITY_REVIEW.md`](./SECURITY_REVIEW.md).

## Result

After remediation, re-running Bandit against `secure_app.py` reports
**zero issues**.

##  Run it yourself

```bash
pip install flask bandit
bandit vulnerable_app.py      # see the vulnerabilities
FLASK_SECRET_KEY=devkey python secure_app.py   # run the fixed version
```

