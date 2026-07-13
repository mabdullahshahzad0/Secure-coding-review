"""
secure_app.py
--------------
Remediated version of vulnerable_app.py.
Fixes applied for every finding in SECURITY_REVIEW.md.
"""

import os
import sqlite3
from flask import Flask, request
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# FIX 1: Secret key loaded from environment variable, never hardcoded.
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY environment variable must be set")

DB_PATH = "users.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, "
        "username TEXT UNIQUE, password_hash TEXT)"
    )
    # FIX 2: Passwords are hashed before storage, never stored in plaintext.
    hashed = generate_password_hash("admin123")
    conn.execute(
        "INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)",
        ("admin", hashed),
    )
    conn.commit()
    conn.close()


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # FIX 3: Parameterized query prevents SQL injection.
        conn = get_db()
        cursor = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        )
        row = cursor.fetchone()
        conn.close()

        if row and check_password_hash(row[0], password):
            # FIX 4: User input escaped before rendering (prevents XSS).
            safe_username = escape(username)
            return f"<h1>Welcome back, {safe_username}!</h1>"
        return "Invalid credentials", 401

    return """
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit">
        </form>
    """


@app.route("/search")
def search():
    # FIX 5: Parameterized query + input validated/limited.
    term = request.args.get("q", "")[:100]
    conn = get_db()
    results = conn.execute(
        "SELECT id, username FROM users WHERE username LIKE ?",
        (f"%{term}%",),
    ).fetchall()
    conn.close()
    return str(results)


if __name__ == "__main__":
    init_db()
    # FIX 6: Debug mode off; bind only to localhost by default.
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode, host="127.0.0.1")
