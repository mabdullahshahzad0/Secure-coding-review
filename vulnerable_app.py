"""
vulnerable_app.py
------------------
Sample Flask application created for a Secure Coding Review exercise.
This code INTENTIONALLY contains common security vulnerabilities so they
can be identified, documented, and fixed as part of a code audit.

DO NOT deploy this file as-is. See SECURITY_REVIEW.md for findings
and secure_app.py for the fixed version.
"""

import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)

# --- VULNERABILITY 1: Hardcoded secret key ---
app.secret_key = "supersecret123"

DB_PATH = "users.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, "
        "username TEXT, password TEXT)"
    )
    # --- VULNERABILITY 2: Plaintext password storage ---
    conn.execute(
        "INSERT INTO users (username, password) VALUES ('admin', 'admin123')"
    )
    conn.commit()
    conn.close()


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # --- VULNERABILITY 3: SQL Injection ---
        # User input concatenated directly into the SQL query.
        query = (
            f"SELECT * FROM users WHERE username = '{username}' "
            f"AND password = '{password}'"
        )
        conn = get_db()
        cursor = conn.execute(query)
        user = cursor.fetchone()
        conn.close()

        if user:
            # --- VULNERABILITY 4: Reflected XSS ---
            # Username echoed back without escaping.
            return render_template_string(
                f"<h1>Welcome back, {username}!</h1>"
            )
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
    # --- VULNERABILITY 5: No input validation / injection risk ---
    term = request.args.get("q", "")
    query = f"SELECT * FROM users WHERE username LIKE '%{term}%'"
    conn = get_db()
    results = conn.execute(query).fetchall()
    conn.close()
    return str(results)


if __name__ == "__main__":
    init_db()
    # --- VULNERABILITY 6: Debug mode enabled in "production" ---
    app.run(debug=True, host="0.0.0.0")
