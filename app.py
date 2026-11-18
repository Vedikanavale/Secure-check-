"""
SecureCheck - check a link before you click it, test a password before you use it.

How this file is organised:
  1. Setup            - create the Flask app and the SQLite database
  2. Checker logic    - the two functions that do the real work
  3. Routes           - the pages: home, signup, login, dashboard, logout
"""
import os
import re
import sqlite3
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse

from flask import (Flask, flash, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------- 1. Setup
app = Flask(__name__)
# The secret key signs the login cookie. Set your own on the server:
#   export SECRET_KEY="some-long-random-text"
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")

DB_PATH = os.path.join(os.path.dirname(__file__), "securecheck.db")


def get_db():
    """Open one database connection per request."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create the two tables if they do not exist yet."""
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            kind TEXT NOT NULL,        -- 'link' or 'password'
            subject TEXT NOT NULL,     -- the link, or a note for passwords
            verdict TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        """
    )
    db.commit()
    db.close()


# ------------------------------------------------------- 2. Checker logic
SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "update", "secure", "account", "bank",
    "confirm", "password", "wallet", "free", "bonus", "prize", "gift",
]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly"}
COMMON_PASSWORDS = {
    "password", "password1", "123456", "12345678", "123456789", "qwerty",
    "abc123", "iloveyou", "admin", "welcome", "letmein", "111111",
}


def check_link(raw_url):
    """
    Look at a link and add up warning signs. Returns (verdict, reasons).
    This only reads the text of the link. It never opens the website.
    """
    url = raw_url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url  # so urlparse can read a bare "example.com"

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    reasons = []

    if not host or "." not in host:
        return "Invalid", ["This does not look like a proper web address."]

    if parsed.scheme != "https":
        reasons.append("Does not use HTTPS, so the connection is not encrypted.")
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        reasons.append("Uses an IP address instead of a website name.")
    if "@" in url.split("//", 1)[-1].split("/")[0]:
        reasons.append("Contains '@' before the host, a trick to hide the real site.")
    if host in SHORTENERS:
        reasons.append("Shortened link: you cannot see where it really goes.")
    if host.count(".") >= 4:
        reasons.append("Has many sub-domains, often used to imitate real sites.")
    if "xn--" in host:
        reasons.append("Uses look-alike characters (punycode) in the domain.")
    if host.count("-") >= 3:
        reasons.append("Has many hyphens in the domain name.")
    if len(url) > 100:
        reasons.append("Very long link.")
    found = [w for w in SUSPICIOUS_WORDS if w in url.lower()]
    if len(found) >= 2:
        reasons.append("Contains words often used in scams: " + ", ".join(found[:4]) + ".")

    if len(reasons) == 0:
        return "Looks safe", ["No common warning signs found. Still be careful."]
    if len(reasons) <= 2:
        return "Suspicious", reasons
    return "Likely phishing", reasons


def check_password(pw):
    """Score a password out of 6 and give tips. Returns (verdict, tips)."""
    tips = []
    score = 0

    if len(pw) >= 8:
        score += 1
    else:
        tips.append("Use at least 8 characters.")
    if len(pw) >= 12:
        score += 1
    else:
        tips.append("12 or more characters is much stronger.")
    if re.search(r"[a-z]", pw):
        score += 1
    else:
        tips.append("Add lowercase letters.")
    if re.search(r"[A-Z]", pw):
        score += 1
    else:
        tips.append("Add uppercase letters.")
    if re.search(r"\d", pw):
        score += 1
    else:
        tips.append("Add numbers.")
    if re.search(r"[^A-Za-z0-9]", pw):
        score += 1
    else:
        tips.append("Add a symbol like ! @ # $.")

    if pw.lower() in COMMON_PASSWORDS:
        return "Weak", ["This is one of the most common passwords. Pick another."]

    verdict = "Weak" if score <= 2 else "Medium" if score <= 4 else "Strong"
    if verdict == "Strong" and not tips:
        tips = ["Good password. Do not reuse it on other sites."]
    return verdict, tips


# --------------------------------------------------------------- 3. Routes
def login_required(view):
    """Send people to the login page if they are not logged in."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if len(username) < 3:
            flash("Username must be at least 3 characters.")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.")
        else:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)),  # never store the plain password
                )
                db.commit()
                flash("Account created. Please log in.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username is taken.")
    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))
        flash("Wrong username or password.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    db = get_db()
    result = None

    if request.method == "POST":
        kind = request.form["kind"]
        value = request.form["value"]

        if value.strip():
            if kind == "link":
                verdict, notes = check_link(value)
                subject = value.strip()[:200]
            else:
                verdict, notes = check_password(value)
                subject = "Password check (not saved)"  # we never store the password itself
            result = {"kind": kind, "verdict": verdict, "notes": notes}

            db.execute(
                "INSERT INTO scans (user_id, kind, subject, verdict, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (session["user_id"], kind, subject, verdict,
                 datetime.now().strftime("%d %b %Y, %H:%M")),
            )
            db.commit()

    history = db.execute(
        "SELECT * FROM scans WHERE user_id = ? ORDER BY id DESC LIMIT 20",
        (session["user_id"],),
    ).fetchall()
    return render_template("dashboard.html", result=result, history=history)


init_db()

if __name__ == "__main__":
    app.run(debug=True)
