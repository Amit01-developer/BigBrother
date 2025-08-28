import os
import sqlite3
import smtplib
import ssl
import random
from flask import send_from_directory
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, send_file, abort
)
from dotenv import load_dotenv
from datetime import timedelta

# Load .env when present (for local testing)
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "change_this_in_production")
app.permanent_session_lifetime = timedelta(days=7)

# Config for SMTP (fill via env or .env file)
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT") or 587)
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
FROM_EMAIL = os.getenv("FROM_EMAIL", SMTP_USER)

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")
EMAILS_TXT = os.path.join(os.path.dirname(__file__), "emails.txt")

# -------------------------
# Database helpers
# -------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def add_user_if_not_exists(email):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT OR IGNORE INTO users (email) VALUES (?)", (email,))
        conn.commit()
    finally:
        conn.close()

# -------------------------
# OTP helpers
# -------------------------
def gen_otp():
    return "{:06d}".format(random.randint(0, 999999))

def send_otp_via_smtp(to_email, otp):
    """
    Send OTP by SMTP. If SMTP creds missing or sending fails, raise exception.
    """
    if not (SMTP_HOST and SMTP_USER and SMTP_PASS and FROM_EMAIL):
        raise RuntimeError("SMTP configuration missing. Set SMTP_HOST/USER/PASS in env.")

    message = f"""From: {FROM_EMAIL}
To: {to_email}
Subject: Your OTP for BIGBROTHER

Your OTP is: {otp}
This code is valid for 10 minutes.
"""
    context = ssl.create_default_context()
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls(context=context)
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(FROM_EMAIL, [to_email], message)

# -------------------------
# Utility: append email to emails.txt
# -------------------------
def append_email_txt(email):
    with open(EMAILS_TXT, "a", encoding="utf-8") as f:
        f.write(email + "\n")

# -------------------------
# Routes
# -------------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if "user_email" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not email or "@" not in email:
            flash("Please enter a valid email.", "danger")
            return render_template("login.html", email=email)

        # generate OTP
        otp = gen_otp()
        session["otp_email"] = email
        session["otp_code"] = otp
        session.permanent = True

        # Updated OTP sending with detailed error logging
        try:
            if SMTP_HOST and SMTP_USER and SMTP_PASS:
                send_otp_via_smtp(email, otp)
                flash("OTP sent to your email. Check your inbox.", "success")
            else:
                print(f"[DEV] OTP for {email} is: {otp}")
                flash("OTP printed to server console (dev mode).", "info")
        except Exception as e:
            import traceback
            print("\n[ERROR] OTP send failed!")
            print("Type:", type(e).__name__)
            print("Message:", str(e))
            print("Full Traceback:")
            traceback.print_exc()
            print(f"[DEV] OTP for {email} is: {otp}\n")

            flash("Failed to send OTP via SMTP; OTP printed to server console (dev).", "warning")

        return redirect(url_for("verify"))

    return render_template("login.html", email="")

@app.route("/verify", methods=["GET", "POST"])
def verify():
    # If user already logged in redirect
    if "user_email" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        email = session.get("otp_email")
        real = session.get("otp_code")
        if not email or not real:
            flash("OTP session expired. Start again.", "danger")
            return redirect(url_for("login"))

        if code == real:
            # success: persist user and mark logged in
            add_user_if_not_exists(email)
            append_email_txt(email)
            session.pop("otp_code", None)
            session["user_email"] = email
            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid OTP. Try again.", "danger")
            return render_template("verify.html")

    return render_template("verify.html")

@app.route("/Index")
def dashboard():
    if "user_email" not in session:
        return redirect(url_for("login"))
    email = session["user_email"]
    return render_template("Index.html", email=email)

@app.route("/notes.html")
def notes():
    if "user_email" not in session:
        return redirect(url_for("login"))
    return render_template("notes.html")

@app.route("/paper.html")
def paper():
    if "user_email" not in session:
        return redirect(url_for("login"))
    return render_template("paper.html")

@app.route("/syllabus.html")
def syllabus():
    if "user_email" not in session:
        return redirect(url_for("login"))
    return render_template("syllabus.html")

@app.route("/doubts.html")
def doubts():
    if "user_email" not in session:
        return redirect(url_for("login"))
    return render_template("doubts.html")


@app.route("/pdf/<path:filename>")
def pdf(filename):
    if "user_email" not in session:
        return redirect(url_for("login"))

    safe_dir = os.path.join(app.root_path, "static")
    return send_from_directory(safe_dir, filename, as_attachment=False)

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/download-emails")
def download_emails():
    # Protect: allow only logged-in users
    if "user_email" not in session:
        abort(403)
    if not os.path.exists(EMAILS_TXT):
        # create empty file if missing
        open(EMAILS_TXT, "w").close()
    return send_file(EMAILS_TXT, as_attachment=True, download_name="emails.txt")

# -------------------------
# Start
# -------------------------
if __name__ == "__main__":
    init_db()
    # Ensure emails.txt exists
    if not os.path.exists(EMAILS_TXT):
        open(EMAILS_TXT, "w").close()
    app.run(debug=True, host="127.0.0.1", port=int(os.getenv("PORT", 5000)))
