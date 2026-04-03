# app.py (updated: email alerts + forgot-password + suspicious notifications)
import os
import io
import base64
import qrcode
import bcrypt
import pyotp
import smtplib

from email.message import EmailMessage
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

from flask import (
    Flask, render_template, request, redirect, flash, session, send_file, url_for
)
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename

from models import db, User, OperationLog
from crypto_utils import (
    encrypt_text, decrypt_text,
    encrypt_file_bytes, decrypt_file_bytes,
    is_combined_format
)
from ml_classifier import predict_suspicion
from PIL import Image

# -----------------------------
# CONFIG
# -----------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET") or "replace_this_secret_in_prod"

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "encryption.db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# -----------------------------
# EMAIL (Gmail SMTP) CONFIG
# -----------------------------
EMAIL_ADDRESS = os.environ.get("EMAIL_ADDRESS")    # your Gmail address
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD")  # 16-char app password
EMAIL_SENDER_NAME = "Encryption Tool Security"     # per your choice

# itsdangerous serializer for password reset tokens
TS_SECRET = app.secret_key
URL_SERIALIZER = URLSafeTimedSerializer(TS_SECRET)
RESET_TOKEN_EXPIRY_SECONDS = 30 * 60  # 30 minutes

# -----------------------------
# Limits / allowed types
# -----------------------------
ALLOWED_EXT = {"jpg", "jpeg", "png", "pdf", "txt", "zip", "mp3"}
MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB threshold for warnings

# -----------------------------
# HELPERS: Email send utility
# -----------------------------
def send_email(to_email: str, subject: str, html_body: str, plain_text: str = None):
    """
    Sends an email via Gmail SMTP using EMAIL_ADDRESS / EMAIL_PASSWORD.
    If EMAIL_* env vars not set, this returns False.
    """
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        app.logger.warning("Email credentials not set; cannot send email.")
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"{EMAIL_SENDER_NAME} <{EMAIL_ADDRESS}>"
    msg["To"] = to_email
    if plain_text:
        msg.set_content(plain_text)
    msg.add_alternative(html_body, subtype="html")

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        app.logger.info(f"Sent email to {to_email}: {subject}")
        return True
    except Exception as e:
        app.logger.exception("Failed to send email: " + str(e))
        return False

# -----------------------------
# SECURITY: suspicious-alert wrapper
# -----------------------------
def maybe_send_suspicious_alert(user: User, reason: str, details: str):
    """
    Send suspicious alert email to user when triggers happen.
    """
    try:
        subject = "Suspicious Activity Detected"
        html = f"""
        <p>Dear {user.email},</p>
        <p><b>Suspicious activity detected</b> in your account:</p>
        <ul>
          <li><b>Reason:</b> {reason}</li>
          <li><b>Details:</b> {details}</li>
          <li><b>Time:</b> {datetime.utcnow().isoformat()}</li>
        </ul>
        <p>If this was not you, please reset your password immediately.</p>
        <p>Regards,<br/>{EMAIL_SENDER_NAME}</p>
        """
        plain = f"Suspicious activity: {reason}\nDetails: {details}"
        send_email(user.email, subject, html, plain)
    except Exception:
        app.logger.exception("Error in maybe_send_suspicious_alert")

# -----------------------------
# USER LOADER
# -----------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -----------------------------
# ROUTES (signup/login/otp)
# -----------------------------
@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not email or not password:
            flash("Provide email & password", "danger")
            return redirect("/signup")
        if User.query.filter_by(email=email).first():
            flash("Email already registered", "danger")
            return redirect("/signup")
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        otp_secret = pyotp.random_base32()
        u = User(email=email, password_hash=hashed, otp_secret=otp_secret)
        db.session.add(u)
        db.session.commit()
        session["new_user_id"] = u.id
        return redirect(url_for("setup_otp"))
    return render_template("signup.html", theme="neon")


@app.route("/setup_otp")
def setup_otp():
    uid = session.get("new_user_id")
    if not uid:
        return redirect(url_for("login"))
    user = User.query.get(uid)
    if not user:
        flash("User not found", "danger")
        return redirect(url_for("signup"))

    totp = pyotp.TOTP(user.otp_secret)
    uri = totp.provisioning_uri(name=user.email, issuer_name="EncryptX")
    qr = qrcode.make(uri)
    try:
        img = qr if isinstance(qr, Image.Image) else qr.get_image()
    except Exception:
        img = qr
    buf = io.BytesIO()
    img.save(buf, "PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()

    return render_template("otp_qr.html", qr=b64, secret=user.otp_secret, theme="neon")


# -----------------------------
# LOGIN with OTP + tracking failed attempts + new-ip detection
# -----------------------------
def get_client_ip():
    # If behind proxy set X-Forwarded-For; otherwise remote_addr
    return request.headers.get("X-Forwarded-For", request.remote_addr)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        otp = request.form.get("otp", "").strip()

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Invalid credentials", "danger")
            return redirect("/login")

        # password check
        if not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
            # increment failed attempts
            user.failed_attempts = (user.failed_attempts or 0) + 1
            user.last_failed_at = datetime.utcnow()
            db.session.commit()
            # send alert on 3 attempts
            if user.failed_attempts >= 3:
                maybe_send_suspicious_alert(user, "Multiple failed login attempts", f"failed_attempts={user.failed_attempts}")
                flash("Too many failed attempts. Alert sent to your email.", "danger")
            else:
                flash("Invalid credentials.", "danger")
            return redirect("/login")

        # verify otp
        totp = pyotp.TOTP(user.otp_secret)
        if not totp.verify(otp):
            user.failed_attempts = (user.failed_attempts or 0) + 1
            user.last_failed_at = datetime.utcnow()
            db.session.commit()
            if user.failed_attempts >= 3:
                maybe_send_suspicious_alert(user, "Multiple failed login attempts (OTP)", f"failed_attempts={user.failed_attempts}")
                flash("Too many failed attempts. Alert sent to your email.", "danger")
            else:
                flash("Invalid OTP", "danger")
            return redirect("/login")

        # successful login: check new IP or UA
        client_ip = get_client_ip()
        ua = request.headers.get("User-Agent", "")[:300]

        new_device = False
        if (user.last_login_ip and user.last_login_ip != client_ip) or (user.last_login_ua and user.last_login_ua != ua):
            new_device = True

        user.last_login_ip = client_ip
        user.last_login_ua = ua
        user.failed_attempts = 0
        db.session.commit()

        login_user(user)
        # alert if new device/ip
        if new_device:
            maybe_send_suspicious_alert(user, "New login device/IP detected", f"ip={client_ip}, ua={ua}")

        flash("Logged in", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html", theme="neon")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out", "info")
    return redirect(url_for("login"))
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", theme=current_user.theme)


# -----------------------------
# ENCRYPT / DECRYPT + SUSPICION ALERTS
# -----------------------------
@app.route("/encrypt/text", methods=["GET", "POST"])
@login_required
def encrypt_text_view():
    combined = None
    key_hex = None
    key_strength = None
    key_entropy = None
    key_score = None
    ml_label = None
    ml_score = None

    if request.method == "POST":
        plaintext = request.form.get("plaintext", "").strip()

        if not plaintext:
            flash("Enter text to encrypt", "warning")
            return redirect(url_for("encrypt_text_view"))

        ml_label, ml_score = predict_suspicion(plaintext)

        combined, key_hex, original_hash, key_strength, key_entropy = encrypt_text(plaintext)
        session["last_hash"] = original_hash

        key_entropy = round(key_entropy, 2)
        key_score = round(min((key_entropy / 8) * 100, 100), 2)

        db.session.add(OperationLog(
            user_id=current_user.id,
            operation="encrypt",
            data_type="text",
            details=f"len={len(plaintext)}"
        ))
        db.session.commit()

    return render_template(
        "encrypt_text.html",
        combined=combined,
        key=key_hex,
        key_strength=key_strength,
        key_entropy=key_entropy,
        key_score=key_score,
        ml_label=ml_label,
        ml_score=ml_score,
        theme=current_user.theme
    )



@app.route("/decrypt/text", methods=["GET", "POST"])
@login_required
def decrypt_text_view():
    plaintext = None
    integrity_ok = None

    if request.method == "POST":
        combined = request.form.get("combined_input", "").strip()

        if not is_combined_format(combined):
            flash("Invalid encrypted format", "danger")
            return redirect(url_for("decrypt_text_view"))

        plaintext, decrypted_hash = decrypt_text(combined)
        original_hash = session.get("last_hash")

        integrity_ok = (original_hash == decrypted_hash)

    return render_template(
        "decrypt_text.html",
        plaintext=plaintext,
        integrity_ok=integrity_ok,
        theme=current_user.theme
    )




@app.route("/encrypt/file", methods=["GET", "POST"])
@login_required
def encrypt_file_view():
    combined = None
    key_hex = None
    risk_label = None
    risk_score = None
    if request.method == "POST":
        f = request.files.get("input_file")
        if not f:
            flash("No file uploaded", "danger")
            return redirect(url_for("encrypt_file_view"))
        filename = secure_filename(f.filename)
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext and ext not in ALLOWED_EXT:
            flash("Extension not allowed", "danger")
            return redirect(url_for("encrypt_file_view"))
        data = f.read()
        if len(data) > MAX_FILE_SIZE:
            flash(f"File exceeds max size ({MAX_FILE_SIZE} bytes)", "danger")
            return redirect(url_for("encrypt_file_view"))

        # very simple "ml" for file
        risk_label, risk_score = predict_suspicion(filename + " " + str(len(data)))
        combined, key_hex = encrypt_file_bytes(data)

        ln = OperationLog(user_id=current_user.id, operation="encrypt",
                          data_type=f"file:{filename}", details=f"ml={risk_label}({risk_score}) size={len(data)}")
        db.session.add(ln); db.session.commit()

        if risk_label in ("SUSPICIOUS", "WARNING"):
            maybe_send_suspicious_alert(current_user, "Suspicious file encryption", f"filename={filename}, label={risk_label}")

    return render_template("encrypt_file.html", combined=combined, key=key_hex,
                           ml_label=risk_label, ml_score=risk_score, theme=current_user.theme)


@app.route("/decrypt/file", methods=["GET", "POST"])
@login_required
def decrypt_file_view():
    if request.method == "POST":
        combined = request.form.get("combined_input", "").strip()
        filename = request.form.get("orig_filename", "").strip()
        if not combined or not is_combined_format(combined):
            flash("Provide valid combined string (key::ciphertext)", "danger")
            return redirect(url_for("decrypt_file_view"))
        if filename == "":
            flash("Provide original filename (name.ext) so the file can be restored", "warning")
            return redirect(url_for("decrypt_file_view"))
        try:
            data = decrypt_file_bytes(combined)
        except Exception as e:
            flash("Decryption failed: " + str(e), "danger")
            return redirect(url_for("decrypt_file_view"))

        safe_name = secure_filename(filename)
        out_path = os.path.join(BASE_DIR, "decrypted_output_" + safe_name)
        with open(out_path, "wb") as wf:
            wf.write(data)

        ln = OperationLog(user_id=current_user.id, operation="decrypt",
                          data_type=f"file:{safe_name}", details=f"size={len(data)}")
        db.session.add(ln); db.session.commit()

        ext = safe_name.rsplit(".", 1)[-1].lower() if "." in safe_name else ""
        if ext in {"jpg", "jpeg", "png"}:
            with open(out_path, "rb") as rf:
                b64 = base64.b64encode(rf.read()).decode()
            return render_template("decrypt_file.html", preview_b64=b64, preview_name=safe_name, theme=current_user.theme)
        else:
            return send_file(out_path, as_attachment=True, download_name=safe_name)

    return render_template("decrypt_file.html", theme=current_user.theme)


# -----------------------------
# AUDIO (browser-side)
# -----------------------------
@app.route("/encrypt/audio")
@login_required
def encrypt_audio_page():
    return render_template("audio.html", theme=current_user.theme)

@app.route("/upload_encrypted_audio", methods=["POST"])
@login_required
def upload_encrypted_audio():
    f = request.files.get("audio")
    if not f:
        flash("No encrypted audio received", "danger")
        return redirect(url_for("encrypt_audio_page"))
    out = os.path.join(BASE_DIR, "encrypted_audio.bin")
    f.save(out)
    ln = OperationLog(user_id=current_user.id, operation="encrypt", data_type="audio", details="audio uploaded (encrypted)")
    db.session.add(ln); db.session.commit()
    return send_file(out, as_attachment=True, download_name="encrypted_audio.bin")


# -----------------------------
# FORGOT PASSWORD + RESET
# -----------------------------
@app.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("If the email exists, a reset link will be sent.", "info")
            return redirect(url_for("forgot_password"))

        # generate token
        token = URL_SERIALIZER.dumps(user.email, salt="password-reset-salt")
        reset_url = url_for("reset_with_token", token=token, _external=True)

        html = f"""
        <p>Hi {user.email},</p>
        <p>Click the link below to reset your password (valid for 30 minutes):</p>
        <p><a href="{reset_url}">{reset_url}</a></p>
        <p>If you did not request this, ignore this email.</p>
        """

        send_email(user.email, "Password Reset — Encryption Tool", html,
                   plain_text=f"Reset link: {reset_url}")
        flash("Password reset link sent if the email is registered.", "info")
        return redirect(url_for("login"))

    return render_template("forgot_password.html", theme="neon")


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_with_token(token):
    try:
        email = URL_SERIALIZER.loads(token, salt="password-reset-salt", max_age=RESET_TOKEN_EXPIRY_SECONDS)
    except SignatureExpired:
        flash("Reset link expired. Request a new one.", "danger")
        return redirect(url_for("forgot_password"))
    except BadSignature:
        flash("Invalid reset token.", "danger")
        return redirect(url_for("forgot_password"))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("signup"))

    if request.method == "POST":
        new_pw = request.form.get("password", "")
        if not new_pw:
            flash("Provide new password.", "warning")
            return redirect(url_for("reset_with_token", token=token))
        user.password_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
        db.session.commit()
        flash("Password updated. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token, theme="neon")


# -----------------------------
# LOGS / THEME / ERRORS
# -----------------------------
@app.route("/logs")
@login_required
def logs_view():
    logs = OperationLog.query.filter_by(user_id=current_user.id).order_by(OperationLog.id.desc()).all()
    return render_template("logs.html", logs=logs, theme=current_user.theme)

@app.route("/toggle_theme")
@login_required
def toggle_theme():
    current_user.theme = "light" if current_user.theme == "dark" else "dark"
    db.session.commit()
    return redirect(request.referrer or url_for("dashboard"))

@app.errorhandler(413)
def too_large(e):
    flash("File too large (exceeds server limit).", "danger")
    return redirect(url_for("dashboard"))

# -----------------------------
# DB INIT + RUN
# -----------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5600, debug=True)
