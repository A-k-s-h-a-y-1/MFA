# app.py
from flask import Flask, render_template, redirect, url_for, request, flash, session, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import pyotp
import os
import time
import secrets
import smtplib
from email.message import EmailMessage

# CONFIG
INTERVAL = 120  # seconds per TOTP code. Use same value for generation & verification.
OTP_VALID_WINDOW = 1  # allow +/- 1 interval step for clock skew (optional)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'replace_with_a_real_secret')

# SQLite DB path
db_path = os.path.join(os.path.abspath(os.getcwd()), 'database.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# -------------------------
# Mail config (HARDCODED for local/dummy testing)
# -------------------------
# WARNING: Hardcoding credentials is unsafe for production.
# Replace these with environment variables in real use.
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

# <-- Inserted directly as requested (dummy password) -->
app.config['MAIL_USERNAME'] = "akshaysaran00@gmail.com"
# If your dummy had spaces and you accidentally pasted with spaces, remove them:
app.config['MAIL_PASSWORD'] = "abcd abcd abcd abcd".replace(" ", "")
app.config['MAIL_DEFAULT_SENDER'] = "akshaysaran00@gmail.com"
# -------------------------

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Log current mail config for debugging (do not log sensitive values in production)
app.logger.info("MAIL_USERNAME present: %s", bool(app.config.get('MAIL_USERNAME')))
app.logger.info("MAIL_DEFAULT_SENDER present: %s", bool(app.config.get('MAIL_DEFAULT_SENDER')))

# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    otp_secret = db.Column(db.String(32), nullable=False, default=lambda: pyotp.random_base32())

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper: generate random safe token
def generate_token(n=24):
    return secrets.token_urlsafe(n)

# Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        raw_password = request.form.get('password') or ''
        if not email or not raw_password:
            flash('Please provide email and password', 'danger')
            return render_template('register.html')
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'warning')
            return render_template('register.html')
        hashed = bcrypt.generate_password_hash(raw_password).decode('utf-8')
        new_user = User(email=email, password=hashed)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['pre_mfa_email'] = user.email
            # clear previous send timestamp to allow sending now
            session.pop('mfa_sent_at', None)
            return redirect(url_for('mfa'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html')

# MFA (send & verify)
@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    if 'pre_mfa_email' not in session:
        return redirect(url_for('login'))

    user = User.query.filter_by(email=session['pre_mfa_email']).first()
    if not user:
        flash('User not found. Please login again.', 'danger')
        session.pop('pre_mfa_email', None)
        return redirect(url_for('login'))

    now = int(time.time())

    # Handle explicit resend
    if request.method == 'POST' and 'resend' in request.form:
        last_sent = session.get('mfa_sent_at', 0)
        if now - last_sent < 30:
            flash(f'Please wait {30 - (now - last_sent)}s before resending.', 'warning')
        else:
            if send_otp_email(user):
                session['mfa_sent_at'] = now
                flash('OTP resent to your email.', 'info')
            else:
                flash('Failed to send OTP. Check mail settings.', 'danger')
        return render_template('mfa.html')

    # If POST and otp present -> try verify
    if request.method == 'POST' and request.form.get('otp') is not None:
        submitted_otp = (request.form.get('otp') or '').strip()
        totp = pyotp.TOTP(user.otp_secret, interval=INTERVAL)
        current_code = totp.now()

        # DEBUG: write a short debug note into session so template can show it
        session['debug_note'] = f"submitted={repr(submitted_otp)} current={repr(current_code)}"

        app.logger.debug("Submitted OTP repr=%r current OTP repr=%r", submitted_otp, current_code)

        try:
            if totp.verify(submitted_otp, valid_window=OTP_VALID_WINDOW):
                login_user(user)
                session.pop('pre_mfa_email', None)
                session.pop('mfa_sent_at', None)
                session.pop('debug_note', None)
                flash('OTP verified. Logged in successfully.', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid or expired OTP. Try again or resend.', 'danger')
        except Exception as e:
            app.logger.exception("Error verifying OTP: %s", e)
            flash('Error verifying OTP. Try again.', 'danger')

        return render_template('mfa.html')

    # GET: send OTP once (if cooldown passed)
    if request.method == 'GET':
        last_sent = session.get('mfa_sent_at', 0)
        if now - last_sent >= 5:
            if send_otp_email(user):
                session['mfa_sent_at'] = now
                app.logger.debug('MFA OTP sent to %s', user.email)
            else:
                flash("Couldn't send OTP email — check server logs and mail settings.", 'danger')

    return render_template('mfa.html')


# New send_otp_email using smtplib (fallback that matched your standalone test)
def send_otp_email(user):
    totp = pyotp.TOTP(user.otp_secret, interval=INTERVAL)
    otp_code = totp.now()

    smtp_host = app.config.get('MAIL_SERVER', 'smtp.gmail.com')
    smtp_port = app.config.get('MAIL_PORT', 587)
    username = app.config.get('MAIL_USERNAME')
    password = app.config.get('MAIL_PASSWORD')
    sender = app.config.get('MAIL_DEFAULT_SENDER') or username
    recipient = user.email

    if not username or not password:
        app.logger.error("Mail username/password missing in config; cannot send email.")
        return False

    # Build the message
    em = EmailMessage()
    em['From'] = sender
    em['To'] = recipient
    em['Subject'] = "Your MFA Code"
    em.set_content(f"Your one-time code is: {otp_code}\nIt is valid for {INTERVAL} seconds.")

    try:
        # Connect, start TLS, login and send (same flow as your successful test)
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as smtp:
            smtp.set_debuglevel(0)  # set to 1 for debug output
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(username, password)
            smtp.send_message(em)
        app.logger.info("OTP email sent to %s (via smtplib).", recipient)
        return True
    except Exception as exc:
        app.logger.exception("Failed to send OTP via smtplib: %s", exc)
        return False

# Dashboard Route — render the dashboard template
@app.route('/dashboard')
@login_required
def dashboard():
    # pass any variables your template expects (current_user is available in templates by default)
    return render_template('dashboard.html',
                           heading="Security Dashboard",
                           subheading="Overview of your account and MFA status",
                           title="Dashboard • Secure MFA")


# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
def home():
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

# -----------------------------
# Minimal templates (put these in templates/ folder)
# -----------------------------
# templates/register.html
# ----------------------
# <!doctype html>
# <title>Register</title>
# <h2>Register</h2>
# <form method="post">
#   Email: <input name="email"><br>
#   Password: <input name="password" type="password"><br>
#   <button type="submit">Register</button>
# </form>
# <a href="{{ url_for('login') }}">Login</a>
#
# templates/login.html
# --------------------
# <!doctype html>
# <title>Login</title>
# <h2>Login</h2>
# <form method="post">
#   Email: <input name="email"><br>
#   Password: <input name="password" type="password"><br>
#   <button type="submit">Login</button>
# </form>
# <a href="{{ url_for('register') }}">Register</a>
#
# templates/mfa.html
# ------------------
# <!doctype html>
# <title>MFA</title>
# <h2>MFA Verification</h2>
# <p>An OTP has been sent to your email address.</p>
# <form method="post">
#   Enter OTP: <input name="otp" autocomplete="one-time-code"><br>
#   <button name="verify" type="submit">Verify</button>
#   <button name="resend" type="submit">Resend OTP</button>
# </form>

