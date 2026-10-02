from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    url_for,
    flash
)

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from functools import wraps
from datetime import datetime
import hashlib
from urllib.parse import urlparse
import os
import requests
from dotenv import load_dotenv


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = "CHANGE_THIS_TO_A_RANDOM_SECRET_KEY"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# ============================================================
# DATABASE MODELS
# ============================================================

class User(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(255),
        nullable=False
    )

    role = db.Column(
        db.String(30),
        nullable=False,
        default="community"
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


class ActivityLog(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(100),
        nullable=False
    )

    action = db.Column(
        db.String(255),
        nullable=False
    )

    result = db.Column(
        db.String(255),
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


# ============================================================
# CREATE DATABASE
# ============================================================

with app.app_context():
    db.create_all()


# ============================================================
# ACTIVITY LOGGER
# ============================================================

def save_log(username, action, result=None):

    try:

        log = ActivityLog(
            username=username,
            action=action,
            result=result
        )

        db.session.add(log)
        db.session.commit()

    except Exception as error:

        db.session.rollback()

        print("Activity log error:", error)


# ============================================================
# LOGIN REQUIRED DECORATOR
# ============================================================

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:
            flash(
                "Please login first.",
                "warning"
            )

            return redirect(
                url_for("home")
            )

        return function(*args, **kwargs)

    return wrapper


# ============================================================
# ROLE REQUIRED DECORATOR
# ============================================================

def role_required(*allowed_roles):

    def decorator(function):

        @wraps(function)
        def wrapper(*args, **kwargs):

            if "user_id" not in session:

                flash(
                    "Please login first.",
                    "warning"
                )

                return redirect(
                    url_for("home")
                )

            current_role = session.get("role")

            if current_role not in allowed_roles:

                flash(
                    "You do not have permission to access this page.",
                    "danger"
                )

                return redirect(
                    url_for("dashboard")
                )

            return function(*args, **kwargs)

        return wrapper

    return decorator


# ============================================================
# PASSWORD STRENGTH CHECKER
# ============================================================

def check_password_strength(password):

    score = 0
    suggestions = []

    if len(password) >= 8:
        score += 1
    else:
        suggestions.append(
            "Use at least 8 characters."
        )

    if any(character.isupper() for character in password):
        score += 1
    else:
        suggestions.append(
            "Add uppercase letters."
        )

    if any(character.islower() for character in password):
        score += 1
    else:
        suggestions.append(
            "Add lowercase letters."
        )

    if any(character.isdigit() for character in password):
        score += 1
    else:
        suggestions.append(
            "Add numbers."
        )

    if any(
        not character.isalnum()
        for character in password
    ):
        score += 1
    else:
        suggestions.append(
            "Add special characters."
        )

    if score <= 2:

        strength = "Weak"

    elif score <= 4:

        strength = "Medium"

    else:

        strength = "Strong"

    return strength, suggestions


# ============================================================
# URL SCANNER
# ============================================================

def scan_url(url):

    url_lower = url.lower().strip()

    score = 0
    findings = []

    # --------------------------------------------------------
    # URL format
    # --------------------------------------------------------

    if not url_lower.startswith(
        ("http://", "https://")
    ):

        findings.append(
            "URL does not use HTTP or HTTPS."
        )

        score += 1

    # --------------------------------------------------------
    # Suspicious keywords
    # --------------------------------------------------------

    suspicious_words = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "bank",
        "update",
        "password",
        "confirm",
        "free",
        "gift",
        "reward"
    ]

    for word in suspicious_words:

        if word in url_lower:

            score += 1

            findings.append(
                f"Suspicious keyword detected: {word}"
            )

    # --------------------------------------------------------
    # IP address in URL
    # --------------------------------------------------------

    try:

        parsed = urlparse(url_lower)

        hostname = parsed.hostname

        if hostname:

            parts = hostname.split(".")

            if len(parts) == 4 and all(
                part.isdigit()
                for part in parts
            ):

                score += 2

                findings.append(
                    "URL uses an IP address instead of a domain name."
                )

    except Exception:

        score += 1

        findings.append(
            "Unable to parse the URL."
        )

    # --------------------------------------------------------
    # @ symbol
    # --------------------------------------------------------

    if "@" in url_lower:

        score += 2

        findings.append(
            "URL contains an @ symbol."
        )

    # --------------------------------------------------------
    # URL shortening
    # --------------------------------------------------------

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly"
    ]

    for shortener in shorteners:

        if shortener in url_lower:

            score += 2

            findings.append(
                f"URL shortener detected: {shortener}"
            )

    # --------------------------------------------------------
    # HTTPS
    # --------------------------------------------------------

    if url_lower.startswith("https://"):

        findings.append(
            "HTTPS is present."
        )

    else:

        findings.append(
            "HTTPS is not detected."
        )

        score += 1

    # --------------------------------------------------------
    # Risk
    # --------------------------------------------------------

    if score >= 6:

        risk = "High Risk"

    elif score >= 3:

        risk = "Medium Risk"

    else:

        risk = "Low Risk"

    return risk, findings


# ============================================================
# PHISHING DETECTOR
# ============================================================

def detect_phishing(url):

    url_lower = url.lower()

    indicators = []

    phishing_patterns = [
        "@",
        "bit.ly",
        "tinyurl.com",
        "free-money",
        "gift-card",
        "verify-account",
        "login-confirm",
        "password-reset"
    ]

    for pattern in phishing_patterns:

        if pattern in url_lower:

            indicators.append(
                pattern
            )

    if indicators:

        return (
            "Possible Phishing",
            indicators
        )

    return (
        "No obvious phishing indicator",
        []
    )


# ============================================================
# HOME / LOGIN
# ============================================================

@app.route("/")
def home():

    if "user_id" in session:

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "login.html"
    )


# ============================================================
# REGISTER PAGE
# ============================================================

@app.route("/register")
def register():

    if "user_id" in session:

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "register.html"
    )


# ============================================================
# REGISTER USER
# ============================================================

@app.route(
    "/register_user",
    methods=["POST"]
)
def register_user():

    username = request.form.get(
        "username",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    )

    confirm_password = request.form.get(
        "confirm_password",
        ""
    )

    role = request.form.get(
        "role",
        "community"
    ).lower().strip()

    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    if not username or not password:

        flash(
            "Username and password are required.",
            "danger"
        )

        return redirect(
            url_for("register")
        )

    if len(username) < 3:

        flash(
            "Username must contain at least 3 characters.",
            "danger"
        )

        return redirect(
            url_for("register")
        )

    if len(password) < 8:

        flash(
            "Password must contain at least 8 characters.",
            "danger"
        )

        return redirect(
            url_for("register")
        )

    if confirm_password and password != confirm_password:

        flash(
            "Passwords do not match.",
            "danger"
        )

        return redirect(
            url_for("register")
        )

    # --------------------------------------------------------
    # Prevent self-registration as admin
    # --------------------------------------------------------

    allowed_roles = [
        "community",
        "business",
        "investigation"
    ]

    if role not in allowed_roles:

        role = "community"

    # --------------------------------------------------------
    # Check existing username
    # --------------------------------------------------------

    existing_user = User.query.filter_by(
        username=username
    ).first()

    if existing_user:

        flash(
            "Username already exists.",
            "danger"
        )

        return redirect(
            url_for("register")
        )

    # --------------------------------------------------------
    # Hash password
    # --------------------------------------------------------

    hashed_password = generate_password_hash(
        password
    )

    # --------------------------------------------------------
    # Create user
    # --------------------------------------------------------

    new_user = User(
        username=username,
        password=hashed_password,
        role=role
    )

    try:

        db.session.add(new_user)
        db.session.commit()

    except Exception as error:

        db.session.rollback()

        print("Registration error:", error)

        flash(
            "Registration failed.",
            "danger"
        )

        return redirect(
            url_for("register")
        )

    flash(
        "Registration successful. Please login.",
        "success"
    )

    return redirect(
        url_for("home")
    )


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/login",
    methods=["POST"]
)
def login():

    username = request.form.get(
        "username",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    )

    user = User.query.filter_by(
        username=username
    ).first()

    if user and check_password_hash(
        user.password,
        password
    ):

        session.clear()

        session["user_id"] = user.id
        session["user"] = user.username
        session["role"] = user.role

        save_log(
            user.username,
            "User Login",
            "Successful"
        )

        return redirect(
            url_for("dashboard")
        )

    flash(
        "Invalid username or password.",
        "danger"
    )

    return redirect(
        url_for("home")
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
@login_required
def dashboard():

    username = session["user"]
    role = session.get(
        "role",
        "community"
    )

    # --------------------------------------------------------
    # User statistics
    # --------------------------------------------------------

    total_activity = ActivityLog.query.filter_by(
        username=username
    ).count()

    total_url_scans = ActivityLog.query.filter_by(
        username=username,
        action="URL Scan"
    ).count()

    total_password_checks = ActivityLog.query.filter_by(
        username=username,
        action="Password Strength Check"
    ).count()

    total_hashes = ActivityLog.query.filter_by(
        username=username,
        action="Hash Generated"
    ).count()

    recent_activity = ActivityLog.query.filter_by(
        username=username
    ).order_by(
        ActivityLog.created_at.desc()
    ).limit(10).all()

    return render_template(
        "dashboard.html",
        username=username,
        role=role,
        total_activity=total_activity,
        total_url_scans=total_url_scans,
        total_password_checks=total_password_checks,
        total_hashes=total_hashes,
        recent_activity=recent_activity
    )


# ============================================================
# COMMUNITY DASHBOARD
# ============================================================

@app.route("/community")
@role_required("community")
def community():

    return render_template(
        "community.html",
        username=session["user"],
        role=session["role"]
    )


# ============================================================
# BUSINESS DASHBOARD
# ============================================================

@app.route("/business")
@role_required("business")
def business():

    return render_template(
        "business.html",
        username=session["user"],
        role=session["role"]
    )


# ============================================================
# INVESTIGATION DASHBOARD
# ============================================================

@app.route("/investigation")
@role_required("investigation")
def investigation():

    return render_template(
        "investigation.html",
        username=session["user"],
        role=session["role"]
    )


# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.route("/admin")
@role_required("admin")
def admin():

    users = User.query.order_by(
        User.created_at.desc()
    ).all()

    logs = ActivityLog.query.order_by(
        ActivityLog.created_at.desc()
    ).limit(50).all()

    total_users = User.query.count()

    total_logs = ActivityLog.query.count()

    return render_template(
        "admin.html",
        username=session["user"],
        users=users,
        logs=logs,
        total_users=total_users,
        total_logs=total_logs
    )


# ============================================================
# PASSWORD STRENGTH CHECKER
# ============================================================

@app.route(
    "/password",
    methods=["POST"]
)
@login_required
def password_checker():

    password = request.form.get(
        "password",
        ""
    )

    strength, suggestions = check_password_strength(
        password
    )

    save_log(
        session["user"],
        "Password Strength Check",
        strength
    )

    return render_template(
        "dashboard.html",
        username=session["user"],
        role=session.get("role"),
        result=strength,
        suggestions=suggestions
    )


# ============================================================
# HASH GENERATOR
# ============================================================

@app.route(
    "/hash",
    methods=["POST"]
)
@login_required
def hash_generator():

    text = request.form.get(
        "text",
        ""
    )

    md5 = hashlib.md5(
        text.encode("utf-8")
    ).hexdigest()

    sha256 = hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest()

    save_log(
        session["user"],
        "Hash Generated",
        "MD5 + SHA256"
    )

    return render_template(
        "dashboard.html",
        username=session["user"],
        role=session.get("role"),
        md5=md5,
        sha256=sha256
    )


# ============================================================
# URL SCANNER
# ============================================================

@app.route(
    "/urlscan",
    methods=["POST"]
)
@login_required
def urlscan():

    url = request.form.get(
        "url",
        ""
    ).strip()

    if not url:

        flash(
            "Please enter a URL.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    risk, findings = scan_url(
        url
    )

    phishing, phishing_indicators = detect_phishing(
        url
    )

    result = (
        f"{risk} | {phishing}"
    )

    save_log(
        session["user"],
        "URL Scan",
        result
    )

    return render_template(
        "dashboard.html",
        username=session["user"],
        role=session.get("role"),
        scanned_url=url,
        risk=risk,
        findings=findings,
        phishing=phishing,
        phishing_indicators=phishing_indicators
    )


# ============================================================
# REPORTS
# ============================================================

@app.route("/reports")
@login_required
def reports():

    logs = ActivityLog.query.filter_by(
        username=session["user"]
    ).order_by(
        ActivityLog.created_at.desc()
    ).all()

    return render_template(
        "reports.html",
        username=session["user"],
        role=session.get("role"),
        logs=logs
    )


# ============================================================
# PROFILE
# ============================================================

@app.route("/profile")
@login_required
def profile():

    user = User.query.get(
        session["user_id"]
    )

    activity_count = ActivityLog.query.filter_by(
        username=user.username
    ).count()

    return render_template(
        "profile.html",
        user=user,
        activity_count=activity_count
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    username = session.get(
        "user"
    )

    if username:

        save_log(
            username,
            "User Logout",
            "Successful"
        )

    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("home")
    )


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def page_not_found(error):

    return """
    <h1>404 - Page Not Found</h1>
    <a href="/">Go to Login</a>
    """, 404


@app.errorhandler(500)
def internal_server_error(error):

    db.session.rollback()

    return """
    <h1>500 - Internal Server Error</h1>
    <a href="/">Go to Login</a>
    """, 500


# ============================================================
# THREAT INTELLIGENCE
# ============================================================

def check_ip_reputation(ip_address):

    if not ABUSEIPDB_API_KEY:
        return {
            "success": False,
            "message": "AbuseIPDB API key is not configured."
        }

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }

    try:

        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=10
        )

        if response.status_code != 200:

            return {
                "success": False,
                "message": "Threat intelligence service returned an error."
            }

        data = response.json().get("data", {})

        return {
            "success": True,
            "ip": data.get("ipAddress"),
            "abuse_confidence": data.get(
                "abuseConfidenceScore"
            ),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get(
                "totalReports"
            ),
            "last_reported": data.get(
                "lastReportedAt"
            )
        }

    except requests.RequestException:

        return {
            "success": False,
            "message": "Unable to connect to threat intelligence service."
        }
        
        
def check_hash_reputation(file_hash):
    
    if not VIRUSTOTAL_API_KEY:
        return {
            "success": False,
            "message": "VirusTotal API key is not configured."
        }

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:

        response = requests.get(
            url,
            headers=headers,
            timeout=10
        )

        if response.status_code == 404:

            return {
                "success": True,
                "found": False,
                "message": "Hash was not found in the VirusTotal database."
            }

        if response.status_code != 200:

            return {
                "success": False,
                "message": "VirusTotal returned an error."
            }

        data = response.json()

        attributes = data["data"]["attributes"]

        stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        return {
            "success": True,
            "found": True,
            "hash": file_hash,
            "malicious": stats.get(
                "malicious",
                0
            ),
            "suspicious": stats.get(
                "suspicious",
                0
            ),
            "undetected": stats.get(
                "undetected",
                0
            ),
            "harmless": stats.get(
                "harmless",
                0
            ),
            "type": attributes.get(
                "type_description"
            ),
            "size": attributes.get(
                "size"
            )
        }

    except requests.RequestException:

        return {
            "success": False,
            "message": "Unable to connect to VirusTotal."
        }
# ============================================================
# THREAT INTELLIGENCE PAGE
# ============================================================

@app.route("/threat-intelligence")
@login_required
def threat_intelligence():

    return render_template(
        "threat_intelligence.html",
        username=session["user"],
        role=session.get("role")
    )



# ============================================================
# IP THREAT INTELLIGENCE
# ============================================================

@app.route(
    "/threat-intelligence/ip",
    methods=["POST"]
)
@login_required
def threat_ip():

    ip_address = request.form.get(
        "ip",
        ""
    ).strip()

    if not ip_address:

        flash(
            "Please enter an IP address.",
            "danger"
        )

        return redirect(
            url_for("threat_intelligence")
        )

    result = check_ip_reputation(
        ip_address
    )

    save_log(
        session["user"],
        "IP Threat Intelligence",
        ip_address
    )

    return render_template(
        "threat_intelligence.html",
        username=session["user"],
        role=session.get("role"),
        ip_result=result
    )
    
# ============================================================
# HASH THREAT INTELLIGENCE
# ============================================================

@app.route(
    "/threat-intelligence/hash",
    methods=["POST"]
)
@login_required
def threat_hash():

    file_hash = request.form.get(
        "hash",
        ""
    ).strip().lower()

    if not file_hash:

        flash(
            "Please enter a hash.",
            "danger"
        )

        return redirect(
            url_for("threat_intelligence")
        )

    result = check_hash_reputation(
        file_hash
    )

    save_log(
        session["user"],
        "Hash Threat Intelligence",
        file_hash[:20]
    )

    return render_template(
        "threat_intelligence.html",
        username=session["user"],
        role=session.get("role"),
        hash_result=result
    )



# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )