from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib

app = Flask(__name__)

app.secret_key = "cyberforge_secret"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ==========================
# DATABASE
# ==========================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(255),
        nullable=False
    )

with app.app_context():
    db.create_all()

# ==========================
# PASSWORD CHECKER
# ==========================

def check_password_strength(password):

    score = 0

    if len(password) >= 8:
        score += 1

    if any(c.isupper() for c in password):
        score += 1

    if any(c.isdigit() for c in password):
        score += 1

    if any(not c.isalnum() for c in password):
        score += 1

    if score <= 1:
        return "Weak"

    elif score <= 3:
        return "Medium"

    return "Strong"

# ==========================
# URL SCANNER
# ==========================

def scan_url(url):

    suspicious_words = [
        "login",
        "verify",
        "secure",
        "bank",
        "update",
        "free",
        "gift"
    ]

    score = 0

    for word in suspicious_words:

        if word in url.lower():
            score += 1

    if score >= 3:
        return "High Risk"

    elif score >= 1:
        return "Medium Risk"

    return "Low Risk"

# ==========================
# PHISHING DETECTOR
# ==========================

def detect_phishing(url):

    suspicious = [
        "@",
        "bit.ly",
        "tinyurl",
        "free-money",
        "gift-card"
    ]

    for item in suspicious:

        if item in url.lower():
            return "Possible Phishing"

    return "Looks Safe"

# ==========================
# ROUTES
# ==========================

@app.route("/")
def home():
    return render_template("login.html")

@app.route("/register")
def register():
    return render_template("register.html")

@app.route("/register_user", methods=["POST"])
def register_user():

    username = request.form["username"]
    password = request.form["password"]

    existing_user = User.query.filter_by(
        username=username
    ).first()

    if existing_user:
        return "Username already exists"

    hashed_password = generate_password_hash(password)

    new_user = User(
        username=username,
        password=hashed_password
    )

    db.session.add(new_user)
    db.session.commit()

    return redirect("/")

@app.route("/login", methods=["POST"])
def login():

    username = request.form["username"]
    password = request.form["password"]

    user = User.query.filter_by(
        username=username
    ).first()

    if user and check_password_hash(
        user.password,
        password
    ):

        session["user"] = username

        return redirect("/dashboard")

    return "Invalid Username or Password"

@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/")

    return render_template(
        "dashboard.html",
        username=session["user"]
    )

@app.route("/password", methods=["POST"])
def password_checker():

    password = request.form["password"]

    result = check_password_strength(password)

    return render_template(
        "dashboard.html",
        username=session["user"],
        result=result
    )

@app.route("/hash", methods=["POST"])
def hash_generator():

    text = request.form["text"]

    md5 = hashlib.md5(
        text.encode()
    ).hexdigest()

    sha256 = hashlib.sha256(
        text.encode()
    ).hexdigest()

    return render_template(
        "dashboard.html",
        username=session["user"],
        md5=md5,
        sha256=sha256
    )

@app.route("/urlscan", methods=["POST"])
def urlscan():

    url = request.form["url"]

    risk = scan_url(url)

    phishing = detect_phishing(url)

    return render_template(
        "dashboard.html",
        username=session["user"],
        risk=risk,
        phishing=phishing
    )

@app.route("/logout")
def logout():

    session.pop("user", None)

    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)