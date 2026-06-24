from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.secret_key = "cyberforge_secret"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(100), unique=True)

    password = db.Column(db.String(200))

with app.app_context():
    db.create_all()

@app.route("/")
def home():
    return render_template("login.html")

@app.route("/register")
def register():
    return render_template("register.html")

@app.route("/register_user", methods=["POST"])
def register_user():

    username = request.form["username"]

    password = generate_password_hash(
        request.form["password"]
    )

    user = User(
        username=username,
        password=password
    )

    db.session.add(user)

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

    return "Invalid Login"

@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/")

    return render_template(
        "dashboard.html",
        username=session["user"]
    )

@app.route("/logout")
def logout():

    session.pop("user", None)

    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)