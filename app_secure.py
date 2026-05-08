from flask import Flask, request, redirect, session, render_template_string
from markupsafe import escape
import sqlite3
import bcrypt
import os
from cryptography.fernet import Fernet

app = Flask(__name__)

DB_NAME = "secure_app.db"
KEY_FILE = "secret.key"


BASE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        * { box-sizing: border-box; }
        body { margin: 0; font-family: Arial, sans-serif; background: linear-gradient(135deg, #eef2ff, #f8fafc); color: #1e293b; }
        .navbar { background: #0f172a; color: white; padding: 18px 48px; display: flex; justify-content: space-between; align-items: center; }
        .navbar a { color: white; text-decoration: none; margin-left: 18px; font-weight: bold; }
        .container { min-height: calc(100vh - 70px); display: flex; align-items: center; justify-content: center; padding: 40px 20px; }
        .card { width: 100%; max-width: 520px; background: white; padding: 34px; border-radius: 18px; box-shadow: 0 18px 45px rgba(15, 23, 42, 0.12); }
        h1, h2 { margin-top: 0; color: #0f172a; }
        p { line-height: 1.6; }
        label { display: block; margin-top: 15px; margin-bottom: 6px; font-weight: bold; }
        input { width: 100%; padding: 12px 14px; border: 1px solid #cbd5e1; border-radius: 10px; font-size: 15px; }
        button, .btn { display: inline-block; margin-top: 20px; padding: 12px 18px; border: none; border-radius: 10px; background: #2563eb; color: white; text-decoration: none; font-weight: bold; cursor: pointer; }
        .btn.secondary { background: #475569; margin-left: 8px; }
        .alert { background: #fee2e2; color: #991b1b; padding: 12px; border-radius: 10px; margin-top: 14px; }
        .info-box { background: #f1f5f9; padding: 15px; border-radius: 12px; margin-top: 15px; border-left: 5px solid #2563eb; }
        .badge { display: inline-block; padding: 6px 10px; background: #dbeafe; color: #1d4ed8; border-radius: 999px; font-size: 13px; font-weight: bold; }
    </style>
</head>
<body>
    <div class="navbar">
        <div><strong>Secure Web App</strong></div>
        <div>
            <a href="/">Home</a>
            <a href="/register">Register</a>
            <a href="/login">Login</a>
        </div>
    </div>
    <div class="container">
        <div class="card">
            {{ content|safe }}
        </div>
    </div>
</body>
</html>
"""

def page(title, content):
    return render_template_string(BASE_HTML, title=title, content=content)



def load_or_create_key():
    """
    Creates a persistent encryption key the first time the app runs.
    The same key must be reused so encrypted data can be decrypted later.
    """
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as file:
            return file.read()

    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as file:
        file.write(key)
    return key


cipher = Fernet(load_or_create_key())

# Strong secret key for session protection.
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32))


app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        bio TEXT
    )
    """)

    cursor.execute("SELECT * FROM users WHERE username = ?", ("admin",))
    admin = cursor.fetchone()

    if not admin:
        # Secure password storage using bcrypt.
        hashed_password = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode()

        # Encrypt sensitive stored data.
        encrypted_bio = cipher.encrypt("Admin account".encode()).decode()

        cursor.execute(
            "INSERT INTO users (username, password, role, bio) VALUES (?, ?, ?, ?)",
            ("admin", hashed_password, "admin", encrypted_bio)
        )

    conn.commit()
    conn.close()


@app.route("/")
def home():
    return page("Home", """
    <h1>Secure Web Application</h1>
    <p>This version mitigates security vulnerabilities.</p>
    <div class="info-box">
        <span class="badge">After Mitigation</span>
        <p>bcrypt, parameterized queries, XSS prevention, RBAC, encryption, and HTTPS.</p>
    </div>
    <a class="btn" href="/register">Create Account</a>
    <a class="btn secondary" href="/login">Login</a>
    """)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        bio = request.form["bio"].strip()

        if not username or not password:
            return page("Register", '<div class="alert">Username and password are required</div><a class="btn" href="/register">Try Again</a>')

        if len(username) > 30:
            return page("Register", '<div class="alert">Username is too long</div><a class="btn" href="/register">Try Again</a>')

        if len(password) < 6:
            return page("Register", '<div class="alert">Password must be at least 6 characters</div><a class="btn" href="/register">Try Again</a>')

        # Mitigation: use bcrypt instead of MD5.
        # Because it is secure and resistant to brute-force attacks.
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        # Mitigation: encrypt sensitive user data before storing it.
        encrypted_bio = cipher.encrypt(bio.encode()).decode()

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        try:
            # Mitigation: parameterized query prevents SQL Injection.
            cursor.execute(
                "INSERT INTO users (username, password, role, bio) VALUES (?, ?, ?, ?)",
                (username, hashed_password, "user", encrypted_bio)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return page("Register", '<div class="alert">Username already exists</div><a class="btn" href="/register">Try Again</a>')

        conn.close()
        return redirect("/login")

    return page("Register", """
    <h2>Create Account</h2>
    <form method="POST">
        <label>Username</label>
        <input name="username" placeholder="Enter username">
        <label>Password</label>
        <input name="password" type="password" placeholder="Enter password">
        <label>Bio</label>
        <input name="bio" placeholder="Write a profile bio">
        <button type="submit">Register</button>
    </form>
    """)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        # Mitigation: parameterized query prevents SQL Injection.
        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()
        conn.close()

        if user:
            stored_hash = user[2]

            # Mitigation: bcrypt verification.
            if bcrypt.checkpw(password.encode(), stored_hash.encode()):
                session.clear()
                session["user_id"] = user[0]
                session["username"] = user[1]
                session["role"] = user[3]
                return redirect("/dashboard")

        return page("Login", '<div class="alert">Invalid username or password</div><a class="btn" href="/login">Try Again</a>')

    return page("Login", """
    <h2>Login</h2>
    <form method="POST">
        <label>Username</label>
        <input name="username" placeholder="Enter username">
        <label>Password</label>
        <input name="password" type="password" placeholder="Enter password">
        <button type="submit">Login</button>
    </form>
    """)


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect("/login")

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Mitigation: parameterized query.
    cursor.execute(
        "SELECT bio FROM users WHERE username = ?",
        (session["username"],)
    )
    result = cursor.fetchone()
    conn.close()

    encrypted_bio = result[0] if result else ""

    try:
        decrypted_bio = cipher.decrypt(encrypted_bio.encode()).decode()
    except Exception:
        decrypted_bio = ""

    # Mitigation: escape output to prevent XSS.
    safe_username = escape(session["username"])
    safe_bio = escape(decrypted_bio)

    return page("Dashboard", f"""
    <h2>Dashboard</h2>
    <p>Welcome, <strong>{safe_username}</strong></p>
    <div class="info-box">
        <p><strong>Your bio:</strong></p>
        <div>{safe_bio}</div>
    </div>
    <a class="btn" href="/admin">Admin Page</a>
    <a class="btn secondary" href="/logout">Logout</a>
    """)


@app.route("/admin")
def admin():
    if "username" not in session:
        return redirect("/login")

    # Mitigation: Restrict access to admin users only (role-based access control).
    if session.get("role") != "admin":
        return page("Dashboard", '<div class="alert">Access Denied: Admins only</div><a class="btn" href="/login">Try Again</a>')

    return page("Admin Page", """
    <h2>Admin Page</h2>
    <div class="info-box">
        <p>Welcome Admin. This page is protected using RBAC.</p>
    </div>
    <a class="btn secondary" href="/dashboard">Back to Dashboard</a>
    """)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    init_db()

    # Mitigation: enable HTTPS using an adhoc SSL certificate for secure communication.
    app.run(debug=True, ssl_context="adhoc")
