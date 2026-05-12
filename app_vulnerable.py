from flask import Flask, request, redirect, session, render_template_string
import sqlite3
import hashlib

app = Flask(__name__)

# Vulnerability: weak and predictable secret key
app.secret_key = "12345"

DB_NAME = "vulnerable_app.db"


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
        .alert { background: #f1f5f9; color: #333333; padding: 12px; border-radius: 10px; margin-top: 14px; }
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



def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT,
        role TEXT DEFAULT 'user',
        bio TEXT
    )
    """)

    # Default admin account
    cursor.execute("SELECT * FROM users WHERE username='admin'")
    admin = cursor.fetchone()

    if not admin:
        # Vulnerability: weak password hashing using MD5
        weak_password = hashlib.md5("admin123".encode()).hexdigest()
        cursor.execute(
            "INSERT INTO users (username, password, role, bio) VALUES ('admin', ?, 'admin', '')",
            (weak_password,)
        )

    conn.commit()
    conn.close()


@app.route("/")
def home():
    return page("Home", """
    <h1>Vulnerable Web Application</h1>
    <p>This version contains security vulnerabilities.</p>
    <div class="info-box">
        <span class="badge">Before Mitigation</span>
        <p>This version to demonstrate SQL Injection, XSS, weak password storage, and broken access control.</p>
    </div>
    <a class="btn" href="/register">Create Account</a>
    <a class="btn secondary" href="/login">Login</a>
    """)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        bio = request.form["bio"]

        # Vulnerability: MD5 is weak and not suitable for password storage
        hashed_password = hashlib.md5(password.encode()).hexdigest()

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        # Vulnerability: SQL Injection because user input is concatenated directly
        query = f'
        INSERT INTO users (username, password, role, bio)
        VALUES ("{username}", "{hashed_password}", "user", "{bio}")
        '
        cursor.execute(query)

        conn.commit()
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
        username = request.form["username"]
        password = request.form["password"]

        hashed_password = hashlib.md5(password.encode()).hexdigest()

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        # Vulnerability: SQL Injection
        query = f"""
        SELECT * FROM users
        WHERE username = '{username}'
        AND password = '{hashed_password}'
        """
        cursor.execute(query)
        user = cursor.fetchone()

        conn.close()

        if user:
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

    # Vulnerability: SQL query uses session value directly
    cursor.execute(f"SELECT bio FROM users WHERE username='{session['username']}'")
    result = cursor.fetchone()
    conn.close()

    bio = result[0] if result else ""

    # Vulnerability: XSS because bio is rendered directly without sanitization
    return page("Dashboard", f"""
    <h2>Dashboard</h2>
    <p>Welcome, <strong>{session["username"]}</strong></p>
    <div class="info-box">
        <p><strong>Your bio:</strong></p>
        <div>{bio}</div>
    </div>
    <a class="btn" href="/admin">Admin Page</a>
    <a class="btn secondary" href="/logout">Logout</a>
    """)


@app.route("/admin")
def admin():
    # Vulnerability: broken access control
    # Any logged-in or non-logged-in user can access this page
    return page("Admin Page", """
    <h2>Admin Page</h2>
    <div class="alert">This page should be for admins only, but it is not protected.</div>
    <a class="btn secondary" href="/dashboard">Back to Dashboard</a>
    """)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    init_db()

    # Vulnerability: runs over HTTP, not HTTPS
    app.run(debug=True)
