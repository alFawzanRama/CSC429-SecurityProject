# Secure Web Application Project

**Developers:** Rama Alfawzan, Lama Alarfaj, Ghaliah Alsubaie, Joharah Alhajlan

## Overview
This project showcases the detection and mitigation of common web application security vulnerabilities. It consists of two Flask applications:
1. `app_vulnerable.py`: A baseline application containing intentional security flaws (SQL Injection, Weak Password Storage, XSS, Broken Access Control, and Unencrypted Communication).
2. `app_secure.py`: The secured version of the application where all identified vulnerabilities have been mitigated using secure coding practices.

## Installation Instructions
To run this application, you will need Python installed on your system. 

1. Clone the repository to your device.
2. (Optional but recommended) Create a virtual environment using the Command Line:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use: venv\Scripts\activate
   ```
3. Install the required libraries:
   ```bash
   pip install -r requirements.txt
   ```

### Database Viewer
To inspect the `.db` files and verify the password storage methods, you will need an SQLite viewer. You can use either:
* **DB Browser for SQLite:** A free standalone application ([sqlitebrowser.org](https://sqlitebrowser.org/)).
* **VS Code Extension:** Search for and install the "SQLite Viewer" extension inside Visual Studio Code.


## Running the Application
To run the **secure** version of the application:
```bash
python app_secure.py
```
*Note: The secure application runs over HTTPS using an ad-hoc SSL certificate. Your browser will likely show a "Connection is not private" warning because the certificate is self-signed. You can safely bypass this warning for testing purposes.*

To run the **vulnerable** version for comparison:
```bash
python app_vulnerable.py
```

## Testing Security Features

Here is how you can test and verify the security mitigations implemented in `app_secure.py`:

### 1. SQL Injection Prevention
* **Vulnerable App:** Navigate to the `/login` page and enter `' OR '1'='1` as the username and anything for the password. You will successfully bypass authentication.
* **Secure App:** Attempt the exact same input. The login will fail because the parameterized queries treat the input strictly as a literal string rather than an executable command.

### 2. Weak Password Storage Fix
* **Vulnerable App:** Open `vulnerable_app.db` using an SQLite viewer. You will see passwords stored as easily crackable MD5 hashes.
* **Secure App:** Open `secure_app.db`. You will see that passwords are now securely hashed and salted using the `bcrypt` algorithm.

### 3. Cross-Site Scripting (XSS) Prevention
* **Vulnerable App:** Register a new user and enter `<script>alert('XSS Attack!')</script>` into the "Bio" field. When you log in and view the dashboard, an alert box will pop up, executing the script.
* **Secure App:** Register a user with the same script in the "Bio" field. On the dashboard, the script will not execute. Instead, it will be safely displayed as plain text because the application escapes the HTML entities.

### 4. Access Control (RBAC)
* **Vulnerable App:** Without logging in, navigate directly to `http://127.0.0.1:5000/admin`. You will be granted access to the page.
* **Secure App:** Navigate to `https://127.0.0.1:5000/admin` either without logging in, or while logged in as a regular user. You will be denied access and redirected. To view the page, you must log in with the admin credentials.
 
*Important:* You must have the Flask app running in your terminal (using `python app_vulnerable.py`) *before* you type that URL into your browser, otherwise the browser will just say "Site cannot be reached."

### 5. Data and Transit Encryption
* **In Transit:** Notice that `app_secure.py` runs on `https://` instead of `http://`, ensuring all network traffic is encrypted using TLS/SSL.
* **At Rest:** Open `secure_app.db` using an SQLite viewer. Look at the `bio` column for any user. The data is unreadable because it has been symmetrically encrypted using the `Fernet` library. It is only decrypted seamlessly when rendered on the dashboard.
