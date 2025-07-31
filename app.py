from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import bcrypt
import pyotp
import qrcode
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Create QR code folder if not exists
if not os.path.exists('static/qrcodes'):
    os.makedirs('static/qrcodes')

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    otp_secret TEXT NOT NULL
                )''')
    conn.commit()
    conn.close()

init_db()

# --- Routes ---
@app.route('/')
def index():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        hashed = bcrypt.hashpw(password, bcrypt.gensalt())

        otp_secret = pyotp.random_base32()
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password, otp_secret) VALUES (?, ?, ?)",
                      (username, hashed, otp_secret))
            conn.commit()
        except sqlite3.IntegrityError:
            return "User already exists!"
        conn.close()

        # Generate QR Code
        uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(name=username, issuer_name="2FA-App")
        img = qrcode.make(uri)
        qr_path = f'static/qrcodes/{username}.png'
        img.save(qr_path)

        return f"Scan this QR Code with Google Authenticator:<br><img src='/{qr_path}'><br><a href='/login'>Login</a>"

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        conn.close()

        if result and bcrypt.checkpw(password, result[0]):
            session['username'] = username
            return redirect('/verify')
        else:
            return "Invalid username or password"
    return render_template('login.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if 'username' not in session:
        return redirect('/login')

    if request.method == 'POST':
        code = request.form['code']
        username = session['username']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT otp_secret FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        conn.close()

        if result and pyotp.TOTP(result[0]).verify(code):
            return redirect('/dashboard')
        else:
            return "Invalid OTP. Try again."

    return render_template('verify.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
