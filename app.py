import os
from flask import Flask, request, render_template, redirect, url_for, session, jsonify, make_response, flash
import mysql.connector
from flask_cors import CORS
from flask_mail import Mail, Message
import joblib
import secrets
from datetime import datetime, timedelta
from dotenv import load_dotenv
from utils import is_url_live
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your_secret_key_here')
CORS(app)

# ---------------- ML MODEL LOAD ----------------
model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# ---------------- MYSQL CONFIG (Aiven) ----------------
def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT")),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        ssl_disabled=False
    )

# ---------------- MAIL CONFIG ----------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']

mail = Mail(app)

def no_cache(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

# ✅ Default page
@app.route('/')
def index():
    return redirect(url_for('register'))

# ✅ Main page
@app.route('/home')
def home():
    response = make_response(render_template('index.html'))
    return no_cache(response)

# ✅ Registration Page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['username']   # form field name is 'username' but treat as name
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, hashed_password))
        conn.commit()
        cursor.close()
        conn.close()

        return redirect(url_for('homemsg', msg='Registration Successful!'))
    return render_template('Regi.html')

# ✅ Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = request.args.get('msg')
    if request.method == 'POST':
        email = request.form['username']   # your login form field, but now treat input as email
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE email=%s", (email,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()

        if result and check_password_hash(result[0], password):
            session['username'] = email
            return redirect(url_for('homemsg', msg='Login Successful!'))
        else:
            return render_template('login.html', error='Invalid email or password')
    return render_template('login.html', msg=msg)

# ✅ Forgot Password Page (GET)
@app.route('/forgot', methods=['GET'])
def forgot():
    return render_template('forgot.html')

# ✅ Send Reset Link (POST)
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    email = request.form.get("email")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()

    if not user:
        flash("Email not found", "error")
        cursor.close()
        conn.close()
        return redirect(url_for("forgot"))

    token = secrets.token_hex(32)
    expiry = datetime.now() + timedelta(minutes=15)

    cursor.execute(
        "UPDATE users SET reset_token=%s, token_expiry=%s WHERE email=%s",
        (token, expiry, email)
    )
    conn.commit()

    reset_link = url_for("reset_page", token=token, _external=True)

    msg = Message(subject="Reset Your Password", recipients=[email])
    msg.body = f"""
Hello,

You requested a password reset.

Click the link below:

{reset_link}

This link expires in 15 minutes.

If you did not request this, ignore this email.
"""
    mail.send(msg)
    cursor.close()
    conn.close()

    flash("📧 Please check your mail. Password reset link has been sent.", "success")
    return redirect(url_for("forgot"))

# ✅ Reset Page (GET)
@app.route("/reset-password/<token>", methods=["GET"])
def reset_page(token):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE reset_token=%s AND token_expiry > NOW()", (token,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        return "Invalid or Expired Reset Link"

    return render_template("reset_password.html", token=token)

# ✅ Update Password (POST)
@app.route("/reset-password", methods=["POST"])
def reset_password():
    token = request.form.get("token")
    new_password = request.form.get("password")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE reset_token=%s AND token_expiry > NOW()", (token,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        return jsonify({"success": False, "error": "Invalid or Expired Token"}), 400

    hashed_password = generate_password_hash(new_password)

    cursor.execute(
        """
        UPDATE users
        SET password=%s, reset_token=NULL, token_expiry=NULL
        WHERE reset_token=%s
        """,
        (hashed_password, token)
    )
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"success": True})

# ✅ URL Detection Page
@app.route('/detect', methods=['POST'])
def detect():
    url = request.form['url']
    live = is_url_live(url)

    url_vector = vectorizer.transform([url])
    prediction = model.predict(url_vector)[0]
    label = "fraud" if prediction == 1 else "safe"

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO url_logs (url, result) VALUES (%s, %s)", (url, label))
    conn.commit()
    cursor.close()
    conn.close()

    return render_template("result.html", result=label, is_live=live, url=url)

# ---------------- SUBMIT FEEDBACK ----------------
@app.route("/submit_feedback", methods=["POST"])
def submit_feedback():
    data = request.get_json()
    name = data.get("name")
    email = data.get("email")
    message = data.get("message")

    if not name or not email or not message:
        return jsonify({"status": "error", "message": "All fields are required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO feedbacks (name, email, message)
        VALUES (%s, %s, %s)
    """, (name, email, message))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"status": "success", "message": "Feedback Submitted Successfully"})

# ---------------- GET FEEDBACKS ----------------
@app.route("/get_feedbacks")
def get_feedbacks():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, name, email, message, submitted_at
        FROM feedbacks
        ORDER BY id DESC
    """)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    feedbacks = []
    for row in rows:
        feedbacks.append({
            "id": row[0],
            "name": row[1],
            "email": row[2],
            "message": row[3],
            "submitted_at": str(row[4])
        })

    return jsonify(feedbacks)

# ✅ API Registration (Optional)
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    user_name = data.get('user_name')
    email = data.get('email')
    password = data.get('password')

    if not user_name or not email or not password:
        return jsonify({'error': 'All fields required'}), 400

    hashed_password = generate_password_hash(password)

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
                       (user_name, email, hashed_password))
        conn.commit()
        return jsonify({'message': 'Registration successful!'}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# ✅ Home Page (popup message)
@app.route('/homemsg')
def homemsg():
    msg = request.args.get('msg')
    response = make_response(render_template('index.html', msg=msg))
    return no_cache(response)

# ✅ api login
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'All fields required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE name=%s", (username,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()

    if result and check_password_hash(result[0], password):
        return jsonify({'message': 'Login successful'}), 200
    elif result:
        return jsonify({'error': 'Incorrect password'}), 401
    else:
        return jsonify({'error': 'User not found'}), 404

# ✅ Session check
@app.route('/check_session')
def check_session():
    if 'username' not in session:
        return '', 401
    response = make_response('', 200)
    return no_cache(response)

# ✅ Run
if __name__ == '__main__':
    app.run(debug=True)