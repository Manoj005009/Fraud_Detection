import os
import secrets
import joblib
import mysql.connector

from datetime import datetime, timedelta

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    session,
    flash,
    make_response
)

from flask_mail import Mail, Message
from flask_cors import CORS
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

from utils import is_url_live


# ---------------- LOAD ENV ----------------

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY")

CORS(app)


# ---------------- LOAD ML MODEL ----------------

model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")


# ---------------- DATABASE ----------------

def get_db_connection():

    return mysql.connector.connect(

        host=os.getenv("DB_HOST"),

        port=int(os.getenv("DB_PORT")),

        user=os.getenv("DB_USER"),

        password=os.getenv("DB_PASSWORD"),

        database=os.getenv("DB_NAME"),

        ssl_disabled=False
    )


# ---------------- MAIL ----------------

app.config["MAIL_SERVER"] = "smtp.gmail.com"

app.config["MAIL_PORT"] = 587

app.config["MAIL_USE_TLS"] = True

app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")

app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")

app.config["MAIL_DEFAULT_SENDER"] = app.config["MAIL_USERNAME"]

mail = Mail(app)


# ---------------- NO CACHE ----------------

def no_cache(response):

    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"

    response.headers["Pragma"] = "no-cache"

    response.headers["Expires"] = "0"

    return response


# =====================================================
# PAGE ROUTES
# =====================================================

@app.route("/")
def index():
    return redirect(url_for("register"))


@app.route("/register")
def register():
    return render_template("Regi.html")


@app.route("/login")
def login():

    msg = request.args.get("msg")

    return render_template("login.html", msg=msg)
    

@app.route("/forgot")
def forgot():
    return render_template("forgot.html")



@app.route("/home")
def home():

    if "user" not in session:

        return redirect(url_for("login"))

    response = make_response(render_template("index.html"))

    return no_cache(response)


@app.route("/homemsg")
def homemsg():

    msg = request.args.get("msg")

    response = make_response(
        render_template("index.html", msg=msg)
    )

    return no_cache(response)

# =====================================================
# API REGISTER
# =====================================================

@app.route("/api/register", methods=["POST"])
def api_register():

    data = request.get_json()

    if not data:
        return jsonify({"success": False, "error": "Invalid request"}), 400

    name = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "").strip()

    if not name or not email or not password:
        return jsonify({
            "success": False,
            "error": "All fields are required"
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:

        cursor.execute(
            "SELECT id FROM users WHERE email=%s",
            (email,)
        )

        if cursor.fetchone():
            return jsonify({
                "success": False,
                "error": "Email already exists"
            }), 409

        hashed_password = generate_password_hash(password)

        cursor.execute(
            """
            INSERT INTO users(name,email,password)
            VALUES(%s,%s,%s)
            """,
            (
                name,
                email,
                hashed_password
            )
        )

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Registration Successful"
        }), 201

    except Exception as e:

        conn.rollback()

        print(e)

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

    finally:

        cursor.close()
        conn.close()


# =====================================================
# API LOGIN
# =====================================================

@app.route("/api/login", methods=["POST"])
def api_login():

    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "error": "Invalid request"
        }), 400

    email = data.get("email", "").strip().lower()
    password = data.get("password", "").strip()

    if not email or not password:

        return jsonify({
            "success": False,
            "error": "All fields are required"
        }), 400

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id,name,password
        FROM users
        WHERE email=%s
        """,
        (email,)
    )

    user = cursor.fetchone()

    cursor.close()

    conn.close()

    if user is None:

        return jsonify({
            "success": False,
            "error": "Invalid Email"
        }), 404

    if not check_password_hash(user[2], password):

        return jsonify({
            "success": False,
            "error": "Incorrect Password"
        }), 401

    session["user"] = user[1]

    return jsonify({
        "success": True,
        "message": "Login Successful"
    }), 200


@app.route("/forgot-password", methods=["POST"])
def forgot_password():

    email = request.form.get("email", "").strip().lower()

    if email == "":
        flash("Please enter your email", "error")
        return redirect(url_for("forgot"))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id FROM users WHERE email=%s",
        (email,)
    )

    user = cursor.fetchone()

    if user is None:

        cursor.close()
        conn.close()

        flash("Email not found", "error")

        return redirect(url_for("forgot"))

    token = secrets.token_hex(32)

    expiry = datetime.now() + timedelta(minutes=15)

    cursor.execute(
        """
        UPDATE users
        SET reset_token=%s,
            token_expiry=%s
        WHERE email=%s
        """,
        (
            token,
            expiry,
            email
        )
    )

    conn.commit()

    cursor.close()
    conn.close()

    reset_link = url_for(
        "reset_page",
        token=token,
        _external=True
    )

    msg = Message(
        subject="Reset Password",
        recipients=[email]
    )

    msg.body = f"""

Hello,

Click below link to reset password.

{reset_link}

This link expires in 15 minutes.

"""

    mail.send(msg)

    flash(
        "Password reset link sent to your email.",
        "success"
    )

    return redirect(url_for("forgot"))




@app.route("/reset-password/<token>")
def reset_page(token):

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id
        FROM users
        WHERE
        reset_token=%s
        AND token_expiry>NOW()
        """,
        (token,)
    )

    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if user is None:
        return "Invalid or Expired Link"

    return render_template(
        "reset_password.html",
        token=token
    )



@app.route("/reset-password", methods=["POST"])
def reset_password():

    token = request.form.get("token")

    password = request.form.get("password")

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id
        FROM users
        WHERE
        reset_token=%s
        AND token_expiry>NOW()
        """,
        (token,)
    )

    user = cursor.fetchone()

    if user is None:

        cursor.close()
        conn.close()

        return jsonify({
            "success":False,
            "error":"Invalid Token"
        }),400

    hashed = generate_password_hash(password)

    cursor.execute(
        """
        UPDATE users
        SET
        password=%s,
        reset_token=NULL,
        token_expiry=NULL
        WHERE reset_token=%s
        """,
        (
            hashed,
            token
        )
    )

    conn.commit()

    cursor.close()

    conn.close()

    return jsonify({
        "success":True
    })



@app.route("/check_session")
def check_session():

    if "user" not in session:
        return "",401

    response = make_response("",200)

    return no_cache(response)


@app.route("/detect", methods=["POST"])
def detect():

    if "user" not in session:
        return redirect(url_for("login"))

    url = request.form.get("url", "").strip()

    if url == "":
        return render_template(
            "result.html",
            result="No URL Entered",
            is_live=False,
            url=""
        )

    live = is_url_live(url)

    vector = vectorizer.transform([url])

    prediction = model.predict(vector)[0]

    result = "fraud" if prediction == 1 else "safe"

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO url_logs(url,result)
        VALUES(%s,%s)
        """,
        (
            url,
            result
        )
    )

    conn.commit()

    cursor.close()

    conn.close()

    return render_template(
        "result.html",
        result=result,
        is_live=live,
        url=url
    )



@app.route("/submit_feedback", methods=["POST"])
def submit_feedback():

    data = request.get_json()

    name = data.get("name", "").strip()
    email = data.get("email", "").strip()
    message = data.get("message", "").strip()

    if not name or not email or not message:
        return jsonify({
            "status": "error",
            "message": "All fields are required"
        }), 400

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO feedbacks(name,email,message)
        VALUES(%s,%s,%s)
        """,
        (
            name,
            email,
            message
        )
    )

    conn.commit()

    cursor.close()

    conn.close()

    return jsonify({
        "status": "success",
        "message": "Feedback Submitted Successfully"
    })



@app.route("/get_feedbacks")
def get_feedbacks():

    conn = get_db_connection()

    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT
        id,
        name,
        email,
        message,
        submitted_at
        FROM feedbacks
        ORDER BY submitted_at DESC
        """
    )

    feedbacks = cursor.fetchall()

    cursor.close()

    conn.close()

    return jsonify(feedbacks)





@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))




if __name__ == "__main__":
    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000
    )
