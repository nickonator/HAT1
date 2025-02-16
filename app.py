from flask import Flask, render_template, request, make_response, redirect, url_for, jsonify, flash
from flask_jwt_extended import JWTManager, create_access_token
from flask_wtf.csrf import CSRFProtect
from flask_limiter.errors import RateLimitExceeded
import sqlite3
from dotenv import load_dotenv
import os
from email.message import EmailMessage
import smtplib
import certifi
import ssl
import random
import bcrypt
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis


app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
jwt = JWTManager(app)
csrf = CSRFProtect(app)
redis_client = redis.StrictRedis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))
limiter = Limiter(get_remote_address, app=app, storage_uri=os.getenv("REDIS_URL", "redis://localhost:6379"))
logging.basicConfig(level=logging.INFO) 
load_dotenv()

@app.errorhandler(RateLimitExceeded)
def ratelimit_handler(e):
    flash("Rate limit exceeded. Please try again later.", "error")
    return redirect(url_for('login'))

"""
connection = sqlite3.connect('/workspaces/HAT1/database/database.db')
cursor = connection.cursor()
cursor.execute("INSERT INTO catalogue VALUES (?, ?, ?)", ("book1", "images/image.png", "blurb",)) 
connection.commit()
connection.close()

"""

"""
connection = sqlite3.connect('/workspaces/HAT1/database/database.db')
cursor = connection.cursor()
cursor.execute("DELETE FROM users")
connection.commit()
connection.close()
"""


def SendMail(recipient, title, content):
    email_sender = os.getenv('EMAIL')
    email_password = os.getenv('EMAILCODE')
    email_reciever = recipient
    subject = title
    body = content
    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email_reciever
    em['Subject'] = subject
    em.set_content(body)
    context = ssl.create_default_context(cafile=certifi.where())
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, email_reciever, em.as_string())


@app.route('/verify_email', methods=['GET', 'POST'])
def EmailVerificationCode():
    if request.method == 'GET':
        # Get data from query parameters on GET
        username = request.args.get("username")  
        email = request.args.get("email")  
        hashed_password = request.args.get("hashed_password")
        emailCode = request.args.get("code")
        return render_template("emailverify.html",
                               email=email,
                               username=username,
                               hashed_password=hashed_password,
                               code=emailCode)
    else: 
        username = request.form.get("username")
        email = request.form.get("email")
        hashed_password = request.form.get("hashed_password")
        generated_code = request.form.get("generated_code")
        entered_code = request.form.get("email code")
        
        if  PasswordCompare(generated_code, entered_code) == True:
            AddUser(username, email, hashed_password)
            access_token = create_access_token(identity=username)
            response = make_response(redirect(url_for('home')))
            response.set_cookie('access_token_cookie', access_token, secure=True, samesite='Strict') 
            return response
        else:
            logging.warning(f"Email verification failed: Incorrect verification code for user '{username}'")
            return render_template("index.html", error="Incorrect verification code")
 


def UserNameCheck(user):
    with sqlite3.connect('database/database.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, email, password FROM users WHERE LOWER(username) = LOWER(?)", (user,))
        return cursor.fetchone()

def EmailCheck(email):
    with sqlite3.connect('database/database.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE LOWER(email)= LOWER(?)", (email,))
        return cursor.fetchone()

def PasswordCheck(password):
    if len(password)>=8 and any(char.isdigit() for char in password) and any(char.isupper() for char in password) and any(not char.isalnum() for char in password):
        return True
    return False

def PasswordHash(password):
    salt = bcrypt.gensalt()
    password = bcrypt.hashpw(password.encode(), salt)
    hashed_password = password.decode()
    return hashed_password

def PasswordCompare(hashed_password, provided_password):
    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode()
    return bcrypt.checkpw(provided_password.encode(), hashed_password)

def AddUser(username, email, password):
    with sqlite3.connect('database/database.db') as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users VALUES (?, ?, ?)", (username.lower(), email.lower(), password))
        conn.commit()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        user_data = UserNameCheck(username)
        if user_data is None:
            logging.warning(f"Login failed: User '{username}' does not exist")
            return render_template('login.html', error="User does not exist.")
        if not PasswordCompare(user_data[2], password):
            logging.warning(f"Login failed: Incorrect password for user '{username}'")
            return render_template('login.html', error="Incorrect password.")

        access_token = create_access_token(identity=username)
        response = make_response(redirect(url_for('home'))) 
        response.set_cookie('access_token_cookie', access_token, secure=True, samesite='Strict') 
        return response

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        checkPassword = request.form.get('re-enter password', '').strip()

        if not username or len(username) < 5:
            logging.warning(f"SignUp failed: Username '{username}' is too short")
            return render_template('signup.html', error="Username must be at least 5 characters long.")
        if not email or '@' not in email:
            logging.warning(f"SignUp failed: Email '{email}' is invalid")
            return render_template('signup.html', error="Invalid email address.")
        if not PasswordCheck(password):
            logging.warning(f"SignUp failed: Password is invalid for user: '{username}'")
            return render_template('signup.html', error="Password must be at least 8 characters and contain a digit, an uppercase letter, and a special character.")
        if password != checkPassword:
            logging.warning(f"SignUp failed: Passwords do not match for user: '{username}'")
            return render_template('signup.html', error="Passwords do not match.")
        if UserNameCheck(username) is not None:
            logging.warning(f"SignUp failed: Username '{username}' is already taken")
            return render_template('signup.html', error="Username is already taken.")
        if EmailCheck(email) is not None:
            logging.warning(f"SignUp failed: Email '{email}' is already registered")
            return render_template('signup.html', error="Email is already registered.")

        password_hashed = PasswordHash(password)
        emailCode = str(random.randint(1000, 1000000))
        SendMail(email, "Library activation code", str(emailCode))
        return redirect(url_for('EmailVerificationCode', email=email, username=username, hashed_password=password_hashed, code=PasswordHash(emailCode)))
    return render_template('signup.html')

@app.route('/bookCatalogue', methods=['GET', 'POST'])
def bookCatalogue():
    with sqlite3.connect('database/database.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM catalogue")
        return render_template('catalogue.html', cataloguedata=cursor.fetchall())

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/signout')
def signout():
    response = make_response(render_template("index.html"))
    response.set_cookie('access_token_cookie', '', expires=0)
    return response

if __name__ == '__main__':
    app.run(debug=True)