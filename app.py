from flask import Flask, render_template, request, make_response, session, redirect, url_for
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import sqlite3
from dotenv import load_dotenv
import os
from email.message import EmailMessage
import smtplib
import certifi
import ssl
import random
import bcrypt




app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24) 
app.config['JWT_SECRET_KEY'] = 'super-secret-key'
jwt = JWTManager(app)
load_dotenv()

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

def EmailVerificationCode(email):
    emailCode = str(random.randint(1000, 1000000))
    SendMail(email, "Library activation code", str(emailCode))
    session['email_code'] = emailCode
    return redirect(url_for('verify_email'))

@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    if request.method == 'POST':
        email_code = request.form.get("email code")
        
        if email_code:
            # Check if the code entered matches the stored code in the session
            if session.get('email_code') == email_code:
                # Code matches, now add the user to the database
                user_data = session.get('user_data')
                if user_data:
                    AddUser(user_data['username'], user_data['email'], user_data['password'])
                    access_token = create_access_token(identity=user_data['username'])
                    response = make_response(redirect(url_for('home')))  # Redirect to home after successful registration
                    response.set_cookie('access_token_cookie', access_token, secure=True, samesite='Strict') 
                    return response
                else:
                    return render_template("index.html")
            else:
                # Code does not match, render an error message
                return render_template("index.html", error="Incorrect verification code")
    return render_template("emailverify.html")

def UserNameCheck(user):
    connection = sqlite3.connect('/workspaces/HAT1/database/database.db')
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE username= ?", (user,))
    CheckUser = cursor.fetchone()
    connection.close()
    return CheckUser

def EmailCheck(email):
    connection = sqlite3.connect('/workspaces/HAT1/database/database.db')
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE email= ?", (email,))
    CheckEmail = cursor.fetchone()
    connection.close()
    return CheckEmail

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
    connection = sqlite3.connect('/workspaces/HAT1/database/database.db')
    cursor = connection.cursor()
    cursor.execute("INSERT INTO users VALUES (?, ?, ?)", (username, email, password,)) 
    connection.commit()
    connection.close()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = PasswordHash(request.form['password'])
        checkPassword = request.form['re-enter password']
        
        if UserNameCheck(username) == None and len(username) >= 5 and EmailCheck(email) == None and PasswordCompare(password, checkPassword) == True and PasswordCheck(checkPassword) == True:
            checkPassword = None
            # Generate and send email verification code
            emailCode = EmailVerificationCode(email)  # Sends email and stores the code in session
            # Store the user's registration details temporarily (don't add them yet)
            session['user_data'] = {'username': username, 'email': email, 'password': password}
            # Now redirect to the email verification page
            return redirect(url_for('verify_email'))
        else:
            return render_template('signup.html') 
    return render_template('signup.html')


@app.route('/bookCatalogue', methods=['GET', 'POST'])
@jwt_required(locations=['cookies'])
def bookCatalogue():
    current_user = get_jwt_identity()  
    return render_template('catalogue.html')

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