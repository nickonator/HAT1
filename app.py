from flask import Flask, render_template, request, make_response
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import sqlite3
from email.message import EmailMessage
import smtplib
import certifi
import ssl
import random
import bcrypt


app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'super-secret-key'
jwt = JWTManager(app)

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
    cursor.execute("INSERT INTO users VALUES (?, ?, ?)", (username, email, password,)) #FIX THIS
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
            AddUser(username, email, password)
            access_token = create_access_token(identity=username)
            response = make_response(render_template("index.html"))
            response.set_cookie('access_token_cookie', access_token, httponly=True, secure=True, samesite='None') 
            return response
        else:
            return "unsuccessful"  
    return render_template('signup.html')

@app.route('/bookCatalogue', methods=['GET', 'POST'])
@jwt_required(locations=['cookies'])
def bookCatalogue():
    current_user = get_jwt_identity()  
    return render_template('catalogue.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

if __name__ == '__main__':
    app.run(debug=True)