#!/usr/local/bin/python3

from flask import Flask, request, render_template, make_response, redirect, url_for, jsonify
from flask_sslify import SSLify
from flask_api import status

from datetime import datetime
from datetime import timedelta
from datetime import timezone

from flask_jwt_extended import create_access_token
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from flask_jwt_extended import set_access_cookies
from flask_jwt_extended import unset_jwt_cookies
from flask_jwt_extended import get_jwt
from flask_jwt_extended import get_jwt_identity

from argon2 import PasswordHasher
from replit import db
import secrets
import os


app = Flask(__name__, template_folder='templates')
sslify = SSLify(app)

app.config["JWT_TOKEN_LOCATION"] = ["cookies"]

# If true this will only allow the cookies that contain your JWTs to be sent
# over https. In production, this should always be set to True
app.config["JWT_COOKIE_SECURE"] = True
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
app.config["JWT_COOKIE_CSRF_PROTECT"] = False
jwt = JWTManager(app)

ph = PasswordHasher()

# ------------------------------------------------------------------- #
# Create an endpoint to render the home page
@app.route("/", methods=["GET"])
@jwt_required(optional=True)
def index():
    current_identity = get_jwt_identity()
    if current_identity != None:
        notes_key = 'notes_' + current_identity
        if notes_key in db.keys():
            notes = db[notes_key]     # Accessing dictionary value
        else:
            notes = ""
        resp = make_response(render_template('index.html', user=current_identity, secret_notes=notes))
    else:
        resp = make_response(redirect(url_for('login')))
    return resp
# ------------------------------------------------------------------- #


# (Authenticated)
# Create an endpoint that allows us to CREATE objects in the database
@app.route("/note", methods=["POST"])
@jwt_required()
def getNotes():
  # Retrieve user from JWT token/ any auth we are using
  user = get_jwt_identity()
  
  if request.method == "POST":
    try:
        notes = request.form['notes']     # Accessing form dictionary value
    except:
        return jsonify({"error":"Data fields are missing"}), status.HTTP_400_BAD_REQUEST
    
    notes_key = "notes_" + user

    # Insert new entry into database table
    db[notes_key] = notes
    return render_template('index.html', user=user, secret_notes=notes, success=True)
# ------------------------------------------------------------------- #

# Create an endpoint for users to login
@app.route("/login", methods=["POST", "GET"])
def login():

    if request.method == "GET":
        resp = make_response(render_template("login.html"))
        return resp

    # Accessing form dictionary values
    username = request.form['username']
    password = request.form['password']
    
    try:
        hash = db['user_' + username]     # Retrieve hash from database
        if ph.verify(hash, password):
            access_token = create_access_token(identity=username)
            response = make_response(redirect(url_for('index')))
            set_access_cookies(response, access_token)
            return response
    except:
        pass

    response = render_template("login.html", error="Wrong credentials")
    return response
# ------------------------------------------------------------------- #

# Create an endpoint for users to register for an account
@app.route("/signup", methods=["GET", "POST"])
def signup():
    # Check if user is login via a valid JWT token
    if request.method == "GET":
        resp = make_response(render_template("signup.html"))
    else:
        print(request.form)
        # Accessing form ictionary values
        username = request.form['username']
        password = request.form['password']
      
        passwordcfm = request.form['password-cfm']
        db_keys = db.keys()
        print(db_keys)

        if password != passwordcfm:
            resp = make_response(render_template("signup.html", error="Passwords do not match"))
        elif "user_" + username in db_keys:
            resp = make_response(render_template("signup.html", error="User already exists"))
        else:
            hash = ph.hash(password)
            db['user_' + username] = hash
            resp = make_response(redirect(url_for('index')))
            access_token = create_access_token(identity=username)
            set_access_cookies(resp, access_token)
    return resp

# Create an endpoint for users to logout of their account
@app.route("/logout", methods=["GET"])
def logout():
    response = make_response(redirect(url_for('login')))
    unset_jwt_cookies(response)
    return response
# ------------------------------------------------------------------- #

# Using an `after_request` callback, we refresh any token that is within 2
# minutes of expiring. Change the timedeltas to match the needs of your application.
@app.after_request
def refresh_expiring_jwts(response):
    try:
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(minutes=2))
        if target_timestamp > exp_timestamp:
            access_token = create_access_token(identity=get_jwt_identity())
            set_access_cookies(response, access_token)
        return response
    except (RuntimeError, KeyError):
        # Case where there is not a valid JWT. Just return the original respone
        return response

# For internal use to clean up the database
def clear_db():
    for i in db.keys():
        del db[i]

def init_db():
    db['user_admin'] = secrets.randbits(20)
    db['notes_admin'] = os.getenv("NOTES_SECRET") or "Admin Super Secret: No one can see it!"

if __name__ == "__main__":
    # clear_db()
    init_db()
    app.run(
		host='0.0.0.0',
		port=8080
	)