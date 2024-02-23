import os
import json
import stripe

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for, jsonify
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required


app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///care.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/user_login",methods=["GET", "POST"])
def user_login():
    # Forget any user_id
    session.clear()

    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("user_name") or not request.form.get("user_password"):
            return render_template("user_login.html", string='You must enter both username and password')
        
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("user_name")
        )

        if len(rows) != 1:
            return render_template("user_login.html", string='You must register first')
        if not check_password_hash(
            rows[0]["hash"], request.form.get("user_password")
        ):
            return render_template("user_login.html", string='Your password is incorrect')
        if not rows[0]["email"] == request.form.get("user_email"):
            return render_template("user_login.html", string='Your email is incorrect')
        
        session["user_id"] = rows[0]["user_id"]

        return redirect("user_home")
    elif request.method == "GET":
        return render_template("user_login.html")

@app.route("/user_register", methods=["GET", "POST"])
def user_register():
    if request.method == "POST":
        name = request.form.get("user_name")
        password = request.form.get("user_password")
        confirmation = request.form.get("user_confirmation")
        email = request.form.get("user_email")
        if not name:
            return render_template("register.html", string="You need to enter a username")
        taken_name = db.execute("SELECT * FROM users")
        for k in taken_name:
                if k["username"] == name:
                    return render_template("register.html", string="The entered username is already in use")
        if not password or not confirmation:
                return render_template("register.html", string="Both password and confirmation are necessary fields")
        if password != confirmation:
            return render_template("register.html", string="Both password and reentered password must be same")
        db.execute(
                "INSERT INTO users (username, email, hash) VALUES (?, ?, ?)",
                name, 
                email,
                generate_password_hash(password),
        )
        id = db.execute("SELECT * FROM users WHERE username = ?", name)
        session["user_id"] = id[0]["user_id"]
        return redirect("user_home")
    elif request.method == "GET":
        return render_template("user_register.html")

@app.route("/ngo_login", methods=["GET", "POST"])
def ngo_login():
    
    session.clear()

    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("ngo_name") or not request.form.get("ngo_password") or not request.form.get("ngo_id"):
            return render_template("ngo_login.html", string='You must enter all the fields')
        
        rows = db.execute(
            "SELECT * FROM ngo WHERE name = ?", request.form.get("ngo_name")
        )

        if len(rows) != 1:
            return render_template("ngo_login.html", string='You must register first')
        if not check_password_hash(
            rows[0]["hash"], request.form.get("ngo_password")
        ):
            return render_template("ngo_login.html", string='Your password is incorrect')
        
        session["user_id"] = rows[0]["ngo_id"]

        return redirect("ngo_home")
    elif request.method == "GET":
        return render_template("ngo_login.html")

@app.route("/ngo_register", methods=["GET", "POST"])
def ngo_register():
    if request.method == "POST":
        name = request.form.get("ngo_name")
        password = request.form.get("ngo_password")
        confirmation = request.form.get("ngo_confirmation")
        email = request.form.get("ngo_email")
        id = request.form.get("ngo_id")
        if not name:
            return render_template("register.html", string="You need to enter a username")
        taken_name = db.execute("SELECT * FROM users")
        for k in taken_name:
                if k["username"] == name:
                    return render_template("register.html", string="The entered username is already in use")
        if not password or not confirmation:
                return render_template("register.html", string="Both password and confirmation are necessary fields")
        if password != confirmation:
            return render_template("register.html", string="Both password and reentered password must be same")
        db.execute(
                "INSERT INTO ngo (name, email, hash, ngo_id) VALUES (?, ?, ?, ?)",
                name, 
                email,
                generate_password_hash(password),
                id,
        )
        session["user_id"] = id
        return redirect("ngo_home")
    elif request.method == "GET":
        return render_template("ngo_register.html")

@app.route("/user_home")
@login_required
def user_home():
    name = db.execute("SELECT name FROM users WHERE user_id = ?", session["user_id"])
    sub_ngo = db.execute("SELECT ngo_name FROM subscriptions WHERE username = ?", name)
    sub_posts = db.execute("SELECT * FROM posts WHERE ngo_name IN sub_ngo")
    sub_petitions = db.execute("SELECT * FROM petitions WHERE ngo_name IN sub_ngo")
    return render_template("user_home.html", sub_ngo=sub_ngo, sub_posts=sub_posts, sub_petitions=sub_petitions)

@app.route("/explore_ngo")
def explore_ngo():
    ngo_list = db.execute("SELECT name FROM ngo")
    return render_template("explore_ngo.html", ngo_list=ngo_list)

@app.route("/ngo_home")
def ngo_home():
    return render_template("ngo_home.html")


@app.route("/newpetition", methods=["GET", "POST"])
@login_required
def newpetition():
    if request.method == "POST":
        row = db.execute("SELECT name FROM ngo WHERE ngo_id = ?", session["user_id"])
        name = row[0]["name"]
        title = request.form.get("petition_title")
        description = request.form.get("petition_description")
        vote_goal = request.form.get("petition_goal")
        date = request.form.get("petition_date")
        db.execute("INSERT INTO petitions (ngo_name, petition_title, petition_description, petvot_goal, date, petition_vote) VALUES (?, ?, ?, ?, ?, 0)",
                   name, 
                   title, 
                    description,
                    vote_goal,
                    date,
                   )
        return redirect("ngo_home")
    else:
        return render_template("newpetition.html")


@app.route("/newpost", methods=["GET", "POST"])
@login_required
def newpost():
    if request.method == "POST":
        row = db.execute("SELECT name FROM ngo WHERE ngo_id = ?", session["user_id"])
        name = row[0]["name"]
        title = request.form.get("post_title")
        description = request.form.get("post_description")
        date = request.form.get("post_date")
        db.execute("INSERT INTO posts (ngo_name, post_title, post_description, date, likes) VALUES (?, ?, ?, ?, 0)",
                   name, 
                   title, 
                    description,
                    date,
                   )
        return redirect("ngo_home")
    else:
        return render_template("newpost.html")


@app.route("/donation")
def donation():
    return render_template("donation.html")


@app.errorhandler(404)
def page_not_found(e):
    return render_template('blunder.html'), 404


#donations !!!!!

stripe_keys = {
    "secret_key": os.environ["STRIPE_SECRET_KEY"],
    "publishable_key": os.environ["STRIPE_PUBLISHABLE_KEY"],
    "endpoint_secret": os.environ["STRIPE_ENDPOINT_SECRET"], 
}

stripe.api_key = stripe_keys["secret_key"]


@app.route("/config")
def get_publishable_key():
    stripe_config = {"publicKey": stripe_keys["publishable_key"]}
    return jsonify(stripe_config)

@app.route("/create-checkout-session")
def create_checkout_session():
    domain_url = "http://127.0.0.1:5000/"
    stripe.api_key = stripe_keys["secret_key"]

    try:
       
        checkout_session = stripe.checkout.Session.create(
            success_url=domain_url + "success?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=domain_url + "cancelled",
            payment_method_types=["card"],
            mode="payment",
            line_items=[
                {
                    "price_data": {
                        "currency": "usd",
                        "product_data": {
                            "name": "NGO 1",
                        },
                        "unit_amount": 2000,  
                    },
                    "quantity": 1,
                }
            ]
        )
        return jsonify({"sessionId": checkout_session["id"]})
    except Exception as e:
        return jsonify(error=str(e)), 403


    
@app.route("/success")
def success():
    return render_template("success.html")


@app.route("/cancelled")
def cancelled():
    return render_template("cancelled.html")

@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, stripe_keys["endpoint_secret"]
        )

    except ValueError as e:
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError as e:
        return "Invalid signature", 400

    if event["type"] == "checkout.session.completed":
        print("Payment was successful.")


    return "Success", 200
