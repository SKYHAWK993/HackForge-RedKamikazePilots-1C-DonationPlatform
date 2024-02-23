import os
import json

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/user_login")
def user_login():
    return render_template("user_login.html")

@app.route("/user_register")
def user_register():
    return render_template("user_register.html")

@app.route("/ngo_login")
def ngo_login():
    return render_template("ngo_login.html")

@app.route("/ngo_register")
def ngo_register():
    return render_template("ngo_register.html")

@app.route("/user_home")
def user_home():
    return render_template("user_home.html")

@app.route("/explore_ngo")
def explore_ngo():
    return render_template("explore_ngo.html")

@app.route("/ngo_home")
def ngo_home():
    return render_template("ngo_home.html")


@app.route("/newpetition")
def newpetition():
    return render_template("newpetition.html")


@app.route("/newpost")
def newpost():
    return render_template("newpost.html")


@app.route("/donation")
def donation():
    return render_template("donation.html")


@app.errorhandler(404)
def page_not_found(e):
    return render_template('blunder.html'), 404
