from flask import (
    Flask,
    render_template,
    session,
    redirect,
    request,
    url_for,
    flash,
    Response,
    make_response,
    Markup,
)
from flask_bcrypt import Bcrypt

from functools import wraps
import json
import razorpay
from flask_pymongo import PyMongo
import pymongo
import random
from flask_mail import Message
from flask_mail import Mail
import os

# from sendgrid import SendGridAPIClient
# from sendgrid.helpers.mail import Mail
import re

import pdfkit

basedir = os.path.abspath(os.path.dirname(__file__))
config = pdfkit.configuration(
    wkhtmltopdf=r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe"
)
app = Flask(__name__)

# app.secret_key = os.getenv("APP_SECRET_KEY")
app.config["SECRET_KEY"] = os.getenv("APP_SECRET_KEY")
app.config["MONGO_URI"] = "mongodb://localhost:27017/dvc"
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_DEBUG"] = True
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_USE_TSL"] = False
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_MAX_EMAILS"] = None
app.config["MAIL_SUPPRESS_SEND "] = False
app.config["MAIL_ASCII_ATTACHMENTS"] = None
app.config["SESSION_TYPE"] = "filesystem"
app.config["WKHTMLTOPDF_USE_CELERY"] = True
app.config["WKHTMLTOPDF_BIN_PATH"] = r"C:\Program Files\wkhtmltopdf\bin"
app.config["PDF_DIR_PATH"] = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "static", "pdf"
)
mongo = PyMongo(app)
mail = Mail(app)
bcrypt = Bcrypt(app)
razorpay_client = razorpay.Client(
    auth=(os.getenv("RAZORPAY_PRIVATE"), os.getenv("RAZORPAY_SECRET"))
)


def login_required(f):
    @wraps(f)
    def wrap(*arg, **kwarg):
        if "logged_in" in session:
            return f(*arg, *kwarg)
        else:
            return redirect("/")

    return wrap


# from user import routes


@app.route("/")
def home():

    return render_template("home.html")


@app.route("/signup/", methods=["GET", "POST"])
def signup():
    user = {}
    pattern = re.compile("[@_!#$%^&*()<>?/\|}{~:]")
    if request.method == "POST":
        user = {
            "name": request.form.get("name"),
            "email": request.form.get("email"),
            "contact": request.form.get("contact"),
            "password": request.form.get("password"),
            "cpassword": request.form.get("cpassword"),
            "token": random.randint(11111, 99999),
            "verified": False,
        }

        if user["email"] == "":
            flash("Email cannot be empty.", "danger")
            return render_template("signup.html", user=user)

        if user["name"] == "":
            flash("Name cannot be empty.", "danger")
            return render_template("signup.html", user=user)

        if not user["contact"].isnumeric() or len(user["contact"]) != 10:
            flash("Please enter a valid mobile number .", "danger")
            return render_template("signup.html", user=user)

        if user["password"] == "":
            flash("Password cannot be empty!", "danger")
            return render_template("signup.html", user=user)

        if user["password"] != user["cpassword"]:
            flash("Both the passwords should match.", "danger")
            return render_template("signup.html", user=user)

        if len(user["password"]) < 8:
            flash("Password should atleast contain 8 characters.", "warning")
            return render_template("signup.html", user=user)

        if user["password"].isdigit():
            flash("The password cannot be only numeric.", "warning")
            return render_template("signup.html", user=user)

        if user["password"].isalpha():
            flash("The password must contain atleast one numeric character.", "warning")
            return render_template("signup.html", user=user)

        if re.search(pattern, user["password"]) == None:
            flash("The passwotd must contain atleast one special character", "warning")
            return render_template("signup.html", user=user)

        if mongo.db.users.find_one({"contact": user["contact"]}):
            flash("This mobile number is already in use .", "danger")
            return render_template("signup.html", user=user)

        if mongo.db.users.find_one({"email": user["email"]}):
            flash("Email address already taken .", "danger")
            return render_template("signup.html", user=user)

        hashed_pw = bcrypt.generate_password_hash(user["password"]).decode("utf-8")
        user["password"] = hashed_pw

        try:
            del user["cpassword"]
            mongo.db.users.insert_one(user)
            msg = Message("Confirm email", recipients=[user["email"]])
            link = url_for("verify", token=user["token"], _external=True)
            msg.html = (
                """<h1>Confirm your email!</h1>
                           <a href=" """
                + link
                + """ "><button class="btn btn-primary">Verify Email</button></a>"""
            )
            mail.send(msg)
            # message = Mail(
            #     to_emails=user["email"],
            #     from_email="ogtechtest2@gmail.com",
            #     subject="Account verification",
            #     html_content="<h1><a href ="
            #     + link
            #     + ">Click Here to verify your account</a></h1>",
            # )

            # sg = SendGridAPIClient(os.getenv("SENDGRID_KEY"))

            # response = sg.send(message)
            mongo.db.users.update_one(
                {"email": user["email"]}, {"$set": {"token": user["token"]}}
            )
            flash(
                "We've sent you a verification mail . Please check your mail to continue .",
                "success",
            )
            return redirect(url_for("signup"))
        except Exception as e:
            print(e)
            flash(
                "Due to unknown reasons , the verification email could not be sent . Please try signing up again . ",
                "warning",
            )
            mongo.db.users.delete_one({"email": user["email"]})
            return redirect(url_for("signup"))

    return render_template("signup.html")


@app.route("/verify/<token>", methods=["POST", "GET"])
def verify(token):
    user = mongo.db.users.find_one({"token": int(token)})
    mongo.db.users.update_one({"email": user["email"]}, {"$set": {"verified": True}})
    mongo.db.users.update_one({"email": user["email"]}, {"$set": {"token": None}})
    flash("You have been verified!", "success")
    return redirect(url_for("login"))


@app.route("/login/", methods=["POST", "GET"])
def login():
    if "logged_in" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        if request.form.get("lemail") == "":
            flash("Email cannot be empty .", "danger")
            return redirect(url_for("login"))
        if request.form.get("lpassword") == "":
            flash("Password cannot be empty .", "danger")
            return redirect(url_for("login"))

        user = mongo.db.users.find_one({"email": request.form.get("lemail")})
        if user:
            if not user["verified"]:
                flash("Please verify your email to continue!", "warning")
                return redirect(url_for("login"))
            if bcrypt.check_password_hash(
                user["password"], request.form.get("lpassword")
            ):
                session["logged_in"] = True
                session["email"] = user["email"]
                session["name"] = user["name"]
                session["contact"] = user["contact"]
                if request.form.get("remember") == "on":
                    session.permanent = True
                return redirect(url_for("dashboard"))
            else:
                flash("Incorrect Password , please try again .", "danger")
                return redirect(url_for("login"))
        else:
            flash("Email address not found .", "danger")
            return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/logout/")
def logout():

    session.clear()
    flash("You have been logged out ", "success")
    return redirect(url_for("home"))


@app.route("/dashboard/")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/forgot_password", methods=["POST", "GET"])
def forgot():
    if request.method == "POST":
        entered_user = request.form.get("forgotemail")
        # print(entered_user)
        if entered_user == "":
            return redirect(url_for("login"))
        user = mongo.db.users.find_one({"email": entered_user})
        if user:

            # message = Mail(
            #     to_emails=entered_user,
            #     from_email="ogtechtest2@gmail.com",
            #     subject="Password reset link",
            #     html_content="<h1><a href ="
            #     + link
            #     + ">Click Here to reset password</a></h1>",
            # )
            try:
                token = random.randint(11111, 99999)
                link = url_for("reset", token=token, _external=True)
                msg = Message("Change Password", recipients=[user["email"]])
                msg.html = (
                    """<h1>Change Your Password!</h1>
                        <a href=" """
                    + link
                    + """ "><button class="btn btn-primary">Click Here to reset password</button></a>"""
                )
                mail.send(msg)
                # sg = SendGridAPIClient(os.getenv("SENDGRID_KEY"))

                # response = sg.send(message)
                mongo.db.users.update_one(
                    {"email": entered_user}, {"$set": {"token": token}}
                )
                flash(
                    "We've sent you an email . Please check your inbox to continue ",
                    "success",
                )
                return redirect(url_for("login"))
            except Exception as e:
                flash(
                    "Due to unknown reasons , the email could not be sent . Please try again . ",
                    "warning",
                )
                return redirect(url_for("login"))

        else:
            flash("This email address is not registered with us .", "danger")
            return redirect(url_for("login"))
        # print(entered_user)

    return render_template("forgot.html")


@app.route("/resetpassword/<token>", methods=["POST", "GET"])
def reset(token):
    user = mongo.db.users.find_one({"token": int(token)})
    # print(user)
    if request.method == "POST":
        if user:
            reset_password = request.form.get("reset_password")
            reset_confirm_password = request.form.get("reset_confirm_password")
            if reset_password != reset_confirm_password:
                flash("Both the passwords should match", "danger")
                return redirect(url_for("reset"))
            mongo.db.users.update(
                {"email": user["email"]},
                {
                    "$set": {
                        "password": bcrypt.generate_password_hash(
                            reset_password
                        ).decode("utf-8")
                    }
                },
            )

            flash(
                "Your password has been updated . Please log in to continue !",
                "success",
            )
            mongo.db.users.update_one(
                {"email": user["email"]}, {"$set": {"token": None}}
            )
            return redirect(url_for("login"))

    return render_template("reset.html")


@app.route("/make_payment/", methods=["POST", "GET"])
def make_payment():
    if request.method == "POST":
        amount = request.form.get("amount")
        price = int(amount) * 100
        user = mongo.db.users.find_one({"email": session["email"]})
        # print(user)
        # print(amount)
        return render_template("pay.html", user=user, price=price)


@app.route("/pay", methods=["POST", "GET"])
def app_charge():

    return redirect("/make_payment/")


@app.route("/create", methods=["POST", "GET"])
def create():
    return render_template("create.html")


@app.route("/create_card", methods=["POST", "GET"])
def create_card():
    if request.method == "POST":
        if (
            request.form.get("email") == ""
            or request.form.get("name") == ""
            or request.form.get("contact") == ""
        ):
            flash("Please enter sufficient information", "Danger")
            return redirect(url_for("create_card"))
        else:
            card = {
                "creater_email": session["email"],
                "on_card_email": request.form.get("email"),
                "on_card_name": request.form.get("name"),
                "on_card_contact": "+91" + request.form.get("contact"),
                "on_card_link": request.form.get("website-link"),
                "on_card_address": request.form.get("address"),
            }
            mongo.db.cards.insert_one(card)
            del card["_id"]
            return redirect(url_for("convert", card=json.dumps(card)))
    else:

        return redirect(url_for("create"))


@app.route("/card2", methods=["POST", "GET"])
def card():
    return render_template("card2.html")


@app.route("/convert/<card>", methods=["POST", "GET"])
def convert(card):
    c = json.loads(card)
    css = basedir + "\static\css\card.css"
    options = {
        "enable-internal-links": "",
        "enable-external-links": "",
    }
    pdf = pdfkit.from_string(
        render_template("card2.html", card=c), False, css=css, configuration=config
    )
    response = make_response(pdf)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = "attachment; filename=" + "trial" + ".pdf"

    return response


if __name__ == "__main__":
    app.run(debug=True)
