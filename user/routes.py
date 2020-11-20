from flask import Flask  ,render_template 
from app import app 
from user.models import User
@app.route("/user/signup/" , methods= ["POST"]) 
def signUp():
    temp = User()
    return(temp.signup()) 

@app.route("/user/signout/" , methods= ["GET","POST"]) 
def signout():
    temp = User()
    return(temp.signout())

@app.route("/user/login/" , methods = ["POST" , "GET"])
def Login():
    temp = User()
    return(temp.login()) 

@app.route("/user/forgot/" , methods = ["POST", "GET"]) 
def forgotpassword():
    temp = User()
    return(temp.forgot()) 

@app.route("/user/reset/" , methods = ["POST" , "GET"])
def resetpassword():
    temp = User()
    return(temp.reset())  

@app.route("/make_payment/" , methods = ["POST" , "GET"])
def make_Payment():
    return(render_template("pay.html"))