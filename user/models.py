from flask import Flask ,jsonify , request , session , redirect , flash
from flask_bcrypt import Bcrypt
from flask_mail import Message

import uuid 
import hashlib
from app import mongo , mail
bcrypt = Bcrypt()
class User():
    def start_session(self , user):
        session['logged_in'] = True 
        session['user'] = user 
        return(jsonify(user),200)
    def signup(self):
        user = {
            "_id":uuid.uuid4().hex,
            "name": request.form.get('name'), 
            "email" : request.form.get('email') ,
            "contact": request.form.get('contact') ,
            "password" :  request.form.get('password') , 
        }
       
        if user["email"]=="":
            return(jsonify({"error" : "Please enter an email address"}),400)
        if user["name"] == "" :
            return(jsonify({"error" : "Please enter a name"}),400)
        if not user["contact"].isnumeric() or len(user["contact"])!=10:
            return(jsonify({"error" : "Please enter a valid contact number"}),400) 
        if user["password"] == "":
            return(jsonify({"error" : "Please enter a password"}),400)
        

        if mongo.db.users.find_one({"email" : user["email"]}):
            return(jsonify({"error" : "Email address is already taken"}),400)
        hashed = bcrypt.generate_password_hash(user["password"]).decode("utf-8")
        user["password"] = hashed

        mongo.db.users.insert_one(user)
        flash("You have been signed up ! Please login to continue ")
        return(jsonify(user),200) 
    
    def signout(self):
        session.clear()
        return(redirect('/')) 

    def login(self):
        user = mongo.db.users.find_one({"email" :request.form.get('lemail')}) 
        if user:
            if bcrypt.check_password_hash(user["password"], request.form.get("lpassword")): 
                return(self.start_session(user)) 
            else:
                return(jsonify({"error" : "Incorrect Password , please try again . "}),400) 
        else:

            return(jsonify({"error" : "Email address not found"}),400)

    def forgot(self):
        entered_user = {"email":request.form.get('forgotemail')} 
        print(entered_user)
        if entered_user == "":
            return(jsonify({"error" : "Please enter an email address"}),400)
        if mongo.db.users.find_one({"email" : request.form.get('forgotemail')}):
            msg = Message("test message", recipients = [request.form.get('forgotemail')])
            msg.body = "This is a trial message ! Hope it reaches you "
            msg.html = "<h1><a href ='http://127.0.0.1:5000/resetpassword'>Click Here to reset password</a></h1>"
            mail.send(msg)
            session["email"] = entered_user["email"]
            return(jsonify({"success":"woho you have been enrolled"}),200) 
        else:
            return(jsonify({"error" : "Please enter a valid email address"}),400)
        print(entered_user)
        return(jsonify({"error" : "User was found"})) 

    def reset(self):
        rpassword = request.form.get('rpassword')
        rcpassword = request.form.get('rcpassword')
        if rpassword != rcpassword:
            
            return(jsonify({"error" : "Both the password should match"}),400)
        user = mongo.db.users.find_one({"email" : session["email"]}) 
        print(session["email"])
        print(user) 
        mongo.db.users.update({"email" : session["email"]} ,  {"$set": {"password":  bcrypt.generate_password_hash(rpassword).decode("utf-8")}})
        user = mongo.db.users.find_one({"email" : session["email"]}) 
        print(user)
        flash("Your password has been updated . Please log in to continue !")
        del(session["email"])
        return(jsonify({"msg" :"found user"}),200)

          