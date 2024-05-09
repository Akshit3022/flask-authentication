from flask import Flask, request, jsonify, session
from flask_restful import Api, Resource, reqparse
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
from flask_mail import Mail, Message
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
app.secret_key = 'FCx20gm4Lp'
app.config['MAIL_SERVER'] = 'smtp.gmail.com' 
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] =  os.environ.get('EMAIL')
app.config['MAIL_PASSWORD'] =  os.environ.get('PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] =  os.environ.get('EMAIL')

db = SQLAlchemy(app)
mail = Mail(app)
api = Api(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

# Add request parser for user input
parser = reqparse.RequestParser()
parser.add_argument('email', type=str, required=True, help='Email is required')
parser.add_argument('password', type=str, required=True, help='Password is required')

password_not_req = reqparse.RequestParser()
password_not_req.add_argument('email', type=str, required=True, help='Email is required')
password_not_req.add_argument('password', type=str)

class Register(Resource):
    def post(self):
        args = parser.parse_args()
        email = args['email']
        password = generate_password_hash(args['password'])

        if User.query.filter_by(email=email).first():
            return {'message': 'User already exists'}, 400
        
        user = User(email=email, password=password)
        db.session.add(user)
        db.session.commit()

        return {'message': 'User created successfully'}, 201
    
class Login(Resource):
    def post(self):
        args = parser.parse_args()
        email = args['email']
        password = args['password']
        
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['email'] = email
            return {'message': 'User login successfully', 'email':session['email']}, 200
        else:
            return {'message': 'Invalid email or password'}, 400

class ForgotPassword(Resource):
    def post(self):        
        args = password_not_req.parse_args()
        email = args['email']
        
        user = User.query.filter_by(email=email).first()
        if session['email'] is None:
            if user:
                # Generate a random password
                new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
                user.password = generate_password_hash(new_password)  # Update user's password
                db.session.commit()

                # Send email with the new password
                msg = Message('Password Reset', recipients=[email])
                msg.body = f'Your new password is: {new_password}'
                mail.send(msg)

                return {'message': 'Password reset instructions sent to your email'}, 200
            else:
                return {'message': 'Email not found'}, 404
        else:
            return {'message': 'You are logged in'}, 401
        

class Logout(Resource):
    def post(self):
        session.pop('email', None)  
        return {'message': 'User logged out successfully'}, 200

api.add_resource(Register, "/register")
api.add_resource(Login, "/login")
api.add_resource(Logout, "/logout")
api.add_resource(ForgotPassword, "/forgot-password")

if __name__ == "__main__":
    app.run(debug=True)
