from flask import Flask, jsonify, request, session, abort
from flask_restful import Api, Resource
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_pymongo import PyMongo
import hashlib
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sso_platform.db'

Session(app)
db = SQLAlchemy(app)
mongo = PyMongo(app)
api = Api(app)

# Define the User model for SQL databases
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(64), nullable=False)
    data = db.Column(db.String(255), nullable=False)

# DataManager class for database abstraction
class DataManager:
    def __init__(self, app):
        self.app = app

    def add_user(self, username, password, data):
        raise NotImplementedError("Method not implemented")

    def get_user(self, username, password):
        raise NotImplementedError("Method not implemented")

# SQLDataManager for SQL databases
class SQLDataManager(DataManager):
    def add_user(self, username, password, data):
        new_user = User(username=username, password=hashlib.sha256(password.encode()).hexdigest(), data=data)
        db.session.add(new_user)
        db.session.commit()

    def get_user(self, username, password):
        return User.query.filter_by(username=username, password=hashlib.sha256(password.encode()).hexdigest()).first()

# MongoDataManager for MongoDB
class MongoDataManager(DataManager):
    def add_user(self, username, password, data):
        mongo.db.users.insert_one({'username': username, 'password': hashlib.sha256(password.encode()).hexdigest(), 'data': data})

    def get_user(self, username, password):
        return mongo.db.users.find_one({'username': username, 'password': hashlib.sha256(password.encode()).hexdigest()})

# TokenManager for token verification
class TokenManager:
    def verify_token(self, token):
        raise NotImplementedError("Method not implemented")

# SimpleTokenManager for demonstration (replace with a more secure solution in production)
class SimpleTokenManager(TokenManager):
    def verify_token(self, token):
        return len(token) == 32  # A simple verification for demonstration purposes

# SSO Platform Resources
class HomeResource(Resource):
    def get(self):
        if 'username' in session:
            username = session['username']
            user_data = data_manager.get_user(username, session['password'])
            return f'Welcome, {username}! <br> Your Data: {user_data["data"]}'
        return 'You are not logged in.'

class LoginResource(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username', '')
        password = data.get('password', '')

        user_data = data_manager.get_user(username, password)
        if user_data:
            token = secrets.token_hex(16)
            session['username'] = username
            session['token'] = token
            session['password'] = password
            return {'token': token}
        else:
            return {'error': 'Invalid username or password'}, 401

class LogoutResource(Resource):
    def get(self):
        session.clear()
        return {'message': 'Logged out successfully'}

class TokenVerificationResource(Resource):
    def post(self):
        data = request.get_json()
        token = data.get('token', '')
        if token_manager.verify_token(token):
            return {'message': 'Token is legitimate'}
        else:
            return {'error': 'Invalid token'}, 401

# Choose the DataManager and TokenManager based on your desired database and token verification method
data_manager = MongoDataManager(app)
token_manager = SimpleTokenManager()

api.add_resource(HomeResource, '/')
api.add_resource(LoginResource, '/login')
api.add_resource(LogoutResource, '/logout')
api.add_resource(TokenVerificationResource, '/verify-token')

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
