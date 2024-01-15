from flask import Flask, jsonify, request, session
from flask_restful import Api, Resource, reqparse
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_pymongo import PyMongo
import hashlib
import secrets
import datetime

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

# Define the Token model for storing tokens
class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    token = db.Column(db.String(32), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# DataManager class for database abstraction
class DataManager:
    def __init__(self, app):
        self.app = app

    def add_user(self, username, password, data):
        raise NotImplementedError("Method not implemented")

    def get_user(self, username, password):
        raise NotImplementedError("Method not implemented")

    def add_token(self, username, token):
        raise NotImplementedError("Method not implemented")

    def get_token(self, token):
        raise NotImplementedError("Method not implemented")

# SQLDataManager for SQL databases
class SQLDataManager(DataManager):
    def add_user(self, username, password, data):
        new_user = User(username=username, password=hashlib.sha256(password.encode()).hexdigest(), data=data)
        db.session.add(new_user)
        db.session.commit()

    def get_user(self, username, password):
        return User.query.filter_by(username=username, password=hashlib.sha256(password.encode()).hexdigest()).first()

    def add_token(self, username, token):
        new_token = Token(username=username, token=token)
        db.session.add(new_token)
        db.session.commit()

    def get_token(self, token):
        return Token.query.filter_by(token=token).first()

# MongoDataManager for MongoDB
class MongoDataManager(DataManager):
    def add_user(self, username, password, data):
        mongo.db.users.insert_one({'username': username, 'password': hashlib.sha256(password.encode()).hexdigest(), 'data': data})

    def get_user(self, username, password):
        return mongo.db.users.find_one({'username': username, 'password': hashlib.sha256(password.encode()).hexdigest()})

    def add_token(self, username, token):
        mongo.db.tokens.insert_one({'username': username, 'token': token})

    def get_token(self, token):
        return mongo.db.tokens.find_one({'token': token})

# TokenManager for token verification
class TokenManager:
    def verify_token(self, token):
        raise NotImplementedError("Method not implemented")

# SimpleTokenManager for demonstration (replace with a more secure solution in production)
class SimpleTokenManager(TokenManager):
    def verify_token(self, token):
        return data_manager.get_token(token) is not None

# SSO Platform Resources
class HomeResource(Resource):
    def get(self):
        if 'username' in session:
            username = session['username']
            user_data = data_manager.get_user(username, session['password'])
            return {'message': f'Welcome, {username}!', 'data': user_data["data"]}
        return {'error': 'You are not logged in.'}, 401

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

            # Save the token to the database
            data_manager.add_token(username, token)

            return {'token': token}
        else:
            return {'error': 'Invalid username or password'}, 401

class LogoutResource(Resource):
    def get(self):
        # Remove the token from the database
        if 'token' in session:
            data_manager.get_token(session['token']).delete()
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

class UserDataUpdateResource(Resource):
    def put(self):
        if 'username' in session:
            username = session['username']
            # Implement data update logic here
            return {'message': 'User data updated successfully'}
        return {'error': 'You are not logged in.'}, 401

class UserDataDeletionResource(Resource):
    def delete(self):
        if 'username' in session:
            username = session['username']
            # Implement data deletion logic here
            return {'message': 'User data deleted successfully'}
        return {'error': 'You are not logged in.'}, 401

# Choose the DataManager and TokenManager based on your desired database and token verification method
data_manager = MongoDataManager(app)
token_manager = SimpleTokenManager()

api.add_resource(HomeResource, '/')
api.add_resource(LoginResource, '/login')
api.add_resource(LogoutResource, '/logout')
api.add_resource(TokenVerificationResource, '/verify-token')
api.add_resource(UserDataUpdateResource, '/update-data')
api.add_resource(UserDataDeletionResource, '/delete-data')

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
