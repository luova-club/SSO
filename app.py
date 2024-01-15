from flask import Flask, jsonify, request, session
from flask_restful import Api, Resource
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
import hashlib
import secrets
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sso_platform.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

Session(app)
db = SQLAlchemy(app)
api = Api(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(64), nullable=False)
    data = db.Column(db.String(255), nullable=False)

class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    token = db.Column(db.String(32), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

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

class TokenManager:
    def verify_token(self, token):
        raise NotImplementedError("Method not implemented")

    def get_username_from_token(self, token):
        raise NotImplementedError("Method not implemented")

class SimpleTokenManager(TokenManager):
    def verify_token(self, token):
        return db.session.query(Token).filter_by(token=token).first() is not None

    def get_username_from_token(self, token):
        token_data = db.session.query(Token).filter_by(token=token).first()
        return token_data.username if token_data else None

    def generate_token(self, username):
        token = secrets.token_hex(16)
        data_manager.add_token(username, token)
        return token

class HomeResource(Resource):
    def get(self):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return {'error': 'Token is missing in the header'}, 401

        if token_manager.verify_token(token):
            username = token_manager.get_username_from_token(token)
            print(username)
            user_data = data_manager.get_user(username, '')
            return {'message': f'Welcome, {username}!', 'data': user_data.get("data") if not user_data == None else None}
        else:
            return {'error': 'Invalid token'}, 401

class LoginResource(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username', '')
        password = data.get('password', '')

        user_data = data_manager.get_user(username, password)
        if user_data:
            token = token_manager.generate_token(username)
            session['username'] = username
            session['token'] = token
            session['password'] = password

            return {'token': token}
        else:
            return {'error': 'Invalid username or password'}, 401

class LogoutResource(Resource):
    def get(self):
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
            return {'message': 'User data updated successfully'}
        return {'error': 'You are not logged in.'}, 401

class UserDataDeletionResource(Resource):
    def delete(self):
        if 'username' in session:
            username = session['username']
            return {'message': 'User data deleted successfully'}
        return {'error': 'You are not logged in.'}, 401

class RegisterResource(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username', '')
        password = data.get('password', '')
        additional_data = data.get('data', '')

        if not username or not password:
            return {'error': 'Username and password are required'}, 400

        if data_manager.get_user(username, password):
            return {'error': 'Username already exists'}, 400

        data_manager.add_user(username, password, additional_data)
        return {'message': 'User registered successfully'}

data_manager = SQLDataManager(app)
token_manager = SimpleTokenManager()

api.add_resource(HomeResource, '/')
api.add_resource(LoginResource, '/login')
api.add_resource(LogoutResource, '/logout')
api.add_resource(RegisterResource, '/register')
api.add_resource(TokenVerificationResource, '/verify-token')
api.add_resource(UserDataUpdateResource, '/update-data')
api.add_resource(UserDataDeletionResource, '/delete-data')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
