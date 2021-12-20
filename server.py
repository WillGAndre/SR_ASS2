from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
from sqlite3 import Connection as SQLite3Connection
from sqlalchemy import event
from sqlalchemy.engine import Engine
from datetime import datetime, timedelta
from flask import Flask, json, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

jwt_secret = 'secret_is_secret'

#app
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///sqlitedb.file"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = 0

#sqlite3 config (enforce foreign key constraints)
@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, SQLite3Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()

#               *----*

db = SQLAlchemy(app)

#models/db tables
class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(50))
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(50))
    posts = db.relationship("BlogPost")
    token = db.Column(db.String(128), index=True, unique=True)
    token_exp = db.Column(db.DateTime)

    def to_dict(self):
        return {'id': str(self.id), 'username': self.username, 'role': self.role}

    def jwt_payload(self):
        return {"id": self.id, "exp": self.token_exp, "role": self.role}

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_token(self, exp_in = 3600):
        now = datetime.now()
        if self.token and self.token_exp > now + timedelta(seconds=60):
            return self.token
        self.token_exp = now + timedelta(seconds=exp_in)
        self.token = jwt.encode(
            self.jwt_payload(),
            jwt_secret
        )
        db.session.flush()
        db.session.commit()
        return self.token

    def revoke_token(self):
        self.token_exp = datetime.utcnow() - timedelta(seconds=1)
    
    @staticmethod
    def check_token(token):
        user = User.query.filter_by(token=token).first()
        if user is None or user.token_exp < datetime.utcnow():
            return None
        token = jwt.encode(
            user.jwt_payload(),
            jwt_secret
        )
        if token != user.token:
            return None
        return user

class BlogPost(db.Model):
    __tablename__ = "blogpost"
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(50))
    body = db.Column(db.String(200))
    date = db.Column(db.DateTime, index = True, default = datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable = False)

#               *----*

basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth()

@basic_auth.verify_password
def verify_password(username, password):
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        return user

@basic_auth.error_handler
def basic_auth_error():
    return jsonify({"auth_error": "Authentication error"}), 401

@token_auth.verify_token
def verify_token(token):
    return User.check_token(token) if token else None

@token_auth.error_handler
def token_auth_error():
    return jsonify({"token_auth_error": "Token authentication error"}), 401

@app.route('/tokens', methods = ['POST'])
@basic_auth.login_required
def get_token():
    token = basic_auth.current_user().get_token()
    db.session.commit()
    return jsonify({"token": token})

@app.route('/tokens', methods=['DELETE'])
@token_auth.login_required
def revoke_token():
    token_auth.current_user().revoke_token()
    db.session.commit()
    return '', 204

#               *----*

# http GET <URL> \ 
# "Authorization:Bearer <token>"
# http --raw '{"username": "test", "password": "test", "role": "default"}' POST http://localhost:5000/register

#routes
@app.route("/register", methods=["POST"])
def register_user(): 
    try:
        data = request.get_json()
        user = User(username = data['username'], role = 'default')
        user.set_password(data['password'])
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "User successfully created"}), 200
    except:
        return jsonify({"error": "Failed to register user"}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        user = verify_password(data['username'], data['password'])
        token = user.get_token()
        return jsonify({"message": "User logged in successfully", "token": token})
    except:
        return jsonify({"error": "Failed to log in"}), 403

@app.route("/user/<user_id>", methods=["GET"])
@token_auth.login_required
def get_user(user_id):
    user = User.query.filter_by(id=user_id).first()
    if user:
        return jsonify({"message": user.to_dict()}), 200
    return jsonify({"error": "User not found"}), 500

@app.route("/blog_post/<user_id>", methods=["POST"])
def create_blog_post(user_id):
    pass

@app.route("/blog_post/<blog_post_id>", methods=["GET"])
def get_blog_post():
    pass

@app.route("/blog_post/<user_id>", methods=["GET"])
def get_blog_posts():
    pass

#               *----*

if __name__ == "__main__":
    app.run(debug=True)