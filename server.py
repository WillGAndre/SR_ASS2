from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
from sqlite3 import Connection as SQLite3Connection
from sqlalchemy import event
from sqlalchemy.engine import Engine
from datetime import datetime, timedelta
from flask import Flask, json, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

jwt_secret = 'secret_is_secret'

#app
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# #sqlite3 config (enforce foreign key constraints)
@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, SQLite3Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()

#               *----*

db = SQLAlchemy(app)

ma = Marshmallow(app)

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

# blog post
class BlogPost(db.Model):
    __tablename__ = "blogpost"
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(50))
    body = db.Column(db.String(200))
    date = db.Column(db.DateTime, index = True, default = datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable = False)
    visibility = db.Column(db.String(10))
    edited = db.Column(db.String(3), default='no')
    
    def __init__(self, title, body, date, user_id, visibility, edited):
        self.title = title
        self.body = body
        self.date = date
        self.user_id = user_id
        self.visibility = visibility
        self.edited = edited

# post schema
class PostSchema(ma.Schema):
    class Meta:
        fields = ('id', 'title', 'body', 'date', 'user_id', 'visibility', 'edited')

# init schema
post_schema = PostSchema()
posts_schema = PostSchema(many=True) 

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


#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------
# BLOG POSTS
#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------

# create new blog post
@app.route("/blog_post", methods=["POST"])
def create_blog_post():
    
    # fields
    title = request.json['title']
    body = request.json['body']
    date = datetime.now()
    user_id = request.json['user_id']
    visibility = request.json['visibility']
    edited = "no"
    
    if(visibility != 'private' and visibility != 'public'):
        return forbidden()
    
    try:
        new_post =  BlogPost(title, body, date, user_id, visibility, edited)
        
        db.session.add(new_post)
        db.session.commit()
    except:
        return forbidden()

# edit blog post
@app.route("/blog_post/<blog_post_id>", methods=["PUT"])
def edit_blog_post(blog_post_id):
    post = BlogPost.query.get(blog_post_id)
    
    post.body = request.json['body']
    post.visibility = request.json['visibility']
    post.edited = "yes"
    
    db.session.commit()
    
    return post_schema.jsonify(post)


# delete blog post
@app.route("/blog_post/<blog_post_id>", methods=["DELETE"])
def delete_blog_post(blog_post_id):
    post = BlogPost.query.get(blog_post_id)
    
    db.session.delete(post)
    db.session.commit()
    
    return post_schema.jsonify(post)


# get all public blog posts (explore page)
@app.route("/blog_posts", methods=["GET"])
def get_public_blog_posts():
    all_public_posts = BlogPost.query.filter_by(visibility='public')
    result = posts_schema.dump(all_public_posts)
    
    return jsonify(result)

# get all blog posts from user (private and public)
@app.route("/blog_posts/<user_id>", methods=["GET"])
def get_my_blog_posts(user_id):
    all_posts = BlogPost.query.filter_by(user_id=user_id)
    result = posts_schema.dump(all_posts)
    
    return jsonify(result)

# get blog post by id
@app.route("/blog_post/<blog_post_id>", methods=["GET"])
def get_blog_post(blog_post_id):
    post = BlogPost.query.get(blog_post_id)
    result = posts_schema.dump(post)
    
    return jsonify(result)


#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------
# ERRORS
#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------

@app.errorhandler(404)
def page_not_found():
    return "<h1>404</h1><p>The resource could not be found.</p>", 404

@app.errorhandler(403)
def forbidden():
    return "<h1>403</h1><p>Forbidden</p>", 403


#               *----*

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5050, debug=True)