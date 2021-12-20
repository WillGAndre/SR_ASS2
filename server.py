from sqlite3 import Connection as SQLite3Connection
from sqlalchemy import event
from sqlalchemy.engine import Engine
from datetime import datetime
from flask import Flask, json, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow

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

db = SQLAlchemy(app)
dt_now = datetime.now()

ma = Marshmallow(app)

#models/db tables
class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(50))
    role = db.Column(db.String(50))
    posts = db.relationship("BlogPost")

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


#routes
@app.route("/user", methods=["POST"])
def create_user():                         
    try:
        data = request.get_json()
        user = User(
            username=data['username'],
            role=data['role']
        )
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "User successfully created"}), 200
    except Exception as e:
        print(e)
        return jsonify({"error": "Failed to create user"}), 500

@app.route("/user/<user_id>", methods=["GET"])
def get_user(user_id):
    users = User.query.all()
    for user in users:
        if int(user_id) == int(user.id):
            return jsonify({
                "id": user_id,
                "username": user.username,
                "role": user.role
            }), 200
    return jsonify({"error": "User not found"}), 500





# -------------------------------- #
#           BLOG POSTS             #
# -------------------------------- #

# create new blog post
@app.route("/blog_post", methods=["POST"])
def create_blog_post(user_id):
    
    # fields
    title = request.json['title']
    body = request.json['body']
    date = datetime.now()
    #user_id = request.json['user_id']
    visibility = request.json['visibility']
    
    if(visibility != 'private' and visibility != 'public'):
        return forbidden()
    
    try:
        new_post =  BlogPost(title, body, date, user_id, visibility)
        
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
    all_posts = BlogPost.all() # add user
    result = posts_schema.dump(all_posts)
    
    return jsonify(result)

# get blog post by id
@app.route("/blog_post/<blog_post_id>", methods=["GET"])
def get_blog_post(blog_post_id):
    post = BlogPost.query.get(blog_post_id)
    result = posts_schema.dump(post)
    
    return jsonify(result)


# -------------------------------- #
#               ERRORS             #
# -------------------------------- #

@app.errorhandler(404)
def page_not_found():
    return "<h1>404</h1><p>The resource could not be found.</p>", 404

@app.errorhandler(403)
def forbidden():
    return "<h1>403</h1><p>Forbidden</p>", 403

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5050, debug=True)