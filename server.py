from sqlite3 import Connection as SQLite3Connection
from sqlalchemy import event
from sqlalchemy.engine import Engine
from datetime import datetime
from flask import Flask, json, request, jsonify
from flask_sqlalchemy import SQLAlchemy

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

#models/db tables
class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(50))
    role = db.Column(db.String(50))
    posts = db.relationship("BlogPost")

class BlogPost(db.Model):
    __tablename__ = "blogpost"
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(50))
    body = db.Column(db.String(200))
    date = db.Column(db.DateTime, index = True, default = datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable = False)

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

@app.route("/blog_post/<user_id>", methods=["POST"])
def create_blog_post(user_id):
    pass

@app.route("/blog_post/<blog_post_id>", methods=["GET"])
def get_blog_post():
    pass

@app.route("/blog_post/<user_id>", methods=["GET"])
def get_blog_posts():
    pass

if __name__ == "__main__":
    app.run(debug=True)