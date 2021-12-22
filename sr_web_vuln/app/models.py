from datetime import datetime
from app import db, ma
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app import login

# user model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), index=True, unique=True)
    role = db.Column(db.String(50), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    posts = db.relationship("BlogPost")

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_role(self, role):
        self.role = role


# blogpost model
class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(50))
    body = db.Column(db.String(200))
    date = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable = False)
    username = db.Column(db.String(50))
    visibility = db.Column(db.String(10))
    edited = db.Column(db.String(3))
    
    def __repr__(self):
        return '<BlogPost {}>'.format(self.title)

    def to_dict(self):
        data = {
            'id': self.id,
            'title': self.title,
            'body': self.body,
            'user_id': self.user_id,
            'username': self.username,
            'visibility': self.visibility
        }
        return data

    def from_dict(self, data):
        for field in ['id', 'title', 'body', 'date', 'user_id', 'username', 'visibility', 'edited']:
            if field in data:
                setattr(self, field, data[field])


class PostSchema(ma.Schema):
    class Meta:
        fields = ('id', 'title', 'body', 'date', 'user_id', 'username', 'visibility', 'edited')


@login.user_loader
def load_user(id):
    return User.query.get(int(id))