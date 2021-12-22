from datetime import datetime
from flask import render_template, flash, redirect, url_for, jsonify
from app import app, db
from app.forms import LoginForm, PostCreation, RegistrationForm, PostEdit
from flask_login import current_user, login_user
from app.models import User, BlogPost, PostSchema
from app.errors import forbidden
from flask_login import logout_user, login_required
from flask import request
from werkzeug.urls import url_parse
import requests
import json
import os

api_url = "http://127.0.0.1:5000/"
post_schema = PostSchema()
posts_schema = PostSchema(many=True) 

# @app.route('/')
# @app.route('/index')
# # @login_required
# def index():
#     pass


#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------
# USER RELATED ROUTES
#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, role='default')
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!', "success")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# Profile page
@app.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = [
        {'author': user, 'title': 'Test title post #1', 'body': 'Test post #1'},
        {'author': user, 'title': 'Test title post #2', 'body': 'Test post #2'}
    ]
    filename = os.path.join(app.config['UPLOAD_FOLDER'], username)
    if (os.path.exists(filename)):
        return render_template('user.html', user=user, posts=posts, filename=username)
    return render_template('user.html', user=user, posts=posts)


@app.route('/upload')
@login_required
def upload():
    return render_template('upload_file.html')


@app.route('/uploader', methods = ['POST'])
@login_required
def uploader():
    if 'file' not in request.files:
        return redirect(request.url)

    file = request.files['file']
    if file.filename == "":
        return redirect(request.url)

    if file:
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], current_user.username))
        posts = [
            {'author': user, 'title': 'Test title post #1', 'body': 'Test post #1'},
            {'author': user, 'title': 'Test title post #2', 'body': 'Test post #2'}
        ]
        return render_template('user.html', user=current_user, posts=posts, filename=current_user.username)
    else:
        return redirect(request.url)


@app.route('/display/<filename>')
def display(filename):
    return redirect(url_for('static', filename='uploads/'+filename), code=301)


@app.route('/subscribe')
def subscribe():
    user = User.query.filter_by(username=current_user.username).first_or_404()
    user.role = "subscriber"
    db.session.flush()
    db.session.commit()
    return redirect(url_for('user', username=current_user.username), code=301)

#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------
# WEB SERVER: BLOG POST RELATED ROUTES
#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------

# GET request to API for all public blog posts
@app.route('/')
@app.route('/index')
@app.route('/explore')
@login_required
def explore():
    posts_array = []

    try:
        response = requests.get(api_url + "blog_posts")
        response_json = response.json()
        for post_json in response_json:
            post = BlogPost()
            post.from_dict(post_json)
            posts_array.append(post)      
    except Exception:
        return render_template('404.html')

    return render_template("explore.html", posts=posts_array)

# GET request to API for all blog posts from user
@app.route('/my_posts')
@login_required
def my_posts():
    posts_array = []

    try:
        user = db.session().query(User).filter_by(username=current_user.username).first()
        response = requests.get(api_url + "blog_posts/"+str(int(user.id)))
        response_json = response.json()
        for post_json in response_json:
            post = BlogPost()
            post.from_dict(post_json)
            posts_array.append(post)
    except Exception:
        return render_template('404.html')

    return render_template("my_posts.html", posts=posts_array)

# POST request to API to create new post
@app.route('/create_post',  methods=['GET', 'POST'])
@login_required
def create_post():
    form = PostCreation()
    if form.validate_on_submit():
        title = form.title.data
        body = form.body.data
        visibility = form.visibility.data
        user = db.session().query(User).filter_by(username=current_user.username).first()

        post = {
            'title': title,
            'body': body,
            'user_id': int(user.id),
            'username': current_user.username,
            'visibility': visibility
        }
        post_data = json.dumps(post)
        
        try:
            headers = {'Content-type': 'application/json'}
            response = requests.post(api_url + "blog_post", data=post_data, headers=headers)
            if response.status_code == 403:
                error = "Post invalid!"
                return render_template('create_post.html', form=form, error=error)
        except Exception:
            return render_template('404.html')

        flash("New post created with success (Title: " + title + ")", "success")
        return redirect(url_for('explore'))
        
    return render_template("create_post.html", form=form)


# PUT request to API to edit post
@app.route('/post_update/<id>',  methods=['GET', 'POST'])
@login_required
def post_update(id):

    # check if user can do this (by id, token...)
    # vulnerable and not vulnerable
    # IDEA: check if user can do this by checking user's id, if it matches with the user_id in the post, proceed (can we manipulate this to be vulnerable)
    # IDEA: send user id in request body -> it allows any user to forge the request body and edit other's posts (vulnerable)
    
    post = db.session().query(BlogPost).filter_by(id=id).first()
    
    form = PostEdit()
    if form.validate_on_submit():
        body = form.body.data
        visibility = form.visibility.data

        post = {
            'body': body,
            'visibility': visibility
        }
        post_data = json.dumps(post)
        
        try:
            headers = {'Content-type': 'application/json'}
            response = requests.put(api_url + "blog_post/" + id, data=post_data, headers=headers)
            if response.status_code == 403:
                error = "Post invalid!"
                return render_template('create_post.html', post=post, form=form, error=error)
        except Exception:
            return render_template('404.html')
    
        flash("Blog Post updated with success", "success")
        return redirect(url_for('my_posts'))

    return render_template("update_post.html", post=post, form=form)


# DELETE request to API to delete post
@app.route('/post_delete/<id>')
@login_required
def post_delete(id):

    # check if user can do this

    try:
        response = requests.delete(api_url + "blog_post/" + id)
    except Exception:
        return render_template('404.html')
    
    flash("Blog Post deleted with success", "success")
    return redirect(url_for('my_posts'))

#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------
# API: BLOG POST RELATED ROUTES
#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------

# TODO: Tokens + CORS
# SEARCH: JWT vuln
#         CORS vuln

@app.route("/blog_post", methods=["POST"])
def create_blog_post():
    try:
        data = request.get_json()
        if (data['visibility'] != 'private' and data['visibility'] != 'public'):
            return forbidden()
        post = BlogPost()
        post.title = data['title']
        post.body = data['body']
        post.visibility = data['visibility']
        post.user_id = data['user_id']
        post.username = data['username']
        date = datetime.utcnow()
        post.date = date.strftime("%H:%M:%S %b %d %Y")
        
        db.session.add(post)
        db.session.commit()
        return jsonify({"data": {"message": "Valid Post"}}), 200
    except Exception:
        print('Error reading data')
        return forbidden()

# get blog post by id
@app.route("/blog_post/<blog_post_id>", methods=["GET"])
def get_blog_post(blog_post_id):
    post = BlogPost.query.get(blog_post_id)
    result = posts_schema.dump(post)
    
    return jsonify(result), 200

# edit blog post
@app.route("/blog_post/<blog_post_id>", methods=["PUT"])
def edit_blog_post(blog_post_id):
    post = BlogPost.query.get(blog_post_id)
    
    post.body = request.json['body']
    post.visibility = request.json['visibility']
    post.edited = "yes"
    
    db.session.commit()
    
    return post_schema.jsonify(post), 200

# delete blog post
@app.route("/blog_post/<blog_post_id>", methods=["DELETE"])
def delete_blog_post(blog_post_id):
    post = BlogPost.query.get(blog_post_id)
    
    db.session.delete(post)
    db.session.commit()
    
    return post_schema.jsonify(post), 200

# get all public blog posts (explore page)
@app.route("/blog_posts", methods=["GET"])
def get_public_blog_posts():
    all_public_posts = BlogPost.query.filter_by(visibility='public')
    result = posts_schema.dump(all_public_posts)
    
    return jsonify(result), 200

# get all blog posts from user (private and public)
@app.route("/blog_posts/<user_id>", methods=["GET"])
def get_my_blog_posts(user_id):
    all_posts = BlogPost.query.filter_by(user_id=user_id)
    result = posts_schema.dump(all_posts)
    
    return jsonify(result), 200

