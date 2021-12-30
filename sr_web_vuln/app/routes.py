import json
import os
from datetime import datetime

import requests
from flask import flash, jsonify, redirect, render_template, request, url_for, send_from_directory, send_file
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.urls import url_parse

from app import app, db
from app.cors import _corsify_reflect, _corsify_whitelist, _corsify_regex_whitelist, _corsify_any
from app.auth import (basic_auth, gen_token, token_auth, verify_password,
                      verify_token, ws_auth_verify_password,
                      ws_auth_verify_token)
from app.errors import forbidden
from app.forms import LoginForm, PostCreation, PostEdit, RegistrationForm, ChangePasswordForm
from app.models import BlogPost, PostSchema, User
#from sr_web_vuln.app import auth

api_url = "http://127.0.0.1:5000/"
post_schema = PostSchema()
posts_schema = PostSchema(many=True) 

# GET /favicon.ico returns 500
@app.route("/favicon.ico")
def favicon():
    return "", 200

#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------
# USER RELATED ROUTES
#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('explore'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        token_response = requests.get(api_url + 'api/auth/gen_token/'+str(user.id))
        data = token_response.json()
        token = data['token']
        if user is None or \
            ws_auth_verify_password(username=form.username.data, password=form.password.data) != 200 or \
            ws_auth_verify_token(token) != 200:
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('explore')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('explore'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, role='default')
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# Created just to be able to test the jwt vulnerable endpoint
@app.route('/register_admin', methods=['GET', 'POST'])
def register_admin():
    if current_user.is_authenticated:
        return redirect(url_for('explore'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, role='default')
        user.set_password(form.password.data)
        user.set_role("admin")
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# Profile page
@app.route('/user/<username>')
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    filename = os.path.join(app.config['UPLOAD_FOLDER'], username)
    if (os.path.exists(filename)):
        return render_template('user.html', user=user, filename=username)
    return render_template('user.html', user=user)

@app.route('/upload')
def upload():
    return render_template('upload_file.html')

@app.route('/uploader', methods = ['POST'])
def uploader():
    if 'file' not in request.files:
        return redirect(request.url)

    file = request.files['file']
    if file.filename == "":
        return redirect(request.url)

    if file:
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], current_user.username))
        return render_template('user.html', user=current_user, filename=current_user.username)
    else:
        return redirect(request.url)

@app.route('/display/<filename>')
def display(filename):
    return redirect(url_for('static', filename='uploads/'+filename), code=301)

# Example:
# http --raw '{"path": "../README"}' http://127.0.0.1:5000/download
# https://stackoverflow.com/questions/38252955/flask-when-to-use-send-file-send-from-directory/38262406
@app.route('/download', methods = ['POST', 'OPTIONS'])
def download():
    if request.method == 'OPTIONS':
        cors_opts = {'result': 'Success'}
        response = jsonify(cors_opts)
        response.headers.add('Access-Control-Allow-Origin', str(request.headers['Origin']))
        response.headers.add('Access-Control-Allow-Methods', 'DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT')
        response.headers.add('Access-Control-Allow-Headers', 'content-type')
        return response
    # Insecure: Doesn't parse path
    path = request.get_json()['path']
    print(path)
    response = send_file(path, as_attachment=True)
    _corsify_reflect(request, response)
    return response
    # Secure: send_from_dir --> does parsing of path before sending file
    # full_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])
    # return send_from_directory(full_path, filename)

@app.route('/subscribe')
def subscribe():
    user = User.query.filter_by(username=current_user.username).first_or_404()
    user.role = "subscriber"
    db.session.flush()
    db.session.commit()
    return redirect(url_for('user', username=current_user.username), code=301)

# insecure method -> allows any user to change someone's password
# Does not verify the current password
# Any user can access method by changing <username> - IDOR
# This can lead to privilege escalation
@app.route('/change_password/<username>', methods=['GET', 'POST'])
def change_password(username):
    
    form = ChangePasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=username).first_or_404()
        user.set_password(form.password.data)

        db.session.commit()
        return redirect(url_for('user', username=username))
    return render_template('change_password.html', form=form)


# admin page
@app.route('/admin')
def admin():
    
    try:
        authorization = request.headers.get("Authorization")
        if(authorization == None):
            return render_template('404.html')
        
        auth_token = str(authorization[7:])

        response = requests.get(api_url + "api/auth/check_inscure_token/" + auth_token)
        response_json = response.json()

        if(response_json['role'] == "admin"):
            return render_template("admin_control.html")
        else:
            return render_template('404.html')
    except Exception:
        return render_template('404.html')


#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------
# WEB SERVER: BLOG POST RELATED ROUTES
#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------

# GET request to API for all public blog posts
@app.route('/')
@app.route('/index')
@app.route('/explore')
@basic_auth.login_required
def explore():
    posts_array = []

    try:
        response = requests.get(api_url + "api/blog_posts")
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
def my_posts():
    posts_array = []

    try:
        user = db.session().query(User).filter_by(username=current_user.username).first()
        response = requests.get(api_url + "api/blog_posts/"+str(int(user.id)))
        response_json = response.json()
        for post_json in response_json:
            post = BlogPost()
            post.from_dict(post_json)
            posts_array.append(post)
    except Exception:
        return render_template('404.html')

    return render_template("my_posts.html", posts=posts_array)


# GET request to API for all blog posts (admin)
# admins have special access to all blog posts
# for this method to work the Referer in the header must be /admin, verifying the current user is admin and comes from admin page
@app.route('/all_posts_admin')
def all_posts_admin():
    posts_array = []

    try:
        referer = request.headers.get("Referer")
        if(referer != "http://127.0.0.1:5000/admin"):
            return render_template('404.html')
        
        response = requests.get(api_url + "api/blog_posts_admin")
        response_json = response.json()
        for post_json in response_json:
            post = BlogPost()
            post.from_dict(post_json)
            posts_array.append(post)      
    except Exception:
        return render_template('404.html')

    return render_template("admin_all_posts.html", posts=posts_array)


# POST request to API to create new post
@app.route('/create_post',  methods=['GET', 'POST'])
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
            response = requests.post(api_url + "api/blog_post", data=post_data, headers=headers)
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
            response = requests.put(api_url + "api/blog_post/" + id, data=post_data, headers=headers)
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
        response = requests.delete(api_url + "api/blog_post/" + id)
    except Exception:
        return render_template('404.html')
    
    flash("Blog Post deleted with success", "success")
    return redirect(url_for('my_posts'))

#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------
# API: BLOG POST RELATED ROUTES
#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------

# CORS:
#   - https://flask-cors.readthedocs.io/en/latest/
#   - https://stackoverflow.com/questions/25594893/how-to-enable-cors-in-flask
#  ---
# JWT:
#   - https://www.netsparker.com/blog/web-security/json-web-token-jwt-attacks-vulnerabilities/
#   - https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
#  ---
#   - Add @token_auth.login_required to API methods that need token auth (IN HEADER --> "Authorization:Bearer <token>")
#   - Add @basic_auth.login_required to WS methods that need basic auth (<username>:<password>)

@app.route("/api/blog_post", methods=["POST"])
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
@app.route("/api/blog_post/<blog_post_id>", methods=["GET"])
def get_blog_post(blog_post_id):
    post = BlogPost.query.get(blog_post_id)
    result = posts_schema.dump(post)
    
    return jsonify(result), 200

# edit blog post
@app.route("/api/blog_post/<blog_post_id>", methods=["PUT"])
def edit_blog_post(blog_post_id):
    post = BlogPost.query.get(blog_post_id)
    
    post.body = request.json['body']
    post.visibility = request.json['visibility']
    post.edited = "yes"
    
    db.session.commit()
    
    return post_schema.jsonify(post), 200

# delete blog post
@app.route("/api/blog_post/<blog_post_id>", methods=["DELETE"])
def delete_blog_post(blog_post_id):
    post = BlogPost.query.get(blog_post_id)
    
    db.session.delete(post)
    db.session.commit()
    
    return post_schema.jsonify(post), 200

# get all public blog posts (explore page)
@app.route("/api/blog_posts", methods=["GET"])
def get_public_blog_posts():
    all_public_posts = BlogPost.query.filter_by(visibility='public')
    result = posts_schema.dump(all_public_posts)
    
    return jsonify(result), 200

# get all blog posts from user (private and public)
# CORS route
@app.route("/api/blog_posts/<user_id>", methods=["GET"])
def get_my_blog_posts(user_id):
    all_posts = BlogPost.query.filter_by(user_id=user_id)
    result = posts_schema.dump(all_posts)
    response = jsonify(result)
    # CORS Methods:
    _corsify_any(response)
    #_corsify_reflect(request, response)
    #_corsify_whitelist(request, response)
    #_corsify_regex_whitelist(request, response)
    return response, 200

# get all blog posts (private and public) (admin)
@app.route("/api/blog_posts_admin/", methods=["GET"])
# @cross_origin()
def get_all_blog_posts_admin():
    all_posts = BlogPost.query.all()
    result = posts_schema.dump(all_posts)
    response = jsonify(result)
    # response.headers.add('Access-Control-Allow-Origin', 'null') # '*'
    return response, 200