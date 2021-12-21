from flask import render_template, flash, redirect, url_for
from app import app, db
from app.forms import LoginForm, PostCreation, RegistrationForm
from flask_login import current_user, login_user
from app.models import User, BlogPost
from flask_login import logout_user, login_required
from flask import request
from werkzeug.urls import url_parse
import requests
import json

api_url = "http://127.0.0.1:5050/"

#
#   Add routes
#

@app.route('/')
@app.route('/index')
@login_required
def index():
    pass


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



#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------
# BLOG POST RELATED ROUTES
#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------

# GET request to API for all public blog posts
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
        pass
        # response = requests.get(api_url + "blog_posts")
        # response_json = response.json()
        # for post_json in response_json:
        #     post = BlogPost()
        #     post.from_dict(post_json)
        #     posts_array.append(post)      
    except Exception:
        return render_template('404.html')

    return render_template("explore.html", posts=posts_array)

# POST request to API to create new post
@app.route('/create_post',  methods=['GET', 'POST'])
@login_required
def create_post():
    form = PostCreation()
    if form.validate_on_submit():
        title = form.title.data
        body = form.body.data
        visibility = form.visibility.data
        # get user id
        
        post = BlogPost()
        post.title = title
        post.body = body
        post.visibility = visibility
        post.user_id = 1
        post_data = json.dumps(post.to_dict())
        
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
