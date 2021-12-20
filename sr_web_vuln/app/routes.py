from flask import render_template, flash, redirect, url_for
import flask
from app import app, db
from app.forms import LoginForm, RegistrationForm
from flask_login import current_user, login_user
from app.models import User
from flask_login import logout_user, login_required
from flask import request
from werkzeug.urls import url_parse
import os
# import requests
# import json

api_url = "http://127.0.0.1:5000/"

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