from datetime import datetime, timedelta
import json

import base64
import jwt
import requests
from flask import jsonify
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
from werkzeug.security import check_password_hash

from app import app, db
from app.models import User

api_url = "http://127.0.0.1:5000/"
HS256_SECRET = 'secret_is_secret'

RS256_PUB_KEY = open("app/auth/public-key.pem", "r").read()
RS256_PRV_KEY = open("app/auth/private-key.pem", "r").read()

#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------
# WEB SERVER: AUTHENTICATION METHODS
#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------

def ws_auth_verify_password(username, password):
    password_response = requests.get(api_url + 'api/auth/check_password/'+username+'/'+password)
    return password_response.status_code

def ws_auth_verify_token(token):
    token_response = requests.get(api_url + 'api/auth/check_token/'+token)
    return token_response.status_code

#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------
# API: PASSWORD AUTHENTICATION + METHOD
#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------

basic_auth = HTTPBasicAuth()

@basic_auth.verify_password
def verify_password(username, password):
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        return user, 200
    return None, 403 

@basic_auth.error_handler
def basic_auth_error():
    return jsonify({"auth_error": "Authentication error"}), 401

@app.route('/api/auth/check_password/<username>/<password>', methods=['GET'])
def check_password(username, password):
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        return jsonify({"user": user.to_dict()}), 200
    return jsonify({"user": None}), 403 

#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------
# API: TOKEN AUTHENTICATION
#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------

token_auth = HTTPTokenAuth()

# For insecure verification:
# call insec_verify_token
@token_auth.verify_token
def verify_token(token):
    user = User.query.filter_by(token=token).first()
    if user is None or user.token_exp < datetime.utcnow():
        return None
    return user

@token_auth.error_handler
def token_auth_error():
    return jsonify({"token_auth_error": "Token authentication error"}), 401

#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------
# API: TOKEN AUTHENTICATION METHODS
#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------

# Default secure auth method
# ---
# Assumes default algo: HS256
@app.route('/api/auth/check_token/<token>', methods = ['GET'])
def check_token(token):
    user = User.query.filter_by(token=token).first()
    if user is None or user.token_exp < datetime.utcnow():
        return jsonify({"user": None}), 401
    return jsonify({"user": user.to_dict()}), 200

# JWT Introduction - Insecure auth method
# ---
# Assumes public key field in payload: user.jwt_pk_payload()
#  
#  TODO:
#     - Use this method to set faulty tokens (before accessing admin page in XSS attack)
#       By doing this he is able to exploit the system using the 'admin' role (and their page)
@app.route('/api/auth/insec_verify_token/<token>', methods = ['GET'])
def insec_verify_token(token):
    token_info = token.split('.')
    header = json.loads(base64.b64decode(token_info[0]).decode('UTF-8'))
    payload = json.loads(base64.b64decode(token_info[1]).decode('UTF-8'))
    user_id = -1
    user_role = ''
    if header['alg'] == 'none':
        if header['typ'] == 'JWT' and RS256_PUB_KEY == payload['pk']:
            user_id = payload['id']
            user_role = payload['role']
    elif header['alg'] == 'RS256' and RS256_PUB_KEY == payload['pk']:
        try:
            token_dec = jwt.decode(token, RS256_PUB_KEY, algorithms=['RS256'])
            user_id = token_dec['id']
            user_role = token_dec['role']
        except:
            return jsonify({"authentication_error": "Error authenticating user"}), 403
    elif header['alg'] == 'HS256':
        try:
            token_dec = jwt.decode(token, HS256_SECRET, algorithms=['HS256'])
            user_id = token_dec['id']
            user_role = token_dec['role']
        except:
            return jsonify({"authentication_error": "Error authenticating user"}), 403
    
    user = User.query.filter_by(id=user_id).first()
    if user is None or user_role == '':
        jsonify({"message": "User not found"}), 401
    user.role = user_role
    user.token = token
    db.session.flush()
    db.session.commit()
    return jsonify({"user": user.to_dict()}), 200

# JWT Introduction - Generate fresh public key token
# ---
# Generates fresh token with user.jwt_pk_payload() as payload
@app.route('/api/auth/gen_pk_token/<user_id>', methods = ['GET'])
def gen_pk_token(user_id, exp_in = 3600):
    user = User.query.filter_by(id=user_id).first()
    now = datetime.now()
    user.token_exp = now + timedelta(seconds=exp_in)
    user.token = jwt.encode(
        user.jwt_pk_payload(),
        RS256_PRV_KEY,
        'RS256'
    )
    db.session.flush()
    db.session.commit()
    return jsonify({"token": user.token}), 200

@app.route('/api/auth/gen_token/<user_id>', methods = ['GET'])
def gen_token(user_id, exp_in = 3600):
    user = User.query.filter_by(id=user_id).first()
    now = datetime.now()
    # if user.token and user.token_exp > now + timedelta(seconds=60):
    #     return jsonify({"token": user.token}), 200
    user.token_exp = now + timedelta(seconds=exp_in)
    user.token = jwt.encode(
        user.jwt_payload(),
        HS256_SECRET
    )
    db.session.flush()
    db.session.commit()
    return jsonify({"token": user.token}), 200

@app.route('/api/auth/revoke_token/<user_id>', methods = ['DELETE'])
def revoke_token_from_user(user_id):
    user = User.query.filter_by(id=user_id).first()
    user.token_exp = datetime.utcnow() - timedelta(seconds=1)
    return jsonify({"message": "Token revoked"})


# @app.route('/tokens', methods = ['POST'])
# @basic_auth.login_required
# def get_token():
#     token = basic_auth.current_user().get_token()
#     db.session.commit()
#     return jsonify({"token": token})

# @app.route('/tokens', methods=['DELETE'])
# @token_auth.login_required
# def revoke_token():
#     token_auth.current_user().revoke_token()
#     db.session.commit()
#     return '', 204
