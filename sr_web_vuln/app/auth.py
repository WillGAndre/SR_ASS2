from datetime import datetime, timedelta
import json

import jwt
import requests
from flask import jsonify
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
from werkzeug.security import check_password_hash

from app import app, db
from app.models import User

api_url = "http://127.0.0.1:5000/"
jwt_secret = 'secret_is_secret'

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

@token_auth.verify_token
def verify_token(token):
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

@token_auth.error_handler
def token_auth_error():
    return jsonify({"token_auth_error": "Token authentication error"}), 401

#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------
# API: TOKEN AUTHENTICATION METHODS
#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------

# This constitutes as a secure method since the token
# is first verified in the db, then its internal contents
# are also verified.
@app.route('/api/auth/check_token/<token>', methods = ['GET'])
def check_token(token):
    user = User.query.filter_by(token=token).first()
    if user is None or user.token_exp < datetime.utcnow():
        return jsonify({"user": None}), 401
    token = jwt.encode(
        user.jwt_payload(),
        jwt_secret
    )
    if token != user.token:
        return jsonify({"user": None}), 401
    return jsonify({"user": user.to_dict()}), 200

# Insecure token verification, assumes default encode algorithm: HS256
# ---
# In order for token generation to also be insecure,
# the payload should be constituted by deterministic variables.
# ATM, the payload includes the token experation TTL which isn't easily
# inferred by the attacker. One possibility could be to create a POST
# vuln_gen_token that accepts as POST arguments the payload of the 
# future token.
@app.route('/api/auth/vuln_check_token/<token>', methods = ['GET'])
def vuln_check_token(token):
    token_dec = jwt.decode(token, jwt_secret, algorithms=["HS256"])
    user_id = token_dec['id']
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        jsonify({"message": "User not found"}), 401
    return jsonify(token_dec), 200

@app.route('/api/auth/gen_token/<user_id>', methods = ['GET'])
def gen_token(user_id, exp_in = 3600):
    user = User.query.filter_by(id=user_id).first()
    now = datetime.now()
    if user.token and user.token_exp > now + timedelta(seconds=60):
        return jsonify({"token": user.token}), 200
    user.token_exp = now + timedelta(seconds=exp_in)
    user.token = jwt.encode(
        user.jwt_payload(),
        jwt_secret
    )
    db.session.flush()
    db.session.commit()
    return jsonify({"token": user.token}), 200

@app.route('/api/auth/revoke_token/<user_id>', methods = ['DELETE'])
def revoke_token_from_user(user_id):
    user = User.query.filter_by(id=user_id).first()
    user.token_exp = datetime.utcnow() - timedelta(seconds=1)
    return jsonify({"message": "Token revoked"})


# INSECURE: create jwt token based on passed user_id
@app.route('/api/auth/gen_insecure_token/<user_id>', methods = ['GET'])
def gen_insecure_token(user_id, exp_in = 3600):
    # ex: create token with admin user_id, but then allow an attacker to use this token

    now = datetime.now()
    token_exp = now + timedelta(seconds=exp_in)
    payload = {"id": user_id, "exp": token_exp}
    
    token = jwt.encode(
        payload,
        jwt_secret
    )
    return jsonify({"token": token}), 200


#INSECURE: validate jwt token based on user_id -> return user role
@app.route('/api/auth/check_inscure_token/<token>', methods = ['GET'])
def check_inscure_token(token):
    token_dec = jwt.decode(token, jwt_secret, algorithms=["HS256"])
    user_id = token_dec['id']
    user = User.query.filter_by(id=user_id).first()
    
    if user is None:
        jsonify({"message": "User not found"}), 401
    
    print(user.role)
    
    return jsonify({"role" : user.role}), 200

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
