import jwt
import base64
import json

import hmac
import hashlib

#   TODO:
#       Create 2 examples: One where None algorithm is supported
#                          and another with algo confusion.
#       Token decode should be done manually in order to explore
#       these vulns.

#   Use RS256
public_key = open("public-key.pem", "r").read()
private_key = open("private-key.pem", "r").read()
payload = {
    'id': 1,
    'user': 'test',
    'role': 'default',
    'pk': public_key
}
# ---

# Assumes payloads with public key
def insec_verify_token(token):
    token_info = token.split('.')
    header = json.loads(base64.b64decode(token_info[0]).decode('UTF-8'))
    payload = json.loads(base64.b64decode(token_info[1]).decode('UTF-8'))
    user_id = -1
    if header['alg'] == 'none':
        if header['typ'] == 'JWT' and public_key == payload['pk']:
            user_id = payload['id']
    elif header['alg'] == 'RS256' and public_key == payload['pk']:
        try:
            token_dec = jwt.decode(token, public_key, algorithms=['RS256'])
            user_id = token_dec['id']
        except:
            return 403
    elif header['alg'] == 'HS256':
        try:
            token_dec = jwt.decode(token, 'HS256_SECRET', algorithms=['HS256'])
            user_id = token_dec['id']
        except:
            return 403
    print('hit')
    # user = User.query.filter_by(id=user_id).first()
    # if user is None or user.role != payload['role']:
    #     jsonify({"message": "User not found"}), 401
    # return jsonify({"user": user.to_dict()}), 200

def sec_verify_token(token):
    token_dec = jwt.decode(token, public_key, algorithms=['RS256', 'HS256'])
    print(token_dec)

# ---
# Explain why this doesn't work anymore: CVE-2018-0114
# token_hs = jwt.encode(payload, public_key, "HS256")

token_rs = jwt.encode(payload, private_key, "RS256")

# print(header + '\n' + payload)
sec_verify_token(token_rs)
# insec_verify_token(token_rs)