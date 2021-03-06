import re

#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------
# CORS FUNCTIONS: static.html + static_xss.html
#----------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------

# SHOULD ONLY WORK FOR GET REQUESTS
# POST REQUESTS NEED OPTIONS METHOD

CORS_WHITELIST = ['*', 'null', 'localhost']
CORS_REGEX_WHITELIST = [r'http://127.0.0.1:5000/api/.*', r'http://127.0.0.1:5000/.*', r'.*/api/.*', r'.*']

# Simplest method: Used in /blog_posts (XSS)
def _corsify_any(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response

def _corsify_reflect(request, response):
    response.headers.add('Access-Control-Allow-Origin', str(request.headers['Origin']))
    return response

def _corsify_whitelist(request, response):
    request_origin = str(request.headers['Origin'])
    if request_origin in CORS_WHITELIST:
        response.headers.add('Access-Control-Allow-Origin', request_origin)
    else:
        response.headers.add('Access-Control-Allow-Origin', '*')
    return response

def _corsify_regex_whitelist(request, response):
    request_origin = str(request.headers['Origin'])
    for regex in CORS_REGEX_WHITELIST:
        if re.match(regex, request_origin):
            response.headers.add('Access-Control-Allow-Origin', request_origin)
    return response