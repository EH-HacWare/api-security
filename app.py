import logging
import secrets
import jwt

from flask import Flask, request

"""
a minimal web app to 
"""

app = Flask(__name__)

logging.basicConfig(format='%(levelname)s:%(message)s %(filename)s:%(lineno)d', level=logging.DEBUG)

# these credentials are included here to simplify the code
# in a live setting, they should never be included in the code or in source control
lst_secret = ['epLrzZeoc-We_FI_21dKoNc9yC9rr63gcAHluv7w6Mg', 'a48b045e-9b49-4be7-80c7-71c3c98c70ec']
jwt_secret = 'qdBGTW5Tm_SkIPLZNZZOoLvALBA_K7PaFfWNUFF9Fr4'


@app.route('/api/v1/version', methods=['GET'])
def version():
    return '1.3'


@app.route('/api/v1/secret_validation', methods=['GET'])
def secret_validation():
    if 'Api-Key' not in request.headers:
        logging.warning('Invalid headers')
        return {"message": "Unauthorized"}, 401

    api_key = request.headers['Api-Key']
    if api_key not in lst_secret:
        logging.warning('Invalid headers')
        return {"message": "Unauthorized"}, 401

    return 'Authentication Success'


@app.route('/api/v1/user_validation', methods=['GET'])
def user_validation():

    try:
        bearer = request.headers.get('Authorization')
        jwt_token = bearer.split()[1]
        jwt_data = jwt.decode(jwt_token, jwt_secret, "HS256")
        user_id = jwt_data['user_id']
        role = jwt_data['role']
    except Exception as e:
        logging.error('User validation error ' + str(e))
        return {"message": "Unauthorized"}, 401

    # the jwt appears valid
    return 'Authentication Success'


@app.route('/api/v1/admin_validation', methods=['GET'])
def admin_validation():

    try:
        bearer = request.headers.get('Authorization')
        jwt_token = bearer.split()[1]
        jwt_data = jwt.decode(jwt_token, jwt_secret, "HS256")
        user_id = jwt_data['user_id']
        role = jwt_data['role']
    except Exception as e:
        logging.error('Admin validation error ' + str(e))
        return {"message": "Unauthorized"}, 401

    if 'admin' != role:
        logging.info('Admin role required. User: ' + user_id)
        return {"message": "Unauthorized"}, 403

    return 'Authentication Success'


if __name__ == '__main__':
    app.run()
