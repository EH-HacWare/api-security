import base64
import json
import jwt
import secrets

"""
this code was used to generate the tokens used to test the flask application
"""

def create_jwt():
    user_id_1 = secrets.token_urlsafe(16)
    user_id_2 = secrets.token_urlsafe(16)

    secret = secrets.token_urlsafe(32)

    print(secret)
    print(user_id_1)
    print(user_id_2)

    payload = {"user_id": user_id_1, "role": "user"}
    encoded_jwt_user = jwt.encode(payload, secret, algorithm="HS256")
    print(encoded_jwt_user)

    dct_payload = {"user_id": user_id_2, "role": "admin"}
    encoded_jwt_admin = jwt.encode(dct_payload, secret, algorithm="HS256")
    print(encoded_jwt_admin)


def decode_jwt(jwt_token):
    secret = 'M1L0ozCc0auzNdMGFDfvostm5DoG-TY4XbqIss8kxwY'
    xx = jwt.decode(jwt_token, secret, algorithms=["HS256"])
    print(xx)


def main():
    create_jwt()


if __name__ == '__main__':
    main()
