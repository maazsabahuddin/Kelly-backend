from functools import wraps

import jwt
from flask import jsonify, request
from flask_api import status
from Main.settings.production import NOT_CATCHABLE_ERROR_CODE, NOT_CATCHABLE_ERROR_MESSAGE
from User.models import Token, User
from .exceptions import MissingField, UserNotFound, DuplicateUser, UserException


def login_required(f):

    @wraps(f)
    def decorator(*args, **kwargs):

        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({
                'message': 'Token Missing'
            })

        try:
            from app import app
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms='HS256')
            token_obj = Token.objects(key=data.get('key')).first()
            if not token_obj:
                return jsonify({
                    'status': status.HTTP_401_UNAUTHORIZED,
                    'message': 'Unauthorized attempt.'
                })

            user = User.objects(phone_number=token_obj.user.phone_number).first()
            data = {'user': user}
            return f(args[0], request, data)

        except Exception as e:
            return jsonify({
                'message': 'token is invalid'
            })

    return decorator


# def login_decorator(f):
#     @wraps(f)
#     def decorated_function(*args):
#         try:
#             # token = request.headers.get('authorization')
#             token = None
#             if 'x-access-tokens' in request.headers:
#                 token = request.headers['x-access-tokens']
#
#             if not token:
#                 raise MissingField(status_code=status.HTTP_400_BAD_REQUEST, message='Token required for authentication.')
#
#             user_token = Token.objects.filter(key=token).first()
#             if not user_token:
#                 raise UserNotFound(status_code=status.HTTP_404_NOT_FOUND, message='Login session expire.')
#
#             # user = CustomUserCheck.check_user_separately(user_token.user.email, user_token.user.phone_number)
#             user = User.objects(phone_number=user_token.user.phone_number).first()
#
#             data = {'user': user}
#             return f(args[0], request, data)
#
#         except (UserNotFound, MissingField, DuplicateUser, UserException) as e:
#             return jsonify({
#                 'status': e.status_code,
#                 'message': e.message,
#             })
#
#         except Exception as e:
#             return jsonify({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})
#
#     return decorated_function

def password_change_decorator(f):
    def password_change(*args):
        request = args[1]
        user = args[2].get('user')

        payload = request.get_json()
        password = payload.get('password')

        password = password.strip()
        if not user:
            raise MissingField(status_code=400, message="Pin required")

        from .views import hash_password
        hashed_password = hash_password(password)
        # if user.check_password(hashed_password):
        #     raise UserException(status_code=400, message="You cannot set old pin as new pin.")

        data = {'user': user, 'password': hashed_password}
        return f(args[0], request, data)

    return password_change
