from functools import wraps

import jwt
from flask import jsonify, request
from flask_api import status

from User.models import Token


def login_required(f):

    @wraps(f)
    def decorator(*args, **kwargs):

        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

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

        except Exception as e:
            return jsonify({
                'message': 'token is invalid'
            })

        return f(args[0], token_obj, **kwargs)

    return decorator
