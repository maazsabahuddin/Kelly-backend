from functools import wraps
import uuid
import flask
from flask import jsonify, request, Response
from flask.views import View, MethodView
from flask_api import status
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import jwt

from .decorators import login_required
from .models import User, Token
from .models import local_timezone_conversion


class GetUser(MethodView):

    def get(self):
        users = User.objects().to_json()
        return Response(users, mimetype="application/json", status=200)

    def post(self):
        return jsonify({
            'message': 'Method \"POST\" not allowed.'
        })


def hash_password(password):
    hashed_password = generate_password_hash(password, method='sha256')
    return hashed_password


class Register(MethodView):

    def post(self):
        try:
            payload = request.get_json()

            if not payload:
                return jsonify({
                    'status': status.HTTP_400_BAD_REQUEST,
                    'message': 'Missing body',
                })

            name = payload.get('name')
            phone = payload.get('phone_number')
            email = payload.get('email')
            password = payload.get('password')

            phone_number = User.objects(phone_number=phone)
            if phone_number:
                return jsonify({
                    'status': status.HTTP_404_NOT_FOUND,
                    'message': 'User already registered with this phone_number',
                })

            hashed_password = hash_password(password)
            user = User(
                name=name,
                phone_number=phone,
                email=email,
                password=hashed_password,
                last_login=local_timezone_conversion(datetime.datetime.now()),
                is_active=True,
                is_admin=False
            ).save()

            key = uuid.uuid4()
            user_token = Token(
                key=str(key),
                user=user
            ).save()

            from app import app
            token = jwt.encode({'key': user_token.key}, app.config['SECRET_KEY'], algorithm='HS256')

            return jsonify({
                'status': status.HTTP_200_OK,
                'token': token.decode('UTF-8'),
                'message': 'Account Successfully created.',
            })

        except Exception as e:
            return jsonify({
                'status': status.HTTP_400_BAD_REQUEST,
                'message': "Missing body",
            })


class A(View):

    def dispatch_request(self):
        return Response("HAAHHAHA", mimetype="application/json", status=200)


class Login(MethodView):

    def post(self):
        try:
            payload = request.get_json()

            phone_number = payload.get('phone_number')
            phone_number = phone_number.strip()
            user = User.objects(phone_number=phone_number).first()
            if not check_password_hash(user.password, payload.get('password')):
                return jsonify({
                    'status': status.HTTP_404_NOT_FOUND,
                    'message': 'Invalid Credentials',
                })

            from app import app
            token_obj = Token.objects(user=user.id).first()
            if token_obj:
                token = jwt.encode({'key': token_obj.key}, app.config['SECRET_KEY'], algorithm='HS256')
                data = {
                    'status': status.HTTP_200_OK,
                    'token': token.decode('UTF-8'),
                    'message': 'Login successfully.',
                }
                return jsonify(data)
            else:
                key = uuid.uuid4()
                user_token = Token(
                    key=str(key),
                    user=user
                ).save()

                from app import app
                token = jwt.encode({'key': user_token.key}, app.config['SECRET_KEY'], algorithm='HS256')

                return jsonify({
                    'status': status.HTTP_200_OK,
                    'token': token.decode('UTF-8'),
                    'message': 'Account Successfully created.',
                })

        except Exception as e:
            return jsonify({
                'status': status.HTTP_400_BAD_REQUEST,
                'message': str(e),
            })


class Logout(MethodView):

    @login_required
    def get(self, token_obj, **kwargs):
        try:
            token_obj.delete()
            return jsonify({
                'status': status.HTTP_200_OK,
                'message': 'Logged Out!',
            })

        except ValueError as e:
            return jsonify({
                'status': status.HTTP_200_OK,
                'message': 'Unable to Logout',
            })

