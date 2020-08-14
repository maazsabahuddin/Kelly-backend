from functools import wraps
import uuid
import flask
import transaction as transaction
from flask import jsonify, request, Response
from flask.views import View, MethodView
from flask_api import status
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import jwt

from Main.settings.production import OTP_INITIAL_COUNTER
from .decorators import login_required
from .models import User, Token, UserOTP
from .models import local_timezone_conversion


# from pymongo import MongoClient
# from app import DB_URI
# client = MongoClient(DB_URI)


class DelUser(MethodView):

    @login_required
    def post(self):

        payload = request.get_json()
        if not payload:
            return jsonify({
                'status': status.HTTP_400_BAD_REQUEST,
                'message': 'Missing body',
            })
        # Pending state

        return jsonify({
            'message': 'Method \"POST\" not allowed.'
        })


class GetUser(MethodView):

    @login_required
    def get(self, token, **kwargs):
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
        phone = ''
        try:
            payload = request.get_json()

            if not payload:
                return jsonify({
                    'status': status.HTTP_400_BAD_REQUEST,
                    'message': 'Missing body',
                })

            name = payload.get('name').strip()
            phone = payload.get('phone_number').strip()
            email = payload.get('email').strip()
            password = payload.get('password').strip()

            phone_number = User.objects(phone_number=phone).first()
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
                is_active=False,
                is_admin=False
            ).save()

            from .twilio_func import UserOTPMixin
            otp = UserOTPMixin.generate_otp()
            user_otp = UserOTP(
                user=user,
                otp=otp,
                otp_counter=OTP_INITIAL_COUNTER,
                is_verified=False,
                password_reset_uuid=None,
            )
            user_otp.save()

            result = UserOTPMixin.send_otp_phone_via_twilio(user.phone_number, otp)
            if not result:
                return jsonify({
                    'status': status.HTTP_400_BAD_REQUEST,
                    'message': 'Invalid phone number.',
                })

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
                'message': 'OTP has been successfully sent.',
                # 'message': 'Account Successfully created.',
            })

        except Exception as e:
            # User.object.delete_one(phone_number=phone).first()
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

            phone_number = payload.get('phone_number').strip()
            user = User.objects(phone_number=phone_number).first()
            if not user:
                return jsonify({
                    'status': status.HTTP_404_NOT_FOUND,
                    'message': 'The sign-in credentials does not exist. Try again or create a new account',
                })

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
                    'message': 'Login successfully.',
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
