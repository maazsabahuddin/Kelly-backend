from functools import wraps
import uuid, pytz
import flask
import transaction as transaction
from flask import jsonify, request, Response
from flask.views import View, MethodView
from flask_api import status
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import jwt

from Main.settings.production import OTP_INITIAL_COUNTER, OTP_COUNTER_LIMIT
from .decorators import login_required
from .models import User, Token, UserOTP
from .models import local_timezone_conversion
from .exceptions import WrongPhonenumber, TwilioException, UserException, WrongOtp, UserNotFound, WrongPassword, \
    UserNotActive, UserNotAuthorized, MissingField, InvalidUsage
from Main.settings.production import NOT_CATCHABLE_ERROR_MESSAGE, NOT_CATCHABLE_ERROR_CODE


# from pymongo import MongoClient
# from app import DB_URI
# client = MongoClient(DB_URI)
from .twilio_func import UserOTPMixin


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
    def get(self, request, data):
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

            if email:
                email_obj = User.objects(email=email).first()
                if email_obj:
                    return jsonify({
                        'status': status.HTTP_404_NOT_FOUND,
                        'message': 'User already registered with this email address',
                    })

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

            key = uuid.uuid4()
            user_token = Token(
                key=str(key),
                user=user
            ).save()

            from app import app
            token = jwt.encode({'key': user_token.key}, app.config['SECRET_KEY'], algorithm='HS256')

            result = UserOTPMixin.send_otp_phone_via_twilio(user.phone_number, otp)
            if not result:
                return jsonify({
                    'status': status.HTTP_200_OK,
                    'token': token.decode('UTF-8'),
                    'message': 'Phonenumber is not verified on your twilio trial account. OTP not sent.',
                })

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
                'message': "Exception encountered.",
            })


class VerifyUser(MethodView):

    @staticmethod
    def verify_otp(user, otp):

        otp_result = UserOTPMixin.verify_user_otp(user, otp)
        if not otp_result:
            return False
        user.is_active = True
        user.save()
        return True

    @login_required
    def post(self, request, data=None):
        try:
            user = data.get('user')
            payload = request.get_json()
            otp = payload.get('otp')

            result = VerifyUser.verify_otp(user, otp)
            if not result:
                raise WrongOtp(status_code=401, message="OTP not matched.")

            return jsonify({'status': status.HTTP_200_OK, 'message': 'User verified.'})

        except (UserException, WrongOtp, UserNotFound) as e:
            return jsonify({'status': e.status_code, 'message': e.message})
        except Exception as e:
            return jsonify({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})


class A(View):

    def dispatch_request(self):
        return Response("HAAHHAHA", mimetype="application/json", status=200)


class Login(MethodView):

    def post(self):
        token = ''
        user = ''
        try:
            payload = request.get_json()

            phone_number = payload.get('phone_number').strip()
            user = User.objects(phone_number=phone_number).first()

            if not user:
                raise UserNotFound(status_code=status.HTTP_404_NOT_FOUND,
                                   message='The sign-in credentials does not exist. Try again or create a new account')

            if not check_password_hash(user.password, payload.get('password')):
                raise WrongPassword(status_code=401, message="Invalid Credentials.")
            if not user.is_active:
                raise UserNotActive(status_code=401, message="User not authenticated. Please verify first.")

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

        except UserNotActive as e:
            otp = UserOTPMixin.generate_otp()
            print(otp)

            user_otp = UserOTP.objects.filter(user=user).first()
            if not user_otp:
                user_otp = UserOTP.objects.create(user=user)
            if user_otp.otp_counter >= OTP_COUNTER_LIMIT:
                return jsonify({
                    'status': 401,
                    'message': "User not authenticated. Please contact Sawari helpline."
                })
            user_otp.otp = otp
            user_otp.otp_time = local_timezone_conversion(datetime.datetime.now())
            user_otp.otp_counter += 1
            user_otp.save()

            result = UserOTPMixin.send_otp_phone_via_twilio(user.phone_number, otp)
            if not result:
                user.is_active = True
                user.save()
                return jsonify({
                    'status': status.HTTP_200_OK,
                    'token': token.key,
                    'message': 'User verified and login successfully.',
                })

            from app import app
            token_obj = Token.objects(user=user.id).first()
            if token_obj:
                token = jwt.encode({'key': token_obj.key}, app.config['SECRET_KEY'], algorithm='HS256')

            return jsonify({
                'status': status.HTTP_200_OK,
                'token': token.decode('UTF-8'),
                'message': 'OTP has been successfully sent.',
            })

        except (WrongPassword, UserNotAuthorized, UserNotFound, TwilioException) as e:
            return jsonify({
                'status': e.status_code,
                'message': str(e.message),
            })

        except Exception as e:
            return jsonify({
                'status': status.HTTP_400_BAD_REQUEST,
                'message': str(e),
            })


class Logout(MethodView):

    @login_required
    def get(self, request, data=None):
        try:
            user = data.get('user')
            user_token = Token.objects.filter(user=user).first()

            is_logout = user_token.delete()
            if not is_logout:
                return jsonify({
                    'status': status.HTTP_200_OK,
                    'message': 'Logged out',
                })
            return jsonify({
                'status': status.HTTP_404_NOT_FOUND,
                'message': 'Unable to logout',
            })
        except ValueError as e:
            return jsonify({
                'status': status.HTTP_200_OK,
                'message': 'Unable to Logout',
            })


class UserDetails(MethodView):

    @login_required
    def get(self, request, data=None):
        try:
            user = data.get('user')
            if not user.email:
                user.email = ""
            if not user.phone_number:
                user.phone_number = ""

            return jsonify({
                'status': status.HTTP_200_OK,
                'email': user.email,
                'name': user.name,
                'phone_number': user.phone_number,
            })

        except Exception as e:
            return jsonify({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})


class UpdateName(MethodView):

    @staticmethod
    def has_numbers(name):
        return any(char.isdigit() for char in name)

    @staticmethod
    def check_string_for_numbers(**kwargs):
        first_name = kwargs.get('first_name')
        last_name = kwargs.get('last_name')

        name = first_name + ' ' + last_name
        return any(char.isdigit() for char in name)

    @login_required
    def post(self, request, data=None):
        try:
            user = data.get('user')
            payload = request.get_json()
            name = payload.get('name')

            if not name:
                raise MissingField(status_code=400, message='Field missing.')

            if UpdateName.check_string_for_numbers(first_name=name, last_name=''):
                raise InvalidUsage(status_code=400, message='Name cannot contain digits.')

            user.name = name
            user.save()

            return jsonify({
                'status': status.HTTP_200_OK,
                'name': user.name,
                'message': "Your name successfully updated.",
            })

        except (MissingField, InvalidUsage) as e:
            return jsonify({'status': e.status_code, 'message': e.message})
        except Exception as e:
            return jsonify({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})
