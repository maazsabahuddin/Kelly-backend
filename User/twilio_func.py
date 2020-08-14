import datetime

import math
import random

from Main.settings.production import TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, EMAIL_HOST_USER, OTP_COUNTER_LIMIT, \
    OTP_VALID_TIME, SENDER_PHONE_NUMBER

from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
from .models import UserOTP

from User.exceptions import InvalidUsage, UserException, UserNotFound, WrongOtp

account_sid = TWILIO_ACCOUNT_SID
auth_token = TWILIO_AUTH_TOKEN
client = Client(account_sid, auth_token)


class UserOTPMixin(object):

    @staticmethod
    def send_otp_phone_via_twilio(phone_number, otp):
        try:
            message_body = 'Kelly, your OTP is: {}'.format(otp)
            sender_phone_number = SENDER_PHONE_NUMBER

            client.messages.create(
                from_=sender_phone_number,
                body=message_body,
                to=phone_number,
            )
            return True

        except TwilioRestException:
            return False


    @classmethod
    def verify_user_otp(cls, user, otp):

        otp_user_obj = UserOTP.objects.filter(user=user).first()
        if not otp_user_obj:
            raise UserNotFound(status_code=404,
                               message="The sign-in credentials does not exist. Try again or create a new account")
        if otp_user_obj.otp_counter > OTP_COUNTER_LIMIT:
            raise WrongOtp(status_code=401,
                           message="OTP not matched. User not authenticated. Please contact Sawari helpline.")

        from django.utils import timezone
        current_time = timezone.localtime(timezone.now())

        # fetching db time
        OTP_SEND_TIME = otp_user_obj.otp_time

        # adding OTP TIME to db time..
        OTP_END_TIME = OTP_SEND_TIME + datetime.timedelta(0, OTP_VALID_TIME)

        # convert db time to local time (UTC to LOCAL)
        otp_end_time_local = cls.utc_to_local(OTP_END_TIME)

        if current_time > otp_end_time_local:
            raise WrongOtp(status_code=401, message="OTP not matched.")

        if otp_user_obj.otp == otp:
            otp_user_obj.otp_counter = 0
            otp_user_obj.is_verified = True
            otp_user_obj.save()
            return True

        return False

    @staticmethod
    def generate_otp():
        try:
            digits = "0123456789"
            otp = ""
            for i in range(6):
                otp += digits[math.floor(random.random() * 10)]
            return otp

        except Exception as e:
            raise InvalidUsage(status_code=410)
