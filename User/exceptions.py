

class InvalidUsage(Exception):
    status_code = 400
    message = ""

    def __init__(self, status_code=status_code, message=message):
        self.status_code = status_code
        self.message = message


class TwilioException(Exception):
    status_code = 400
    message = ""

    def __init__(self, status_code=status_code, message=message):
        self.status_code = status_code
        self.message = message


class UserException(Exception):
    status_code = 404
    message = ""

    def __init__(self, status_code=status_code, message=message):
        self.status_code = status_code
        self.message = message


class UserNotFound(UserException):
    pass


class DuplicateUser(UserException):
    pass


class PinNotMatched(UserException):
    pass


class MissingField(UserException):
    pass


class PlaceException(UserException):
    pass


class OldPin(UserException):
    pass


class WrongPassword(UserException):
    pass


class WrongOtp(UserException):
    pass


class UserNotAuthorized(UserException):
    pass


class UserNotActive(UserException):
    pass


class NameException(UserException):
    pass


class WrongPhonenumber(UserException):
    pass


class TemporaryUserMessage(UserException):
    pass


class MisMatchField(UserException):
    pass


class UserAlreadyExist(UserException):
    pass
