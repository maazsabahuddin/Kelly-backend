from flask import Blueprint
from User.views import GetUser, Register, Login, Logout, VerifyUser, UserDetails

my_view = Blueprint('my_view', __name__)
my_view.add_url_rule("/login/", view_func=Login.as_view('login_view'))
my_view.add_url_rule("/get/users/", view_func=GetUser.as_view('get_users'))
my_view.add_url_rule("/user/details/", view_func=UserDetails.as_view('user_details'))
my_view.add_url_rule("/register/", view_func=Register.as_view('add_users'))
my_view.add_url_rule("/verify/user/", view_func=VerifyUser.as_view('verify_user'))
my_view.add_url_rule("/logout/", view_func=Logout.as_view('logout_user'))
