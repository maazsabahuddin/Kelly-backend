import datetime, pytz

from Main.settings.config import local_timezone

current_time = datetime.datetime.now(pytz.timezone('Asia/Karachi'))
print(current_time)


def local_timezone_conversion(utc_datetime):
    local_dt = utc_datetime.replace(tzinfo=pytz.utc).astimezone(local_timezone)
    return local_timezone.normalize(local_dt)


print(datetime.datetime.now())

print(local_timezone_conversion(datetime.datetime.now()))