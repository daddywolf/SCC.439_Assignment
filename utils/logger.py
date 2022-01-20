import functools
import logging

logger = logging.getLogger()
fh = logging.FileHandler("files/message.log", mode='w')


def log(text):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kw):
            formatter = logging.Formatter("%(asctime)s %(clientip)-15s %(user)-8s %(message)s")
            fh.setLevel(logging.INFO)
            fh.setFormatter(formatter)
            logger.addHandler(fh)
            d = {'clientip': '192.168.0.1', 'user': 'fbloggs'}
            dd = func.__name__
            logger.warning('Protocol problem: %s', 'connection reset', extra=d)
            return func(*args, **kw)

        return wrapper

    return decorator
