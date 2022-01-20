import functools
import logging

logger = logging.getLogger()
fh = logging.FileHandler("files/message.log", mode='w')


def log(text):
    def decorator(func):
        def wrapper(*args, **kw):
            formatter = logging.Formatter("%(asctime)s %(clientip)-15s %(user)-8s %(message)s")
            fh.setLevel(logging.INFO)
            fh.setFormatter(formatter)
            logger.addHandler(fh)
            d = {'clientip': '192.168.0.1', 'user': 'fbloggs'}
            logger.warning('Protocol problem: %s', 'connection reset', extra=d)
            print(args[0][0])
            return func(*args, **kw)

        return wrapper

    return decorator
