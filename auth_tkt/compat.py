from base64 import b64decode, b64encode
import sys


IS_PY2 = (sys.version_info.major == 2)


def base64encode(s, encoding='utf-8'):
    if IS_PY2:
        return b64encode(s)
    return b64encode(bytes(s, encoding)).decode()


def base64decode(s, encoding='utf-8'):
    if IS_PY2:
        return b64decode(s)
    return b64decode(s).decode(encoding)


def to_bytes(s, encoding='utf-8'):
    if IS_PY2:
        if isinstance(s, unicode):
            return s.encode(encoding)
        return s
    return bytes(s, encoding)
