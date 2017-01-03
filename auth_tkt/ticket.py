# Copyright (c) 2009-2013, Yola, Inc.
# Copyright (c) 2005, Imaginary Landscape LLC and Contributors
# The AuthTkt class is derived from Ian Bicking's Python port (now shipped
# with mod_auth_tkt)

import binascii
import hashlib
import socket
import struct
from time import time

try:
    # Python 2
    import Cookie as http_cookies
except ImportError:
    # Python 3
    import http.cookies as http_cookies

from auth_tkt.compat import base64decode, base64encode, to_bytes


def validate(ticket, secret, ip='0.0.0.0', timeout=7200, encoding='utf-8'):
    """Validate a given authtkt ticket for the secret and ip provided"""
    if len(ticket) < 40:
        return False

    raw = ticket
    base64 = False

    if '!' not in ticket:
        try:
            raw = base64decode(ticket, encoding)
            base64 = True
        except binascii.Error:
            return False

    if '!' not in raw:
        return False

    raw = raw[32:]
    ts, raw = raw[:8], raw[8:]
    uid, extra = raw.split('!', 1)
    tokens = data = ''

    try:
        ts = int(ts, 16)
    except ValueError:
        return False

    if timeout and time() - ts > timeout:
        return False

    if extra:
        if '!' in extra:
            tokens, data = extra.split('!', 1)
        else:
            data = extra

    auth_ticket = AuthTkt(
        secret, uid, data, ip, tokens.split(','), base64, ts,
        encoding=encoding)
    if auth_ticket.ticket() == ticket:
        return auth_ticket

    return False


class AuthTkt(object):
    def __init__(self, secret, uid, data='', ip='0.0.0.0', tokens=(),
                 base64=True, ts=None, encoding='utf-8'):
        self.secret = str(secret)
        self.uid = str(uid)
        self.data = data
        self.encoding = encoding
        self.ip = ip
        self.tokens = ','.join(tok.strip() for tok in tokens)
        self.base64 = base64
        self.ts = int(time() if ts is None else ts)

    def ticket(self):
        v = self.cookie_value()
        if self.base64:
            return base64encode(v).strip().replace('\n', '')
        return v

    def cookie(self, name, **kwargs):
        name = str(name)
        c = http_cookies.SimpleCookie()
        c[name] = self.ticket()

        kwargs.setdefault('path', '/')
        c[name].update(kwargs)

        return c

    def cookie_value(self):
        parts = ['%s%08x%s' % (self._digest(), self.ts, self.uid)]
        if self.tokens:
            parts.append(self.tokens)
        parts.append(self.data)
        return '!'.join(parts)

    def _digest(self):
        parts = [self._digest0(), self.secret]
        parts = b''.join([to_bytes(part) for part in parts])
        return hashlib.md5(parts).hexdigest()

    def _digest0(self):
        parts = (
            self._encode_ip(self.ip), self._encode_ts(self.ts),
            to_bytes(self.secret), to_bytes(self.uid), b'\0',
            to_bytes(self.tokens), b'\0', to_bytes(self.data))
        return hashlib.md5(b''.join(parts)).hexdigest()

    def _encode_ip(self, ip):
        return socket.inet_aton(ip)

    def _encode_ts(self, ts):
        return struct.pack('!I', ts)
