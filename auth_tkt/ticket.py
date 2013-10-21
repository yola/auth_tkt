# Copyright (c) 2009-2013, Yola, Inc.
# Copyright (c) 2005, Imaginary Landscape LLC and Contributors
# The AuthTkt class is derived from Ian Bicking's Python port (now shipped with mod_auth_tkt)

from time import time
import Cookie
import binascii
import hashlib
import socket
import struct


def validate(ticket, secret, ip='0.0.0.0', timeout=7200):
    """Validate a given authtkt ticket for the secret and ip provided"""
    if len(ticket) < 40:
        return False

    raw = ticket
    base64 = False

    if '!' not in ticket:
        try:
            raw = ticket.decode('base64')
            base64 = True
        except binascii.Error:
            return False

    if '!' not in raw:
        return False

    digest, raw = raw[:32], raw[32:]
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

    auth_ticket = AuthTkt(secret, uid, data, ip, tokens.split(','), base64, ts)
    if auth_ticket.ticket() == ticket:
        return auth_ticket

    return False


class AuthTkt(object):
    def __init__(self, secret, uid, data='', ip='0.0.0.0', tokens=(),
                 base64=True, ts=None):
        self.secret = str(secret)
        self.uid = str(uid)
        self.data = data
        self.ip = ip
        self.tokens = ','.join(tok.strip() for tok in tokens)
        self.base64 = base64
        self.ts = int(time() if ts is None else ts)

    def ticket(self):
        v = self.cookie_value()
        if self.base64:
            return v.encode('base64').strip().replace('\n', '')
        return v

    def cookie(self, name, **kwargs):
        name = str(name)
        c = Cookie.SimpleCookie()
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
        return hashlib.md5(self._digest0() + self.secret).hexdigest()

    def _digest0(self):
        parts = (self._encode_ip(self.ip), self._encode_ts(self.ts),
                 self.secret, self.uid, '\0', self.tokens, '\0', self.data)
        return hashlib.md5(''.join(parts)).hexdigest()

    def _encode_ip(self, ip):
        return socket.inet_aton(ip)

    def _encode_ts(self, ts):
        return struct.pack('!I', ts)
