from gzip import zlib
from time import time
import Cookie
import binascii
import cStringIO
import hashlib
import hmac
import json
import os
import socket
import struct

from M2Crypto import EVP
from yoconfig.util import get_config


def validate(ticket, secret, ip='0.0.0.0'):
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
    tokens, data = '', ''

    try:
        ts = int(ts, 16)
    except ValueError:
        return False

    if extra:
        if '!' in extra:
            tokens, data = extra.split('!', 1)
        else:
            data = extra

    at = AuthTkt(secret, uid, data, ip, tokens.split(','), base64, ts)
    if at.ticket() == ticket:
        return at

    return False


class AuthTkt(object):
    def __init__(self, secret, uid, data='', ip='0.0.0.0', tokens=(),
                 base64=True, ts=None):
        self.secret = secret
        self.uid = str(uid)
        self.data = data
        self.ip = ip
        self.tokens = ','.join(tok.strip() for tok in tokens)
        self.base64 = base64

        if ts is None:
            self.ts = int(time())
        else:
            self.ts = int(ts)

    def ticket(self):
        v = self.cookie_value()
        if self.base64:
            return v.encode('base64').strip().replace('\n', '')
        else:
            return v

    def cookie(self, name, domain=None, path='/', secure=False):
        c = Cookie.SimpleCookie()
        c[name] = self.ticket()
        c[name]['path'] = path

        if domain:
            c[name]['domain'] = domain

        if secure:
            c[name]['secure'] = 'true'

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


class DecryptionError(Exception):
    """
    Failed to decrypt. Can happen with wrong password, for example.
    """


class EncryptionError(Exception):
    """
    Failed to encrypt. Can happen with wrong password, for example.
    """


class EncryptedAuthTkt(object):

    @staticmethod
    def from_data(secret, uid,
            data={}, ip='0.0.0.0', tokens=[], base64=True, ts=None):
        data = EncryptedAuthTkt._encrypt(data)
        at = AuthTkt(secret, uid, data, ip, tokens, base64, ts)
        return EncryptedAuthTkt(at)

    def __init__(self, authticket):
        self.authticket = authticket

    @property
    def uid(self):
        return self.authticket.uid

    @property
    def data(self):
        return EncryptedAuthTkt._decrypt(self.authticket.data)

    def ticket(self):
        return self.authticket.ticket()

    def cookie(self, cookie_name,
            cookie_domain=None, cookie_path='/', cookie_secure=False):
        return self.authticket.cookie(cookie_name, cookie_domain, cookie_path,
            cookie_secure)

    def cookie_value(self):
        return self.authticket.cookie_value()

    @staticmethod
    def _encrypt(cleartext):
        cleartext = json.dumps(cleartext)
        secret = get_config('CRYPTO_SECRET')
        # the crypto algorithms are unicode unfriendly
        if isinstance(secret, unicode):
            secret = secret.encode('utf8')

        # get 256 bit random encryption salt
        salt = os.urandom(32)
        # derive 256 bit encryption key using the pbkdf2 standard
        key = EVP.pbkdf2(secret, salt, iter=1000, keylen=32)

        # Derive encryption key and HMAC key from it
        # See Practical Cryptography section 8.4.1.
        hmacKey = hashlib.sha256(key + 'MAC').digest()
        encKey = hashlib.sha256(key + 'encrypt').digest()
        del key

        # get 128 bit random iv
        iv = os.urandom(16)

        # Add HMAC to cleartext so that we can check during decrypt if we got
        # the right cleartext back. We are doing sign-then-encrypt, which let's
        # us encrypt empty cleartext (otherwise we'd need to pad with some
        # string to encrypt). Practical Cryptography by Schneier & Ferguson
        # also recommends doing it in this order in section 8.2.
        mac = hmac.new(
            hmacKey, cleartext + iv + salt, hashlib.sha256).hexdigest()
        del hmacKey

        try:
            ciphertext = _encipher(
                zlib.compress(cleartext + mac), encKey, iv, 'aes_128_ofb')
        except EVP.EVPError, e:
            raise EncryptionError(str(e))

        return (
            iv + salt + ciphertext).encode('base64').strip().replace("\n","")

    @staticmethod
    def _decrypt(ciphertext):
        ciphertext = ciphertext.decode('base64')
        iv, salt, ciphertext = (
            ciphertext[:16], ciphertext[16:48], ciphertext[48:])

        secret = get_config('CRYPTO_SECRET')
        if isinstance(secret, unicode):
            secret = secret.encode('utf8')

        # derive 256 bit key using the pbkdf2 standard
        key = EVP.pbkdf2(secret, salt, iter=1000, keylen=32)

        # Derive encryption key and HMAC key from it
        # See Practical Cryptography section 8.4.1.
        hmacKey = hashlib.sha256(key + 'MAC').digest()
        encKey = hashlib.sha256(key + 'encrypt').digest()
        del key

        # decrypt
        try:
            ret = zlib.decompress(
                _decipher(ciphertext, encKey, iv, 'aes_128_ofb'))
        except EVP.EVPError, e:
            raise DecryptionError(str(e))
        finally:
            del encKey

        # Check MAC
        mac = ret[-64:]
        ret = ret[:-64]
        try:
            if hmac.new(hmacKey, ret + iv + salt,
                    hashlib.sha256).hexdigest() != mac:
                raise DecryptionError('HMAC does not match')
        finally:
            del hmacKey

        return json.loads(ret)


def _cipherFilter(cipher, inf, outf):
    while 1:
        buf = inf.read()
        if not buf:
            break
        outf.write(cipher.update(buf))
    outf.write(cipher.final())
    return outf.getvalue()


def _decipher(ciphertext, key, iv, alg):
    cipher = EVP.Cipher(alg=alg, key=key, iv=iv, op=0)
    del key
    pbuf = cStringIO.StringIO()
    cbuf = cStringIO.StringIO(ciphertext)
    plaintext = _cipherFilter(cipher, cbuf, pbuf)
    pbuf.close()
    cbuf.close()
    return plaintext


def _encipher(plaintext, key, iv, alg):
    cipher = EVP.Cipher(alg=alg, key=key, iv=iv, op=1)
    del key
    pbuf = cStringIO.StringIO(plaintext)
    cbuf = cStringIO.StringIO()
    ciphertext = _cipherFilter(cipher, pbuf, cbuf)
    pbuf.close()
    cbuf.close()
    return ciphertext
