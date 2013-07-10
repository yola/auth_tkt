from gzip import zlib
import cStringIO
import hashlib
import hmac
import json
import os

from M2Crypto import EVP
from yoconfig.util import get_config

from authtkt.ticket import AuthTkt


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
    def from_data(secret, uid, data=None, ip='0.0.0.0', tokens=(),
                  base64=True, ts=None):
        if data is None:
            data = {}
        data = _encrypt_userdata(data)
        authticket = AuthTkt(secret, uid, data, ip, tokens, base64, ts)
        return EncryptedAuthTkt(authticket)

    def __init__(self, authticket):
        self.authticket = authticket

    @property
    def uid(self):
        return self.authticket.uid

    @property
    def data(self):
        return _decrypt_userdata(self.authticket.data)

    def ticket(self):
        return self.authticket.ticket()

    def cookie(self, name, domain=None, path='/', secure=False):
        return self.authticket.cookie(name, domain, path, secure)

    def cookie_value(self):
        return self.authticket.cookie_value()


def _encrypt_userdata(cleartext):
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
        iv + salt + ciphertext).encode('base64').strip().replace('\n', '')


def _decrypt_userdata(ciphertext):
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
    while True:
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
