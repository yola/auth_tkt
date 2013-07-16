from gzip import zlib
import hashlib
import hmac
import json

from M2Crypto import EVP, Rand

from authtkt.ticket import AuthTkt


class DecryptionError(Exception):
    """
    Failed to decrypt. Can happen with wrong password, for example.
    """


class EncryptedAuthTkt(object):

    @staticmethod
    def from_data(authtkt_secret, payload_secret, uid, data=None, ip='0.0.0.0',
                  tokens=(), base64=True, ts=None):
        payload_secret = str(payload_secret)
        data = _encrypt_userdata(data or {}, payload_secret)
        auth_ticket = AuthTkt(authtkt_secret, uid, data, ip, tokens, base64, ts)
        return EncryptedAuthTkt(auth_ticket, payload_secret)

    def __init__(self, auth_ticket, payload_secret):
        self.auth_ticket = auth_ticket
        self._payload_secret = payload_secret

    @property
    def uid(self):
        return self.auth_ticket.uid

    @property
    def data(self):
        return _decrypt_userdata(self.auth_ticket.data, self._payload_secret)

    def ticket(self):
        return self.auth_ticket.ticket()

    def cookie(self, name, **kwargs):
        return self.auth_ticket.cookie(name, **kwargs)

    def cookie_value(self):
        return self.auth_ticket.cookie_value()


def _derive_keys(secret, salt=None):
    if salt is None:
        salt = Rand.rand_bytes(32)

    # derive 256 bit encryption key using the pbkdf2 standard
    key = EVP.pbkdf2(secret, salt, iter=1000, keylen=32)

    # Derive encryption key and HMAC key from it
    # See Practical Cryptography section 8.4.1.
    hmacKey = hashlib.sha256(key + 'MAC').digest()
    encKey = hashlib.sha256(key + 'encrypt').digest()
    del key

    return hmacKey, encKey, salt


def _encrypt_userdata(cleartext, secret):
    cleartext = json.dumps(cleartext)

    hmacKey, encKey, salt = _derive_keys(secret)

    # get 128 bit random iv
    iv = Rand.rand_bytes(16)

    # Add HMAC to cleartext so that we can check during decrypt if we got
    # the right cleartext back. We are doing sign-then-encrypt, which lets
    # us encrypt empty cleartext (otherwise we'd need to pad with some
    # string to encrypt). Practical Cryptography by Schneier & Ferguson
    # also recommends doing it in this order in section 8.2.
    mac = hmac.new(
        hmacKey, cleartext + iv + salt, hashlib.sha256).hexdigest()
    del hmacKey

    ciphertext = _encipher(zlib.compress(cleartext + mac), encKey, iv,
                           'aes_128_ofb')

    return (
        iv + salt + ciphertext).encode('base64').strip().replace('\n', '')


def _decrypt_userdata(ciphertext, secret):
    ciphertext = ciphertext.decode('base64')
    iv, salt, ciphertext = (
        ciphertext[:16], ciphertext[16:48], ciphertext[48:])

    hmacKey, encKey, salt = _derive_keys(secret, salt)

    # decrypt
    try:
        ret = zlib.decompress(_decipher(ciphertext, encKey, iv, 'aes_128_ofb'))
    except (zlib.error, EVP.EVPError), e:
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


def _decipher(ciphertext, key, iv, alg):
    return _cipherFilter(alg, key, iv, 0, ciphertext)


def _encipher(plaintext, key, iv, alg):
    return _cipherFilter(alg, key, iv, 1, plaintext)


def _cipherFilter(alg, key, iv, op, input_):
    cipher = EVP.Cipher(alg=alg, key=key, iv=iv, op=op)
    del key
    return cipher.update(input_) + cipher.final()
