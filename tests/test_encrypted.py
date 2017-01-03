import json
import base64
import unittest

from cryptography.hazmat.primitives.ciphers import algorithms

from auth_tkt.ticket import AuthTkt
from auth_tkt.encrypted import (EncryptedAuthTkt, DecryptionError,
                                _derive_keys, _encrypt_userdata,
                                _decrypt_userdata, _encipher,
                                _decipher)


class EncryptedAuthTktTests(unittest.TestCase):
    def test_construction(self):
        tkt = AuthTkt('secret', '123')
        etkt = EncryptedAuthTkt(tkt, 'cryptosecret')
        self.assertEqual(etkt.auth_ticket, tkt)

    def test_from_data_empty(self):
        etkt = EncryptedAuthTkt.from_data('secret', 'cryptosecret', '123')
        self.assertTrue(isinstance(etkt.auth_ticket, AuthTkt))
        self.assertEqual(etkt.data, {})

    def test_from_data_dict(self):
        etkt = EncryptedAuthTkt.from_data('secret', 'cryptosecret', '123',
                                          {'foo': 'bar'})
        self.assertTrue(isinstance(etkt.auth_ticket, AuthTkt))
        self.assertEqual(etkt.data, {'foo': 'bar'})

    def test_tkt_attributes(self):
        tkt = AuthTkt('secret', '123')
        etkt = EncryptedAuthTkt(tkt, 'cryptosecret')
        self.assertEqual(tkt.uid, etkt.uid)
        self.assertEqual(tkt.cookie_value(), etkt.cookie_value())
        self.assertEqual(tkt.ticket(), etkt.ticket())
        self.assertEqual(tkt.cookie('cookie'), etkt.cookie('cookie'))


class DataEncryptionTests(unittest.TestCase):
    cleartext = b'this is a secret message'
    ciphertext = (
        b'tJzLGOp95tK4YMCy+PTmq3vJ/qT+MCFjKJC7GpmLJivlmL1WNeaUTUSp9nV'
        b'FTtyZ419htUd7dZeAM0oHs9Nul6DcR4FxU6U38dYUjMyFtsWsmoMAYQY4PK'
        b'Zivdw+icFIGIyXzUC8HOVfbnh+cIbJEGj+7kvPOvXxKcThxX64usrYbQ==')
    secret = b'cryptosecret'

    def flip_ciphertext_bit(self, byte, bit=0):
        ciphertext = bytearray(base64.b64decode(self.ciphertext))
        ciphertext[byte] = ciphertext[byte] ^ (2 ** bit)
        return base64.b64encode(ciphertext)

    def test_derive_keys_salted(self):
        salt = base64.b64decode(self.ciphertext)[16:48]
        hmackey, enckey, salt = _derive_keys(self.ciphertext, salt)
        expected_hmackey = 'xbNKad7dTFt7wNYCxkFLVwXtMuiF9eCKCXt3oabIPj0='
        expected_enckey = '7IJke6/xvQSdz/L1tFrvkBjHGWVD5hn5WneFaXTytT8='
        self.assertEqual(base64.b64encode(hmackey).decode(), expected_hmackey)
        self.assertEqual(base64.b64encode(enckey).decode(), expected_enckey)

    def test_encrypt_userdata(self):
        ciphertext = _encrypt_userdata(
            self.cleartext, self.secret)
        ciphertext = base64.b64decode(ciphertext)
        # Hand-wavey are-we-encrypted tests
        self.assertTrue(self.cleartext not in ciphertext)
        self.assertTrue(len(ciphertext) >= len(self.cleartext) + 16 + 32)

    def test_decrypt_userdata(self):
        self.assertEqual(
            json.loads(_decrypt_userdata(
                self.ciphertext, self.secret).decode()),
            self.cleartext.decode())

    def test_invalid_contents(self):
        ciphertext = self.flip_ciphertext_bit(byte=128)
        self.assertRaises(DecryptionError, _decrypt_userdata, ciphertext,
                          self.secret)

    def test_derive_keys(self):
        hmackey, enckey, salt = _derive_keys(self.secret)
        self.assertNotEqual(hmackey, enckey)
        self.assertTrue(salt)


class CipherHelperTests(unittest.TestCase):
    plaintext = b'hello there'
    ciphertext = b'Z\xed\xc5\xe8\xb2&\x8b0\x8cK\x05'
    key = b'1' * 16
    iv = b'2' * 16
    alg = algorithms.AES

    def test_encipher(self):
        ciphertext = _encipher(self.plaintext, self.key, self.iv, self.alg)
        self.assertEqual(ciphertext, self.ciphertext)

    def test_decipher(self):
        plaintext = _decipher(self.ciphertext, self.key, self.iv, self.alg)
        self.assertEqual(plaintext, self.plaintext)
