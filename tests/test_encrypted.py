import unittest
import zlib

from yoconfig.util import configure

from authtkt.ticket import AuthTkt
from authtkt.encrypted import (EncryptedAuthTkt, _encrypt_userdata,
                               _decrypt_userdata, _encipher, _decipher)


def setUpModule():
    configure(CRYPTO_SECRET='cryptosecret')


class EncryptedAuthTktTests(unittest.TestCase):
    def test_construction(self):
        tkt = AuthTkt('secret', '123')
        etkt = EncryptedAuthTkt(tkt)
        self.assertEqual(etkt.authticket, tkt)

    def test_from_data_empty(self):
        etkt = EncryptedAuthTkt.from_data('secret', '123')
        self.assertTrue(isinstance(etkt.authticket, AuthTkt))
        self.assertEqual(etkt.data, {})

    def test_from_data_dict(self):
        etkt = EncryptedAuthTkt.from_data('secret', '123', {'foo': 'bar'})
        self.assertTrue(isinstance(etkt.authticket, AuthTkt))
        self.assertEqual(etkt.data, {'foo': 'bar'})

    def test_tkt_attributes(self):
        tkt = AuthTkt('secret', '123')
        etkt = EncryptedAuthTkt(tkt)
        self.assertEqual(tkt.uid, etkt.uid)
        self.assertEqual(tkt.cookie_value(), etkt.cookie_value())
        self.assertEqual(tkt.ticket(), etkt.ticket())
        self.assertEqual(tkt.cookie('cookie'), etkt.cookie('cookie'))


class DataEncryptionTests(unittest.TestCase):
    cleartext = 'this is a secret message'
    ciphertext = ('tJzLGOp95tK4YMCy+PTmq3vJ/qT+MCFjKJC7GpmLJivlmL1WNeaUTUSp9nV'
                  'FTtyZ419htUd7dZeAM0oHs9Nul6DcR4FxU6U38dYUjMyFtsWsmoMAYQY4PK'
                  'Zivdw+icFIGIyXzUC8HOVfbnh+cIbJEGj+7kvPOvXxKcThxX64usrYbQ==')
    secret = 'secret'

    def flip_ciphertext_bit(self, byte, bit=0):
        ciphertext = self.ciphertext.decode('base64')
        ciphertext = (ciphertext[:-byte]
                      + chr(ord(ciphertext[byte]) ^ (2 ** bit))
                      + ciphertext[byte + 1:])
        return ''.join(ciphertext.encode('base64').split())

    def test_encrypt_userdata(self):
        ciphertext = _encrypt_userdata(self.cleartext).decode('base64')
        # Hand-wavey are-we-encrypted tests
        self.assertTrue(self.cleartext not in ciphertext)
        self.assertTrue(len(ciphertext) >= len(self.cleartext) + 16 + 32)

    def test_decrypt_userdata(self):
        self.assertEqual(_decrypt_userdata(self.ciphertext), self.cleartext)

    def test_invalid_contents(self):
        ciphertext = self.flip_ciphertext_bit(byte=128)
        # Probably should be DecryptionError...
        self.assertRaises(zlib.error, _decrypt_userdata, ciphertext)


class HelperFunctionTests(unittest.TestCase):
    plaintext = 'hello there'
    ciphertext = 'Z\xed\xc5\xe8\xb2&\x8b0\x8cK\x05'
    key = '1' * 16
    iv = '2' * 16
    alg = 'aes_128_ofb'

    def test_encipher(self):
        ciphertext = _encipher(self.plaintext, self.key, self.iv, self.alg)
        self.assertEqual(ciphertext, self.ciphertext)

    def test_decipher(self):
        plaintext = _decipher(self.ciphertext, self.key, self.iv, self.alg)
        self.assertEqual(plaintext, self.plaintext)
