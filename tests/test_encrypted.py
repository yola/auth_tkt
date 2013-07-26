import unittest

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
    cleartext = 'this is a secret message'
    ciphertext = ('tJzLGOp95tK4YMCy+PTmq3vJ/qT+MCFjKJC7GpmLJivlmL1WNeaUTUSp9nV'
                  'FTtyZ419htUd7dZeAM0oHs9Nul6DcR4FxU6U38dYUjMyFtsWsmoMAYQY4PK'
                  'Zivdw+icFIGIyXzUC8HOVfbnh+cIbJEGj+7kvPOvXxKcThxX64usrYbQ==')
    secret = 'cryptosecret'

    def flip_ciphertext_bit(self, byte, bit=0):
        ciphertext = self.ciphertext.decode('base64')
        ciphertext = (ciphertext[:-byte]
                      + chr(ord(ciphertext[byte]) ^ (2 ** bit))
                      + ciphertext[byte + 1:])
        return ''.join(ciphertext.encode('base64').split())

    def test_derive_keys_salted(self):
        salt = self.ciphertext.decode('base64')[16:48]
        hmackey, enckey, salt = _derive_keys(self.ciphertext, salt)
        expected_hmackey = 'xbNKad7dTFt7wNYCxkFLVwXtMuiF9eCKCXt3oabIPj0='
        expected_enckey = '7IJke6/xvQSdz/L1tFrvkBjHGWVD5hn5WneFaXTytT8='
        self.assertEqual(hmackey, expected_hmackey.decode('base64'))
        self.assertEqual(enckey, expected_enckey.decode('base64'))

    def test_encrypt_userdata(self):
        ciphertext = _encrypt_userdata(self.cleartext, self.secret)
        ciphertext = ciphertext.decode('base64')
        # Hand-wavey are-we-encrypted tests
        self.assertTrue(self.cleartext not in ciphertext)
        self.assertTrue(len(ciphertext) >= len(self.cleartext) + 16 + 32)

    def test_decrypt_userdata(self):
        self.assertEqual(_decrypt_userdata(self.ciphertext, self.secret),
                         self.cleartext)

    def test_invalid_contents(self):
        ciphertext = self.flip_ciphertext_bit(byte=128)
        self.assertRaises(DecryptionError, _decrypt_userdata, ciphertext,
                          self.secret)

    def test_derive_keys(self):
        hmackey, enckey, salt = _derive_keys(self.secret)
        self.assertNotEqual(hmackey, enckey)
        self.assertTrue(salt)


class CipherHelperTests(unittest.TestCase):
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
