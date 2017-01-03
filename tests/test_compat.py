from auth_tkt import compat
from unittest import TestCase


class Base64DecodeTestCase(TestCase):

    def test_returns_decoded_string(self):
        self.assertEqual(
            compat.base64decode('ZGVjb2RlZA=='), 'decoded')


class Base64EncodeTestCase(TestCase):

    def test_encodes_passed_string(self):
        self.assertEqual(
            compat.base64encode('decoded'), 'ZGVjb2RlZA==')


class ToBytesTestCase(TestCase):

    def test_returns_encoded_byte_string(self):
        returns = compat.to_bytes('test')
        self.assertIsInstance(returns, bytes)
        self.assertEqual(returns, b'test')

    def test_encodes_unicode_strings(self):
        self.assertEqual(compat.to_bytes(u'\u2603'), b'\xe2\x98\x83')
