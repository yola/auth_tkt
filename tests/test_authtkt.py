import unittest

from yoconfig.util import configure

import authtkt


class AuthTktTests(unittest.TestCase):
    def setUp(self):
        self.secret = 'hmac secret'
        self.crypto_secret = 'top secret'
        self.cookie = (
            'MjQ4MWQ3ODEzNGI2MjE3N2I4OGQ4MDRjNTZkY2YxZGU1MWRkNjY3NjEyMzQ1Njc4O'
            'TAhdGVzdCFnTGpIMGluemJTZTZHYzNaU2J6S1ljWTZkUlZ5VXloR0pWMWxpWXBYY3'
            'RmTjAxQlRWZFRlOS96M0g0dmEyOUFEWFlDLytFNFpDTmQ5S09OSlBJZnFoWUNnNlF'
            'DYWFDODM3NXdjS1RTbERVUlVUZlV6TUxWZHRZSVpic0JxeGxuRDgyWHBjeE9ORjZB'
            'Y3pvQjlkNkU0N0xScGVVNjNmUTFpdFhOcFkwRExyUG8xdnlGWUtxZHNRTHBYUHc9P'
            'Q==')
        configure(SECRET=self.secret)
        configure(CRYPTO_SECRET=self.crypto_secret)

    def test_get_ticket_data_returns_proper_data(self):
        data = authtkt.get_ticket_data(self.cookie)
        self.assertTrue(all(
            [key in data for key in (
                'surname', 'name', 'id', 'tokens')]
        ))

    def test_valid_ticket_validates_correctly(self):
        self.assertTrue(authtkt.validate(self.cookie, self.secret))

    def test_invalid_ticket_does_not_validate(self):
        self.assertFalse(authtkt.validate('I am a banana', self.secret))
