import unittest

from yoconfig.util import configure

from authtkt.helpers import get_ticket_data


class IntegrationTests(unittest.TestCase):
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
        configure(AUTHTKT_SECRET=self.secret)
        configure(CRYPTED_COOKIE_SECRET=self.crypto_secret)

    def test_get_ticket_data_returns_proper_data(self):
        data = get_ticket_data(self.cookie)
        self.assertEqual(sorted(data), ['id', 'name', 'surname', 'tokens'])

    def test_get_ticket_no_decrypt(self):
        data = get_ticket_data(self.cookie, decrypt=False)
        self.assertEqual(sorted(data), ['id', 'tokens'])
