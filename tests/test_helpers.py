import unittest

from auth_tkt.helpers import get_ticket_data


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.authtkt_secret = 'hmac secret'
        self.crypted_cookie_secret = 'top secret'
        self.cookie = (
            'MjQ4MWQ3ODEzNGI2MjE3N2I4OGQ4MDRjNTZkY2YxZGU1MWRkNjY3NjEyMzQ1Njc4O'
            'TAhdGVzdCFnTGpIMGluemJTZTZHYzNaU2J6S1ljWTZkUlZ5VXloR0pWMWxpWXBYY3'
            'RmTjAxQlRWZFRlOS96M0g0dmEyOUFEWFlDLytFNFpDTmQ5S09OSlBJZnFoWUNnNlF'
            'DYWFDODM3NXdjS1RTbERVUlVUZlV6TUxWZHRZSVpic0JxeGxuRDgyWHBjeE9ORjZB'
            'Y3pvQjlkNkU0N0xScGVVNjNmUTFpdFhOcFkwRExyUG8xdnlGWUtxZHNRTHBYUHc9P'
            'Q==')

    def test_get_ticket_with_data(self):
        data = get_ticket_data(self.cookie, self.authtkt_secret,
                               self.crypted_cookie_secret)
        self.assertEqual(sorted(data), ['id', 'name', 'surname', 'tokens'])

    def test_get_ticket_no_decrypt(self):
        data = get_ticket_data(self.cookie, self.authtkt_secret)
        self.assertEqual(sorted(data), ['id', 'tokens'])

    def test_get_ticket_unicode(self):
        data = get_ticket_data(unicode(self.cookie),
                               unicode(self.authtkt_secret),
                               unicode(self.crypted_cookie_secret))
        self.assertEqual(sorted(data), ['id', 'name', 'surname', 'tokens'])
