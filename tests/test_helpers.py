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
        # Encoding of the encrypted data
        self.encoding = 'latin_1'

    def test_get_ticket_with_data(self):
        data = get_ticket_data(self.cookie, self.authtkt_secret,
                               self.crypted_cookie_secret, timeout=0,
                               encoding=self.encoding)
        self.assertEqual(sorted(data), ['id', 'name', 'surname', 'tokens'])

    def test_get_ticket_no_decrypt(self):
        data = get_ticket_data(
            self.cookie, self.authtkt_secret, timeout=0,
            encoding=self.encoding)
        self.assertEqual(sorted(data), ['id', 'tokens'])

    def test_get_ticket_unicode(self):
        data = get_ticket_data(
            u'%s' % self.cookie, u'%s' % self.authtkt_secret,
            u'%s' % self.crypted_cookie_secret, 0, encoding=self.encoding)
        self.assertEqual(sorted(data), ['id', 'name', 'surname', 'tokens'])
