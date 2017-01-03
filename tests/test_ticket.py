import base64
import unittest

from auth_tkt.compat import base64decode
from auth_tkt.ticket import AuthTkt, validate


class AuthTktTests(unittest.TestCase):
    def test_construction_minimal(self):
        tkt = AuthTkt('secret', '123')
        self.assertEqual(tkt.secret, 'secret')
        self.assertEqual(tkt.uid, '123')
        self.assertEqual(tkt.data, '')
        self.assertEqual(tkt.ip, '0.0.0.0')
        self.assertEqual(tkt.tokens, '')
        self.assertTrue(tkt.base64)
        self.assertTrue(tkt.ts > 0)

    def test_construction_optional(self):
        tkt = AuthTkt('secret', '123', 'userdata', '127.0.0.1',
                      ('foo ', 'bar'), False, 9001)
        self.assertEqual(tkt.secret, 'secret')
        self.assertEqual(tkt.uid, '123')
        self.assertEqual(tkt.data, 'userdata')
        self.assertEqual(tkt.ip, '127.0.0.1')
        self.assertEqual(tkt.tokens, 'foo,bar')
        self.assertFalse(tkt.base64)
        self.assertEqual(tkt.ts, 9001)

    def construct(self, secret='secret', uid='123', **kwargs):
        if kwargs.get('tokens') is True:
            kwargs['tokens'] = ('foo', 'bar')
        kwargs.setdefault('data', 'userdata')
        kwargs.setdefault('ts', 9001)
        return AuthTkt(secret, uid, **kwargs)

    def test_cookie_value(self):
        tkt = self.construct()
        body = tkt.cookie_value()
        digest = '7f31d235ecc1a1c566ebd51469ed8a59'
        ip = '0000'  # 0.0.0.0
        ts = '2329'  # 9001
        id_ = '123'
        userdata = 'userdata'
        self.assertEqual(body, digest + ip + ts + id_ + '!' + userdata)

    def test_cookie_value_with_tokens(self):
        tkt = self.construct(tokens=True)
        body = tkt.cookie_value()
        digest = '575cd7937781c0636da95f0f4f423aef'
        ip = '0000'  # 0.0.0.0
        ts = '2329'  # 9001
        id_ = '123'
        tokens = 'foo,bar'
        userdata = 'userdata'
        self.assertEqual(body, digest + ip + ts + id_ + '!' + tokens + '!'
                         + userdata)

    def test_cookie(self):
        tkt = self.construct(base64=False)
        c = tkt.cookie('test_cookie', domain='example.com')['test_cookie']
        self.assertEqual(c.key, 'test_cookie')
        self.assertEqual(c['path'], '/')
        self.assertEqual(c['domain'], 'example.com')
        for key in ('expires', 'comment', 'max-age', 'secure', 'version',
                    'httponly'):
            self.assertFalse(c[key])
        self.assertEqual(c.value, tkt.cookie_value())

    def test_cookie_unicode(self):
        tkt = self.construct()
        cookies = tkt.cookie(u'test_cookie', domain=u'example.com')
        self.assertTrue('test_cookie' in cookies)

    def test_ticket(self):
        tkt = self.construct(base64=False)
        self.assertEqual(tkt.ticket(), tkt.cookie_value())

    def test_ticket_b64(self):
        tkt = self.construct()
        self.assertEqual(base64decode(tkt.ticket()), tkt.cookie_value())

    def test_construct_unicode(self):
        tkt = self.construct(u'secret', u'123', data=u'userdata',
                             ip=u'0.0.0.0', tokens=(u'foo', u'bar'),
                             base64=False)
        self.assertEqual(tkt.ticket(), tkt.cookie_value())


class AuthTktInternalTests(unittest.TestCase):
    def setUp(self):
        self.tkt = AuthTkt('secret', '123', 'userdata', '123.45.67.89',
                           ('foo', 'bar'), ts=9001)

    def test_digest0(self):
        self.assertEqual(self.tkt._digest0(),
                         '7c7ab37013af6e77759ec5e2f6129928')

    def test_encode_ip(self):
        self.assertEqual(self.tkt._encode_ip(self.tkt.ip), b'{-CY')

    def test_encode_ts(self):
        self.assertEqual(self.tkt._encode_ts(self.tkt.ts), b'\x00\x00#)')


class ValidateTests(unittest.TestCase):
    secret = 'secret'

    def test_garbage(self):
        self.assertFalse(validate('blergh', self.secret))

    def build_ticket(self, digest=b'575cd7937781c0636da95f0f4f423aef',
                     ip=b'0000', ts=b'2329', id_=b'123', tokens=b'foo,bar',
                     data=b'userdata', base64encode=False):
        if tokens:
            ticket = digest + ip + ts + id_ + b'!' + tokens + b'!' + data
        else:
            ticket = digest + ip + ts + id_ + b'!' + data
        if base64encode:
            ticket = b''.join(base64.b64encode(ticket).split())
        return ticket.decode('latin_1')

    def test_valid(self):
        body = self.build_ticket()
        tkt = validate(body, self.secret, timeout=0)
        self.assertTrue(tkt)
        self.assertTrue(isinstance(tkt, AuthTkt))

    def test_valid_b64(self):
        body = self.build_ticket(base64encode=True)
        self.assertTrue(validate(body, self.secret, timeout=0))

    def test_wrong_digest(self):
        body = self.build_ticket(digest=b'1234567890abcdef' * 2)
        self.assertFalse(validate(body, self.secret, timeout=0))

    def test_wrong_digest_b64(self):
        body = self.build_ticket(
            digest=b'1234567890abcdef' * 2, base64encode=True)
        self.assertFalse(validate(body, self.secret, timeout=0))

    def test_invalid_digest(self):
        body = self.build_ticket(digest=b'\x00\xff' * 16)
        self.assertFalse(validate(body, self.secret, timeout=0))

    def test_invalid_digest_b64(self):
        body = self.build_ticket(digest=b'\x00\xff' * 16, base64encode=True)
        self.assertFalse(validate(
            body, self.secret, timeout=0, encoding='latin_1'))

    def test_wrong_ip(self):
        body = self.build_ticket(ip=b'1234')
        self.assertFalse(validate(body, self.secret, timeout=0))

    def test_wrong_ip_b64(self):
        body = self.build_ticket(ip=b'1234', base64encode=True)
        self.assertFalse(validate(body, self.secret, timeout=0))

    def test_wrong_ts(self):
        body = self.build_ticket(ts=b'0000')
        self.assertFalse(validate(body, self.secret, timeout=0))

    def test_wrong_ts_b64(self):
        body = self.build_ticket(ts=b'0000', base64encode=True)
        self.assertFalse(validate(body, self.secret, timeout=0))

    def test_timed_out(self):
        body = self.build_ticket()
        self.assertFalse(validate(body, self.secret))

    def test_wrong_id(self):
        body = self.build_ticket(id_=b'124')
        self.assertFalse(validate(body, self.secret, timeout=0))

    def test_wrong_id_b64(self):
        body = self.build_ticket(id_=b'124', base64encode=True)
        self.assertFalse(validate(body, self.secret, timeout=0))

    def test_no_tokens(self):
        body = self.build_ticket(tokens=None)
        self.assertFalse(validate(body, self.secret, timeout=0))

    def test_no_tokens_b64(self):
        body = self.build_ticket(tokens=None, base64encode=True)
        self.assertFalse(validate(body, self.secret, timeout=0))

    def test_wrong_tokens(self):
        body = self.build_ticket(tokens=b'foo,baz')
        self.assertFalse(validate(body, self.secret, timeout=0))

    def test_wrong_tokens_b64(self):
        body = self.build_ticket(tokens=b'foo,baz', base64encode=True)
        self.assertFalse(validate(body, self.secret, timeout=0))

    def test_wrong_userdata(self):
        body = self.build_ticket(data=b'!' * 32)
        self.assertFalse(validate(body, self.secret, timeout=0))

    def test_wrong_userdata_b64(self):
        body = self.build_ticket(data=b'!' * 32, base64encode=True)
        self.assertFalse(validate(body, self.secret, timeout=0))
