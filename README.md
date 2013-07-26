# mod_auth_tkt cookie implementation

[![Build Status](https://travis-ci.org/yola/auth_tkt.png)](https://travis-ci.org/yola/auth_tkt)

## Modules

`auth_tkt.ticket` is a Python re-implementation of the [mod_auth_tkt][]
cookie. Cookies can be created with `AuthTkt` and verified with
`verify`.

[mod_auth_tkt]: http://www.openfusion.com.au/labs/mod_auth_tkt/

`auth_tkt.encrypted`'s `EncryptedAuthTkt` is a wrapper around `AuthTkt`
that stores an encrypted JSON payload in the mod_auth_tkt cookie's
user-data section.

## Helpers

There is a `get_ticket_data` function in `auth_tkt.helepers`, that
decrypts and verifies a cookie.

## Testing

Install development requirements:

    pip install -r requirements.txt

Tests can then be run by doing:

    nosetests
