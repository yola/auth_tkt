# mod_auth_tkt cookie implementation

[![Build Status](https://travis-ci.org/yola/authtkt.png)](https://travis-ci.org/yola/authtkt)

## Modules

`authtkt.ticket` is a Python re-implementation of the [mod_auth_tkt][]
cookie. Cookies can be created with `AuthTkt` and verified with
`verify`.

[mod_auth_tkt]: http://www.openfusion.com.au/labs/mod_auth_tkt/

`authtkt.encrypted`'s `EncryptedAuthTkt` is a wrapper around `AuthTkt`
that stores an encrypted JSON payload in the mod_auth_tkt cookie's
user-data section.

## Helpers

There is a `get_ticket_data` function in `authtkt.helepers`, that
decrypts and verifies a cookie.

## Testing

Install development requirements:

    pip install -r requirements.txt

Tests can then be run by doing:

    nosetests
