# mod_auth_tkt cookie implementation

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
decrypts and verifies a cookie, getting the encryption keys from
`yoconfig`.

This module has two required settings:

* `AUTHTKT_SECRET` - The secret that AuthTKT uses to verify cookies
* `CRYPTED_COOKIE_SECRET` - The secret used to encrypt cookie payloads

The settings can be specified globally using yoconfig's configure method
like so:

```python
from yoconfig.util import configure
configure(AUTHTKT_SECRET='secret', CRYPTED_COOKIE_SECRET='crypto_secret')
```

In Django projects, `AUTHTKT_SECRET` and `CRYPTED_COOKIE_SECRET` can be
defined in the project's settings module. There is no need to call
`configure`.

In most cases, these values should be set to DeployConfig's
`common.authtkt.secret_key` and `common.authtkt.crypto_key`.

## Testing

Install development requirements:

    pip install -r requirements.txt

Tests can then be run by doing:

    nosetests
