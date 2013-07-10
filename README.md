# mod_auth_tkt cookie implementation

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
