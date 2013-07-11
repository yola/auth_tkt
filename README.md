# mod_auth_tkt cookie implementation

This module has two required settings:

* `CRYPTO_SECRET`
* `SECRET`

The settings can be specified globally using yocommon's configure method
like so:

```python
from yocommon.util import configure
configure(SECRET='secret', CRYPTO_SECRET='crypto_secret')
```

In Django projects, `SECRET` and `CRYPTO_SECRET` can be defined in the
project's settings module. There is no need to call `configure`.

In most cases, these values should be set to DeployConfig's
`common.authtkt.secret_key` and `common.authtkt.crypto_key`.

## Testing

Install development requirements:

    pip install -r requirements.txt

Tests can then be run by doing:

    nosetests
