from yoconfig.util import get_config

from authtkt.encrypted import EncryptedAuthTkt
from authtkt.ticket import validate


def get_ticket_data(ticket, decrypt=True):
    """We store user information in our session hashes. You can retreive that
    data with this function."""
    ticket = validate(ticket, get_config('SECRET'))

    if not ticket:
        return None

    data = {
        'id': ticket.uid,
        'tokens': ticket.tokens,
    }

    if decrypt:
        ticket = EncryptedAuthTkt(ticket, get_config('CRYPTO_SECRET'))
        data.update(ticket.data)

    return data
