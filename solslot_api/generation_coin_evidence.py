"""Strict confirmed coin records for conserved generation asset inputs."""
from chia.types.blockchain_format.coin import Coin
from .vault_chain_evidence import ConfirmedVaultCoin


def read_confirmed_coin(raw,expected,*,allow_zero=False):
    try:
        if not isinstance(raw,dict) or not isinstance(raw.get('coin'),dict):
            raise ValueError('confirmed coin record is unavailable')
        amount,confirmed,spent=raw['coin'].get('amount'),raw.get('confirmed_block_index'),raw.get('spent_block_index')
        if (type(amount) is not int or not (0 if allow_zero else 1)<=amount<2**64 or type(confirmed) is not int or confirmed<=0
                or type(spent) is not int or spent<0 or (spent and spent<confirmed)
                or ('spent' in raw and (type(raw['spent']) is not bool or raw['spent']!=bool(spent)))):
            raise ValueError('coin has inconsistent amount, confirmation or spend fields')
        coin=Coin.from_json_dict(raw['coin'])
        if coin.name()!=expected:raise ValueError('coin fields differ from the requested coin')
        return ConfirmedVaultCoin(coin,confirmed,spent)
    except (KeyError,TypeError,AttributeError,ValueError) as exc:
        raise ValueError('confirmed coin evidence is missing or inconsistent') from exc
