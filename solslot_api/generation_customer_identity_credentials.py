"""Protected request-local Base relayer material; never an environment value."""
import os
import re
import stat

from eth_account import Account


def current_relayer_account(path, expected_address):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid())
                or stat.S_IMODE(info.st_mode) & 0o027 or info.st_nlink != 1
                or info.st_size not in (64, 65, 66, 67)):
            raise ValueError('CURRENT_ID_RELAYER_FILE_REJECTED')
        raw = os.read(fd, 68).strip()
        if re.fullmatch(rb'(?:0x)?[0-9a-fA-F]{64}', raw) is None:
            raise ValueError('CURRENT_ID_RELAYER_FILE_REJECTED')
        try:
            account = Account.from_key(raw.decode())
        except Exception:
            raise ValueError('CURRENT_ID_RELAYER_FILE_REJECTED') from None
        if account.address.lower() != expected_address.lower():
            raise ValueError('CURRENT_ID_RELAYER_PUBLIC_BINDING_CHANGED')
        return account
    finally:
        os.close(fd)
