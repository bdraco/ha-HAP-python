"""This module partially implements crypt for HAP."""
import logging

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pyhap.const import __version__

SNAPSHOT_TIMEOUT = 10

logger = logging.getLogger(__name__)

CRYPTO_BACKEND = default_backend()


class HAP_CRYPTO:
    HKDF_KEYLEN = 32  # bytes, length of expanded HKDF keys
    HKDF_HASH = hashes.SHA512()  # Hash function to use in key expansion
    TAG_LENGTH = 16  # ChaCha20Poly1305 tag length
    TLS_NONCE_LEN = 12  # bytes, length of TLS encryption nonce


def pad_tls_nonce(nonce, total_len=HAP_CRYPTO.TLS_NONCE_LEN):
    """Pads a nonce with zeroes so that total_len is reached."""
    return nonce.rjust(total_len, b"\x00")


def hap_hkdf(key, salt, info):
    """Just a shorthand."""
    hkdf = HKDF(
        algorithm=HAP_CRYPTO.HKDF_HASH,
        length=HAP_CRYPTO.HKDF_KEYLEN,
        salt=salt,
        info=info,
        backend=CRYPTO_BACKEND,
    )
    return hkdf.derive(key)
