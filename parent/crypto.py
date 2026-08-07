from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import json
import os


def encrypt_request(enclave_public_key, obj):

    enclave_pub = X25519PublicKey.from_public_bytes(
        bytes.fromhex(enclave_public_key)
    )

    client_private = X25519PrivateKey.generate()

    client_public = client_private.public_key()

    shared_secret = client_private.exchange(enclave_pub)

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pryvx",
    ).derive(shared_secret)

    aes = AESGCM(aes_key)

    nonce = os.urandom(12)

    ciphertext = aes.encrypt(
        nonce,
        json.dumps(obj).encode(),
        None,
    )

    return {

        "client_public_key":
            client_public.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,).hex(),

        "nonce":
            nonce.hex(),

        "ciphertext":
            ciphertext.hex(),
    }
