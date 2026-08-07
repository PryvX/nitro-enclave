from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import os


class CryptoManager:

    def __init__(self):

        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def get_public_key(self):

        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

    def decrypt(self, request):

        client_pub = X25519PublicKey.from_public_bytes(
            bytes.fromhex(request["client_public_key"])
        )

        shared_secret = self.private_key.exchange(client_pub)

        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"pryvx",
        ).derive(shared_secret)

        aes = AESGCM(aes_key)

        plaintext = aes.decrypt(
            bytes.fromhex(request["nonce"]),
            bytes.fromhex(request["ciphertext"]),
            None,
        )

        return plaintext.decode()
        

crypto = CryptoManager()
