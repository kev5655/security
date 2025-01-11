import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from schema import KeyPair


def get_key_pair() -> KeyPair:
    private_key = X25519PrivateKey.generate()
    return KeyPair(
        private_key=private_key,
        public_key=private_key.public_key())


def get_random() -> bytes:
    return os.urandom(32)
