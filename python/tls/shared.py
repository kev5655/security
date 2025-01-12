import os

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from schema import KeyPair

CERT_FOLDER = "./certificate"
CA_KEY_PEM = f"{CERT_FOLDER}/ca_key.pem"
CA_CERT_PEM = f"{CERT_FOLDER}/ca_certificate.pem"

SERVER_CERTIFICATE_PEM = f"{CERT_FOLDER}/server_cert.pem"
SERVER_KEY_PEM = f"{CERT_FOLDER}/server_key.pem"

def get_key_pair() -> KeyPair:
    private_key = X25519PrivateKey.generate()
    return KeyPair(
        private_key=private_key,
        public_key=private_key.public_key())


def get_random() -> bytes:
    return os.urandom(32)
