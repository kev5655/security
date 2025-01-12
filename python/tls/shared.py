import os
from typing import List

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from requests import Response
from schema import KeyPair

CERT_FOLDER = "./certificate"
CA_KEY_PEM = f"{CERT_FOLDER}/ca_key.pem"
CA_CERT_PEM = f"{CERT_FOLDER}/ca_certificate.pem"

SERVER_CERTIFICATE_PEM = f"{CERT_FOLDER}/server_cert.pem"
SERVER_KEY_PEM = f"{CERT_FOLDER}/server_key.pem"

SERVER_PORT = 8000
SERVER_URL = f"http://127.0.0.1:{SERVER_PORT}"
CLIENT_PORT = 8001
CLIENT_URL = f"http://127.0.0.1:{CLIENT_PORT}"
CA_PORT = 8002
CA_URL = f"http://127.0.0.1:{CA_PORT}"


def get_key_pair() -> KeyPair:
    private_key = X25519PrivateKey.generate()
    return KeyPair(
        private_key=private_key,
        public_key=private_key.public_key())

def get_random() -> bytes:
    return os.urandom(32)

def merge_handshake(handshakes: List[str]) -> bytes:
    return b"".join(msg.encode('utf-8') for msg in handshakes)

    

def raise_request(server: str, url: str, resp_server_hello: Response) -> Exception:
    return Exception(f"{server} Failed {url} request: {resp_server_hello.status_code} {
                        resp_server_hello.reason}. Response content: {resp_server_hello.text}")


