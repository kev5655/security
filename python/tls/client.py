
import base64
import datetime
import os
import traceback
from types import TracebackType
from typing import Dict, List, Tuple

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.x509 import Certificate, DNSName
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError
from pydantic import ValidationError
from schema import ClientHello, ExtensionClient, KeyShare, ServerHello
from settings import SERVER_PORT
from shared import CA_CERT_PEM, get_key_pair, get_random


def client_hello(server_url: str) -> ServerHello:
    keys = get_key_pair()
    random = get_random()
    cipher_suites = get_cipher_suites()
    data = create_client_hello(keys.public_key, random, cipher_suites)

    resp = requests.post(f"{server_url}/ClientHello", json=data.model_dump())
    print("Response:", resp.status_code, resp.json())

    if not resp.ok:
        raise Exception(f"Failed client hello request: {resp.status_code} {
                        resp.reason}. Response content: {resp.text}")

    try:
        server_hello = ServerHello(**resp.json())
        return server_hello
    except ValidationError as e:
        raise Exception(f"Validation failed: {resp.status_code} {
            resp.reason}. Response content: {resp.text}")


def get_cipher_suites() -> List[str]:
    return ["TLS_AES_256_GCM_SHA256", "TLS_AES_256_CCM_SHA256"]


def create_client_hello(public_key: X25519PublicKey, random: bytes, cipher_suites: List[str]) -> ClientHello:
    public_key_byes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

    session_id = base64.b64encode(os.urandom(8)).decode("utf-8")

    return ClientHello(
        client_random=random.hex(),
        session_id=session_id,
        cipher_suites=cipher_suites,
        extension=ExtensionClient(
            supported_groups=["x25519"],
            key_share=KeyShare(
                group="x25519",
                public_key=public_key_byes.hex()
            ),
            signature_algorithms=[
                "rsa_pss_rsae_sha256", "ecdsa_secp256r1_sha256"],
            supported_version=["TLS 1.3", "TLS 1.2"]
        )
    )

def check_server_cert(server_url: str):
    # Fetch the server
    server_cert = get_server_cert(server_url)
    # inspect_certificate(server_cert)

    # Load the CA certificate
    ca_cert = get_ca_server_cert()
    
    store = Store([ca_cert])
    builder = PolicyBuilder().store(store)
    
    builder = builder.time(datetime.datetime.now())
    verifier = builder.build_server_verifier(DNSName("my-tls-server.com"))
    # verifier = PolicyBuilder().store(store)
    # chain = verifier.verify(server_cert, [])
    try:
        chain = verifier.verify(server_cert, [])
        print("Certificate is valid!")
        print(f"Validated chain: {chain}")
    except VerificationError as e:
        # Print full stack trace
        # print("Verification failed! Full stack trace:")
        # print(traceback.format_exc())

        # Print the full server certificate details
        # print("\n=== Server Certificate Details ===")
        # print(server_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"))

        # Print the CA certificate details
        # print("\n=== CA Certificate Details ===")
        # print(ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"))

        raise Exception(f"Error verifying a valid chain cannot be constructed: {e}")
    except Exception as e:
        raise Exception(f"Error verifying: {e}")
    
    
def inspect_certificate(cert: x509.Certificate):
    print("Extensions in certificate:")
    for ext in cert.extensions:
        print(f"- {ext.oid}: Critical={ext.critical}, Value={ext.value}")
    
def get_server_cert(server_url) -> Certificate:
    resp = requests.get(f"{server_url}/certificate")
    
    if not resp.ok:
        raise Exception(f"Failed get certificate form server {resp.status_code} {
            resp.reason}. Response content: {resp.text}")
    
     # Get the server certificate from the response
    server_cert_raw = resp.json().get("certificate")
    if not server_cert_raw:
        raise ValueError("No certificate found in the server response.")

    # Load the server certificate
    return x509.load_pem_x509_certificate(server_cert_raw.encode("utf-8"))
    
def get_ca_server_cert() -> Certificate:
    with open(CA_CERT_PEM, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


if __name__ == "__main__":
    server_url = f"http://127.0.0.1:{SERVER_PORT}"
    server_hello = client_hello(server_url)
    check_server_cert(server_url)    