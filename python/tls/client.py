
import base64
import os
from shutil import ExecError
from typing import Dict, List

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from pydantic import ValidationError
from schema import ClientHello, ExtensionClient, KeyShare, ServerHello
from settings import SERVER_PORT
from shared import get_key_pair, get_random


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
    resp = requests.get(f"{server_url}/certificate")
    
    if not resp.ok:
        raise Exception(f"Failed get certificate form server {resp.status_code} {
            resp.reason}. Response content: {resp.text}")
    
    try:
        # Get the server certificate from the response
        server_cert_raw = resp.json().get("certificate")
        if not server_cert_raw:
            raise ValueError("No certificate found in the server response.")

        # Load the server certificate
        server_cert = x509.load_pem_x509_certificate(server_cert_raw.encode("utf-8"))

        # Load the CA certificate
        with open("./certificate.pem", "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        # Get the public key from the CA certificate (must be Ed25519)
        ca_public_key = ca_cert.public_key()
        if not isinstance(ca_public_key, Ed25519PublicKey):
            raise TypeError("The CA public key is not an Ed25519 key.")

        # Verify the server certificate signature
        ca_public_key.verify(
            server_cert.signature,  # The signature from the server certificate
            server_cert.tbs_certificate_bytes,  # The signed data
        )
        print("Server certificate verified successfully.")
    except Exception as e:
        raise Exception(f"Error verifying server certificate: {e}")
        
        
        

if __name__ == "__main__":
    server_url = f"http://127.0.0.1:{SERVER_PORT}"
    server_hello = client_hello(server_url)
    server_cert = check_server_cert(server_url)