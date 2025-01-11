import requests
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from pydantic import ValidationError
from schema import (
    CertificateSigningRequest,
    ClientHello,
    ExtensionServer,
    KeyShare,
    ServerHello,
)
from settings import CA_PORT, SERVER_PORT
from shared import get_key_pair, get_random

app = FastAPI(title="Server")


@app.get("/")
def root():
    return {"name": "server"}


@app.post("/ClientHello")
def clientHello(resp: ClientHello):
    random = get_random()
    key_pair = get_key_pair()

    public_key_byes = key_pair.public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

    if "TLS 1.3" in resp.extension.supported_version:
        chosen_TLS_version = "TLS 1.3"
    else:
        chosen_TLS_version = "TLS 1.2"

    if "TLS_AES_256_GCM_SHA256" not in resp.cipher_suites:
        raise Exception("Missing cipher suite")

    return ServerHello(
        version=chosen_TLS_version,
        server_random=random.hex(),
        session_id=resp.session_id,
        cipher_suites=resp.cipher_suites,
        extension=ExtensionServer(
            key_share=KeyShare(
                group=resp.extension.key_share.group,
                public_key=public_key_byes.hex()
            )
        ),
    ).model_dump()


@app.get("/certificate")
def get_certificate():
    with open("./server_cert.pem", "rb") as cert_file:
        cert_data = cert_file.read()

    return {"certificate": cert_data.decode("utf-8")}


if __name__ == "__main__":

    private_key = Ed25519PrivateKey.generate()

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CH"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Bern"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Wichtrach"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "tls-server-org"),
        x509.NameAttribute(NameOID.COMMON_NAME, "tls-server.com"),
    ])).add_extension(
        x509.SubjectAlternativeName([
            # Describe what sites we want this certificate for.
            x509.DNSName("my-tls-server.com")
        ]),
        critical=False,
    ).sign(private_key, None)

    csrPayload = CertificateSigningRequest(
        certificate=csr.public_bytes(
            serialization.Encoding.PEM).decode("utf-8"))

    # Send the POST request
    resp = requests.post(
        f"http://127.0.0.1:{CA_PORT}/sign-certificate",
        json=csrPayload.model_dump()  # Convert Pydantic model to dictionary
    )

    if not resp.ok:
        raise Exception(f"Failed signing request: {resp.status_code} {
            resp.reason}. Response content: {resp.text}")

    try:
        certificate_data = CertificateSigningRequest(**resp.json())
        print("Certificate PEM:", certificate_data.certificate)

        # Save the certificate to a file
        with open("./server_cert.pem", "w") as cert_file:
            cert_file.write(certificate_data.certificate)

        # Save the private key to a file
        with open("./server_key.pem", "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
        print("Zertifikat und Schlüssel erfolgreich gespeichert.")

    except ValidationError as e:
        print("Validation failed:", e)

    except Exception as e:
        print("An error occurred:", e)

    uvicorn.run(app, host="127.0.0.1", port=SERVER_PORT)
