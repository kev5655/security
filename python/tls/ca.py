import datetime

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from schema import CertificateSigningRequest
from settings import CA_PORT

app = FastAPI()


@app.get("/")
def root():
    return {"name": "ca"}


@app.post("/sign-certificate")
def sign_certificate(req: CertificateSigningRequest):

    # Lade den Root-CA-Schlüssel
    with open("./key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None)

        # Ensure the private key is of type Ed25519PrivateKey
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("The loaded key is not an Ed25519 private key")

        root_private_key: Ed25519PrivateKey = private_key

    # Lade die CSR
    csr = x509.load_pem_x509_csr(req.certificate.encode("utf-8"))

    # Zertifikat aus der CSR erstellen
    certificate = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        x509.Name([  # Root-CA-Daten
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "CH"),
            x509.NameAttribute(
                x509.NameOID.ORGANIZATION_NAME, "root-cert-org"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "kevin-ca.com"),
        ])
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now()
    ).not_valid_after(
        datetime.datetime.now() + datetime.timedelta(days=365)  # Gültigkeit: 1 Jahr
    ).sign(root_private_key, None)

    return CertificateSigningRequest(
        certificate=certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8"))


if __name__ == "__main__":
    private_key = Ed25519PrivateKey.generate()

    with open("./key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CH"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Bern"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Wichtrach"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "root-cert-org"),
        x509.NameAttribute(NameOID.COMMON_NAME, "kevin-ca.com"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) +
        datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False
    ).sign(private_key, None)  # Because Ed25519

    with open("./certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    uvicorn.run(app, host="127.0.0.1", port=CA_PORT)
