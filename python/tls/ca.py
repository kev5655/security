import datetime

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509 import Name
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import FastAPI
from schema import CertificateSigningRequest
from settings import CA_PORT
from shared import CA_CERT_PEM, CA_KEY_PEM

app = FastAPI()
    # Lade die CSR
ca_subject: Name

@app.get("/")
def root():
    return {"name": "ca"}


@app.post("/sign-certificate")
def sign_certificate(req: CertificateSigningRequest):

    # Lade den Root-CA-Schlüssel
    with open(CA_KEY_PEM, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None)

        # Ensure the private key is of type EllipticCurvePrivateKey
        if not isinstance(private_key, EllipticCurvePrivateKey):
            raise TypeError("The loaded key is not an Ed25519 private key")

        root_private_key: EllipticCurvePrivateKey = private_key

    # Lade die CSR
    csr = x509.load_pem_x509_csr(req.certificate.encode("utf-8"))
    
    with open(CA_CERT_PEM, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    # Extract the CA’s SKI value (the raw digest)
    try:
        ca_ski_ext = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        ca_ski_value = ca_ski_ext.value.digest
    except x509.ExtensionNotFound:
        raise Exception("Root CA certificate has no SubjectKeyIdentifier extension")

    # Zertifikat aus der CSR erstellen
    certificate = x509.CertificateBuilder().subject_name(csr.subject
        ).issuer_name(ca_subject
        ).public_key(csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now()
        ).not_valid_after(
            datetime.datetime.now() + datetime.timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),  # Wichtig: CA ist False
            critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,  # Key Usage ist eine kritische Erweiterung
        ).add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName("my-tls-server.com")]),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier(
            key_identifier=ca_ski_value,
            authority_cert_issuer=None,
            authority_cert_serial_number=None,
        ),
        critical=False
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False
        ).sign(root_private_key, hashes.SHA256())

    return CertificateSigningRequest(
        certificate=certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8"))


if __name__ == "__main__":
    root_private_key = ec.generate_private_key(ec.SECP256R1())

    with open(CA_KEY_PEM, "wb") as f:
        f.write(root_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    ca_subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CH"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Bern"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Wichtrach"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "root-cert-org"),
        x509.NameAttribute(NameOID.COMMON_NAME, "kevin-ca.com"),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(issuer)
        .public_key(root_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
        )
        # The critical piece: CA=True + path_length as needed
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
        # Also mark it can sign certs:
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True
        )
        # Good practice to include SKI in a root cert too
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(
            root_private_key.public_key()
            ), critical=False
        )
        # Optionally include authorityKeyIdentifier as well
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_private_key.public_key()),
            critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False
        )
        .sign(root_private_key, hashes.SHA256())
    )

    with open(CA_CERT_PEM, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    uvicorn.run(app, host="127.0.0.1", port=CA_PORT)
