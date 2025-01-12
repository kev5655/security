
import os
from typing import Any, List

import requests
import uvicorn
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID
from fastapi import BackgroundTasks, FastAPI, HTTPException, Response
from pydantic import ValidationError
from schema import (
    CertificateRequest,
    ClientHello,
    ExtensionServer,
    Finished,
    KeyShare,
    ServerHello,
)
from shared import (
    CA_PORT,
    CLIENT_URL,
    SERVER_CERTIFICATE_PEM,
    SERVER_KEY_PEM,
    SERVER_PORT,
    get_key_pair,
    get_random,
    merge_handshake,
    raise_request,
)

app = FastAPI(title="Server")
key_pair = get_key_pair()
shared_key: bytes | None
handshake_messages: List[str] = []

@app.get("/")
def root():
    return {"name": "server"}


@app.post("/ClientHello")
def clientHello(resp: ClientHello, background_tasks: BackgroundTasks):
    handshake_messages.append(resp.model_dump_json())

    client_public_key = X25519PublicKey.from_public_bytes(bytes.fromhex(resp.extension.key_share.public_key))
    
    global shared_key
    shared_key = key_pair.private_key.exchange(client_public_key)

    public_key_bytes = key_pair.public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    
    if resp.extension.highest_tls_version != "TLS 1.3":
        raise HTTPException(status_code=500, detail="Wrong TLS version")

    if "TLS_AES_256_GCM_SHA256" not in resp.cipher_suites:
        raise HTTPException(status_code=500, detail="Missing cipher suite")
    
    
    background_tasks.add_task(send_server_response, resp, public_key_bytes)
    
    return Response(status_code=200)

    
def send_server_response(resp: ClientHello, public_key_bytes: bytes):
    send_server_hello(resp, public_key_bytes)
    send_change_cipher_spec()
    send_finish()

def send_server_hello(req: ClientHello, public_key_byes: bytes):
    random = get_random()
    with open(SERVER_CERTIFICATE_PEM, "rb") as cert_file:
        cert_data = cert_file.read()
    
    severHello = ServerHello(
        version=req.extension.highest_tls_version,
        server_random=random.hex(),
        session_id=req.session_id,
        cipher_suites="TLS_AES_256_GCM_SHA256",
        extension=ExtensionServer(
            key_share=KeyShare(
                group=req.extension.key_share.group,
                public_key=public_key_byes.hex()
            )
        ),
        certificate=cert_data.decode("utf-8")
    )
    handshake_messages.append(severHello.model_dump_json())

    print("Server send ServerHello")
    resp = requests.post(f"{CLIENT_URL}/ServerHello", json=severHello.model_dump())
    if not resp.ok:
        raise raise_request("Server", "/ServerHello", resp)

def send_change_cipher_spec():
    resp = requests.get(f"{CLIENT_URL}/ChangeCipherSpec")
    if not resp.ok:
        raise raise_request("Server", "/ChangeCipherSpec", resp)
        
def send_finish():
    if shared_key == None:
        raise Exception("Key exchange are not successfully")
    
    print(shared_key.hex())
    handshake_data = merge_handshake(handshake_messages)
    digest = hashes.Hash(hashes.SHA3_256())
    digest.update(handshake_data)
    handshake_hash = digest.finalize()
    
    h = hmac.HMAC(shared_key, hashes.SHA3_256()) # Not standard TLS 1.3
    h.update(handshake_hash)
    finished_mac = h.finalize()
    
    iv = os.urandom(12)
    algo = algorithms.AES256(shared_key)
    cipher = Cipher(algo, modes.GCM(iv))
    encryptor = cipher.encryptor()
    
    cipher_text = encryptor.update(finished_mac) + encryptor.finalize()
    tag = encryptor.tag
    
    data = Finished(
        cipher_text=cipher_text.hex(),
        iv=iv.hex(),
        tag=tag.hex()
    )
    
    print("Server send Finished")
    resp = requests.post(f"{CLIENT_URL}/Finished", json=data.model_dump())
    if not resp.ok:
        raise raise_request("Server", "/Finished", resp)
        
@app.get("/ChangeCipherSpec")
def change_cipher_spec():
    global cipherActive
    cipherActive = True        

@app.post("/Finished")
def finish(req: Finished):
    if shared_key == None:
        raise Exception("Key exchange are not successfully")
    
    algo = algorithms.AES256(shared_key)
    cipher = Cipher(algo, modes.GCM(bytes.fromhex(req.iv), bytes.fromhex( req.tag)))
    decryptor = cipher.decryptor()
    
    finished_mac = decryptor.update(bytes.fromhex(req.cipher_text)) + decryptor.finalize()
    
    handshake_data = merge_handshake(handshake_messages)
    digest = hashes.Hash(hashes.SHA3_256()) # Not standard TLS 1.3
    digest.update(handshake_data)
    handshake_hash = digest.finalize()
    
    h = hmac.HMAC(shared_key, hashes.SHA3_256())
    h.update(handshake_hash)
    try:
        h.verify(finished_mac)
    except InvalidSignature as e:
        raise HTTPException(status_code=500, detail=f"Finished message verification failed: {e}")
    
    print("Server verified client finish")
    print("TSL 1.3 Connection established send request on /send-to-server")
    return Response(status_code=200)
    
        
@app.post("/message")
def message(data: Any):
    # Encrypt Message
    # Print
    # Decrypt Message
    return data

# @app.get("/certificate")
# def get_certificate():
#     with open(SERVER_CERTIFICATE_PEM, "rb") as cert_file:
#         cert_data = cert_file.read()

#     return {"certificate": cert_data.decode("utf-8")}

if __name__ == "__main__":

    private_key = ec.generate_private_key(ec.SECP256R1())

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
    ).sign(private_key, hashes.SHA256())

    csrPayload = CertificateRequest(
        certificate=csr.public_bytes(
            serialization.Encoding.PEM).decode("utf-8"))

    # Send the POST request
    resp = requests.post(
        f"http://127.0.0.1:{CA_PORT}/sign-certificate",
        json=csrPayload.model_dump()  # Convert Pydantic model to dictionary
    )

    if not resp.ok:
        raise raise_request("Server", "/sign-certificate", resp)


    try:
        certificate_data = CertificateRequest(**resp.json())
        print("Certificate PEM:", certificate_data.certificate)

        # Save the certificate to a file
        with open(SERVER_CERTIFICATE_PEM, "w") as cert_file:
            cert_file.write(certificate_data.certificate)

        # Save the private key to a file
        with open(SERVER_KEY_PEM, "wb") as key_file:
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
