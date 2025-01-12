
import base64
import datetime
import os
import threading
from typing import List

import requests
import uvicorn
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509 import Certificate, DNSName
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, Response
from schema import ClientHello, ExtensionClient, Finished, KeyShare, ServerHello
from shared import (
    CA_CERT_PEM,
    CLIENT_PORT,
    SERVER_URL,
    get_key_pair,
    get_random,
    merge_handshake,
    raise_request,
)

app = FastAPI(title="Client")
shared_key: bytes | None
key_pair = get_key_pair()
cipherActive = False
handshake_messages: List[str] = []

def client_hello():
    random = get_random()
    cipher_suites = get_cipher_suites()
    data = create_client_hello(key_pair.public_key, random, cipher_suites)
    handshake_messages.append(data.model_dump_json())

    print("Client send ClientHello")
    resp = requests.post(f"{SERVER_URL}/ClientHello", json=data.model_dump())

    if not resp.ok:
        raise raise_request("Client", "/ClientHello", resp)

@app.post("/ServerHello")
def server_hello(resp: ServerHello):
    print(f"Trigger ServerHello data: {resp}")
    handshake_messages.append(resp.model_dump_json())
    
    server_cert = x509.load_pem_x509_certificate(resp.certificate.encode("utf-8"))
    ca_cert = get_ca_server_cert()
    
    store = Store([ca_cert])
    builder = PolicyBuilder().store(store)
    
    builder = builder.time(datetime.datetime.now())
    verifier = builder.build_server_verifier(DNSName("my-tls-server.com"))
    try:
        chain = verifier.verify(server_cert, [])
        print(f"Certificate is valid! Validated chain: {chain}")
    except VerificationError as e:
        raise HTTPException(status_code=500, detail=f"Error verifying a valid chain cannot be constructed: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error verifying: {e}")
    
    
    server_public_key = X25519PublicKey.from_public_bytes(bytes.fromhex(resp.extension.key_share.public_key)) 
    client_private_key = key_pair.private_key
    
    global shared_key 
    shared_key = client_private_key.exchange(server_public_key)
    
    return Response(status_code=200)
    

@app.get("/ChangeCipherSpec")
def change_cipher_spec():
    global cipherActive
    cipherActive = True
    
    
@app.post("/Finished")
def finished(req: Finished, background_tasks: BackgroundTasks):
    if shared_key is None:
        raise Exception("Key exchange are not successfully")
    
    algo = algorithms.AES256(shared_key)
    cipher = Cipher(algo, modes.GCM(bytes.fromhex(req.iv), bytes.fromhex( req.tag)))
    decryptor = cipher.decryptor()
    
    finished_mac = decryptor.update(bytes.fromhex(req.cipher_text)) + decryptor.finalize()
    
    handshake_data = merge_handshake(handshake_messages)
    digest = hashes.Hash(hashes.SHA3_256()) # Not standard TLS 1.3
    digest.update(handshake_data)
    handshake_hash = digest.finalize()
    
    # HMAC verifizieren
    h = hmac.HMAC(shared_key, hashes.SHA3_256())
    h.update(handshake_hash)
    try:
        h.verify(finished_mac)
    except InvalidSignature as e:
        raise HTTPException(status_code=500, detail=f"Finished message verification failed: {e}")
    
    background_tasks.add_task(send_client_response)

    print("Client verified server finish")
    print("TSL 1.3 Connection established send request on /send-to-server")
    
    return Response(status_code=200)
    
def send_client_response():
    send_change_cipher_spec()
    send_finish()

def send_change_cipher_spec():
    resp = requests.get(f"{SERVER_URL}/ChangeCipherSpec")
    if not resp.ok:
        raise raise_request("Client", "/ChangeCipherSpec", resp)

def send_finish():
    if shared_key == None:
        raise Exception("Key exchange are not successfully")
    
    handshake_data = merge_handshake(handshake_messages)
    digest = hashes.Hash(hashes.SHA3_256())
    digest.update(handshake_data)
    handshake_hash = digest.finalize()
    
    h = hmac.HMAC(shared_key, hashes.SHA3_256())
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
    
    print("Client send Finished")
    resp = requests.post(f"{SERVER_URL}/Finished", json=data.model_dump())
    if not resp.ok:
        raise raise_request("Client", "/Finished", resp)

@app.post("/send-to-server")
async def send_to_server(req: Request):
    if shared_key == None:
        raise Exception("Key exchange are not successfully")

    data = await req.body()
    
    data_string = str(data)
    print("Data (raw as string):", data_string)

    iv = os.urandom(12)
    algo = algorithms.AES256(shared_key)
    cipher = Cipher(algo, modes.GCM(iv))
    encryptor = cipher.encryptor()
    
    cipher_text = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag

    msg = Finished(
        cipher_text=cipher_text.hex(),
        iv=iv.hex(),
        tag=tag.hex()
    )
    
    print("Encrypted:", cipher_text.hex())
    
    print(f"Client send send-to-server {msg.model_dump()}")
    resp = requests.post(f"{SERVER_URL}/message", json=msg.model_dump())
    
    if not resp.ok:
        raise raise_request("Client", "/message", resp)
    
    try:
        json_data = resp.json()  # JSON-Daten parsen
        print("Server response (raw):", json_data)

        # JSON zu Finished parsen
        finished = Finished.model_validate(json_data)
        print("Parsed Finished:", finished)
    except ValueError as e:  # Falls die Antwort kein JSON ist
        print("Server response (raw):", resp.text)
        raise Exception(e)

    
    algo = algorithms.AES256(shared_key)
    cipher = Cipher(algo, modes.GCM(bytes.fromhex(finished.iv), bytes.fromhex(finished.tag)))
    decryptor = cipher.decryptor()
    
    plain_text = decryptor.update(bytes.fromhex(finished.cipher_text)) + decryptor.finalize()
    
    print("Plain_text (raw as string):", str(plain_text))
    
    

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
            highest_tls_version="TLS 1.3",
        )
    )
    
def get_ca_server_cert() -> Certificate:
    with open(CA_CERT_PEM, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def run_server():
    uvicorn.run(app, host="127.0.0.1", port=CLIENT_PORT)

if __name__ == "__main__":
    server_thread = threading.Thread(target=run_server)
    server_thread.start()

    import time
    time.sleep(0.5)

    client_hello()
