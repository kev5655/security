
from dataclasses import dataclass
from typing import List, Literal, TypeAlias

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from pydantic import BaseModel

# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/
# https://www.rfc-editor.org/rfc/rfc8446#section-4.2.7
Groupe_ECDHE: TypeAlias = Literal["x25519", "x448",
                                  "secp256r1", "secp384r1", "secp521r1"]
TLS_Version: TypeAlias = Literal["TLS 1.3", "TLS 1.2"]


class KeyShare(BaseModel):
    group: Groupe_ECDHE
    public_key: str


class ExtensionClient(BaseModel):
    supported_groups: List[Groupe_ECDHE]
    key_share: KeyShare
    signature_algorithms: List[str]
    highest_tls_version: TLS_Version


class ClientHello(BaseModel):
    client_random: str
    session_id: str
    cipher_suites: List[str]
    extension: ExtensionClient


class ExtensionServer(BaseModel):
    key_share: KeyShare


class ServerHello(BaseModel):
    version: TLS_Version
    server_random: str
    session_id: str
    cipher_suites: str
    extension: ExtensionServer
    certificate: str
    

class CertificateRequest(BaseModel):
    certificate: str

class Finished(BaseModel):
    cipher_text: str
    iv: str
    tag: str
    

@dataclass
class KeyPair:
    private_key: X25519PrivateKey
    public_key: X25519PublicKey



