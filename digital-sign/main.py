from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

sign_padding = padding.PSS(mgf=padding.MGF1(
    hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def main():
    data = "That is my important pdf"
    pk, signature = sign(data)
    validate(data, pk, signature)


def sign(data: str):
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2028)

    public_key = private_key.public_key()

    signature = private_key.sign(
        data.encode(), sign_padding, hashes.SHA3_256())
    return public_key, signature


def validate(data: str, pk: RSAPublicKey, signature: bytes):
    try:
        pk.verify(signature, data.encode(), sign_padding, hashes.SHA3_256())

        print("signature is valid ✅")
    except Exception as e:
        print("signature is not valid ❌")


if __name__ == "__main__":
    print("Hey from Alice 🔒")
    main()
