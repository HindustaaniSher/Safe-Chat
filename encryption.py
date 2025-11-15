from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
import base64

# ===========================================================
#  RSA KEYPAIR GENERATION AND SERIALIZATION
# ===========================================================

def generate_rsa_keypair():
    """Generate a 2048-bit RSA key pair (private + public)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key):
    """Convert RSA public key to PEM format (text)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def serialize_private_key(private_key):
    """Convert RSA private key to PEM format (text)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()


# ===========================================================
#  PASSWORD-BASED ENCRYPTION OF PRIVATE KEY (USERS)
# ===========================================================

def password_to_fernet_key(password: str) -> bytes:
    """
    Derive a 32-byte Fernet key from a password.
    It pads/truncates the password to fit Fernet key requirements.
    """
    key_bytes = password.encode('utf-8')
    key_bytes = key_bytes.ljust(32, b'0')[:32]
    return base64.urlsafe_b64encode(key_bytes)


def encrypt_private_key_pem(private_pem: str, password: str) -> str:
    """Encrypt a PEM private key using Fernet and a password."""
    fernet = Fernet(password_to_fernet_key(password))
    encrypted = fernet.encrypt(private_pem.encode('utf-8'))
    return encrypted.decode('utf-8')


def decrypt_private_key_pem(encrypted_pem: str, password: str) -> str:
    """Decrypt a previously encrypted PEM private key."""
    fernet = Fernet(password_to_fernet_key(password))
    decrypted = fernet.decrypt(encrypted_pem.encode('utf-8'))
    return decrypted.decode('utf-8')


# ===========================================================
#  ENCRYPTION/DECRYPTION USING PUBLIC-PRIVATE KEYS
# ===========================================================

def encrypt_with_public_key_bytes(public_key_pem: str, plaintext: bytes) -> bytes:
    """Encrypt plaintext using a PEM-format public key."""
    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def decrypt_with_private_key_bytes(private_key_pem: str, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext using a PEM-format private key."""
    private_key = serialization.load_pem_private_key(private_key_pem.encode('utf-8'), password=None)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext
