from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def generate_key_pair():
    """Generates an Ed25519 key pair for dynamic digital signatures."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return priv_bytes, pub_bytes

def sign_data(private_key_bytes: bytes, data: bytes) -> bytes:
    """Signs data ensuring authenticity utilizing our securely housed private Ed25519 parameter."""
    private_key = serialization.load_pem_private_key(private_key_bytes, password=None)
    return private_key.sign(data)

def verify_signature(public_key_bytes: bytes, signature: bytes, data: bytes) -> bool:
    """Mathematical confirmation of data authenticity using the generic Ed25519 public-key wrapper."""
    try:
        public_key = serialization.load_pem_public_key(public_key_bytes)
        public_key.verify(signature, data)
        return True
    except Exception:
        return False
