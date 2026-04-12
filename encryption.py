import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_data(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypts data using AES-256-GCM.
    
    AES-GCM is an Authenticated Encryption with Associated Data (AEAD) algorithm.
    It ensures both confidentiality (via AES encryption) and integrity 
    (via GMAC tags). Using AEAD is crucial to prevent malleability attacks,
    where an attacker alters ciphertext to decrypt into meaningful data.
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256")
        
    # Generate a random 12-byte initialization vector (IV/nonce)
    # Never reuse the same nonce with the same key in GCM mode!
    nonce = os.urandom(12)
    
    # Initialize AES-GCM with the 32-byte key
    aesgcm = AESGCM(key)
    
    # Encrypt the plaintext. 
    # AESGCM.encrypt appends a 16-byte authentication tag to the ciphertext automatically.
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    # Prepend the nonce to the ciphertext so we can retrieve it during decryption
    return nonce + ciphertext

def decrypt_data(key: bytes, encrypted_data: bytes) -> bytes:
    """
    Decrypts data using AES-256-GCM.
    
    Returns the original plaintext if the key and data (including the tag) are valid.
    If the tag verification fails (e.g. data corrupted or wrong key), 
    an InvalidTag exception will be raised.
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256")
        
    # 12 bytes nonce + 16 bytes auth tag + at least 0 bytes ciphertext
    if len(encrypted_data) < 28: 
        raise ValueError("Invalid encrypted data length")
        
    # Extract the 12-byte nonce
    nonce = encrypted_data[:12]
    
    # The rest is the actual encrypted payload (ciphertext + tag)
    ciphertext = encrypted_data[12:]
    
    aesgcm = AESGCM(key)
    
    # Decrypt and authenticate. Raises an exception if authentication fails.
    return aesgcm.decrypt(nonce, ciphertext, None)
