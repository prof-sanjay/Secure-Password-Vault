from Crypto.Protocol.SecretSharing import Shamir

def generate_shares(secret: bytes, k: int, n: int) -> list:
    """
    Shamir's Secret Sharing Scheme implementation.
    
    Splits a symmetric secret key into 'n' parts/shares, such that
    any combination of 'k' (or more) shares is sufficient to retrieve 
    the original secret. Any fewer than 'k' pieces provides zero information.
    
    In PyCryptodome, Shamir.split requires exact 16-byte chunks.
    Since our encryption key is a random 32-byte AES-256 key, we
    split the key into two 16-byte halves and reconstruct both.
    """
    if len(secret) != 32:
        raise ValueError("This routine strictly handles 32-byte generic secrets")
        
    chunk1 = secret[:16]
    chunk2 = secret[16:]
    
    # Shamir.split returns a List of Tuple(index, byte_share)
    shares1 = Shamir.split(k, n, chunk1)
    shares2 = Shamir.split(k, n, chunk2)
    
    # We combine chunk1 and chunk2 shares sharing the same mathematical 'index'
    # Format per combined share: (index, s1_bytes, s2_bytes)
    combined_shares = []
    for i in range(n):
        idx = shares1[i][0]
        s1 = shares1[i][1]
        s2 = shares2[i][1]
        combined_shares.append((idx, s1, s2))
        
    return combined_shares

def recover_secret(shares: list) -> bytes:
    """
    Recovers the exact original 32-byte secure key securely combining 
    the mathematically relevant chunks via Lagrange polynomials.
    """
    try:
        shares1 = [(s[0], s[1]) for s in shares]
        shares2 = [(s[0], s[2]) for s in shares]
        
        chunk1 = Shamir.combine(shares1)
        chunk2 = Shamir.combine(shares2)
        
        return chunk1 + chunk2
    except ValueError as e:
        raise ValueError("Invalid combination of shares for recovery") from e
