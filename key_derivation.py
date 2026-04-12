import os
from argon2.low_level import hash_secret_raw, Type

def generate_salt(length: int = 16) -> bytes:
    """Generate a random cryptographic salt."""
    return os.urandom(length)

def derive_key(password: str, salt: bytes, key_length: int = 32) -> bytes:

    return hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=2, # Number of iterations, provides computational hardness
        memory_cost = 65536, # Memory required (64 MB), limits concurrent attacks (ASIC/GPU resistance)
        parallelism=2, # Number of threads
        hash_len=key_length, 
        type=Type.ID
    )
