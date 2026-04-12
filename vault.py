import json
import base64
import os
from key_derivation import generate_salt, derive_key
from encryption import encrypt_data, decrypt_data
from signature import generate_key_pair, sign_data, verify_signature

class Vault:
    """
    Manages secure persistence and memory retrieval of login criteria.
    Uses Argon2-cffi key derivation for brute-forcing resilience 
    and AES-256 for symmetric, authenticated encryption.
    """
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.sig_key_path = filepath + ".sig.key"
        self.public_key = None
        self.salt = None
        self.key = None # The 32-byte memory-held AES-256 symmetric key
        self.entries = []

    def create(self, master_password: str):
        """Initializes a net-new vault protected by a user-generated master password."""
        # Generating a unique salt for each new vault prevents salt reuse
        # and stops attackers from comparing common password hashes
        self.salt = generate_salt()
        
        priv_bytes, pub_bytes = generate_key_pair()
        with open(self.sig_key_path, 'wb') as f:
            f.write(priv_bytes)
        self.public_key = pub_bytes
        
        # Stretches the provided password into a computationally hard 32-byte signature
        self.key = derive_key(master_password, self.salt)
        self.entries = []
        
        self._save()
        print(f"Vault securely created at {self.filepath}.")

    def unlock(self, master_password: str) -> bool:
        """Attempts to decrypt the stored database utilizing master password key regeneration."""
        try:
            with open(self.filepath, 'r') as f:
                data = json.load(f)
                
            self.salt = base64.b64decode(data['salt'])
            encrypted_payload = base64.b64decode(data['payload'])
            
            # Ed25519 Security Constraint 
            if 'signature' in data and 'public_key' in data:
                sig = base64.b64decode(data['signature'])
                pub = base64.b64decode(data['public_key'])
                self.public_key = pub
                if not verify_signature(pub, sig, encrypted_payload):
                    raise ValueError("Digital signature verification failed! Metadata has been cryptographically tampered with.")
            
            # Reconstruct the 32-byte key
            self.key = derive_key(master_password, self.salt)
            
            # The payload will fail to decrypt here (InvalidTag) 
            # if the generated key and the payload tag misalign. 
            decrypted_json = decrypt_data(self.key, encrypted_payload).decode('utf-8')
            self.entries = json.loads(decrypted_json)
            
            print("Vault decrypted successfully!")
            return True
            
        except FileNotFoundError:
            print("Vault file is missing. Please create a new one first.")
            return False
        except Exception:
            # We fail uniformly here primarily to avoid returning 
            # side-channel insight whether decryption or missing structure caused the failure.
            print("Failed to unlock vault! Master password invalid or data corrupted.")
            return False

    def unlock_with_key(self, raw_32_key: bytes) -> bool:
        """Fallback method using raw geometric key chunks (e.g. from Shamir backup recovery)."""
        try:
            with open(self.filepath, 'r') as f:
                data = json.load(f)
                
            self.salt = base64.b64decode(data['salt'])
            encrypted_payload = base64.b64decode(data['payload'])
            
            # Ed25519 Security Constraint Backup Layer
            if 'signature' in data and 'public_key' in data:
                sig = base64.b64decode(data['signature'])
                pub = base64.b64decode(data['public_key'])
                self.public_key = pub
                if not verify_signature(pub, sig, encrypted_payload):
                    raise ValueError("Digital signature verification failed on Shamir Recovery. Metadata tampered.")
            
            self.key = raw_32_key
            
            decrypted_json = decrypt_data(self.key, encrypted_payload).decode('utf-8')
            self.entries = json.loads(decrypted_json)
            print("Warning: Vault decrypted via recovery keys!")
            return True
        except Exception:
            print("Invalid recovery shares. Vault remains locked.")
            return False

    def _save(self):
        """Dumps encrypted runtime JSON stringification back into a cold storage base64 map."""
        if not self.key or not self.salt:
            raise ValueError("Vault hasn't been instantiated nor unlocked securely!")
            
        payload_json = json.dumps(self.entries).encode('utf-8')
        encrypted_payload = encrypt_data(self.key, payload_json)
        
        vault_data = {
            'salt': base64.b64encode(self.salt).decode('utf-8'),
            'payload': base64.b64encode(encrypted_payload).decode('utf-8')
        }
        
        if self.public_key and os.path.exists(self.sig_key_path):
            with open(self.sig_key_path, 'rb') as f:
                priv_bytes = f.read()
            signature = sign_data(priv_bytes, encrypted_payload)
            vault_data['signature'] = base64.b64encode(signature).decode('utf-8')
            vault_data['public_key'] = base64.b64encode(self.public_key).decode('utf-8')
        
        with open(self.filepath, 'w') as f:
            json.dump(vault_data, f, indent=4)

    def add_password(self, website, username, password):
        """Append credentials inside the secure boundaries."""
        self.entries.append({
            'website': website,
            'username': username,
            'password': password
        })
        # Instant save to commit changes under AES encryption immediately
        self._save()
        print(f"Credentials for '{website}' stored safely.")

    def view_passwords(self):
        """Render sensitive credentials."""
        if not self.entries:
            print("The vault is currently empty.")
            return

        print("\n--- Unlocked Credentials ---")
        for idx, entry in enumerate(self.entries):
            print(f"[{idx+1}] Website: {entry['website']}")
            print(f"    Username: {entry['username']}")
            print(f"    Password: {entry['password']}\n")
        print("----------------------------\n")

    def delete_password(self, index: int):
        """
        Removes a stored credential by its list number.
        The vault is immediately re-encrypted after deletion so
        the removed entry is gone from disk as well as memory.
        """
        if index < 1 or index > len(self.entries):
            print(f"Invalid entry number. Choose between 1 and {len(self.entries)}.")
            return

        removed = self.entries.pop(index - 1)
        self._save()
        print(f"Entry for '{removed['website']}' has been permanently deleted and vault re-encrypted.")

