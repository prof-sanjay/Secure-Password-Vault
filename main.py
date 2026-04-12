import argparse
import sys
import getpass
import base64
from vault import Vault
from secret_sharing import generate_shares, recover_secret

def main():
    parser = argparse.ArgumentParser(description="Secure Cryptographically Safe Password Manager")
    parser.add_argument('command', choices=['create', 'add', 'view', 'delete', 'backup', 'recover'], 
                        help="Cryptographic action to run")
    parser.add_argument('--vault', default='vault.json', help="Vault file JSON path")
    args = parser.parse_args()

    v = Vault(args.vault)

    if args.command == 'create':
        pwd = getpass.getpass("Enter secure new master password: ")
        pwd2 = getpass.getpass("Confirm password: ")
        if pwd != pwd2:
            print("Passwords do not computationally match!")
            sys.exit(1)
            
        print("\nUsing Argon2id key derivation processing...")
        v.create(pwd)

    elif args.command == 'add':
        pwd = getpass.getpass("Enter master password to authorize additions: ")
        if v.unlock(pwd):
            website = input("Website URI: ")
            username = input("Website Username: ")
            password = getpass.getpass("Credentials to store: ")
            print("\nUpdating AES-256-GCM cipher envelope...")
            v.add_password(website, username, password)

    elif args.command == 'view':
        pwd = getpass.getpass("Enter master password: ")
        if v.unlock(pwd):
            v.view_passwords()

    elif args.command == 'delete':
        pwd = getpass.getpass("Enter master password: ")
        if v.unlock(pwd):
            v.view_passwords()
            try:
                num = int(input("Enter the number of the entry to delete: "))
                confirm = input(f"Are you sure you want to delete entry [{num}]? (yes/no): ").strip().lower()
                if confirm == 'yes':
                    v.delete_password(num)
                else:
                    print("Deletion cancelled.")
            except ValueError:
                print("Please enter a valid number.")

    elif args.command == 'backup':
        pwd = getpass.getpass("Please provide your vault password to extract chunks: ")
        if v.unlock(pwd):
            print("\nGenerating AES-256 underlying key fragments using Shamir Secret Sharing...")
            try:
                k = int(input("Enter minimal threshold to successfully recover (k): "))
                n = int(input("Enter total combination shares to generate (n): "))
                if k > n:
                    print("Impossible threshold. k cannot be mathematically greater than n")
                    sys.exit(1)
            except ValueError:
                print("Must input base-10 numerical integers.")
                sys.exit(1)

            shares = generate_shares(v.key, k, n)
            print("\n--- RECOVERY FRAGMENTS (Do not lose these) ---")
            for i, share in enumerate(shares):
                idx, s1, s2 = share
                s1_b64 = base64.b64encode(s1).decode()
                s2_b64 = base64.b64encode(s2).decode()
                share_str = f"{idx}:{s1_b64}:{s2_b64}"
                print(f"Share Fragment {i+1}: {share_str}")
            print("----------------------------------------------")

    elif args.command == 'recover':
        print("\n--- AES Key Structural Recreation (Shamir Combined Output) ---")
        try:
            k = int(input("How many valid fragments do you currently possess? "))
        except ValueError:
            print("Enter an integer value.")
            sys.exit(1)
            
        shares = []
        for i in range(k):
            try:
                share_str = input(f"Enter combined base64 fragment {i+1}: ").strip()
                parts = share_str.split(':')
                
                if len(parts) != 3:
                    print("Syntax breakdown: Expected fragment struct is idx:s1:s2")
                    sys.exit(1)
                    
                idx = int(parts[0])
                s1 = base64.b64decode(parts[1])
                s2 = base64.b64decode(parts[2])
                shares.append((idx, s1, s2))
            except Exception:
                print("Fragmentation encoding parse error. Fragment might be damaged.")
                sys.exit(1)
            
        try:
            recovered_key = recover_secret(shares)
            
            # Using our backup decryption handler
            if v.unlock_with_key(recovered_key):
                print("\nRescue operation successful!")
                
                # Automatically reset boundaries back to a known master password.
                print("Vault boundary successfully restored. Reseeding new master credentials to abandon exposed fragments.")
                new_pwd = getpass.getpass("Assign new primary master password: ")
                
                current_entries = v.entries
                v.create(new_pwd) # This overwrites AES underlying memory key
                v.entries = current_entries
                v._save()
                print("Resealing complete! Previous backup fragments mathematically invalidated automatically.")
            else:
                print("Rescue operation failed to decrypt main container format. Wrong data or fragments.")
        except Exception as e:
            print("Recombination polynomial failure:", e)

if __name__ == '__main__':
    main()
