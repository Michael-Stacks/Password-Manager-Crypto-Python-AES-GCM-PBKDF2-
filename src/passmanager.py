
import os
import sys
import base64
import sqlite3
import argparse
import getpass
import secrets
import string

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def hash_password(password: str, salt: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(password.encode('utf-8') + salt)
    return digest.finalize()

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=100000, backend=default_backend())
    return kdf.derive(password.encode('utf-8'))

def encrypt_password(plaintext: str, key: bytes) -> tuple:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    plaintext_bytes = plaintext.encode('utf-8')
    ct = aesgcm.encrypt(nonce, plaintext_bytes, None)
    tag = ct[-16:]
    ciphertext = ct[:-16]
    return nonce, tag, ciphertext

def decrypt_password(nonce: bytes, ciphertext: bytes, tag: bytes, key: bytes) -> str:
    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext + tag, None)
    return plaintext_bytes.decode('utf-8')

def generate_password(length: int) -> str:
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def error_exit(message: str):
    print(f"{RED}Error: {message}{RESET}", file=sys.stderr)
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(prog='passmanager', description="CLI Password Manager")
    parser.add_argument('-r', metavar='username', help='Register new user')
    parser.add_argument('-u', metavar='username', help='Username for operations')
    parser.add_argument('-a', metavar='label', help='Add a password entry with label (requires -u)')
    parser.add_argument('-s', metavar='label', help='Show password entry with label (requires -u)')
    parser.add_argument('-d', metavar='label', help='Delete password entry with label (requires -u)')
    parser.add_argument('-g', metavar='length', type=int, help='Generate a strong password of given length')
    args, unknown = parser.parse_known_args()

    # Load DB password from .env (not used further, but required by spec)
    db_password = os.getenv('DB_PASSWORD')

    # Setup database path (data.sqlite in db/ directory, one level up from src)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
    db_dir = os.path.join(base_dir, 'db')
    if not os.path.isdir(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    db_path = os.path.join(db_dir, 'data.sqlite')

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # Create tables if not exist
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "username TEXT PRIMARY KEY, "
        "salt TEXT NOT NULL, "
        "master_hash TEXT NOT NULL"
        ")"
    )
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS entries ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT NOT NULL, "
        "label TEXT NOT NULL, "
        "salt TEXT NOT NULL, "
        "data TEXT NOT NULL, "
        "FOREIGN KEY(username) REFERENCES users(username), "
        "UNIQUE(username, label)"
        ")"
    )
    conn.commit()

    # Register new user
    if args.r:
        username = args.r
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            error_exit(f"User '{username}' already exists.")
        master_pw = getpass.getpass(prompt="Set master password: ")
        confirm_pw = getpass.getpass(prompt="Confirm master password: ")
        if master_pw != confirm_pw:
            error_exit("Passwords do not match.")
        # Generate salt and hash the master password
        salt = os.urandom(16)
        pwd_hash = hash_password(master_pw, salt)
        salt_b64 = base64.b64encode(salt).decode()
        hash_b64 = base64.b64encode(pwd_hash).decode()
        cursor.execute("INSERT INTO users (username, salt, master_hash) VALUES (?, ?, ?)",
                       (username, salt_b64, hash_b64))
        conn.commit()
        print(f"{GREEN}User '{username}' registered successfully.{RESET}")
        sys.exit(0)

    # Operations for existing user
    if args.u:
        username = args.u
        cursor.execute("SELECT salt, master_hash FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            error_exit(f"User '{username}' not found. Please register first.")
        salt_b64, stored_hash_b64 = row
        salt = base64.b64decode(salt_b64)
        master_pw = getpass.getpass(prompt="Master password: ")
        pwd_hash = hash_password(master_pw, salt)
        if base64.b64encode(pwd_hash).decode() != stored_hash_b64:
            error_exit("Invalid master password.")
        # Check for conflicting options
        if args.a and args.s: error_exit("Cannot use -a and -s together.")
        if args.a and args.d: error_exit("Cannot use -a and -d together.")
        if args.s and args.d: error_exit("Cannot use -s and -d together.")

        # Add entry
        if args.a:
            label = args.a
            cursor.execute("SELECT id FROM entries WHERE username = ? AND label = ?", (username, label))
            if cursor.fetchone():
                error_exit(f"Entry '{label}' already exists for user '{username}'.")
            if args.g:
                password_val = generate_password(args.g)
                print(f"{YELLOW}Generated password: {password_val}{RESET}")
            else:
                if len(unknown) < 1:
                    error_exit(f"No password specified for label '{label}'.")
                password_val = unknown[0]
            salt_entry = os.urandom(16)
            key = derive_key(master_pw, salt_entry)
            nonce, tag, ciphertext = encrypt_password(password_val, key)
            encrypted_bytes = nonce + tag + ciphertext
            encrypted_b64 = base64.b64encode(encrypted_bytes).decode()
            salt_entry_b64 = base64.b64encode(salt_entry).decode()
            cursor.execute("INSERT INTO entries (username, label, salt, data) VALUES (?, ?, ?, ?)",
                           (username, label, salt_entry_b64, encrypted_b64))
            conn.commit()
            print(f"{GREEN}Entry '{label}' added for user '{username}'.{RESET}")
            sys.exit(0)

        # Show entry
        if args.s:
            label = args.s
            cursor.execute("SELECT salt, data FROM entries WHERE username = ? AND label = ?", (username, label))
            entry = cursor.fetchone()
            if not entry:
                error_exit(f"Entry '{label}' not found for user '{username}'.")
            salt_entry_b64, encrypted_b64 = entry
            salt_entry = base64.b64decode(salt_entry_b64)
            encrypted_bytes = base64.b64decode(encrypted_b64)
            nonce = encrypted_bytes[:12]
            tag = encrypted_bytes[12:28]
            ciphertext = encrypted_bytes[28:]
            key = derive_key(master_pw, salt_entry)
            try:
                decrypted_pwd = decrypt_password(nonce, ciphertext, tag, key)
            except Exception:
                error_exit("Decryption failed or invalid password entry.")
            print(f"{GREEN}Password for '{label}': {decrypted_pwd}{RESET}")
            sys.exit(0)

        # Delete entry
        if args.d:
            label = args.d
            cursor.execute("SELECT id FROM entries WHERE username = ? AND label = ?", (username, label))
            entry = cursor.fetchone()
            if not entry:
                error_exit(f"Entry '{label}' not found for user '{username}'.")
            cursor.execute("DELETE FROM entries WHERE username = ? AND label = ?", (username, label))
            conn.commit()
            print(f"{GREEN}Entry '{label}' deleted for user '{username}'.{RESET}")
            sys.exit(0)

        # Generate password (user context but no other action)
        if args.g:
            pwd = generate_password(args.g)
            print(f"{GREEN}Generated password: {pwd}{RESET}")
            sys.exit(0)

        error_exit("No action specified for user. Use -a, -s, or -d.")

    # Generate password (no user specified)
    if args.g:
        pwd = generate_password(args.g)
        print(f"{GREEN}Generated password: {pwd}{RESET}")
        sys.exit(0)

    parser.print_help()
    sys.exit(1)

if __name__ == '__main__':
    main()

