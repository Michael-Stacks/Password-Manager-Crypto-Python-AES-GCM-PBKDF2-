# 🔐 Password Manager (Python, AES-GCM, PBKDF2)

A command-line Password Manager built in Python with modern encryption standards.  
Designed to demonstrate secure credential handling, cryptographic key management, and safe storage practices.

## 🚀 Summary (Recruiter-Friendly)
- Built in Python using industry-grade cryptography  
- Stores all passwords encrypted with AES-256-GCM  
- Master password hashed + salted (SHA-256)  
- Secure key derivation using PBKDF2 (100k iterations)  
- SQLite persistence with per-entry encryption  
- CLI interface, clean code, maintainable architecture  
- Implements real-world security patterns (salts, KDF, AEAD)

## ⚡ Core Features
- Add, retrieve, delete encrypted password entries  
- Generate strong passwords  
- Enforced master password authentication  
- Zero plaintext credential storage  
- Environment-based secret configuration (`.env`)

---

# 🧪 Technical Details (For Developers / Security Review)

## Cryptography
### Master Password Protection
- Salt: 16 bytes (random per user)
- Hashing: SHA-256
- Storage: base64(sha256(master_password + salt))
- Goal: prevent rainbow table and dictionary attacks

### Key Derivation
- PBKDF2-HMAC-SHA256  
- 100,000 iterations  
- 16-byte salt per entry  
- Produces a 256-bit encryption key  
- Protects against brute-force and GPU cracking

### Password Encryption (Stored Data)
- Algorithm: AES-256-GCM (Authenticated Encryption)
- Nonce: 12 bytes (recommended for GCM)
- Tag: 16 bytes (authentication tag)
- Storage format: base64(nonce || tag || ciphertext)
- Provides confidentiality + integrity

## Database Architecture (SQLite)
Tables:
- `users(username TEXT PRIMARY KEY, salt BLOB, master_hash TEXT)`
- `entries(id INTEGER PRIMARY KEY, username TEXT, label TEXT, salt BLOB, ciphertext TEXT)`
- Foreign key relations ensured in schema

No sensitive material stored unencrypted.

---

# 📁 Project Structure
password-manager/  
├── .env (not committed)  
├── .env.example  
├── db/  
│   └── data.sqlite (auto-generated)  
├── src/  
│   └── passmanager.py  
└── README.md

---

# 🛠 Installation
Requires Python 3.8+.  
Install dependencies:  
pip install cryptography python-dotenv

Create `.env` in the project root:
DB_PASSWORD=yourDatabasePassword

---

# ▶️ Usage
Register a user:  
python src/passmanager.py -r <username>

Add an entry:  
python src/passmanager.py -u <username> -a <label> <password>

Retrieve an entry:  
python src/passmanager.py -u <username> -s <label>

Generate a password:  
python src/passmanager.py -g <length>

Add with generated password:  
python src/passmanager.py -u <username> -a <label> -g <length>

Delete an entry:  
python src/passmanager.py -u <username> -d <label>

---

# 📜 License
Educational use only.
