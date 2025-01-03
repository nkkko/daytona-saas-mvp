#!/usr/bin/env python3
import hashlib
import hmac
import sys
import os
from dotenv import load_dotenv

def hash_password(password: str, salt: str) -> str:
    """Hash a password with a salt using PBKDF2."""
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000  # number of iterations
    )
    return hashlib.sha256(key).hexdigest()

def verify_password(stored_password: str, stored_salt: str, provided_password: str) -> bool:
    """Verify a password against its hash."""
    new_hash = hash_password(provided_password, stored_salt)
    return hmac.compare_digest(stored_password.encode('utf-8'), new_hash.encode('utf-8'))

def main():
    # Load environment variables
    load_dotenv()

    # Get stored values
    salt = os.getenv('PASSWORD_SALT')
    stored_hash = os.getenv('HASHED_PASSWORD')

    if len(sys.argv) != 2:
        print("Usage: python3 verify_password.py <password>")
        return

    test_password = sys.argv[1]
    match = verify_password(stored_hash, salt, test_password)

    print(f"Testing password: {test_password}")
    print(f"Salt: {salt}")
    print(f"Stored hash:    {stored_hash}")
    print(f"Match: {match}")

if __name__ == "__main__":
    main()