#!/usr/bin/env python3
import os
from dotenv import load_dotenv
import hashlib
import hmac
import sys

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
    key = hashlib.pbkdf2_hmac(
        'sha256',
        provided_password.encode('utf-8'),
        stored_salt.encode('utf-8'),
        100000  # number of iterations
    )
    new_hash = hashlib.sha256(key).hexdigest()
    return hmac.compare_digest(stored_password.encode('utf-8'), new_hash.encode('utf-8'))

def main():
    # Load environment variables
    load_dotenv()

    # Get stored values
    stored_hash = os.getenv('HASHED_PASSWORD')
    stored_salt = os.getenv('PASSWORD_SALT')

    if len(sys.argv) != 2:
        print("Usage: python debug_password.py <password>")
        sys.exit(1)

    test_password = sys.argv[1]

    print("=== Debug Password Verification ===")
    print(f"Test Password: {test_password}")
    print(f"Stored Salt: {stored_salt}")
    print(f"Stored Hash: {stored_hash}")

    # Generate new hash with the test password
    computed_hash = hash_password(test_password, stored_salt)
    print(f"Computed Hash: {computed_hash}")

    # Verify using the function
    result = verify_password(stored_hash, stored_salt, test_password)
    print(f"Verification Result: {result}")

if __name__ == "__main__":
    main()