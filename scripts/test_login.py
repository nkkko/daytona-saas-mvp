#!/usr/bin/env python3
import hashlib
import sys
import os
from dotenv import load_dotenv

def verify_password(password, salt, stored_hash):
    computed_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return computed_hash == stored_hash

def main():
    # Load environment variables
    load_dotenv()

    # Get values from environment
    salt = os.getenv('PASSWORD_SALT')
    stored_hash = os.getenv('HASHED_PASSWORD')

    # Get password from command line
    if len(sys.argv) != 2:
        print("Usage: python3 test_login.py <password>")
        sys.exit(1)

    password = sys.argv[1]

    # Verify password
    if verify_password(password, salt, stored_hash):
        print("Password is correct!")
    else:
        print("Password is incorrect!")
        print(f"Debug info:")
        print(f"Input password: {password}")
        print(f"Salt: {salt}")
        print(f"Stored hash: {stored_hash}")
        print(f"Computed hash: {hashlib.sha256((password + salt).encode()).hexdigest()}")

if __name__ == "__main__":
    main()