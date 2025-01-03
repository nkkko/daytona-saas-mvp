#!/usr/bin/env python3
import sys
import hashlib
import os
import getpass

def generate_salt():
    return os.urandom(16).hex()

def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 generate_password.py <username>")
        sys.exit(1)

    username = sys.argv[1]

    # Read password from stdin instead of prompting
    password = sys.stdin.readline().strip()

    if not password:
        print("Error: Password cannot be empty")
        sys.exit(1)

    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    print(f"Username: {username}")
    print(f"Password: {password}")
    print(f"Salt: {salt}")
    print(f"Hash: {hashed_password}")

if __name__ == "__main__":
    main()