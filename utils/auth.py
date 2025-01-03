# utils/auth.py
import hashlib
import hmac
import secrets
from typing import Optional, Tuple
from getpass import getpass

def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Hash a password with a salt using PBKDF2."""
    if salt is None:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000  # number of iterations
    )
    return salt, hashlib.sha256(key).hexdigest()

def verify_password(stored_password: str, stored_salt: str, provided_password: str) -> bool:
    """Verify a password against its hash."""
    _, new_hash = hash_password(provided_password, stored_salt)
    return hmac.compare_digest(stored_password.encode('utf-8'), new_hash.encode('utf-8'))

def generate_env_password() -> Tuple[str, str]:
    """Generate a salt and hash for a password."""
    password = getpass("Enter password: ")
    confirm = getpass("Confirm password: ")

    if password != confirm:
        raise ValueError("Passwords do not match!")

    return hash_password(password)