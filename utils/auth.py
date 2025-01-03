# utils/auth.py
import hashlib
import hmac
import secrets
from typing import Optional, Tuple
from getpass import getpass
import logging

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Hash a password with a salt using PBKDF2."""
    if salt is None:
        salt = secrets.token_hex(16)

    logger.debug(f"Hashing password with salt: {salt}")

    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000  # number of iterations
    )
    hash_value = hashlib.sha256(key).hexdigest()

    logger.debug(f"Generated hash: {hash_value}")

    return salt, hash_value

def verify_password(stored_password: str, stored_salt: str, provided_password: str) -> bool:
    """Verify a password against its hash."""
    logger.debug("=== Password Verification ===")
    logger.debug(f"Provided password: {provided_password}")
    logger.debug(f"Stored salt: {stored_salt}")
    logger.debug(f"Stored hash: {stored_password}")

    key = hashlib.pbkdf2_hmac(
        'sha256',
        provided_password.encode('utf-8'),
        stored_salt.encode('utf-8'),
        100000
    )
    computed_hash = hashlib.sha256(key).hexdigest()

    logger.debug(f"Computed hash: {computed_hash}")
    result = hmac.compare_digest(stored_password.encode('utf-8'), computed_hash.encode('utf-8'))
    logger.debug(f"Match result: {result}")

    return result

def generate_env_password() -> Tuple[str, str]:
    """Generate a salt and hash for a password."""
    password = getpass("Enter password: ")
    confirm = getpass("Confirm password: ")

    if password != confirm:
        raise ValueError("Passwords do not match!")

    return hash_password(password)