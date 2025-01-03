# scripts/generate_password.py
import sys
import os
from pathlib import Path

# Add parent directory to path so we can import utils
sys.path.append(str(Path(__file__).parent.parent))

from utils.auth import generate_env_password

def main():
    try:
        salt, hashed = generate_env_password()
        print("\nAdd these lines to your .env file:")
        print(f"PASSWORD_SALT={salt}")
        print(f"HASHED_PASSWORD={hashed}")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()