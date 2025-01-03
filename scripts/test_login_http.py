# scripts/test_login_http.py
import requests
import os
from dotenv import load_dotenv
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def test_login():
    # Load environment variables
    load_dotenv()

    # Get the server IP and port from BASE_URL
    base_url = os.getenv('BASE_URL', 'http://localhost:5001')

    # Get the admin password from admin_credentials.txt
    with open('/home/daytona/admin_credentials.txt', 'r') as f:
        lines = f.readlines()
        password = [l for l in lines if 'Password:' in l][0].split(':')[1].strip()

    # Test data
    data = {
        'username': 'admin',
        'password': password
    }

    logger.info(f"Testing login with:")
    logger.info(f"URL: {base_url}/login")
    logger.info(f"Username: {data['username']}")
    logger.info(f"Password: {data['password']}")

    # Make the request
    try:
        response = requests.post(f"{base_url}/login", data=data, allow_redirects=False)
        logger.info(f"Status code: {response.status_code}")
        logger.info(f"Headers: {dict(response.headers)}")
        logger.info(f"Response: {response.text}")

        return response.status_code == 303 and response.headers.get('location') == '/'
    except Exception as e:
        logger.error(f"Error testing login: {e}")
        return False

if __name__ == "__main__":
    result = test_login()
    print(f"Login test {'succeeded' if result else 'failed'}")