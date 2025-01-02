from fasthtml.common import *
from dataclasses import dataclass
import requests
import os
from dotenv import load_dotenv
from pathlib import Path
import secrets

def setup_secret_key():
    """Setup and validate secret key with appropriate fallbacks."""
    # Get or generate secret key
    secret_key = os.getenv('SECRET_KEY')
    if not secret_key:
        if os.getenv('ENVIRONMENT') == 'production':
            raise ValueError("""
            SECRET_KEY must be set in production!
            Generate one with:
            python3 -c 'import secrets; print(secrets.token_hex(32))'
            """)

        # Development: Generate and save key
        secret_key = secrets.token_hex(32)
        print(f"Generated development SECRET_KEY: {secret_key}")

        # Save to .env for development consistency
        env_file = '.env'
        if os.path.exists(env_file):
            with open(env_file, 'a') as f:
                f.write(f'\nSECRET_KEY={secret_key}')
        else:
            with open(env_file, 'w') as f:
                f.write(f'SECRET_KEY={secret_key}')

    return secret_key

# Configuration
def setup_config():
    """Setup and validate configuration."""
    # Load environment variables
    env_name = os.getenv('ENVIRONMENT', 'development')
    env_file = f"{env_name}.env"
    if Path(env_file).exists():
        load_dotenv(env_file)
    else:
        load_dotenv()

    config = {
        'DAYTONA_API_URL': os.getenv('DAYTONA_API_URL', 'http://localhost:3986'),
        'GITHUB_CLIENT_ID': os.getenv('GITHUB_CLIENT_ID'),
        'GITHUB_CLIENT_SECRET': os.getenv('GITHUB_CLIENT_SECRET'),
        'SECRET_KEY': setup_secret_key(),
    }

    # Validate required environment variables
    if not all([config['GITHUB_CLIENT_ID'], config['GITHUB_CLIENT_SECRET']]):
        raise ValueError("""
        Missing required environment variables.
        Please create a .env file with:
        GITHUB_CLIENT_ID=your_github_client_id
        GITHUB_CLIENT_SECRET=your_github_client_secret
        DAYTONA_API_URL=http://localhost:3986  # Optional, defaults to http://localhost:3986
        SECRET_KEY=your_secret_key  # Optional, will be auto-generated in development
        """)

    return config

# Use configuration
config = setup_config()
app, rt = fast_app(
    secret_key=config['SECRET_KEY'],
    htmx=True,
    pico=True
)

# Data classes
@dataclass
class ApiKey:
    name: str
    keyHash: str
    type: str

# API Client
class DaytonaClient:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')  # Remove trailing slash if present

    def _make_request(self, method, endpoint, **kwargs):
        """Make HTTP request with error handling."""
        try:
            response = requests.request(method, f"{self.base_url}{endpoint}", **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            print(f"Daytona API error: {e}")
            return None

    def list_api_keys(self):
        response = self._make_request('GET', '/apikey')
        return response.json() if response else []

    def generate_api_key(self, key_name):
        response = self._make_request('POST', f'/apikey/{key_name}')
        return response.text if response else None

    def revoke_api_key(self, key_name):
        response = self._make_request('DELETE', f'/apikey/{key_name}')
        return bool(response)

    def list_workspaces(self, api_key):
        response = self._make_request('GET', '/workspace',
                                    headers={'Authorization': f'Bearer {api_key}'})
        return response.json() if response else []

# Single DaytonaClient initialization
daytona = DaytonaClient(config['DAYTONA_API_URL'])

# Auth middleware
def auth_before(req, sess):
    auth = req.scope['auth'] = sess.get('auth', None)
    if not auth:
        return RedirectResponse('/login', status_code=303)

beforeware = Beforeware(auth_before, skip=[r'/login', r'/github-callback'])

# Routes
@rt("/login")
def get():
    return Titled(
        "Login",  # Title
        Container(  # Content
            A(
                "Login with GitHub",
                href=f"https://github.com/login/oauth/authorize?client_id={config['GITHUB_CLIENT_ID']}&scope=user",
                cls="button"
            )
        )
    )

@rt("/github-callback")
async def get(code: str, session):
    # Exchange code for access token
    response = requests.post(
        'https://github.com/login/oauth/access_token',
        data={
            'client_id': GITHUB_CLIENT_ID,
            'client_secret': GITHUB_CLIENT_SECRET,
            'code': code
        },
        headers={'Accept': 'application/json'}
    )

    if response.ok:
        access_token = response.json().get('access_token')
        # Get user info
        user_response = requests.get(
            'https://api.github.com/user',
            headers={
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json'
            }
        )
        if user_response.ok:
            user = user_response.json()
            session['auth'] = user['login']
            return RedirectResponse('/', status_code=303)

    return RedirectResponse('/login', status_code=303)

@rt("/")
def get(auth):
    api_keys = daytona.list_api_keys()
    return Titled(
        f"Daytona Dashboard - {auth}",  # First positional argument (title)
        # Rest of content as second positional argument
        Container(
            Grid(
                Card(
                    H2("API Keys"),
                    Form(
                        Input(name="key_name", placeholder="API Key Name"),
                        Button("Create New Key", type="submit"),
                        hx_post="/api-keys",
                        hx_target="#keys-list"
                    ),
                    Div(
                        id="keys-list",
                        *[Div(
                            f"Name: {key['name']} (Type: {key['type']})",
                            Button(
                                "Delete",
                                hx_delete=f"/api-keys/{key['name']}",
                                hx_target="#keys-list"
                            )
                        ) for key in api_keys]
                    )
                ),
                Card(
                    H2("Workspaces"),
                    Div(id="workspaces-list")
                )
            ),
            A("Logout", href="/logout", cls="button")
        )
    )

@rt("/api-keys")
def post(key_name: str):
    if not key_name:
        return "Key name is required"

    new_key = daytona.generate_api_key(key_name)
    if not new_key:
        return "Failed to create API key - server error"

    try:
        api_keys = daytona.list_api_keys()
        # Create the list of key divs first
        key_divs = [
            Div(
                f"Name: {key['name']} (Type: {key['type']})",
                Button(
                    "Delete",
                    hx_delete=f"/api-keys/{key['name']}",
                    hx_target="#keys-list"
                )
            )
            for key in api_keys
        ]
        # Then create the container div with all children
        return Div(
            *key_divs,  # Unpack the key divs
            Script(f"alert('New API Key: {new_key}')"),
            id="keys-list"  # keyword args after positional args
        )
    except Exception as e:
        print(f"Error rendering API keys: {e}")
        return "Failed to update API keys list"

@rt("/api-keys/{key_name}")
def delete(key_name: str):
    if daytona.revoke_api_key(key_name):
        api_keys = daytona.list_api_keys()
        # Create the list of key divs first
        key_divs = [
            Div(
                f"Name: {key['name']} (Type: {key['type']})",
                Button(
                    "Delete",
                    hx_delete=f"/api-keys/{key['name']}",
                    hx_target="#keys-list"
                )
            )
            for key in api_keys
        ]
        # Then create the container div with all children
        return Div(
            *key_divs,  # Unpack the key divs
            id="keys-list"  # keyword args after positional args
        )
    return "Failed to delete API key"

@rt("/logout")
def get(session):
    session.clear()
    return RedirectResponse('/login', status_code=303)

if __name__ == "__main__":
    serve()