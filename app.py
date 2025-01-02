from fasthtml.common import *
from dataclasses import dataclass
import requests
import os
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables from .env file
env_path = Path('.') / '.env'
load_dotenv(env_path)

# Configuration
DAYTONA_API_URL = os.getenv('DAYTONA_API_URL', 'http://localhost:3986')
GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')
SECRET_KEY = os.getenv('SECRET_KEY', 'change-me-in-production')

# Validate required environment variables
if not all([GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET]):
    raise ValueError("""
    Missing required environment variables.
    Please create a .env file with:
    GITHUB_CLIENT_ID=your_github_client_id
    GITHUB_CLIENT_SECRET=your_github_client_secret
    DAYTONA_API_URL=http://localhost:3986  # Optional, defaults to http://localhost:3986
    SECRET_KEY=your_secret_key  # Optional, defaults to 'change-me-in-production'
    """)

# Create FastHTML app
app, rt = fast_app(
    secret_key=SECRET_KEY,
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
        self.base_url = base_url

    def list_api_keys(self):
        response = requests.get(f"{self.base_url}/apikey")
        return response.json() if response.ok else []

    def generate_api_key(self, key_name):
        response = requests.post(f"{self.base_url}/apikey/{key_name}")
        return response.text if response.ok else None

    def revoke_api_key(self, key_name):
        response = requests.delete(f"{self.base_url}/apikey/{key_name}")
        return response.ok

    def list_workspaces(self, api_key):
        headers = {'Authorization': f'Bearer {api_key}'}
        response = requests.get(f"{self.base_url}/workspace", headers=headers)
        return response.json() if response.ok else []

daytona = DaytonaClient(DAYTONA_API_URL)

# Auth middleware
def auth_before(req, sess):
    auth = req.scope['auth'] = sess.get('auth', None)
    if not auth:
        return RedirectResponse('/login', status_code=303)

beforeware = Beforeware(auth_before, skip=[r'/login', r'/github-callback'])

# Routes
@rt("/login")
def get():
    return Titled("Login",
        A("Login with GitHub",
          href=f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&scope=user",
          cls="button"))

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
    return Titled(f"Daytona Dashboard - {auth}",
        Grid(
            Card(
                H2("API Keys"),
                Form(
                    Input(name="key_name", placeholder="API Key Name"),
                    Button("Create New Key", type="submit"),
                    hx_post="/api-keys",
                    hx_target="#keys-list"
                ),
                Div(id="keys-list",
                    *[Div(
                        f"Name: {key['name']} (Type: {key['type']})",
                        Button("Delete",
                               hx_delete=f"/api-keys/{key['name']}",
                               hx_target="#keys-list")
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

@rt("/api-keys")
def post(key_name: str):
    new_key = daytona.generate_api_key(key_name)
    if new_key:
        api_keys = daytona.list_api_keys()
        return Div(id="keys-list",
            *[Div(
                f"Name: {key['name']} (Type: {key['type']})",
                Button("Delete",
                       hx_delete=f"/api-keys/{key['name']}",
                       hx_target="#keys-list")
            ) for key in api_keys],
            Script(f"alert('New API Key: {new_key}')")
        )
    return "Failed to create API key"

@rt("/api-keys/{key_name}")
def delete(key_name: str):
    if daytona.revoke_api_key(key_name):
        api_keys = daytona.list_api_keys()
        return Div(id="keys-list",
            *[Div(
                f"Name: {key['name']} (Type: {key['type']})",
                Button("Delete",
                       hx_delete=f"/api-keys/{key['name']}",
                       hx_target="#keys-list")
            ) for key in api_keys]
        )
    return "Failed to delete API key"

@rt("/logout")
def get(session):
    session.clear()
    return RedirectResponse('/login', status_code=303)

if __name__ == "__main__":
    serve()