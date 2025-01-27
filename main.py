from fasthtml.common import *
from dataclasses import dataclass
import requests
import os
from dotenv import load_dotenv
from pathlib import Path
import secrets
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime
import json
from utils.auth import verify_password

# Add some CSS styles
additional_styles = """
:root {
    --pico-theme-color: "dark";
}

html {
    data-theme: "dark";
}

/* Navigation styles */
nav {
    margin-bottom: 2rem;
    border-bottom: 1px solid var(--pico-muted-border-color);
    padding-bottom: 1rem;
}

nav ul {
    margin: 0;
    padding: 0;
}

nav ul li {
    display: inline-block;
    margin-right: 1rem;
}

nav ul li:last-child {
    margin-right: 0;
}

.code-container {
    position: relative;
}

.copy-button {
    position: absolute;
    top: 0.5rem;
    right: 0.5rem;
    padding: 0.25rem 0.75rem;
    background-color: #2b3035;  /* Dark background */
    border: 1px solid #404549;  /* Visible border */
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.875rem;
    color: #e9ecef;  /* Light text color */
    transition: all 0.2s ease;
    z-index: 10;    /* Ensure button stays above code block */
}

.copy-button:hover {
    background-color: #3b4045;  /* Slightly lighter on hover */
    border-color: #505559;
}

.copy-button.copied {
    background-color: #28a745;  /* Success green */
    border-color: #218838;
    color: white;
}

/* Adjust the code container to ensure proper contrast */
.code-container pre {
    background-color: #1a1d20;  /* Darker background for code */
    margin: 0;
}

.key-item {
    display: flex;
    align-items: center;
    padding: 1rem;
    margin: 0.5rem 0;
    background: #f8f9fa;
    border-radius: 8px;
    border: 1px solid #dee2e6;
}

.key-item > div {
    display: flex;
    justify-content: space-between;
    align-items: center;
    width: 100%;
}

.key-name {
    margin: 0;
    font-family: monospace;
}

.delete-button {
    background-color: #dc3545;
    color: white;
    padding: 0.375rem 0.75rem;
    border-radius: 4px;
    border: none;
    cursor: pointer;
}

.delete-button:hover {
    background-color: #c82333;
}

.no-keys-message {
    color: #6c757d;
    text-align: center;
    padding: 1rem;
}

.success-message {
    color: #155724;
    background-color: #d4edda;
    border: 1px solid #c3e6cb;
    padding: 0.75rem 1.25rem;
    border-radius: 0.25rem;
    margin-bottom: 1rem;
}

.error-message {
    color: #dc3545;
    padding: 0.75rem;
    margin: 0.5rem 0;
    background: #f8d7da;
    border: 1px solid #f5c6cb;
    border-radius: 4px;
}

#keys-list {
    margin-top: 1rem;
}

form {
    display: grid;
    gap: 1rem;
    margin-bottom: 1rem;
}

input[type="text"] {
    width: 100%;
}

.button-container {
    display: flex;
    gap: 1rem;
    margin-top: 1rem;
}

.button-container .button {
    flex: 1;
    text-align: center;
}
.setup-step {
    margin-bottom: 2rem;
}

.step-content {
    margin-left: 1rem;
    margin-top: 1rem;
}

.onboarding-card {
    max-width: 800px;
    margin: 0 auto;
}

.api-key {
    background: #f8f9fa;
    padding: 0.5rem;
    border-radius: 4px;
    font-family: monospace;
    word-break: break-all;
    margin: 0.5rem 0;
    display: block;
}

.warning {
    color: #856404;
    background-color: #fff3cd;
    border: 1px solid #ffeeba;
    padding: 0.75rem 1.25rem;
    border-radius: 0.25rem;
    margin-top: 1rem;
}

pre {
    background: #f8f9fa;
    padding: 1rem;
    border-radius: 4px;
    overflow-x: auto;
}

code {
    font-family: monospace;
}

.error {
    color: #721c24;
    background-color: #f8d7da;
    border: 1px solid #f5c6cb;
    padding: 0.75rem 1.25rem;
    border-radius: 0.25rem;
    margin-top: 1rem;
}

.workspace-info {
    flex-grow: 1;
    padding: 15px;
}

.workspace-info h3 {
    margin: 0 0 10px 0;
    color: #2c3e50;
    font-size: 1.2em;
}

.workspace-info p {
    margin: 5px 0;
    color: #666;
}

.project-info {
    margin-top: 10px;
    padding: 10px;
    background-color: #f8f9fa;
    border-radius: 4px;
    border-left: 3px solid #0056b3;
}

.project-info p {
    margin: 3px 0;
    font-size: 0.9em;
}

.project-info p:first-child {
    color: #0056b3;
    font-weight: bold;
}

.workspace-item {
    margin-bottom: 15px;
    border: 1px solid #ddd;
    border-radius: 8px;
    display: flex;
    align-items: flex-start;
    background-color: white;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}

.delete-button {
    margin: 15px;
    align-self: center;
}

.delete-button:hover {
    background-color: #c82333;
}

.danger-button {
    background-color: #dc3545;
    color: white;
    margin-top: 20px;
    width: 100%;
}

.danger-button:hover {
    background-color: #c82333;
}

.button-container {
    display: flex;
    gap: 1rem;
    margin-top: 1rem;
    justify-content: space-between;
}

.button-container .button {
    flex: 1;
    text-align: center;
}

.logout-button {
    background-color: #dc3545;
    color: white;
}

.logout-button:hover {
    background-color: #c82333;
}
"""

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Custom Exceptions
class DaytonaError(Exception):
    """Base exception for Daytona-related errors."""
    pass

class ConfigError(Exception):
    """Configuration-related errors."""
    pass

# Data Models
@dataclass
class ApiKey:
    name: str
    keyHash: str
    type: str

@dataclass
class Workspace:
    id: str
    name: str
    target: str
    projects: List[Dict[str, Any]]

@dataclass
class Project:
    name: str
    repository: Dict[str, Any]
    image: str
    user: str

def filter_user_keys(api_keys):
    """Filter out system keys (default, app) from the list."""
    SYSTEM_KEYS = {'default', 'app'}  # Define system keys to filter out
    return [key for key in api_keys if key.name not in SYSTEM_KEYS]

def create_error_response(title: str, message: str):
    """Create a standardized error response."""
    return Titled(
        title,
        Container(
            Card(
                H2(title),
                P(message, cls="error-message"),
                A("Back to Login", href="/login", cls="button")
            )
        )
    )

def setup_secret_key() -> str:
    """Setup and validate secret key with appropriate fallbacks."""
    secret_key = os.getenv('SECRET_KEY')
    if not secret_key:
        if os.getenv('ENVIRONMENT') == 'production':
            raise ConfigError("""
            SECRET_KEY must be set in production!
            Generate one with:
            python3 -c 'import secrets; print(secrets.token_hex(32))'
            """)
        secret_key = secrets.token_hex(32)
        logger.info("Generated development SECRET_KEY")

        env_file = '.env'
        try:
            mode = 'a' if os.path.exists(env_file) else 'w'
            with open(env_file, mode) as f:
                f.write(f'\nSECRET_KEY={secret_key}')
        except IOError as e:
            logger.warning(f"Could not save SECRET_KEY to .env: {e}")

    return secret_key

def setup_config() -> Dict[str, str]:
    """Setup and validate configuration."""
    env_name = os.getenv('ENVIRONMENT', 'development')
    env_file = f"{env_name}.env"
    if Path(env_file).exists():
        load_dotenv(env_file)
    else:
        load_dotenv()

    config = {
        'DAYTONA_API_URL': os.getenv('DAYTONA_API_URL', 'http://localhost:3986'),
        'DAYTONA_API_KEY': os.getenv('DAYTONA_API_KEY'),
        'BASE_URL': os.getenv('BASE_URL', 'http://localhost:5001'),
        'SECRET_KEY': setup_secret_key(),
        'USER': os.getenv('APP_USER', 'admin'),
        'PASSWORD_SALT': os.getenv('PASSWORD_SALT'),  # Add this line
        'HASHED_PASSWORD': os.getenv('HASHED_PASSWORD'),  # Add this line
    }

    # Validate required authentication configuration
    required_auth_fields = ['USER', 'PASSWORD_SALT', 'HASHED_PASSWORD']
    missing = [f for f in required_auth_fields if not config.get(f)]
    if missing:
        raise ConfigError(f"Missing required authentication configuration: {', '.join(missing)}")

    return config

def format_uptime(seconds: int) -> str:
    """Format uptime from seconds to a human-readable string."""
    if seconds <= 0:
        return "Not running"

    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)

    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if seconds > 0 or not parts:
        parts.append(f"{seconds}s")

    return " ".join(parts)

def before(req, sess):
    """Beforeware function to check authentication."""
    # Get auth from session
    auth = req.scope['auth'] = sess.get('auth', None)

    # Get current path
    path = req.url.path

    # List of paths that don't require authentication
    public_paths = ['/login', '/logout', '/favicon.ico', '/static']

    # Check if current path is public
    is_public = any(path.startswith(p) for p in public_paths)

    # If not authenticated and not accessing public path, redirect to login
    if not auth and not is_public:
        return RedirectResponse('/login', status_code=303)

    # If authenticated and trying to access login page, redirect to home
    if auth and path == '/login':
        return RedirectResponse('/', status_code=303)

    return None

def validate_auth_config():
    """Validate authentication configuration."""
    if os.getenv('ENVIRONMENT') == 'production':
        if config['USER'] == 'admin' or config['PASSWORD'] == 'admin':
            raise ConfigError(
                "Default credentials (admin/admin) are not allowed in production. "
                "Please set USER and PASSWORD in your environment variables."
            )

def Navigation(current_page=""):
    """Common navigation component."""
    return Nav(
        Ul(
            Li(A("Get Started", href="/?show_getting_started=true", cls=("active" if current_page == "dashboard" else ""))),
            Li(A("API Keys", href="/api-keys", cls=("active" if current_page == "api-keys" else ""))),
            Li(A("Workspaces", href="/workspaces", cls=("active" if current_page == "workspaces" else ""))),
            Li(A("SDK ↗", href="https://github.com/daytonaio/sdk/", target="_blank")),
            Li(A("GitHub ↗", href="https://github.com/daytonaio/daytona/", target="_blank")),
            Li(A("Docs ↗", href="https://daytona.io/docs", target="_blank")),
            Li(A("Logout", href="/logout", cls="contrast")),
        )
    )

class DaytonaClient:
    def __init__(self, base_url: str, initial_api_key: Optional[str] = None, timeout: int = 10):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.api_key = initial_api_key

    def _make_request(self, method: str, endpoint: str, skip_auth: bool = False, **kwargs) -> Optional[requests.Response]:
        """Make HTTP request with authentication."""
        try:
            # Add authentication header if we have an API key and skip_auth is False
            if self.api_key and not skip_auth:
                headers = kwargs.get('headers', {})
                headers['Authorization'] = f'Bearer {self.api_key}'
                kwargs['headers'] = headers

            kwargs['timeout'] = kwargs.get('timeout', self.timeout)
            response = self.session.request(method, f"{self.base_url}{endpoint}", **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.Timeout:
            logger.error(f"Request timeout: {endpoint}")
            raise DaytonaError("Request to Daytona API timed out")
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error: {endpoint}")
            raise DaytonaError("Could not connect to Daytona server")
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error {e.response.status_code}: {endpoint}")
            if e.response.status_code == 401:
                raise DaytonaError("Authentication failed. Please check your API key.")
            raise DaytonaError(f"Daytona API returned error: {e.response.status_code}")
        except Exception as e:
            logger.error(f"Unexpected error in Daytona API request: {str(e)}")
            raise DaytonaError(f"Unexpected error: {str(e)}")

    def initialize(self) -> str:
        """Initialize Daytona client and get first API key."""
        if self.api_key:
            try:
                self._make_request('GET', '/apikey')
                logger.info("Successfully verified existing Daytona API key")
                return self.api_key
            except DaytonaError:
                logger.warning("Existing API key is invalid, attempting to generate new one")
                self.api_key = None

        try:
            response = self._make_request(
                'POST',
                '/apikey/initial-key',
                skip_auth=True
            )
            if response and response.text:
                self.api_key = response.text
                logger.info("Successfully generated initial Daytona API key")
                return self.api_key
        except Exception as e:
            logger.error(f"Failed to initialize Daytona client: {e}")
            raise DaytonaError(
                "Could not initialize Daytona connection. "
                "Please ensure DAYTONA_API_KEY is set in your environment "
                "or that you have permission to generate new keys."
            )

    def list_api_keys(self) -> List[ApiKey]:
        """List all API keys."""
        try:
            response = self._make_request('GET', '/apikey')
            if response:
                keys_data = response.json()
                return [ApiKey(**key) for key in keys_data]
            return []
        except Exception as e:
            logger.error(f"Error listing API keys: {e}")
            return []

    def generate_api_key(self, key_name: str, key_type: str = "client") -> Optional[str]:
        """Generate a new API key."""
        try:
            response = self._make_request('POST', f'/apikey/{key_name}')
            return response.text if response else None
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 500:
                logger.error(f"Server error while generating API key: {e.response.text}")
                raise DaytonaError("Server error: Unable to generate API key. The key name might be invalid or already exists.")
            raise DaytonaError(f"Failed to generate API key: {str(e)}")
        except Exception as e:
            logger.error(f"Error generating API key: {e}")
            raise DaytonaError(f"Unexpected error while generating API key: {str(e)}")

    def revoke_api_key(self, key_name: str) -> bool:
        """Revoke an API key."""
        try:
            response = self._make_request('DELETE', f'/apikey/{key_name}')
            return bool(response)
        except Exception as e:
            logger.error(f"Error revoking API key: {e}")
            return False

    def list_workspaces(self) -> List[Dict[str, Any]]:
        """List all workspaces."""
        try:
            response = self._make_request('GET', '/workspace', headers={'Accept': 'application/json'})
            if not response:
                logger.error("No response from workspace listing endpoint")
                return []

            workspaces = response.json()
            logger.info(f"Retrieved workspaces: {workspaces}")  # Debug log

            # Handle both array and object responses
            if isinstance(workspaces, dict):
                workspaces = [workspaces]
            elif not isinstance(workspaces, list):
                logger.error(f"Unexpected workspace data format: {type(workspaces)}")
                return []

            # Filter out any None or invalid entries
            return [w for w in workspaces if isinstance(w, dict) and w.get('id')]

        except Exception as e:
            logger.error(f"Error listing workspaces: {e}")
            return []

    def get_workspace(self, workspace_id: str) -> Optional[Dict[str, Any]]:
        """Get details of a specific workspace."""
        try:
            response = self._make_request('GET', f'/workspace/{workspace_id}')
            if response:
                workspace = response.json()
                logger.info(f"Retrieved workspace details: {workspace}")  # Debug log
                return workspace
            return None
        except Exception as e:
            logger.error(f"Error getting workspace: {e}")
            return None

    def delete_workspace(self, workspace_id: str) -> bool:
        """Delete a specific workspace."""
        try:
            # Add force=true query parameter to ensure deletion
            response = self._make_request('DELETE', f'/workspace/{workspace_id}', params={'force': 'true'})
            return bool(response)
        except Exception as e:
            logger.error(f"Error deleting workspace: {e}")
            return False

    def delete_all_workspaces(self) -> bool:
        """Delete all workspaces."""
        try:
            workspaces = self.list_workspaces()
            for workspace in workspaces:
                self.delete_workspace(workspace['id'])
            return True
        except Exception as e:
            logger.error(f"Error deleting all workspaces: {e}")
            return False

def generate_python_example(api_key: Optional[str] = None, api_url: str = None) -> str:
    """Generate Python example code with optional API key."""
    return f'''from daytona_sdk import Daytona, DaytonaConfig

config = DaytonaConfig(
    api_key="{api_key or 'YOUR_API_KEY'}",
    server_url="{api_url}",
    target="local"
)
daytona = Daytona(config=config)

workspace = daytona.create()

code = """
import platform
import os

print(f"Hello from the sandbox!")
print(f"I'm running on Python {{platform.python_version()}}")
print(f"This code is running in: {{platform.system()}}")
"""

response = workspace.process.code_run(code)
print(response.result)

daytona.remove(workspace)'''

# Initialize app and client
try:
    config = setup_config()
    validate_auth_config()

    # Initialize beforeware
    bware = Beforeware(before, skip=[r'/favicon\.ico', r'/static/.*'])

    app, rt = fast_app(
        secret_key=config['SECRET_KEY'],
        htmx=True,
        pico=True,
        debug=os.getenv('ENVIRONMENT') != 'production',
        before=bware,  # Add beforeware here
        hdrs=(
            Style(additional_styles),
            Meta(name="color-scheme", content="dark light")
        )
    )
    daytona = DaytonaClient(
        base_url=config['DAYTONA_API_URL'],
        initial_api_key=config.get('DAYTONA_API_KEY')  # Pass initial API key if available
    )

    # Initialize Daytona client and verify/get API key
    try:
        initial_key = daytona.initialize()
        logger.info("Daytona client initialized successfully")
    except DaytonaError as e:
        logger.warning(f"Could not initialize Daytona client: {e}")
except (ConfigError, DaytonaError) as e:
    logger.error(f"Failed to initialize app: {e}")
    raise

@rt("/")
def get(auth, req):
    """Main dashboard with onboarding or redirect if already onboarded."""
    try:
        all_keys = daytona.list_api_keys()
        user_keys = filter_user_keys(all_keys)
        has_user_keys = len(user_keys) > 0

        # Check if user has API keys and is not explicitly requesting the getting started page
        if len(user_keys) > 0 and not req.query_params.get('show_getting_started'):
            return RedirectResponse('/api-keys', status_code=303)

        # Otherwise show the getting started page
        python_example = generate_python_example(api_url=config['DAYTONA_API_URL'])

        # Add copy button JavaScript
        copy_script = """
        function copyText(text, buttonEl) {
            navigator.clipboard.writeText(text).then(() => {
                buttonEl.classList.add('copied');
                const originalText = buttonEl.textContent;
                buttonEl.textContent = 'Copied!';

                setTimeout(() => {
                    buttonEl.classList.remove('copied');
                    buttonEl.textContent = originalText;
                }, 2000);
            }).catch(err => console.error('Failed to copy:', err));
        }

        function copyFromElement(elementId, buttonEl) {
            const element = document.getElementById(elementId);
            if (element) {
                copyText(element.textContent.trim(), buttonEl);
            }
        }

        // Simplified copy functions using the generic copyFromElement
        const copyHandlers = {
            'install': 'install-command',
            'code': 'python-example',
            'run': 'run-command'
        };

        Object.entries(copyHandlers).forEach(([action, elementId]) => {
            window[`copy${action.charAt(0).toUpperCase() + action.slice(1)}`] =
                (buttonEl) => copyFromElement(elementId, buttonEl);
        });
        """

        return Titled(
            f"Daytona Demo Dashboard",
            Container(
                Navigation(current_page="dashboard"),
                Card(
                    H2("Create Your First AI Sandbox Super Fast"),
                    Div(
                        H3("1. Create an API key"),
                        Div(
                            Form(
                                Button(
                                    "Get Your First Key",
                                    type="submit",
                                    disabled=has_user_keys
                                ),
                                hx_post="/api-keys/onboarding",
                                hx_target="#api-key-status"
                            ) if not has_user_keys else A(
                                "Manage API Keys",
                                href="/api-keys",
                                cls="button"
                            ),
                            Div(id="api-key-status"),
                            cls="step-content"
                        ),
                        cls="setup-step"
                    ),
                    Div(
                        H3("2. Run any code inside a remote sandbox"),
                        Div(
                            H4("First, install the Daytona SDK"),
                            P("Open your terminal and run:"),
                            Div(
                                Pre(
                                    Code("pip install daytona-sdk"),
                                    cls="language-bash",
                                    id="install-command"
                                ),
                                Button(
                                    "Copy",
                                    onclick="copyInstall(this)",
                                    cls="copy-button"
                                ),
                                cls="code-container"
                            ),
                            H4("Next, create and execute a sample Python script"),
                            P("1. Save this code in a file named ", Code("app.py"), ":"),
                            Div(
                                Pre(
                                    Code(python_example),
                                    cls="language-python",
                                    id="python-example"
                                ),
                                Button(
                                    "Copy",
                                    onclick="copyCode(this)",
                                    cls="copy-button"
                                ),
                                cls="code-container"
                            ),
                            P("2. Run the example script with:"),
                            Div(
                                Pre(
                                    Code("python app.py"),
                                    cls="language-bash",
                                    id="run-command"
                                ),
                                Button(
                                    "Copy",
                                    onclick="copyRun(this)",
                                    cls="copy-button"
                                ),
                                cls="code-container"
                            ),
                            P(
                            "Note: The first workspace creation may take a few minutes as it pulls the image. "
                            "Subsequent workspace creations will be much faster.",
                            cls="warning"
                            ),
                            cls="step-content"
                        ),
                        cls="setup-step"
                    ),
                    cls="onboarding-card"
                ),
                Script(copy_script)
            )
        )
    except DaytonaError as e:
        logger.error(f"Dashboard error: {e}")
        return create_error_response("Error", str(e))

@rt("/api-keys/onboarding")
def post():
    """Create default API key for onboarding."""
    try:
        new_key = daytona.generate_api_key("onboarding", key_type="client")
        if not new_key:
            return Div(
                P("Failed to create API key", cls="error"),
                id="api-key-status"
            )

        # Generate updated example with the new key
        updated_example = generate_python_example(
            api_key=new_key,
            api_url=config['DAYTONA_API_URL']
        )

        return Div(
            P("API key created successfully!"),
            P("Your API key: ", Code(new_key), cls="api-key"),
            P("Please save this key as it won't be shown again.", cls="warning"),
            Script(f"""
                document.getElementById('python-example').textContent = `{updated_example}`;
                // Re-initialize syntax highlighting if you're using it
                if (typeof hljs !== 'undefined') {{
                    document.querySelectorAll('pre code').forEach((el) => {{
                        hljs.highlightElement(el);
                    }});
                }}
            """),
            id="api-key-status"
        )
    except DaytonaError as e:
        return Div(
            P(f"Error creating API key: {str(e)}", cls="error"),
            id="api-key-status"
        )

@rt("/workspaces")
def get(auth):
    """Workspaces management page."""
    try:
        workspaces = daytona.list_workspaces()

        return Titled(
            f"Daytona Workspaces",
            Container(
                Navigation(current_page="api-keys"),
                Card(
                    H2("Workspaces"),
                    Div(
                        id="workspaces-list",
                        *[Div(
                            Div(
                                H3(workspace.get('name', 'Unnamed Workspace')),
                                P(f"ID: {workspace.get('id', 'N/A')}"),
                                P(f"Target: {workspace.get('target', 'N/A')}"),
                                *[Div(
                                    P(f"Repository: {project.get('repository', {}).get('url', 'N/A')}"),
                                    P(f"Branch: {project.get('repository', {}).get('branch', 'N/A')}"),
                                    P(f"Uptime: {format_uptime(project.get('state', {}).get('uptime', 0))}"),
                                    P(f"Last Updated: {project.get('state', {}).get('updatedAt', 'N/A')}"),
                                    cls="project-info"
                                ) for project in workspace.get('projects', [])],
                                _class="workspace-info"
                            ),
                            Button(
                                "Delete",
                                hx_delete=f"/workspace/{workspace['id']}",
                                hx_target="#workspaces-list",
                                hx_confirm="Are you sure you want to delete this workspace?",
                                _class="delete-button"
                            ),
                            _class="workspace-item"
                        ) for workspace in workspaces] if workspaces else [P("No workspaces found")]
                    ),
                    Div(
                        Button(
                            "Delete All Workspaces",
                            hx_delete="/workspace/all",
                            hx_target="#workspaces-list",
                            hx_confirm="Are you sure you want to delete ALL workspaces? This cannot be undone!",
                            _class="danger-button"
                        ) if workspaces else None,
                        id="delete-all-container"
                    )
                )
            )
        )
    except DaytonaError as e:
        logger.error(f"Workspaces view error: {e}")
        return create_error_response("Error", str(e))

@rt("/initialize")
def post():
    """Initialize Daytona and create first API key."""
    try:
        initial_key = daytona.initialize()
        return Div(
            P("Daytona initialized successfully!"),
            Script("setTimeout(function() { window.location.reload(); }, 1500);"),
            id="setup-status"
        )
    except DaytonaError as e:
        return Div(
            P(f"Error initializing Daytona: {str(e)}"),
            cls="error",
            id="setup-status"
        )

@rt("/login")
def get(req):
    """Login page with error handling."""
    error = req.query_params.get('error')
    error_message = None

    if error == 'invalid_credentials':
        error_message = "Invalid username or password"
    elif error == 'server_error':
        error_message = "An error occurred. Please try again."

    return Titled(
        "Daytona AI Sandboxes DEMO",
        Container(
            Card(
                H2("Login"),
                P(error_message, cls="error-message") if error_message else None,
                Form(
                    Input(name="username", type="text", placeholder="Username", required=True),
                    Input(name="password", type="password", placeholder="Password", required=True),
                    Button("Login", type="submit"),
                    method="post",
                    action="/login"
                )
            )
        )
    )

@rt("/login")
def post(username: str, password: str, session):
    """Login handler using hashed password."""
    logger.info("=== Login Attempt ===")
    logger.info(f"Username provided: {username}")
    logger.info(f"Expected username: {config['USER']}")
    logger.info(f"Password provided: {password}")
    logger.info(f"Stored salt: {config['PASSWORD_SALT']}")
    logger.info(f"Stored hash: {config['HASHED_PASSWORD']}")

    if username != config['USER']:
        logger.warning("Login failed - invalid username")
        return RedirectResponse('/login?error=invalid_credentials', status_code=303)

    try:
        # Verify password
        verification_result = verify_password(
            stored_password=config['HASHED_PASSWORD'],
            stored_salt=config['PASSWORD_SALT'],
            provided_password=password
        )
        logger.info(f"Password verification result: {verification_result}")

        if verification_result:
            logger.info("Login successful")
            session['auth'] = username
            return RedirectResponse('/', status_code=303)
        else:
            logger.warning("Login failed - invalid password")
            return RedirectResponse('/login?error=invalid_credentials', status_code=303)

    except Exception as e:
        logger.error(f"Password verification error: {e}")
        logger.exception(e)  # This will log the full stack trace
        return RedirectResponse('/login?error=server_error', status_code=303)

@rt("/logout")
def get(session):
    """Logout handler."""
    try:
        session.clear()
    except Exception as e:
        logger.error(f"Error during logout: {e}")
    return RedirectResponse('/login', status_code=303)

@rt("/api-keys")
def get(auth):
    """API Keys management page."""
    try:
        all_keys = daytona.list_api_keys()
        user_keys = filter_user_keys(all_keys)

        return Titled(
            f"API Keys Management",
            Container(
                Navigation(current_page="api-keys"),
                Card(
                    H2("API Keys"),
                    Form(
                        Input(
                            id="key_name",
                            name="key_name",
                            placeholder="API Key Name",
                            required=True,
                            pattern="[a-zA-Z0-9-_]+",
                            title="Use only letters, numbers, hyphens, and underscores"
                        ),
                        Button("Create New Key", type="submit", cls="primary"),
                        hx_post="/api-keys",
                        hx_target="#keys-list"
                    ),
                    Div(
                        id="keys-list",
                        *[Div(
                            Div(
                                P(f"Name: {key.name}", cls="key-name"),
                                Button(
                                    "Delete",
                                    hx_delete=f"/api-keys/{key.name}",
                                    hx_target="#keys-list",
                                    hx_confirm=f"Are you sure you want to delete the API key '{key.name}'?",
                                    cls="delete-button"
                                ),
                            ),
                            cls="key-item"
                        ) for key in user_keys] if user_keys else [
                            P("No API keys found. Create one above.", cls="no-keys-message")
                        ]
                    )
                )
            )
        )
    except DaytonaError as e:
        logger.error(f"API Keys page error: {e}")
        return create_error_response("Error", str(e))

@rt("/api-keys")
def post(key_name: str):
    """Create a new API key."""
    try:
        # Validate key name
        if not key_name:
            return Div(
                P("Key name is required", cls="error-message"),
                id="keys-list"
            )

        # Add validation for key name format
        import re
        if not re.match("^[a-zA-Z0-9-_]+$", key_name):
            return Div(
                P("Key name can only contain letters, numbers, hyphens, and underscores",
                  cls="error-message"),
                id="keys-list"
            )

        # Check if key already exists
        existing_keys = daytona.list_api_keys()
        if any(key.name == key_name for key in existing_keys):
            return Div(
                P(f"An API key with name '{key_name}' already exists",
                  cls="error-message"),
                id="keys-list"
            )

        # Generate new key
        new_key = daytona.generate_api_key(key_name)
        if not new_key:
            return Div(
                P("Failed to create API key - the server returned an empty response",
                  cls="error-message"),
                id="keys-list"
            )

        # Get updated list and filter system keys
        all_keys = daytona.list_api_keys()
        user_keys = filter_user_keys(all_keys)

        return Div(
            Div(
                P("API key created successfully!", cls="success-message"),
                P("Your API key: ", Code(new_key), cls="api-key"),
                P("Please save this key as it won't be shown again.", cls="warning"),
            ),
            Div(
                *[Div(
                    Div(
                        P(f"Name: {key.name}", cls="key-name"),
                        Button(
                            "Delete",
                            hx_delete=f"/api-keys/{key.name}",
                            hx_target="#keys-list",
                            hx_confirm=f"Are you sure you want to delete the API key '{key.name}'?",
                            cls="delete-button"
                        ),
                    ),
                    cls="key-item"
                ) for key in user_keys] if user_keys else [
                    P("No API keys found. Create one above.", cls="no-keys-message")
                ]
            ),
            id="keys-list"
        )
    except DaytonaError as e:
        return Div(
            P(f"Error: {str(e)}", cls="error-message"),
            id="keys-list"
        )
    except Exception as e:
        logger.error(f"Unexpected error in API key creation: {e}")
        return Div(
            P("An unexpected error occurred while creating the API key. Please try again.",
              cls="error-message"),
            id="keys-list"
        )

@rt("/api-keys/{key_name}")
def delete(key_name: str):
    """Delete API key."""
    try:
        # Prevent deletion of system keys
        if key_name in {'default', 'app'}:
            return Div(
                P("Cannot delete system keys", cls="error-message"),
                id="keys-list"
            )

        if not daytona.revoke_api_key(key_name):
            return Div(
                P("Failed to delete API key", cls="error-message"),
                id="keys-list"
            )

        # Get updated list and filter system keys
        all_keys = daytona.list_api_keys()
        user_keys = filter_user_keys(all_keys)

        return Div(
            *[Div(
                Div(
                    P(f"Name: {key.name}", cls="key-name"),
                    Button(
                        "Delete",
                        hx_delete=f"/api-keys/{key.name}",
                        hx_target="#keys-list",
                        hx_confirm=f"Are you sure you want to delete the API key '{key.name}'?",
                        cls="delete-button"
                    ),
                ),
                cls="key-item"
            ) for key in user_keys] if user_keys else [
                P("No API keys found. Create one above.", cls="no-keys-message")
            ],
            id="keys-list"
        )
    except DaytonaError as e:
        return Div(
            P(f"Error: {str(e)}", cls="error-message"),
            id="keys-list"
        )

# Add routes for workspace operations
@rt("/workspace/{workspace_id}")
def delete(workspace_id: str):
    """Delete a workspace."""
    try:
        if not daytona.delete_workspace(workspace_id):
            return "Failed to delete workspace"

        workspaces = daytona.list_workspaces()
        return Div(
            *[Div(
                Div(
                    H3(workspace.get('name', 'Unnamed Workspace')),
                    P(f"ID: {workspace.get('id', 'N/A')}"),
                    P(f"Target: {workspace.get('target', 'N/A')}"),
                    *[Div(
                        P(f"Repository: {project.get('repository', {}).get('url', 'N/A')}"),
                        P(f"Branch: {project.get('repository', {}).get('branch', 'N/A')}"),
                        P(f"Uptime: {format_uptime(project.get('state', {}).get('uptime', 0))}"),
                        P(f"Last Updated: {project.get('state', {}).get('updatedAt', 'N/A')}"),
                        cls="project-info"
                    ) for project in workspace.get('projects', [])],
                    _class="workspace-info"
                ),
                Button(
                    "Delete",
                    hx_delete=f"/workspace/{workspace['id']}",
                    hx_target="#workspaces-list",
                    hx_confirm="Are you sure you want to delete this workspace?",
                    _class="delete-button"
                ),
                _class="workspace-item"
            ) for workspace in workspaces] if workspaces else [P("No workspaces found")],
            id="workspaces-list"
        )
    except DaytonaError as e:
        return f"Error: {str(e)}"

@rt("/workspace/all")
def delete():
    """Delete all workspaces."""
    try:
        # Get list of all workspaces first
        workspaces = daytona.list_workspaces()

        success = True
        errors = []

        # Delete each workspace individually
        for workspace in workspaces:
            try:
                if not daytona.delete_workspace(workspace['id']):
                    success = False
                    errors.append(f"Failed to delete workspace {workspace.get('name', workspace['id'])}")
            except DaytonaError as e:
                success = False
                errors.append(f"Error deleting workspace {workspace.get('name', workspace['id'])}: {str(e)}")
                logger.error(f"Error deleting workspace {workspace['id']}: {e}")

        if not success:
            return Div(
                P("Failed to delete some workspaces:"),
                *[P(error) for error in errors],
                id="workspaces-list"
            )

        return Div(
            P("No workspaces found"),
            id="workspaces-list"
        )
    except DaytonaError as e:
        logger.error(f"Error in delete all workspaces: {e}")
        return f"Error: {str(e)}"

@rt("/workspace/{workspace_id}")
def delete(workspace_id: str):
    """Delete a workspace."""
    try:
        # Make sure to include force=true in the query parameters
        response = daytona._make_request(
            'DELETE',
            f'/workspace/{workspace_id}',
            params={'force': 'true'}
        )
        if not response:
            return "Failed to delete workspace"

        workspaces = daytona.list_workspaces()
        return Div(
            *[Div(
                Div(
                    H3(workspace.get('name', 'Unnamed Workspace')),
                    P(f"ID: {workspace.get('id', 'N/A')}"),
                    P(f"Target: {workspace.get('target', 'N/A')}"),
                    *[Div(
                        P(f"Repository: {project.get('repository', {}).get('url', 'N/A')}"),
                        P(f"Branch: {project.get('repository', {}).get('branch', 'N/A')}"),
                        P(f"Uptime: {format_uptime(project.get('state', {}).get('uptime', 0))}"),
                        P(f"Last Updated: {project.get('state', {}).get('updatedAt', 'N/A')}"),
                        cls="project-info"
                    ) for project in workspace.get('projects', [])],
                    _class="workspace-info"
                ),
                Button(
                    "Delete",
                    hx_delete=f"/workspace/{workspace['id']}",
                    hx_target="#workspaces-list",
                    hx_confirm="Are you sure you want to delete this workspace?",
                    _class="delete-button"
                ),
                _class="workspace-item"
            ) for workspace in workspaces] if workspaces else [P("No workspaces found")],
            id="workspaces-list"
        )
    except DaytonaError as e:
        logger.error(f"Error deleting workspace {workspace_id}: {e}")
        return f"Error: {str(e)}"

if __name__ == "__main__":
    serve(host="0.0.0.0", port=5001)