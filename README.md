# Daytona SaaS MVP

A web-based dashboard for managing Daytona development environments, built with Python and FastHTML.

## Overview

This project provides a web interface for:
- Managing API keys
- Monitoring workspaces
- Setting up development environments
- User authentication and session management

## Features

- 🔐 Secure authentication system
- 🔑 API key management
- 📊 Workspace monitoring and management
- 🚀 Quick setup wizard for new users
- 🎨 Dark/light theme support
- 📱 Responsive design using PicoCSS

## Prerequisites

- Python 3.8+
- pip package manager
- A running Daytona server instance

## Installation

A. Prepare machine
1. Clone the repository:
```bash
git clone https://github.com/nkkko/daytona-saas-mvp.git
cd daytona-saas-mvp
chmod +x setup.sh
./setup.sh
```

B. Run the dashboard:
1. Clone the repository:
```bash
git clone https://github.com/nkkko/daytona-saas-mvp.git
cd daytona-saas-mvp
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Generate authentication credentials:
```bash
python scripts/generate_password.py
```

4. Create a `.env` file with the following variables:
```env
DAYTONA_API_URL=http://localhost:3986
DAYTONA_API_KEY=your_api_key
BASE_URL=http://localhost:5001
APP_USER=admin
PASSWORD_SALT=generated_salt
HASHED_PASSWORD=generated_hash
ENVIRONMENT=development
```

## Running the Application

Start the server:
```bash
python main.py
```

The application will be available at `http://localhost:5001`

## Project Structure

```
daytona-saas-mvp/
├── favicon.ico
├── requirements.txt        # Project dependencies
├── utils/
│   ├── auth.py            # Authentication utilities
│   └── __init__.py
├── scripts/
│   └── generate_password.py  # Password generation tool
└── main.py                # Main application file
```

## Security Features

- Password hashing using PBKDF2
- Secure session management
- CSRF protection
- Environment-based configuration

## Configuration

The application supports different environment configurations:
- Development: Uses `.env` file
- Production: Requires secure environment variables

### Production Configuration

For production deployment, ensure:
- Strong passwords are set
- HTTPS is enabled
- Appropriate security headers are configured
- Environment variables are securely managed

## License

AGPL v3
