#!/bin/bash
source ~/daytona-web/venv/bin/activate
export GITHUB_CLIENT_ID="your_github_client_id"
export GITHUB_CLIENT_SECRET="your_github_client_secret"
export FLASK_SECRET_KEY="your_secret_key"
python app.py
EOF