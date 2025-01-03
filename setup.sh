#!/bin/bash

# Daytona Installation Script
# This script automates the installation of Daytona with remote profiles

# Error handling
set -e

# Logging function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

error() {
    log "ERROR: $1" >&2
    exit 1
}

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root"
fi

# Configuration variables
DAYTONA_USER="daytona"
DOCKER_KEYRING_DIR="/etc/apt/keyrings"
DOCKER_GPG_FILE="$DOCKER_KEYRING_DIR/docker.asc"
DAYTONA_INSTALL_DIR="/home/$DAYTONA_USER/.local/bin"
APP_DIR="/home/$DAYTONA_USER/daytona-saas-mvp"
VENV_DIR="$APP_DIR/venv"

log "Starting Daytona installation..."

# Update system and cleanup
log "Updating system packages..."
apt-get update -y || error "Failed to update system packages"
apt-get autoremove -y || error "Failed to autoremove packages"
apt-get upgrade -y || error "Failed to upgrade packages"

# Create Daytona user
log "Creating Daytona user..."
if ! id "$DAYTONA_USER" &>/dev/null; then
    adduser --disabled-password --gecos "" $DAYTONA_USER || error "Failed to create Daytona user"
    usermod -aG sudo $DAYTONA_USER || error "Failed to add Daytona user to sudo group"
fi

# Install required packages
log "Installing required packages..."
apt-get install -y systemd-container python3 python3-pip python3.12-venv nginx git || error "Failed to install required packages"

# Function to run commands as daytona user
run_as_daytona() {
    su - $DAYTONA_USER -c "$1"
}

# Create Daytona installation directory and set permissions
log "Creating Daytona installation directory..."
mkdir -p $DAYTONA_INSTALL_DIR
chown -R $DAYTONA_USER:$DAYTONA_USER /home/$DAYTONA_USER/.local
chmod 755 $DAYTONA_INSTALL_DIR

# Add Daytona bin directory to PATH for daytona user
run_as_daytona "echo 'export PATH=\$PATH:$DAYTONA_INSTALL_DIR' >> /home/$DAYTONA_USER/.bashrc"
# Download and install Daytona directly
log "Installing Daytona..."
TEMP_DIR=$(mktemp -d)
DAYTONA_BINARY_URL="https://download.daytona.io/daytona/latest/daytona-linux-amd64"
curl -fsSL $DAYTONA_BINARY_URL -o "$TEMP_DIR/daytona" || error "Failed to download Daytona binary"
chmod +x "$TEMP_DIR/daytona"
mv "$TEMP_DIR/daytona" "$DAYTONA_INSTALL_DIR/"
chown $DAYTONA_USER:$DAYTONA_USER "$DAYTONA_INSTALL_DIR/daytona"
rm -rf "$TEMP_DIR"

# Enable lingering for Daytona user
loginctl enable-linger $DAYTONA_USER || error "Failed to enable lingering for Daytona user"

# Create a systemd service file for Daytona
cat > /etc/systemd/system/daytona.service << EOF
[Unit]
Description=Daytona Server
After=network.target

[Service]
Type=simple
User=$DAYTONA_USER
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/$DAYTONA_USER/.local/bin"
ExecStart=/home/$DAYTONA_USER/.local/bin/daytona serve
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Start and enable Daytona service
log "Starting Daytona service..."
systemctl daemon-reload
systemctl enable daytona
systemctl start daytona

# Wait for server to start and verify it's running
log "Waiting for Daytona server to start..."
for i in {1..30}; do
    if systemctl is-active --quiet daytona; then
        log "Daytona server started successfully"
        # Additional wait to ensure the server is fully initialized
        sleep 10
        break
    fi
    if [ $i -eq 30 ]; then
        error "Timeout waiting for Daytona server to start"
    fi
    sleep 1
done

# Generate API key and save to file
log "Generating API key..."
API_KEY=$(run_as_daytona "PATH=\$PATH:$DAYTONA_INSTALL_DIR daytona api-key generate app")
echo "$API_KEY" > "/home/$DAYTONA_USER/api_key.txt"
chown $DAYTONA_USER:$DAYTONA_USER "/home/$DAYTONA_USER/api_key.txt"

# Clone repository
log "Cloning repository..."
run_as_daytona "cd /home/$DAYTONA_USER && git clone https://github.com/nkkko/daytona-saas-mvp" || error "Failed to clone repository"
# Extract API key and update .env file
log "Updating .env file..."
# Read the entire api_key.txt file into variables, handling multi-line content
while IFS= read -r line; do
    if [[ $line == *"DAYTONA_API_KEY="* ]]; then
        EXTRACTED_API_KEY=$(echo "$line" | cut -d'=' -f2 | tr -d ' ')
    elif [[ $line == *"DAYTONA_SERVER_URL="* ]]; then
        EXTRACTED_SERVER_URL=$(echo "$line" | cut -d'=' -f2 | tr -d ' ')
    fi
done < "/home/$DAYTONA_USER/api_key.txt"

# Create and setup Python virtual environment
log "Setting up Python virtual environment..."
run_as_daytona "cd $APP_DIR && python3 -m venv venv" || error "Failed to create virtual environment"
run_as_daytona "cd $APP_DIR && source venv/bin/activate && pip install -r requirements.txt" || error "Failed to install Python requirements"

# Generate password and update .env file with authentication details
log "Generating password and authentication details..."

# Create a Python script for password hashing that matches auth.py
cat > /tmp/generate_hash.py << 'EOF'
import hashlib
import secrets
import sys
import json

def hash_password(password, salt=None):
    """Hash a password with a salt using PBKDF2."""
    if salt is None:
        salt = secrets.token_hex(16)

    # Print debug information
    print(f"Debug - Password: {password}", file=sys.stderr)
    print(f"Debug - Salt: {salt}", file=sys.stderr)

    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000  # number of iterations
    )
    hash_value = hashlib.sha256(key).hexdigest()

    # Print debug information
    print(f"Debug - Hash: {hash_value}", file=sys.stderr)

    return {
        'salt': salt,
        'hash': hash_value,
        'password': password
    }

if __name__ == "__main__":
    password = sys.argv[1]
    result = hash_password(password)
    print(json.dumps(result))
EOF

# Generate a random password
ADMIN_PASSWORD=$(openssl rand -hex 12)
log "Generated admin password: $ADMIN_PASSWORD"

# Generate salt and hash using the Python script
HASH_OUTPUT=$(python3 /tmp/generate_hash.py "$ADMIN_PASSWORD")
log "Python script output: $HASH_OUTPUT"

# Parse JSON output
SALT=$(echo $HASH_OUTPUT | python3 -c "import sys, json; print(json.load(sys.stdin)['salt'])")
HASH=$(echo $HASH_OUTPUT | python3 -c "import sys, json; print(json.load(sys.stdin)['hash'])")

log "Generated salt: $SALT"
log "Generated hash: $HASH"

# Create a verification script
cat > /tmp/verify_password.py << 'EOF'
import hashlib
import sys
import json

def verify_password(password, salt, stored_hash):
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    )
    computed_hash = hashlib.sha256(key).hexdigest()
    return {
        'password': password,
        'salt': salt,
        'stored_hash': stored_hash,
        'computed_hash': computed_hash,
        'match': computed_hash == stored_hash
    }

if __name__ == "__main__":
    password = sys.argv[1]
    salt = sys.argv[2]
    stored_hash = sys.argv[3]
    result = verify_password(password, salt, stored_hash)
    print(json.dumps(result))
EOF

# Verify the password immediately
VERIFY_OUTPUT=$(python3 /tmp/verify_password.py "$ADMIN_PASSWORD" "$SALT" "$HASH")
log "Verification output: $VERIFY_OUTPUT"

# Get the server's IP address
SERVER_IP=$(hostname -I | awk '{print $1}')

# Create temporary file for env updates
TEMP_ENV=$(mktemp)

# Update or add environment variables
{
    echo "ENVIRONMENT=development"
    echo "BASE_URL=http://$SERVER_IP:5001"
    echo "DAYTONA_API_URL=http://$SERVER_IP:3986"
    echo "DAYTONA_API_KEY=$EXTRACTED_API_KEY"
    echo "SECRET_KEY=$(openssl rand -hex 32)"
    echo "PASSWORD_SALT=$SALT"
    echo "HASHED_PASSWORD=$HASH"
} > "$TEMP_ENV"

# Display the contents of the .env file for verification
log "Generated .env file contents:"
cat "$TEMP_ENV"

# Move temporary file to final location
mv "$TEMP_ENV" "$APP_DIR/.env"
chown $DAYTONA_USER:$DAYTONA_USER "$APP_DIR/.env"
chmod 600 "$APP_DIR/.env"

# Save credentials to a file
echo "Admin Username: admin" > "/home/$DAYTONA_USER/admin_credentials.txt"
echo "Admin Password: $ADMIN_PASSWORD" >> "/home/$DAYTONA_USER/admin_credentials.txt"
chown $DAYTONA_USER:$DAYTONA_USER "/home/$DAYTONA_USER/admin_credentials.txt"
chmod 600 "/home/$DAYTONA_USER/admin_credentials.txt"

# Create a test script in the app directory
cat > "$APP_DIR/test_login.py" << 'EOF'
#!/usr/bin/env python3
import os
from dotenv import load_dotenv
import sys
import hashlib
import hmac

def hash_password(password: str, salt: str) -> str:
    """Hash a password with a salt using PBKDF2."""
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000  # number of iterations
    )
    return hashlib.sha256(key).hexdigest()

def verify_password(stored_password: str, stored_salt: str, provided_password: str) -> bool:
    """Verify a password against its hash."""
    computed_hash = hash_password(provided_password, stored_salt)
    return hmac.compare_digest(stored_password.encode('utf-8'), computed_hash.encode('utf-8'))

if __name__ == "__main__":
    # Load environment variables
    load_dotenv()

    # Get stored values
    salt = os.getenv('PASSWORD_SALT')
    stored_hash = os.getenv('HASHED_PASSWORD')

    # Get password from command line argument
    if len(sys.argv) != 2:
        print("Usage: python test_login.py <password>")
        sys.exit(1)

    test_password = sys.argv[1]

    # Verify all required values are present
    if not all([salt, stored_hash, test_password]):
        print("Missing required values:")
        print(f"Salt: {'Yes' if salt else 'No'}")
        print(f"Stored hash: {'Yes' if stored_hash else 'No'}")
        print(f"Test password: {'Yes' if test_password else 'No'}")
        sys.exit(1)

    # Test the password
    result = verify_password(stored_hash, salt, test_password)
    computed_hash = hash_password(test_password, salt)

    print("=== Password Verification Results ===")
    print(f"Test Password: {test_password}")
    print(f"Salt: {salt}")
    print(f"Stored Hash: {stored_hash}")
    print(f"Computed Hash: {computed_hash}")
    print(f"Match: {result}")
EOF

# Make the test script executable
chmod +x "$APP_DIR/test_login.py"

# Test the login credentials (properly escape the password)
log "Testing login credentials..."
run_as_daytona "cd $APP_DIR && source venv/bin/activate && python3 test_login.py '${ADMIN_PASSWORD}'"

# Also create a verification script that matches your auth.py exactly
cat > "$APP_DIR/verify_auth.py" << 'EOF'
#!/usr/bin/env python3
import os
from dotenv import load_dotenv
import sys
from utils.auth import verify_password

def main():
    # Load environment variables
    load_dotenv()

    # Get stored values
    stored_hash = os.getenv('HASHED_PASSWORD')
    stored_salt = os.getenv('PASSWORD_SALT')

    if len(sys.argv) != 2:
        print("Usage: python verify_auth.py <password>")
        sys.exit(1)

    test_password = sys.argv[1]

    # Test using the actual auth.py implementation
    result = verify_password(stored_hash, stored_salt, test_password)

    print("=== Auth.py Verification Results ===")
    print(f"Password: {test_password}")
    print(f"Salt: {stored_salt}")
    print(f"Stored Hash: {stored_hash}")
    print(f"Result: {result}")

if __name__ == "__main__":
    main()
EOF

# Make the verification script executable
chmod +x "$APP_DIR/verify_auth.py"

# Test with both scripts
log "Testing with test_login.py..."
run_as_daytona "cd $APP_DIR && source venv/bin/activate && python3 test_login.py '${ADMIN_PASSWORD}'"

log "Testing with verify_auth.py..."
run_as_daytona "cd $APP_DIR && source venv/bin/activate && python3 verify_auth.py '${ADMIN_PASSWORD}'"

# Test the HTTP endpoint directly
log "Testing HTTP login endpoint..."
curl -X POST \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "username=admin&password=${ADMIN_PASSWORD}" \
     http://localhost:5001/login -v


# Run the test script
log "Testing login credentials..."
run_as_daytona "cd $APP_DIR && source venv/bin/activate && python test_login.py"

# Clean up
rm /tmp/generate_hash.py /tmp/verify_password.py

# Create and setup Python virtual environment
log "Setting up Python virtual environment..."
run_as_daytona "cd $APP_DIR && python3 -m venv venv" || error "Failed to create virtual environment"
run_as_daytona "cd $APP_DIR && source venv/bin/activate && pip install -r requirements.txt" || error "Failed to install Python requirements"

# Create the systemd service file for the Python application
log "Creating systemd service..."
cat > /etc/systemd/system/daytona-app.service << EOF
[Unit]
Description=Daytona Python Application
After=network.target

[Service]
Type=simple
User=$DAYTONA_USER
WorkingDirectory=$APP_DIR
Environment="PATH=$APP_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$APP_DIR/venv/bin/python main.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Configure Nginx
log "Configuring Nginx..."
cat > /etc/nginx/sites-available/daytona << EOF
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:5001;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Start and enable the Python application
log "Starting Python application..."
systemctl daemon-reload
systemctl enable daytona-app
systemctl start daytona-app

# Wait for the application to start
log "Waiting for application to start..."
sleep 5

# Test the credentials one more time through the running application
log "Testing credentials through the running application..."
CURL_OUTPUT=$(curl -s -X POST -d "username=admin&password=$ADMIN_PASSWORD" http://localhost:5001/login -v 2>&1)
log "Login test result: $CURL_OUTPUT"

# Enable Nginx site
ln -sf /etc/nginx/sites-available/daytona /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test and restart Nginx
nginx -t || error "Nginx configuration test failed"
systemctl restart nginx || error "Failed to restart Nginx"

# Configure firewall
log "Configuring firewall..."
ufw allow 80/tcp || true
ufw allow 5001/tcp || true
ufw allow 3986/tcp || true

# Start the Python application
log "Starting Python application..."
systemctl daemon-reload
systemctl enable daytona-app
systemctl start daytona-app

# Display the credentials
echo "============================================"
echo "Admin Credentials:"
cat "/home/$DAYTONA_USER/admin_credentials.txt"
echo "============================================"

# Final configuration output
log "Installation completed successfully!"
log "API Key has been saved to: /home/$DAYTONA_USER/api_key.txt"
log "Please run the following command on your local machine:"
log "daytona profile add --name <profile-name> --url http://$(hostname -I | awk '{print $1}'):3986 --api-key <your-api-key>"

# Add helpful notes
cat << EOF

=== Important Next Steps ===
1. Configure Git providers using: daytona git-providers add
2. Create your first development environment using: daytona create
3. Access your environment using: daytona code

For more information, visit the Daytona documentation.

The API key has been saved to: /home/$DAYTONA_USER/api_key.txt
The application is accessible at: http://$(hostname -I | awk '{print $1}')

To check the services status:
    sudo systemctl status daytona
    sudo systemctl status daytona-app
    sudo systemctl status nginx

To view the logs:
    sudo journalctl -u daytona -f
    sudo journalctl -u daytona-app -f

Admin credentials have been saved to: /home/$DAYTONA_USER/admin_credentials.txt

=== Service URLs ===
Web Interface: http://$(hostname -I | awk '{print $1}')
Daytona API: http://$(hostname -I | awk '{print $1}'):3986
EOF

# Display API key for convenience
echo -e "\n=== API Key ==="
cat "/home/$DAYTONA_USER/api_key.txt"