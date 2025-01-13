#!/bin/bash

# Daytona Installation Script
# This script automates the installation of Daytona with remote profiles
# chmod +x setup.sh
# sudo ./setup.sh

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

# Configuration variables
DAYTONA_USER="daytona"
DAYTONA_INSTALL_DIR="/home/$DAYTONA_USER/.local/bin"
APP_DIR="/home/$DAYTONA_USER/daytona-saas-mvp"
VENV_DIR="$APP_DIR/venv"
SERVER_IP=$(hostname -I | awk '{print $1}')

# Prompt for username
read -p "Enter the desired username (default: admin): " ADMIN_USERNAME
ADMIN_USERNAME=${ADMIN_USERNAME:-admin}  # Use 'admin' if no input provided

# Validate username
if [[ ! $ADMIN_USERNAME =~ ^[a-zA-Z0-9_-]+$ ]]; then
    error "Invalid username. Username can only contain letters, numbers, underscores, and hyphens."
fi

# Function to run commands as daytona user
run_as_daytona() {
    su - $DAYTONA_USER -c "$1"
}

# Function to verify service status
verify_service() {
    local service_name=$1
    local max_attempts=${2:-30}
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        if systemctl is-active --quiet $service_name; then
            log "$service_name is running"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    error "$service_name failed to start after $max_attempts seconds"
}

# Function to wait for port to be available
wait_for_port() {
    local port=$1
    local max_attempts=${2:-30}
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        if nc -z localhost $port; then
            log "Port $port is available"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    error "Port $port not available after $max_attempts seconds"
}

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root"
fi

log "Starting Daytona installation..."

# System Updates
log "Updating system packages..."
apt-get update -y || error "Failed to update system packages"
apt-get upgrade -y || error "Failed to upgrade packages"
apt-get install -y systemd-container python3 python3-pip python3.12-venv nginx git netcat-openbsd || error "Failed to install required packages"

# Create Daytona User
log "Creating Daytona user..."
if ! id "$DAYTONA_USER" &>/dev/null; then
    adduser --disabled-password --gecos "" $DAYTONA_USER || error "Failed to create Daytona user"
    usermod -aG sudo $DAYTONA_USER || error "Failed to add Daytona user to sudo group"
fi

# Install Docker
log "Installing Docker..."
apt-get install -y ca-certificates curl || error "Failed to install Docker prerequisites"
install -m 0755 -d /etc/apt/keyrings || error "Failed to create keyrings directory"
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc || error "Failed to download Docker GPG key"
chmod a+r /etc/apt/keyrings/docker.asc || error "Failed to set permissions on Docker GPG key"

# Add Docker repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null || error "Failed to add Docker repository"

# Update and install Docker
apt-get update || error "Failed to update package list"
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin || error "Failed to install Docker"

# Add daytona user to docker group and set permissions
log "Configuring Docker permissions..."
usermod -aG docker $DAYTONA_USER || error "Failed to add user to Docker group"
chmod 666 /var/run/docker.sock || error "Failed to set Docker socket permissions"

# Verify Docker installation
log "Verifying Docker installation..."
run_as_daytona "docker run hello-world" || error "Docker verification failed"

# Setup Daytona Installation Directory
log "Setting up Daytona installation directory..."
mkdir -p $DAYTONA_INSTALL_DIR
chown -R $DAYTONA_USER:$DAYTONA_USER /home/$DAYTONA_USER/.local
chmod 755 $DAYTONA_INSTALL_DIR
run_as_daytona "echo 'export PATH=\$PATH:$DAYTONA_INSTALL_DIR' >> /home/$DAYTONA_USER/.bashrc"

# Install Daytona Binary
log "Installing Daytona binary..."
TEMP_DIR=$(mktemp -d)
curl -fsSL https://download.daytona.io/daytona/latest/daytona-linux-amd64 -o "$TEMP_DIR/daytona" || error "Failed to download Daytona binary"
chmod +x "$TEMP_DIR/daytona"
mv "$TEMP_DIR/daytona" "$DAYTONA_INSTALL_DIR/"
chown $DAYTONA_USER:$DAYTONA_USER "$DAYTONA_INSTALL_DIR/daytona"
rm -rf "$TEMP_DIR"

# Setup Systemd Services
log "Setting up systemd services..."

# Daytona Service
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

# Daytona App Service
cat > /etc/systemd/system/daytona-app.service << EOF
[Unit]
Description=Daytona Python Application
After=network.target daytona.service

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

# Start Services
log "Starting services..."
systemctl daemon-reload

# Start Daytona service
systemctl enable daytona
systemctl restart daytona
verify_service daytona

# Generate API key
log "Generating API key..."
sleep 5  # Wait for Daytona service to be fully ready
API_KEY=$(run_as_daytona "PATH=\$PATH:$DAYTONA_INSTALL_DIR daytona api-key generate app")
echo "$API_KEY" > "/home/$DAYTONA_USER/api_key.txt"
chown $DAYTONA_USER:$DAYTONA_USER "/home/$DAYTONA_USER/api_key.txt"

# Setup Application
log "Setting up application..."
run_as_daytona "cd /home/$DAYTONA_USER && git clone https://github.com/nkkko/daytona-saas-mvp" || error "Failed to clone repository"

# Setup Python Environment
log "Setting up Python environment..."
run_as_daytona "cd $APP_DIR && python3 -m venv venv" || error "Failed to create virtual environment"
run_as_daytona "cd $APP_DIR && source venv/bin/activate && pip install -r requirements.txt" || error "Failed to install Python requirements"

# Generate Password and Authentication Details
log "Generating authentication details..."
ADMIN_PASSWORD=$(openssl rand -hex 12)
SALT=$(openssl rand -hex 16)

# Create Python script for password hashing
cat > "$APP_DIR/scripts/generate_hash.py" << 'EOF'
import hashlib
import sys

def hash_password(password, salt):
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    )
    return hashlib.sha256(key).hexdigest()

if __name__ == "__main__":
    print(hash_password(sys.argv[1], sys.argv[2]))
EOF

# Generate password hash
HASH=$(run_as_daytona "cd $APP_DIR && source venv/bin/activate && python scripts/generate_hash.py '$ADMIN_PASSWORD' '$SALT'")

# Create .env file
log "Creating .env file..."
cat > "$APP_DIR/.env" << EOF
ENVIRONMENT=development
BASE_URL=http://$SERVER_IP:5001
DAYTONA_API_URL=http://$SERVER_IP:3986
DAYTONA_API_KEY=$API_KEY
SECRET_KEY=$(openssl rand -hex 32)
PASSWORD_SALT=$SALT
HASHED_PASSWORD=$HASH
APP_USER=$ADMIN_USERNAME
EOF

chown $DAYTONA_USER:$DAYTONA_USER "$APP_DIR/.env"
chmod 600 "$APP_DIR/.env"

# Save credentials
echo "Admin Username: $ADMIN_USERNAME" > "/home/$DAYTONA_USER/admin_credentials.txt"
echo "Admin Password: $ADMIN_PASSWORD" >> "/home/$DAYTONA_USER/admin_credentials.txt"
chown $DAYTONA_USER:$DAYTONA_USER "/home/$DAYTONA_USER/admin_credentials.txt"
chmod 600 "/home/$DAYTONA_USER/admin_credentials.txt"

# Start Application Services
log "Starting application services..."
systemctl enable daytona-app
systemctl restart daytona-app
verify_service daytona-app

# Configure Nginx
ln -sf /etc/nginx/sites-available/daytona /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t || error "Nginx configuration test failed"
systemctl restart nginx
verify_service nginx

# Configure Firewall
log "Configuring firewall..."
ufw allow 80/tcp || true
ufw allow 5001/tcp || true
ufw allow 3986/tcp || true

# Verify Application
log "Verifying application..."
wait_for_port 5001
wait_for_port 3986

# Test Login
log "Testing login..."
sleep 5  # Wait for application to be fully ready
CURL_OUTPUT=$(curl -s -X POST \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "username=$ADMIN_USERNAME&password=$ADMIN_PASSWORD" \
     "http://localhost:5001/login" -v 2>&1)

# Display Configuration
echo "============================================"
echo "Installation Complete!"
echo "============================================"
echo "Admin Credentials:"
cat "/home/$DAYTONA_USER/admin_credentials.txt"
echo "============================================"
echo "Service URLs:"
echo "Web Interface: http://$SERVER_IP"
echo "Daytona API: http://$SERVER_IP:3986"
echo "============================================"

log "Setup completed successfully!"
