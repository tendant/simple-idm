# Deployment Configuration

This directory contains nginx configuration and deployment scripts for Simple IDM.

## Files

- **`.env.example`** - Example environment configuration
- **`nginx.conf.template`** - Nginx configuration template
- **`deploy-nginx.sh`** - Automated nginx deployment script
- **`certbot-cloudflare.sh`** - SSL certificate via Cloudflare DNS challenge
- **`nginx.conf`** - Generated nginx config (not in git)

## Quick Start

### 1. Configure Environment

```bash
# Copy example config
cp .env.example .env

# Edit with your values
vim .env
```

### 2. Deploy

```bash
# On your server
cd /path/to/simple-idm/deploy
sudo ./deploy-nginx.sh
```

The script will:
- Load configuration from `.env`
- Generate `nginx.conf` from template
- Deploy to `/etc/nginx/sites-available/simple-idm`
- Enable the site
- Test and reload nginx

## Configuration (.env)

```bash
# Domain
DOMAIN=idm.example.com

# Backend port
BACKEND_PORT=4000

# Web root directory
WEB_ROOT=/var/www/idm.example.com/html

# Log file prefix
LOG_PREFIX=idm

# SSL certificate paths
SSL_CERT=/etc/letsencrypt/live/idm.example.com/fullchain.pem
SSL_KEY=/etc/letsencrypt/live/idm.example.com/privkey.pem
```

## Architecture

```
Internet → nginx (443)
              ↓
         /var/www/${DOMAIN}/html (SolidJS)
              ↓
         /api/* → IDM Backend (localhost:${BACKEND_PORT})
                      ↓
                  PostgreSQL (localhost:5432)
```

## SSL Certificates

### Option 1: Cloudflare DNS Challenge (Recommended)

No need to stop nginx. Works even if port 80/443 is not accessible.

```bash
# Add your Cloudflare API token to .env
vim .env  # Add CLOUDFLARE_API_TOKEN

# Run the script
sudo ./certbot-cloudflare.sh
```

**Get Cloudflare API token:**
1. Go to https://dash.cloudflare.com/profile/api-tokens
2. Create token with permissions:
   - `Zone.DNS` (Edit)
   - `Zone.Zone` (Read)
3. Add token to `.env` file

### Option 2: Standalone (requires stopping nginx)

```bash
sudo systemctl stop nginx
sudo certbot certonly --standalone -d ${DOMAIN}
sudo systemctl start nginx
```

## Manual Deployment

If the script doesn't work:

```bash
# Generate config from template
export $(cat .env | grep -v '^#' | xargs)
envsubst '${DOMAIN} ${BACKEND_PORT} ${WEB_ROOT} ${LOG_PREFIX} ${SSL_CERT} ${SSL_KEY}' \
    < nginx.conf.template > nginx.conf

# Copy to nginx
sudo cp nginx.conf /etc/nginx/sites-available/simple-idm

# Enable site
sudo ln -s /etc/nginx/sites-available/simple-idm /etc/nginx/sites-enabled/

# Test and reload
sudo nginx -t
sudo systemctl reload nginx
```

## Different Environments

You can use different `.env` files for different environments:

```bash
# Production
cp .env.example .env.prod
# Edit for production

# Staging
cp .env.example .env.staging
# Edit for staging

# Deploy to specific environment
cp .env.prod .env
sudo ./deploy-nginx.sh
```

## Complete Deployment Guide

### 1. Install Dependencies

```bash
# Update system
sudo apt update
sudo apt upgrade -y

# Install Go
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Install nginx
sudo apt install nginx -y

# Install certbot
sudo apt install certbot python3-certbot-nginx -y

# Install PostgreSQL
sudo apt install postgresql postgresql-contrib -y
```

### 2. Setup Database

```bash
sudo -u postgres psql

CREATE DATABASE idm;
CREATE USER idm WITH PASSWORD 'your-strong-password';
GRANT ALL PRIVILEGES ON DATABASE idm TO idm;
\q
```

### 3. Build Backend

```bash
cd /path/to/simple-idm
go build -o /usr/local/bin/simple-idm cmd/quick/main.go
```

### 4. Build Frontend

```bash
cd /path/to/simple-idm/frontend
npm install
npm run build
```

### 5. Create Web Root

```bash
sudo mkdir -p /var/www/idm.example.com/html
sudo cp -r dist/* /var/www/idm.example.com/html/
```

### 6. Deploy Nginx Config

```bash
cd /path/to/simple-idm/deploy
cp .env.example .env
vim .env  # Configure your settings
sudo ./deploy-nginx.sh
```

### 7. Get SSL Certificate

```bash
sudo systemctl stop nginx
sudo certbot certonly --standalone -d idm.example.com
sudo systemctl start nginx
```

### 8. Create Systemd Service

Create `/etc/systemd/system/simple-idm.service`:

```ini
[Unit]
Description=Simple IDM Service
After=network.target postgresql.service

[Service]
Type=simple
User=idm
WorkingDirectory=/opt/simple-idm
Environment="DATABASE_URL=postgres://idm:password@localhost:5432/idm"
Environment="PORT=4000"
Environment="JWT_SECRET=your-jwt-secret-here"
ExecStart=/usr/local/bin/simple-idm
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable simple-idm
sudo systemctl start simple-idm
sudo systemctl status simple-idm
```

### 9. Verify Deployment

```bash
# Check backend
curl http://localhost:4000/health

# Check frontend via nginx
curl https://idm.example.com/health

# Check logs
sudo journalctl -u simple-idm -f
sudo tail -f /var/log/nginx/idm_access.log
```

## Troubleshooting

### Port 4000 already in use

```bash
sudo lsof -i :4000
sudo kill -9 <PID>
```

### Database connection failed

```bash
# Test connection
psql -h localhost -U idm -d idm

# Check PostgreSQL is running
sudo systemctl status postgresql
```

### Frontend not loading

```bash
# Check if files exist
ls -la /var/www/idm.example.com/html/

# Check nginx error logs
sudo tail -f /var/log/nginx/idm_error.log
```

### SSL certificate issues

```bash
# Check certificate
sudo certbot certificates

# Renew if needed
sudo certbot renew
```

## Monitoring

### Check Service Health

```bash
# Backend
curl http://localhost:4000/health

# Frontend
curl https://idm.example.com/health
```

### View Logs

```bash
# Backend logs
sudo journalctl -u simple-idm -f

# Nginx access logs
sudo tail -f /var/log/nginx/idm_access.log

# Nginx error logs
sudo tail -f /var/log/nginx/idm_error.log
```

## Updates

### Update Frontend

```bash
cd /path/to/simple-idm/frontend
git pull
npm install
npm run build
sudo cp -r dist/* /var/www/idm.example.com/html/
```

### Update Backend

```bash
cd /path/to/simple-idm
git pull
go build -o /usr/local/bin/simple-idm cmd/quick/main.go
sudo systemctl restart simple-idm
```

### Update Nginx Config

```bash
cd /path/to/simple-idm/deploy
vim .env  # Make changes
sudo ./deploy-nginx.sh
```
