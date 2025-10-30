#!/bin/bash
# Certbot SSL certificate using Cloudflare DNS challenge

set -e  # Exit on any error

echo "=== Certbot SSL Certificate (Cloudflare DNS) ==="
echo ""

# Check if running as root/sudo
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run with sudo:"
    echo "   sudo ./certbot-cloudflare.sh"
    exit 1
fi

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "❌ Error: .env file not found in $SCRIPT_DIR"
    echo ""
    echo "Please create .env file from .env.example:"
    echo "   cp .env.example .env"
    echo "   vim .env  # Set DOMAIN and CLOUDFLARE_API_TOKEN"
    exit 1
fi

# Load environment variables from .env
echo "📋 Loading configuration from .env..."
export $(cat .env | grep -v '^#' | xargs)

# Validate required variables
if [ -z "$DOMAIN" ]; then
    echo "❌ Error: DOMAIN not set in .env"
    exit 1
fi

if [ -z "$CLOUDFLARE_API_TOKEN" ]; then
    echo "❌ Error: CLOUDFLARE_API_TOKEN not set in .env"
    echo ""
    echo "Get your Cloudflare API token from:"
    echo "https://dash.cloudflare.com/profile/api-tokens"
    echo ""
    echo "Required permissions:"
    echo "  - Zone.DNS (Edit)"
    echo "  - Zone.Zone (Read)"
    exit 1
fi

echo "✅ Configuration loaded:"
echo "   Domain: $DOMAIN"
echo ""

# Check if certbot is installed
if ! command -v certbot &> /dev/null; then
    echo "📦 Installing certbot and cloudflare plugin..."
    apt update
    apt install -y certbot python3-certbot-dns-cloudflare
    echo "✅ Certbot installed"
    echo ""
fi

# Create Cloudflare credentials file
CLOUDFLARE_CREDS="/root/.secrets/certbot/cloudflare.ini"
mkdir -p "$(dirname "$CLOUDFLARE_CREDS")"

echo "🔐 Creating Cloudflare credentials file..."
cat > "$CLOUDFLARE_CREDS" <<EOF
# Cloudflare API token
dns_cloudflare_api_token = ${CLOUDFLARE_API_TOKEN}
EOF

chmod 600 "$CLOUDFLARE_CREDS"
echo "✅ Credentials file created at $CLOUDFLARE_CREDS"
echo ""

# Obtain certificate
echo "🔒 Obtaining SSL certificate for $DOMAIN..."
echo "This may take a few minutes..."
echo ""

certbot certonly \
  --dns-cloudflare \
  --dns-cloudflare-credentials "$CLOUDFLARE_CREDS" \
  --dns-cloudflare-propagation-seconds 60 \
  -d "$DOMAIN" \
  --non-interactive \
  --agree-tos \
  --email "${CERT_EMAIL:-admin@${DOMAIN}}" \
  --keep-until-expiring

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Certificate obtained successfully!"
    echo ""
    echo "Certificate location:"
    echo "  /etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    echo "  /etc/letsencrypt/live/$DOMAIN/privkey.pem"
    echo ""

    # Reload nginx if it's running
    if systemctl is-active --quiet nginx; then
        echo "🔄 Reloading nginx..."
        systemctl reload nginx
        echo "✅ Nginx reloaded"
    else
        echo "ℹ️  Nginx is not running. Start it with:"
        echo "   sudo systemctl start nginx"
    fi

    echo ""
    echo "🎉 SSL certificate ready!"
    echo ""
    echo "Certificate will auto-renew. Test renewal with:"
    echo "  sudo certbot renew --dry-run"
else
    echo ""
    echo "❌ Certificate request failed!"
    echo ""
    echo "Common issues:"
    echo "1. Check your Cloudflare API token has correct permissions"
    echo "2. Verify DNS is managed by Cloudflare for $DOMAIN"
    echo "3. Check Cloudflare API token is not expired"
    exit 1
fi
