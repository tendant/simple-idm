#!/bin/bash
# Nginx deployment script for Simple IDM

set -e  # Exit on any error

echo "=== Simple IDM Nginx Deployment ==="
echo ""

# Check if running as root/sudo
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run with sudo:"
    echo "   sudo ./deploy-nginx.sh"
    exit 1
fi

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "📁 Deploy directory: $SCRIPT_DIR"
echo ""

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "❌ Error: .env file not found in $SCRIPT_DIR"
    echo ""
    echo "Please create .env file from .env.example:"
    echo "   cp .env.example .env"
    echo "   vim .env  # Edit with your values"
    exit 1
fi

# Check if template exists
if [ ! -f "nginx.conf.template" ]; then
    echo "❌ Error: nginx.conf.template not found in $SCRIPT_DIR"
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

if [ -z "$BACKEND_PORT" ]; then
    echo "❌ Error: BACKEND_PORT not set in .env"
    exit 1
fi

if [ -z "$WEB_ROOT" ]; then
    echo "❌ Error: WEB_ROOT not set in .env"
    exit 1
fi

if [ -z "$LOG_PREFIX" ]; then
    echo "❌ Error: LOG_PREFIX not set in .env"
    exit 1
fi

echo "✅ Configuration loaded:"
echo "   Domain: $DOMAIN"
echo "   Backend port: $BACKEND_PORT"
echo "   Web root: $WEB_ROOT"
echo "   Log prefix: $LOG_PREFIX"
echo ""

# Generate nginx.conf from template
echo "🔨 Generating nginx.conf from template..."
envsubst '${DOMAIN} ${BACKEND_PORT} ${WEB_ROOT} ${LOG_PREFIX} ${SSL_CERT} ${SSL_KEY}' \
    < nginx.conf.template \
    > nginx.conf

echo "✅ nginx.conf generated"
echo ""

# Copy config to sites-available
echo "📋 Copying nginx configuration..."
cp nginx.conf /etc/nginx/sites-available/simple-idm
echo "✅ Config copied to /etc/nginx/sites-available/simple-idm"
echo ""

# Create symbolic link to enable site
echo "🔗 Enabling site..."
rm -f /etc/nginx/sites-enabled/simple-idm
ln -s /etc/nginx/sites-available/simple-idm /etc/nginx/sites-enabled/
echo "✅ Site enabled"
echo ""

# Test nginx configuration
echo "🧪 Testing nginx configuration..."
if nginx -t; then
    echo "✅ Nginx configuration is valid"
    echo ""
else
    echo "❌ Nginx configuration test failed!"
    echo "Please fix errors and try again"
    exit 1
fi

# Reload nginx
echo "🔄 Reloading nginx..."
systemctl reload nginx
echo "✅ Nginx reloaded successfully"
echo ""

# Show status
echo "📊 Nginx status:"
systemctl status nginx --no-pager -l | head -n 3
echo ""

echo "✨ Deployment complete!"
echo ""
echo "Enabled site:"
ls -la /etc/nginx/sites-enabled/ | grep simple-idm
echo ""
echo "Configuration:"
echo "  Domain: $DOMAIN"
echo "  Web root: $WEB_ROOT"
echo ""
echo "Next steps:"
echo "1. Ensure DNS record points to this server:"
echo "   $DOMAIN → server IP"
echo ""
echo "2. Create web root directory if it doesn't exist:"
echo "   sudo mkdir -p $WEB_ROOT"
echo ""
echo "3. Obtain SSL certificate (if not already done):"
echo "   sudo systemctl stop nginx"
echo "   sudo certbot certonly --standalone -d $DOMAIN"
echo "   sudo systemctl start nginx"
echo ""
echo "4. Deploy your frontend build:"
echo "   sudo cp -r frontend/dist/* $WEB_ROOT/"
echo ""
echo "5. Test your site:"
echo "   curl https://$DOMAIN/health"
