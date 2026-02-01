#!/bin/bash
# Autho Gateway - One-Line Installer
# Usage: curl -fsSL https://autho.pinkmahi.com/install-gateway.sh | bash
#
# This script downloads and runs an Autho Gateway node.
# Works on Linux, macOS, and WSL.

set -e

echo "🌐 Autho Gateway Node - One-Line Installer"
echo "==========================================="
echo ""

# Check for Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is required but not installed."
    echo ""
    echo "Install Node.js first:"
    echo "  - macOS: brew install node"
    echo "  - Ubuntu/Debian: sudo apt install nodejs npm"
    echo "  - Or visit: https://nodejs.org/"
    exit 1
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    echo "❌ Node.js 18+ required. You have: $(node -v)"
    exit 1
fi

echo "✅ Node.js $(node -v) detected"

# Create directory
INSTALL_DIR="${AUTHO_INSTALL_DIR:-$HOME/autho-gateway}"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "📁 Installing to: $INSTALL_DIR"

# Download gateway package
echo "⬇️  Downloading gateway package..."
curl -fsSL "https://autho.pinkmahi.com/api/gateway/download/gateway-package.js" -o gateway-package.js

# Download package.json
curl -fsSL "https://autho.pinkmahi.com/api/gateway/download/package.json" -o package.json

# Install dependencies
echo "📦 Installing dependencies..."
npm install --production --silent

# Create start script
cat > start.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
node gateway-package.js
EOF
chmod +x start.sh

# Create systemd service file (for Linux)
if [ -d /etc/systemd/system ]; then
    cat > autho-gateway.service << EOF
[Unit]
Description=Autho Gateway Node
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/node $INSTALL_DIR/gateway-package.js
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    echo ""
    echo "📝 Systemd service file created: autho-gateway.service"
    echo "   To install as service:"
    echo "   sudo cp autho-gateway.service /etc/systemd/system/"
    echo "   sudo systemctl enable autho-gateway"
    echo "   sudo systemctl start autho-gateway"
fi

echo ""
echo "✅ Installation complete!"
echo ""
echo "🚀 To start the gateway:"
echo "   cd $INSTALL_DIR && ./start.sh"
echo ""
echo "📊 Once running, check health at:"
echo "   http://localhost:3001/health"
echo ""
echo "🌍 To run as a PUBLIC gateway (serves UI to users):"
echo "   GATEWAY_PUBLIC=true GATEWAY_PUBLIC_URL=https://your-domain.com ./start.sh"
echo ""
