#!/bin/bash
# Autho Gateway Node - One-Line Installer
# Usage: curl -fsSL https://autho.pinkmahi.com/downloads/gateway-node/quick-install.sh | bash

set -e

echo "🌐 Autho Gateway Node - Quick Installer"
echo "========================================"

# Check Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed"
    echo "   Please install Node.js 18+ from: https://nodejs.org/"
    exit 1
fi

NODE_VERSION=$(node -e 'process.stdout.write(process.versions.node.split(".")[0])')
if [ "$NODE_VERSION" -lt 18 ]; then
    echo "❌ Node.js 18+ required. Current: $(node --version)"
    exit 1
fi

echo "✅ Node.js $(node --version)"

# Create temp directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

# Download files
echo "📥 Downloading gateway node..."
CACHE_BUST=$(date +%s)
curl -fsSL "https://autho.pinkmahi.com/downloads/gateway-node/gateway-package.js?v=${CACHE_BUST}" -o gateway-package.js
curl -fsSL "https://autho.pinkmahi.com/downloads/gateway-node/package.json?v=${CACHE_BUST}" -o package.json

# Install directory
INSTALL_DIR="$HOME/autho-gateway-node"
echo "📁 Installing to: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# Copy files
cp gateway-package.js "$INSTALL_DIR/"
cp package.json "$INSTALL_DIR/"
cd "$INSTALL_DIR"

# Install dependencies
echo "📦 Installing dependencies..."
npm install --silent

# Create start script
cat > start.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
node gateway-package.js
EOF
chmod +x start.sh

# Create systemd service (optional)
if command -v systemctl &> /dev/null; then
    echo "🔧 Creating systemd service..."
    sudo tee /etc/systemd/system/autho-gateway.service > /dev/null << EOF
[Unit]
Description=Autho Gateway Node
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/start.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    sudo systemctl daemon-reload
    sudo systemctl enable autho-gateway.service
    echo "✅ Systemd service created"
fi

# Cleanup
rm -rf "$TEMP_DIR"

echo ""
echo "✅ Installation complete!"
echo ""
echo "🚀 Start the gateway node:"
echo "   cd $INSTALL_DIR"
echo "   ./start.sh"
echo ""
if command -v systemctl &> /dev/null; then
    echo "   Or use systemd:"
    echo "   sudo systemctl start autho-gateway"
    echo ""
fi
echo "🌐 Gateway will run on: http://localhost:3001"
echo "📊 Health check: http://localhost:3001/health"
echo ""
echo "🎉 Welcome to the Autho network!"
