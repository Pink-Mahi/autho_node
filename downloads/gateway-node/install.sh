#!/bin/bash

# Autho Gateway Node Installation Script
# For macOS and Linux

set -e

echo "🌐 Autho Gateway Node Installation"
echo "=================================="

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 18+ first."
    echo "   Visit: https://nodejs.org/"
    exit 1
fi

echo "✅ Node.js found: $(node --version)"

# Check Node.js version
NODE_VERSION=$(node -e 'process.stdout.write(process.versions.node.split('.')[0])')
if [ "$NODE_VERSION" -lt 18 ]; then
    echo "❌ Node.js version must be 18 or higher. Current: $(node --version)"
    exit 1
fi

echo "✅ Node.js version is compatible"

# Create installation directory
INSTALL_DIR="$HOME/autho-gateway-node"
echo "📁 Creating installation directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Download the latest release
echo "📥 Downloading Autho Gateway Node..."
if command -v curl &> /dev/null; then
    curl -L https://github.com/Pink-Mahi/autho/archive/main.tar.gz -o autho-gateway.tar.gz
elif command -v wget &> /dev/null; then
    wget https://github.com/Pink-Mahi/autho/archive/main.tar.gz -O autho-gateway.tar.gz
else
    echo "❌ Neither curl nor wget found. Please install one of them."
    exit 1
fi

# Extract the archive
echo "📦 Extracting archive..."
tar -xzf autho-gateway.tar.gz
cd autho-main

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Build the project
echo "🔨 Building the project..."
npm run build

# Create configuration file
echo "⚙️ Creating configuration..."
cat > gateway-config.json <<EOF
{
  "nodeId": "gateway-$(date +%s)",
  "port": 3001,
  "host": "0.0.0.0",
  "seedNodes": ["autho.pinkmahi.com:3000", "autho.cartpathcleaning.com"],
  "dataDir": "./gateway-data",
  "cache": {
    "enabled": true,
    "ttl": 300000
  },
  "rateLimit": {
    "enabled": true,
    "window": 60000,
    "max": 100
  }
}
EOF

# Create startup script
echo "🚀 Creating startup script..."
cat > start-gateway.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
node dist/gateway/gateway-node.js --config=gateway-config.json
EOF

chmod +x start-gateway.sh

# Create systemd service (Linux only)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "🔧 Creating systemd service..."
    sudo tee /etc/systemd/system/autho-gateway.service > /dev/null <<EOF
[Unit]
Description=Autho Gateway Node
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR/autho-main
ExecStart=$INSTALL_DIR/autho-main/start-gateway.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable autho-gateway.service
    echo "✅ Systemd service created and enabled"
fi

# Create macOS launch agent (macOS only)
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "🔧 Creating macOS launch agent..."
    LAUNCH_AGENTS_DIR="$HOME/Library/LaunchAgents"
    mkdir -p "$LAUNCH_AGENTS_DIR"
    
    tee "$LAUNCH_AGENTS_DIR/com.autho.gateway.plist" > /dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.autho.gateway</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/autho-main/start-gateway.sh</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR/autho-main</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

    launchctl load "$LAUNCH_AGENTS_DIR/com.autho.gateway.plist"
    echo "✅ macOS launch agent created"
fi

# Cleanup
echo "🧹 Cleaning up..."
cd ..
rm -f autho-gateway.tar.gz

echo ""
echo "✅ Installation complete!"
echo ""
echo "🚀 To start the gateway node:"
echo "   cd $INSTALL_DIR/autho-main"
echo "   ./start-gateway.sh"
echo ""
echo "🌐 Gateway node will be available at:"
echo "   http://localhost:3001"
echo ""
echo "📊 Check status:"
echo "   curl http://localhost:3001/health"
echo ""
echo "📖 For more information, see:"
echo "   $INSTALL_DIR/autho-main/downloads/gateway-node/README.md"
echo ""
echo "🎉 Welcome to the Autho network!"
