#!/bin/bash
# Autho Operator Node - One-Line Installer
# Usage: curl -fsSL https://autho.pinkmahi.com/downloads/operator-node/quick-install.sh | bash

set -e

echo "⚡ Autho Operator Node - Quick Installer"
echo "======================================="

# Check Node.js
if ! command -v node >/dev/null 2>&1; then
  echo "❌ Node.js is not installed"
  echo "   Please install Node.js 18+ from: https://nodejs.org/"
  exit 1
fi

NODE_MAJOR=$(node -e 'process.stdout.write(process.versions.node.split(".")[0])')
if [ "$NODE_MAJOR" -lt 18 ]; then
  echo "❌ Node.js 18+ required. Current: $(node --version)"
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  echo "❌ Git is not installed"
  echo "   Please install Git first: https://git-scm.com/downloads"
  exit 1
fi

echo "✅ Node.js $(node --version)"
echo "✅ Git $(git --version)"

INSTALL_DIR="$HOME/autho-operator-node"
REPO_URL="https://github.com/Pink-Mahi/autho.git"

echo "📁 Installing to: $INSTALL_DIR"

if [ -d "$INSTALL_DIR/.git" ]; then
  echo "🔄 Existing install found, pulling latest..."
  cd "$INSTALL_DIR"
  git pull --ff-only
else
  rm -rf "$INSTALL_DIR"
  git clone "$REPO_URL" "$INSTALL_DIR"
  cd "$INSTALL_DIR"
fi

echo "📦 Installing dependencies..."
npm install --silent

echo "🏗️  Building..."
npm run build --silent

cat > start.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
# Start operator node
npm run operator
EOF
chmod +x start.sh

echo "✅ Installed. To start:"
echo "   cd $INSTALL_DIR && ./start.sh"
