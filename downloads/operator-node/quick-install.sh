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

# --- Auto-install TURN (coturn) and generate secret ---
TURN_DIR="$INSTALL_DIR/operator-data"
mkdir -p "$TURN_DIR"

if command -v openssl &> /dev/null; then
  TURN_SECRET=$(openssl rand -hex 16)
else
  TURN_SECRET=$(head -c 16 /dev/urandom | xxd -p)
fi

cat > "$TURN_DIR/turn.json" <<EOF
{
  "username": "autho",
  "credential": "${TURN_SECRET}"
}
EOF

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
  echo "🧩 Installing coturn (TURN server)..."
  if command -v apt-get &> /dev/null; then
    sudo apt-get update -y
    sudo apt-get install -y coturn
  elif command -v yum &> /dev/null; then
    sudo yum install -y coturn
  elif command -v dnf &> /dev/null; then
    sudo dnf install -y coturn
  elif command -v pacman &> /dev/null; then
    sudo pacman -Sy --noconfirm coturn
  fi

  if [ -d /etc ]; then
    sudo tee /etc/turnserver.conf > /dev/null <<EOF
listening-port=3478
fingerprint
use-auth-secret
static-auth-secret=${TURN_SECRET}
realm=autho
no-cli
EOF
  fi

  sudo systemctl enable --now coturn 2>/dev/null || sudo systemctl enable --now turnserver 2>/dev/null || true
elif [[ "$OSTYPE" == "darwin"* ]]; then
  if command -v brew &> /dev/null; then
    echo "🧩 Installing coturn via Homebrew..."
    brew install coturn || true
    TURN_CONF="$(brew --prefix)/etc/turnserver.conf"
    cat > "$TURN_CONF" <<EOF
listening-port=3478
fingerprint
use-auth-secret
static-auth-secret=${TURN_SECRET}
realm=autho
no-cli
EOF
    brew services restart coturn || true
  fi
fi

cat > start.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
# Start operator node
npm run operator
EOF
chmod +x start.sh

echo "✅ Installed. To start:"
echo "   cd $INSTALL_DIR && ./start.sh"
