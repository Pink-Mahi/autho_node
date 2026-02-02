# Autho Gateway Node

## 🌐 What is a Gateway Node?

A Gateway Node is a **read-only replication node** that serves registry data to the public. Anyone can run a gateway node to:

- ✅ **Replicate the event log** from the main network
- ✅ **Serve HTTP API endpoints** for public access
- ✅ **Provide local registry access** to customers
- ✅ **Offer white-label solutions** for retail stores
- ✅ **Support the decentralized network** without being an operator

## 🚀 Quick Start

### **Option 1: Run Directly (Easiest)**

```bash
# Clone the repository
git clone https://github.com/Pink-Mahi/autho.git
cd autho

# Install dependencies
npm install

# Build the project
npm run build

# Run the gateway node
node dist/gateway/gateway-node.js --mode=gateway --port=3001 --seed=autho.pinkmahi.com
```

### **Option 2: Download Package**

1. Download the gateway node package from autho.pinkmahi.com
2. Extract the package
3. Run the installation script:
   ```bash
   # Windows
   install.bat
   
   # macOS/Linux
   chmod +x install.sh
   ./install.sh
   ```

## ⚙️ Configuration

### **Easy Configuration (Recommended)**

The gateway package supports a simple editable config file:

- `gateway.env` (in the same folder as `gateway-package.js`)

If `gateway.env` exists, the gateway loads it automatically on startup.
This is the easiest way for non-technical users to set options without editing shortcuts or using the command line.

### **Basic Setup**
```bash
node dist/gateway/gateway-node.js \
  --mode=gateway \
  --port=3001 \
  --seed=autho.pinkmahi.com \
  --data-dir=./gateway-data
```

### **Environment Variables**
```bash
# Create .env file
NODE_ENV=production
GATEWAY_PORT=3001
DNS_SEED=autho.pinkmahi.com
DATA_DIR=./gateway-data
MIN_PEERS=3
MAX_PEERS=50
CACHE_ENABLED=true
RATE_LIMIT_ENABLED=true
```

### **Configuration File**
Create `gateway-config.json`:
```json
{
  "nodeId": "gateway-retail-1",
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
```

## 🌱 Seed List (Multi-Seed)

The gateway download package ships with a **baked-in multi-seed list** so it can still bootstrap if any single domain goes offline.

### **Emergency override (no rebuild)**

You can override the seed list at runtime by setting:

```bash
GATEWAY_SEEDS=autho.pinkmahi.com:3000,autho.cartpathcleaning.com
```

or:

```bash
AUTHO_GATEWAY_SEEDS=autho.pinkmahi.com:3000,autho.cartpathcleaning.com
```

### **Updating the baked-in list (current approach)**

For now, the baked-in seed list is updated by periodically updating this repo’s gateway distribution files (the downloadable `downloads/gateway-node/*` package and the gateway TS sources under `src/gateway/*`) and redeploying.

## 🌐 API Endpoints

Once running, your gateway node provides these HTTP endpoints:

### **Health & Status**
- `GET /health` - Health check
- `GET /stats` - Node statistics
- `GET /status` - Detailed status

### **Registry Data**
- `GET /api/registry/state` - Complete registry state
- `GET /api/registry/items/{itemId}` - Specific item
- `GET /api/registry/owners/{address}/items` - Items by owner
- `GET /api/registry/settlements/{settlementId}` - Settlement info
- `GET /api/registry/operators` - Active operators

### **Events**
- `GET /api/events/latest` - Latest events
- `GET /api/events?from=1&to=100` - Event range
- `GET /api/events/{eventHash}` - Specific event
- `GET /api/events/verify` - Verify hash chain

### **Network**
- `GET /api/network/stats` - Network statistics
- `GET /api/network/peers` - Connected peers

## 🏪 Retail Store Setup

### **For Retail Stores**
1. **Install gateway node** on your local server
2. **Configure with your store ID**
3. **Point customers to your local instance**
4. **Offer white-label branded access**

### **White-Label Configuration**
```json
{
  "branding": {
    "name": "Your Store Name",
    "logo": "https://yourstore.com/logo.png",
    "theme": "dark",
    "domain": "registry.yourstore.com"
  }
}
```

## 🌍 Public Gateway Mode

Want to contribute to the Autho network by running a **publicly accessible gateway**? Public gateways serve the full UI and help distribute traffic away from operators.

### **Enable Public Gateway Mode**

```bash
# Set environment variables
GATEWAY_PUBLIC=true
GATEWAY_PUBLIC_URL=https://your-gateway-domain.com

# Run the gateway
node gateway-package.js
```

### **Public URL Modes**

#### **Mode 1: Quick Tunnel (default, easiest, random URL)**

This mode uses Cloudflare's quick tunnel and prints a random `https://<random>.trycloudflare.com` URL.
This URL is not guaranteed to stay the same after restarts.

Use:

```bash
GATEWAY_TUNNEL_MODE=quick
```

#### **Mode 2: Stable URL (Cloudflare Named Tunnel + Custom Hostname)**

If you want a public URL that stays the same across restarts, use a Cloudflare named tunnel.

You must:

1. Create a tunnel in Cloudflare Zero Trust
2. Configure a Public Hostname (example: `https://mygateway.mydomain.com`) pointing to `http://localhost:3001`
3. Copy the tunnel token

Then set:

```bash
GATEWAY_TUNNEL_MODE=cloudflare_named
GATEWAY_PUBLIC_URL=https://mygateway.mydomain.com
CLOUDFLARED_TOKEN=your_token_here
```

### **What Public Gateways Do**

| Feature | Private Gateway | Public Gateway |
|---------|-----------------|----------------|
| Proxy API requests | ✅ | ✅ |
| Serve UI (HTML/CSS/JS) | ❌ | ✅ |
| Discoverable by network | ❌ | ✅ |
| Full user experience | ❌ | ✅ |

### **Setup Steps**

1. **Get a domain** - Point it to your server (e.g., `gateway.yoursite.com`)

2. **Install the gateway**:
   ```bash
   mkdir autho-gateway && cd autho-gateway
   curl -O https://autho.pinkmahi.com/api/gateway/download
   npm install
   ```

3. **Configure environment**:
   ```bash
   # .env file
   GATEWAY_PUBLIC=true
   GATEWAY_PUBLIC_URL=https://gateway.yoursite.com
   GATEWAY_PORT=3001
   ```

4. **Set up reverse proxy** (nginx example):
   ```nginx
   server {
       listen 443 ssl;
       server_name gateway.yoursite.com;
       
       location / {
           proxy_pass http://localhost:3001;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection 'upgrade';
           proxy_set_header Host $host;
       }
   }
   ```

5. **Start the gateway**:
   ```bash
   node gateway-package.js
   ```

### **Verify It's Working**

```bash
curl https://gateway.yoursite.com/health
```

Should return:
```json
{
  "status": "healthy",
  "isPublicGateway": true,
  "publicHttpUrl": "https://gateway.yoursite.com",
  "uiBundleVersion": 1738412000000
}
```

### **Benefits of Running a Public Gateway**

- 🌐 **Help decentralize** the network
- 🚀 **Reduce load** on operator nodes  
- 🔒 **Provide censorship resistance** - more access points
- 🏪 **Brand it** for your business/website
- 🤝 **Support the community** - no approval needed!

## 🏠 Home User Public Access (NEW!)

**Want to make your home gateway publicly accessible?** Even if you're behind a router/NAT, you can now contribute to the network!

### **Automatic Setup (Easiest)**

Just set one environment variable:

```bash
GATEWAY_AUTO_PUBLIC=true node gateway-package.js
```

The gateway will automatically try:
1. **Direct access** - If your IP is already public
2. **UPnP port forwarding** - Works on most home routers
3. **Tunnel service** - Works everywhere (localtunnel)

### **Manual Enable via API**

Start the gateway normally, then:

```bash
# Enable public access
curl -X POST http://localhost:3001/api/public-access/enable

# Check status
curl http://localhost:3001/api/public-access/status

# Disable when done
curl -X POST http://localhost:3001/api/public-access/disable
```

### **Response Example**

```json
{
  "success": true,
  "enabled": true,
  "url": "https://gw-abc123.loca.lt",
  "method": "tunnel",
  "externalIp": "203.0.113.45",
  "httpPort": 3001,
  "wsPort": 4001
}
```

### **Methods Supported**

| Method | How It Works | Requirements |
|--------|--------------|--------------|
| **Direct** | Uses your public IP directly | Already port-forwarded |
| **UPnP** | Auto-configures router | UPnP-enabled router |
| **Tunnel** | Uses localtunnel.me | `npm install localtunnel` |

### **For Best Results**

1. **Install optional dependency**: `npm install localtunnel`
2. **Run with auto-public**: `GATEWAY_AUTO_PUBLIC=true node gateway-package.js`
3. **Share your public URL** with the community

## 🔧 Advanced Features

### **Caching**
- **In-memory cache** for frequently accessed data
- **TTL-based expiration** (5 minutes default)
- **Automatic invalidation** on new events

### **Rate Limiting**
- **IP-based limiting** (100 requests/minute)
- **Adjustable windows** and limits
- **Automatic cleanup** of expired limits

### **P2P Integration**
- **Auto-discovery** via DNS seeds
- **Persistent connections** with reconnection
- **Event gossip** for real-time updates

### **Health Monitoring**
- **Uptime tracking** and statistics
- **Peer monitoring** and health checks
- **Performance metrics** and logging

## 📊 Monitoring

### **Health Check**
```bash
curl http://localhost:3001/health
```

### **Statistics**
```bash
curl http://localhost:3001/stats
```

### **Registry State**
```bash
curl http://localhost:3001/api/registry/state
```

## 🔍 Troubleshooting

### **Common Issues**

**Port Already in Use**
```bash
# Change port in configuration
--port=3002
```

**DNS Resolution Issues**
```bash
# Use IP address directly
--seed=YOUR_SERVER_IP:3000
```

**Connection Problems**
```bash
# Check firewall settings
# Ensure port 3001 is open
```

**High Memory Usage**
```bash
# Reduce cache size
--cache-size=100
```

### **Logs**
```bash
# Enable debug logging
DEBUG=gateway:* node dist/gateway/gateway-node.js
```

## 🌟 Benefits

### **For Retail Stores**
- **Local performance** - Fast access for customers
- **White-label branding** - Your store's branding
- **Reduced latency** - No external dependencies
- **Customer trust** - Local verification

### **For Network**
- **Decentralization** - No single point of failure
- **Scalability** - More nodes = better performance
- **Resilience** - Network continues if nodes fail
- **Accessibility** - Multiple access points

### **For Users**
- **Privacy** - No tracking by central servers
- **Speed** - Local verification
- **Reliability** - Multiple node options
- **Control** - Choose trusted nodes

## 📚 Documentation

- **API Documentation**: `/api/docs` (when running)
- **Configuration Guide**: See configuration examples
- **Troubleshooting**: Check logs and health endpoints
- **Community**: Join our Discord for support

## 🚀 Next Steps

1. **Download and install** the gateway node
2. **Configure** for your environment
3. **Start the service**
4. **Test API endpoints**
5. **Connect to the network**
6. **Invite others to join**

## 🤝 Contributing

Gateway nodes are essential for network health. By running a gateway node, you:
- **Support decentralization**
- **Provide public access**
- **Enhance network resilience**
- **Enable local verification**

Thank you for supporting the Autho network! 🌐
