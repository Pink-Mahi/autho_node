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
  "seedNodes": ["autho.pinkmahi.com:3000"],
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

## 🧾 Release Notes

### 1.0.1

- Adds gateway proxy endpoints for Bitcoin anchoring and time source:
  - `GET /api/anchors/time`
  - `GET /api/anchors/checkpoints`
  - `GET /api/anchors/commits`
  - `GET /api/anchors/checkpoints/:checkpointRoot/verify`
  - `GET /api/anchors/checkpoints/:checkpointRoot/commitment`
- Optional gateway-side PoW solving when operators require it (disabled by default)

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
