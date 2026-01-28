# Autho Operator Node

Public repository for deploying an Autho Protocol operator node. Operator nodes help secure the network by validating events, syncing the distributed ledger, and providing API endpoints for gateway nodes.

## What is an Operator Node?

Operator nodes are part of the Autho Protocol's decentralized network. They:

- **Sync and validate** all protocol events (item registrations, transfers, authentications)
- **Provide API endpoints** for customer authentication and registry queries
- **Participate in quorum consensus** for critical protocol decisions
- **Earn platform fees** distributed from transactions

Operator nodes **cannot**:
- Access the main node admin dashboard
- Override quorum decisions
- Modify historical events
- Create events without valid signatures

## Security Model

### Operator Approval Process

1. **Deploy your operator node** using this repository
2. **Apply for operator status** via the main node dashboard
3. **Wait for quorum approval** from existing operators
4. **Receive operator credentials** and Bitcoin address for fee payouts
5. **Your node becomes active** and starts earning fees

### What Operators Can Do

✅ Read all public registry data (items, transfers, authentications)  
✅ Validate and relay events with proper signatures  
✅ Serve customer login/authentication requests  
✅ Participate in operator voting (approve/reject new operators, role applications)  
✅ Earn platform fees distributed via Bitcoin  

### What Operators Cannot Do

❌ Access admin-only endpoints (operator management, system config)  
❌ Create events without valid quorum signatures  
❌ Modify or delete historical events  
❌ Override main node decisions  
❌ Access other operators' private keys  

## Prerequisites

- **Node.js 18+** and npm
- **Docker** (for containerized deployment)
- **Bitcoin wallet address** for fee payouts
- **Domain name** or public IP address
- **Open ports**: 3000 (HTTP API), 4001 (WebSocket)

## Quick Start (Docker)

### 1. Clone this repository

```bash
git clone https://github.com/Pink-Mahi/autho_node.git
cd autho_node
```

### 2. Configure environment variables

Create a `.env` file:

```bash
# Operator identity (generate with: npm run generate-keys)
OPERATOR_ID=operator-your-unique-id
OPERATOR_PRIVATE_KEY=your-private-key-hex
OPERATOR_PUBLIC_KEY=your-public-key-hex

# Bitcoin address for fee payouts
OPERATOR_BTC_ADDRESS=bc1q...

# Seed URL - ANY active operator in the Autho network
# The network is fully decentralized - you can connect to any operator
# Examples:
#   SEED_URL=wss://autho.pinkmahi.com
#   SEED_URL=wss://autho.cartpathcleaning.com
#   SEED_URL=wss://autho.steveschickens.com
SEED_URL=wss://autho.pinkmahi.com

# Optional: Fallback seed URLs (comma-separated)
# If primary seed is down, these will be tried in order
# FALLBACK_SEED_URLS=wss://autho.cartpathcleaning.com,wss://autho2.cartpathcleaning.com

# Network (mainnet or testnet)
BITCOIN_NETWORK=mainnet

# API port (default: 3000)
PORT=3000

# Data directory (inside container)
DATA_DIR=/data
```

### 3. Generate operator keys

```bash
npm install
npm run generate-keys
```

Copy the generated keys to your `.env` file.

### 4. Deploy with Docker

```bash
docker build -t autho-operator .
docker run -d \
  --name autho-operator \
  -p 3000:3000 \
  -p 4001:4001 \
  -v $(pwd)/data:/data \
  --env-file .env \
  autho-operator
```

### 5. Verify your node is running

```bash
curl http://localhost:3000/api/health
```

Expected response:
```json
{
  "status": "ok",
  "operatorId": "operator-your-unique-id",
  "connectedToNetwork": true,
  "syncedEvents": 1234
}
```

### 6. Apply for operator status

1. Go to the main node dashboard: https://autho.pinkmahi.com/dashboard
2. Navigate to **Network Status** → **Apply as Operator**
3. Submit your operator ID and Bitcoin address
4. Wait for quorum approval (typically 24-48 hours)

## Deployment on Coolify

### 1. Create a new service in Coolify

- **Type**: Docker Compose or Dockerfile
- **Repository**: https://github.com/Pink-Mahi/autho_node
- **Branch**: main

### 2. Configure environment variables in Coolify

Add all variables from the `.env` example above.

### 3. Configure port mappings

- **3000:3000** (HTTP API)
- **4001:4001** (WebSocket)

### 4. Deploy and verify

Check logs in Coolify to ensure:
```
[Operator] Connecting to main seed: wss://autho.pinkmahi.com:4001
[Operator] Connected to Autho Network
[Operator] Syncing events...
[Operator] Synced 1234 events
[Operator] HTTP API: http://localhost:3000
```

## Manual Deployment (without Docker)

### 1. Install dependencies

```bash
npm install
npm run build
```

### 2. Start the operator node

```bash
npm start
```

Or with PM2 for production:

```bash
npm install -g pm2
pm2 start dist/index.js --name autho-operator
pm2 save
pm2 startup
```

## Monitoring Your Node

### Health check endpoint

```bash
curl http://your-domain.com:3000/api/health
```

### Network status

```bash
curl http://your-domain.com:3000/api/network/status
```

### Operator info

```bash
curl http://your-domain.com:3000/api/operator/info
```

## Earning Fees

Once approved as an operator, you'll automatically earn platform fees distributed from:

- Item registrations (minting)
- Authentication attestations
- Ownership transfers
- Consignment sales

Fees are distributed via Bitcoin transactions to your configured `OPERATOR_BTC_ADDRESS`. The main node rotates fee payouts among active operators to ensure fair distribution.

## Troubleshooting

### Node won't connect to main seed

- Verify `MAIN_SEED_URL` is correct
- Check firewall allows outbound WebSocket connections
- Ensure port 4001 is not blocked

### API returns 404 for all endpoints

- Verify port 3000 is exposed and accessible
- Check Docker port mappings: `-p 3000:3000`
- Verify `PORT` environment variable matches exposed port

### Not receiving fee payouts

- Verify your operator status is **active** (check main node dashboard)
- Confirm `OPERATOR_BTC_ADDRESS` is correct and valid
- Fee distribution is round-robin; you may need to wait for your turn

## Security Best Practices

1. **Keep private keys secure** - Never commit `.env` to version control
2. **Use strong passwords** - If exposing admin endpoints (not recommended)
3. **Enable firewall** - Only expose ports 3000 and 4001
4. **Monitor logs** - Watch for suspicious activity
5. **Keep software updated** - Pull latest changes regularly

## Support

- **Documentation**: https://docs.autho.network (coming soon)
- **Discord**: https://discord.gg/autho (coming soon)
- **GitHub Issues**: https://github.com/Pink-Mahi/autho_node/issues

## License

MIT License - see LICENSE file for details
