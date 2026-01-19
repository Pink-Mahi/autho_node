# Deployment Guide for Autho Operator Node

## Quick Deployment on Coolify

### Step 1: Create New Service in Coolify

1. Log into your Coolify instance at your domain
2. Click **+ New Resource** → **Public Repository**
3. Enter repository URL: `https://github.com/Pink-Mahi/autho_node`
4. Select **Dockerfile** as build method
5. Name your service: `autho-operator-node`

### Step 2: Configure Environment Variables

In Coolify's environment variables section, add:

```
OPERATOR_ID=operator-your-unique-id
OPERATOR_PUBLIC_KEY=your-public-key-hex
OPERATOR_PRIVATE_KEY=your-private-key-hex
OPERATOR_BTC_ADDRESS=bc1q...
BITCOIN_NETWORK=testnet
MAIN_SEED_URL=wss://autho.pinkmahi.com:4001
PORT=3000
WS_PORT=4001
DATA_DIR=/data
```

**To generate keys before deployment:**
```bash
git clone https://github.com/Pink-Mahi/autho_node.git
cd autho_node
npm install
npm run generate-keys
```

Copy the generated keys to Coolify environment variables.

### Step 3: Configure Port Mappings

In Coolify's **Network** section, add port mappings:

- **3000:3000** (HTTP API)
- **4001:4001** (WebSocket - optional, for future P2P)

### Step 4: Configure Domain (Optional)

If you want to access your operator via domain:

1. In Coolify, go to **Domains**
2. Add your domain: `autho.cartpathcleaning.com`
3. Enable **HTTPS** (Let's Encrypt)
4. Coolify will automatically proxy port 3000

### Step 5: Deploy

1. Click **Deploy**
2. Watch build logs to ensure no errors
3. Once deployed, check health endpoint:

```bash
curl https://autho.cartpathcleaning.com/api/health
```

Expected response:
```json
{
  "status": "ok",
  "operatorId": "operator-...",
  "connectedToNetwork": true,
  "syncedEvents": 1234,
  "lastSyncedAt": 1234567890,
  "uptime": 123.45
}
```

### Step 6: Verify Connection to Main Node

Check your main node dashboard at `https://autho.pinkmahi.com/dashboard`:

1. Go to **Network Status**
2. You should see your operator listed under **Gateway Nodes** or **Operator Nodes**
3. Status should show **CONNECTED**

### Step 7: Apply for Operator Status

1. Go to main node dashboard
2. Navigate to **Network** → **Apply as Operator**
3. Submit your operator ID and Bitcoin address
4. Wait for quorum approval (24-48 hours)

## Troubleshooting

### Node won't connect to main seed

**Check logs in Coolify:**
```
[Operator] Connecting to main seed: wss://autho.pinkmahi.com:4001
[Operator] WebSocket error: ...
```

**Solutions:**
- Verify `MAIN_SEED_URL` is correct
- Check if Coolify allows outbound WebSocket connections
- Ensure port 4001 is not blocked by firewall

### Health endpoint returns 404

**Check:**
- Port 3000 is exposed in Coolify
- Domain is correctly configured
- Service is running (check Coolify logs)

### Not syncing events

**Check logs for:**
```
[Operator] Syncing events from main node...
[Operator] Synced X events
```

**If not syncing:**
- Verify WebSocket connection is established
- Check main node is online and accessible
- Restart the service in Coolify

## Monitoring

### Health Check Endpoint

```bash
curl https://autho.cartpathcleaning.com/api/health
```

### Operator Info

```bash
curl https://autho.cartpathcleaning.com/api/operator/info
```

### Network Status

```bash
curl https://autho.cartpathcleaning.com/api/network/status
```

## Updating Your Node

When updates are available:

1. In Coolify, click **Redeploy**
2. Coolify will pull latest code from GitHub
3. Rebuild and restart automatically
4. Check health endpoint to verify

## Security Checklist

- ✅ Private key stored in Coolify environment variables (not in code)
- ✅ HTTPS enabled via Let's Encrypt
- ✅ Firewall configured (only ports 80, 443, 3000, 4001 exposed)
- ✅ Admin endpoints blocked in code
- ✅ Regular backups of `/data` directory

## Next Steps After Deployment

1. **Test customer login** via your operator:
   ```bash
   curl -X POST https://autho.cartpathcleaning.com/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"test@test.com","password":"test"}'
   ```

2. **Update gateway nodes** to include your operator in `operatorUrls`:
   ```javascript
   operatorUrls: [
     'http://autho.pinkmahi.com:3000',
     'https://autho.cartpathcleaning.com',
     'https://autho.pinkmahi.com'
   ]
   ```

3. **Test failover** by stopping main node and verifying gateways still work via your operator

## Support

- GitHub Issues: https://github.com/Pink-Mahi/autho_node/issues
- Main Node Dashboard: https://autho.pinkmahi.com/dashboard
