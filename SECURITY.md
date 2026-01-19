# Security Policy

## Operator Node Security Model

### What Operator Nodes Can Do

✅ **Read public registry data** - Items, transfers, authentications, consignments  
✅ **Validate events** - Verify signatures and quorum consensus  
✅ **Serve API requests** - Customer authentication, registry queries  
✅ **Participate in voting** - Operator admission, role applications  
✅ **Earn platform fees** - Distributed via Bitcoin transactions  

### What Operator Nodes Cannot Do

❌ **Access admin endpoints** - `/api/admin/*` and `/dashboard` are blocked  
❌ **Create events without signatures** - All events require valid quorum signatures  
❌ **Modify historical events** - Event log is append-only and cryptographically secured  
❌ **Override main node decisions** - Quorum consensus is enforced  
❌ **Access other operators' keys** - Each operator has isolated credentials  

### Security Boundaries

1. **Admin Endpoints Blocked**
   - Operator nodes explicitly reject all `/api/admin/*` requests
   - Dashboard UI is not included in operator node package
   - Main node admin functions require `MAIN_NODE_ACCOUNT_ID` verification

2. **Event Validation**
   - All events must have valid quorum signatures
   - Operators can only sign events, not create them unilaterally
   - Event hashes are verified against payload

3. **State Synchronization**
   - Operators sync state from main node via WebSocket
   - State is read-only; operators cannot modify synced data
   - Local state is persisted for offline operation

4. **Authentication**
   - Operators can validate passwords against synced account data
   - 2FA secrets are encrypted and require main node for decryption
   - Sessions are local to each operator node

### Best Practices for Operators

1. **Secure Your Private Key**
   - Never commit `.env` to version control
   - Use environment variables or secrets management
   - Rotate keys if compromised

2. **Network Security**
   - Use firewall to restrict access to ports 3000 and 4001
   - Consider using reverse proxy with TLS (nginx, Caddy)
   - Monitor logs for suspicious activity

3. **Keep Software Updated**
   - Pull latest changes from GitHub regularly
   - Subscribe to security advisories
   - Test updates in staging before production

4. **Monitor Your Node**
   - Check `/api/health` endpoint regularly
   - Set up alerts for disconnections
   - Monitor disk space for state persistence

### Reporting Security Issues

If you discover a security vulnerability in the Autho operator node:

1. **Do NOT open a public GitHub issue**
2. Email security@autho.network (coming soon) with details
3. Include steps to reproduce and potential impact
4. We will respond within 48 hours

### Threat Model

**Trusted**: Main node, quorum of operators, Bitcoin blockchain  
**Untrusted**: Individual operators, gateway nodes, end users  

**Attack Scenarios**:
- ❌ Malicious operator tries to access admin endpoints → Blocked by code
- ❌ Malicious operator tries to create fake events → Rejected (no valid signatures)
- ❌ Malicious operator tries to modify state → Impossible (read-only sync)
- ❌ Compromised operator key → Limited impact (can only sign, not create events)

**Mitigation**:
- Quorum consensus prevents single operator from controlling protocol
- Admin functions isolated to main node with separate authentication
- Event log is cryptographically secured and append-only
- Operators earn fees based on uptime, incentivizing honest behavior

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Audit Status

This software has not yet been formally audited. Use at your own risk.
