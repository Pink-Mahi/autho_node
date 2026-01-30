import * as dotenv from 'dotenv';
import { OperatorNode } from './operator-node';

dotenv.config();

async function main() {
  console.log('=== Autho Operator Node ===');
  console.log('Starting operator node...\n');

  // Validate required environment variables
  // SEED_URL is the new name, MAIN_SEED_URL is supported for backwards compatibility
  // Any active operator can be used as a seed - the network is fully decentralized
  const requiredEnvVars = [
    'OPERATOR_ID',
    'OPERATOR_PUBLIC_KEY',
    'OPERATOR_PRIVATE_KEY',
    'OPERATOR_BTC_ADDRESS',
  ];

  // Check for seed URL (new or legacy name)
  const seedUrl = process.env.SEED_URL || process.env.MAIN_SEED_URL;
  if (!seedUrl) {
    requiredEnvVars.push('SEED_URL'); // Will trigger error message
  }

  const missing = requiredEnvVars.filter(v => !process.env[v]);
  if (missing.length > 0) {
    console.error('ERROR: Missing required environment variables:');
    missing.forEach(v => console.error(`  - ${v}`));
    console.error('\nPlease configure these in your .env file.');
    console.error('Run "npm run generate-keys" to generate operator keys.');
    console.error('\nNote: SEED_URL can be ANY active operator in the Autho network.');
    console.error('Examples:');
    console.error('  SEED_URL=wss://autho.pinkmahi.com');
    console.error('  SEED_URL=wss://autho.cartpathcleaning.com');
    console.error('  SEED_URL=wss://autho.steveschickens.com\n');
    process.exit(1);
  }

  // Parse fallback seed URLs (comma-separated)
  const fallbackSeeds = (process.env.FALLBACK_SEED_URLS || '')
    .split(',')
    .map(s => s.trim())
    .filter(s => s.length > 0);

  const config = {
    operatorId: process.env.OPERATOR_ID!,
    publicKey: process.env.OPERATOR_PUBLIC_KEY!,
    privateKey: process.env.OPERATOR_PRIVATE_KEY!,
    btcAddress: process.env.OPERATOR_BTC_ADDRESS!,
    // BTC wallet private key (from user's seed phrase) - separate from operator signing key
    btcPrivateKey: process.env.OPERATOR_BTC_PRIVATE_KEY || '',
    mainSeedUrl: seedUrl!, // Keep internal name for compatibility
    fallbackSeedUrls: fallbackSeeds,
    port: parseInt(process.env.PORT || '3000', 10),
    wsPort: parseInt(process.env.WS_PORT || '4001', 10),
    dataDir: process.env.DATA_DIR || '/data',
    network: (process.env.BITCOIN_NETWORK || 'testnet') as 'mainnet' | 'testnet',
    operatorName: process.env.OPERATOR_NAME,
    operatorDescription: process.env.OPERATOR_DESCRIPTION
  };

  console.log('Configuration:');
  console.log(`  Operator ID: ${config.operatorId}`);
  console.log(`  Bitcoin Address: ${config.btcAddress}`);
  console.log(`  Network: ${config.network}`);
  console.log(`  Seed URL: ${config.mainSeedUrl}`);
  if (fallbackSeeds.length > 0) {
    console.log(`  Fallback Seeds: ${fallbackSeeds.join(', ')}`);
  }
  console.log(`  HTTP Port: ${config.port}`);
  console.log(`  WebSocket Port: ${config.wsPort}`);
  console.log(`  Data Directory: ${config.dataDir}\n`);

  const node = new OperatorNode(config);

  // Graceful shutdown
  process.on('SIGINT', async () => {
    console.log('\n\nReceived SIGINT, shutting down gracefully...');
    await node.stop();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    console.log('\n\nReceived SIGTERM, shutting down gracefully...');
    await node.stop();
    process.exit(0);
  });

  try {
    await node.start();
  } catch (error: any) {
    console.error('FATAL ERROR:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

main().catch(error => {
  console.error('Unhandled error:', error);
  process.exit(1);
});
