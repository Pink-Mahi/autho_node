import * as dotenv from 'dotenv';
import { OperatorNode } from './operator-node';

dotenv.config();

async function main() {
  console.log('=== Autho Operator Node ===');
  console.log('Starting operator node...\n');

  // Validate required environment variables
  const requiredEnvVars = [
    'OPERATOR_ID',
    'OPERATOR_PUBLIC_KEY',
    'OPERATOR_PRIVATE_KEY',
    'OPERATOR_BTC_ADDRESS',
    'MAIN_SEED_URL'
  ];

  const missing = requiredEnvVars.filter(v => !process.env[v]);
  if (missing.length > 0) {
    console.error('ERROR: Missing required environment variables:');
    missing.forEach(v => console.error(`  - ${v}`));
    console.error('\nPlease configure these in your .env file.');
    console.error('Run "npm run generate-keys" to generate operator keys.\n');
    process.exit(1);
  }

  const config = {
    operatorId: process.env.OPERATOR_ID!,
    publicKey: process.env.OPERATOR_PUBLIC_KEY!,
    privateKey: process.env.OPERATOR_PRIVATE_KEY!,
    btcAddress: process.env.OPERATOR_BTC_ADDRESS!,
    mainSeedUrl: process.env.MAIN_SEED_URL!,
    port: parseInt(process.env.PORT || '3000', 10),
    wsPort: parseInt(process.env.WS_PORT || '4001', 10),
    dataDir: process.env.DATA_DIR || './data',
    network: (process.env.BITCOIN_NETWORK || 'testnet') as 'mainnet' | 'testnet',
    operatorName: process.env.OPERATOR_NAME,
    operatorDescription: process.env.OPERATOR_DESCRIPTION
  };

  console.log('Configuration:');
  console.log(`  Operator ID: ${config.operatorId}`);
  console.log(`  Bitcoin Address: ${config.btcAddress}`);
  console.log(`  Network: ${config.network}`);
  console.log(`  Main Seed: ${config.mainSeedUrl}`);
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
