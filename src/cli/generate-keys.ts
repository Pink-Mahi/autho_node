import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

function generateOperatorKeys() {
  console.log('=== Autho Operator Key Generator ===\n');

  // Generate ECDSA key pair
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'secp256k1',
    publicKeyEncoding: {
      type: 'spki',
      format: 'der'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'der'
    }
  });

  const publicKeyHex = publicKey.toString('hex');
  const privateKeyHex = privateKey.toString('hex');

  // Generate a unique operator ID
  const operatorId = `operator-${crypto.randomBytes(8).toString('hex')}`;

  console.log('Generated operator credentials:\n');
  console.log('OPERATOR_ID=' + operatorId);
  console.log('OPERATOR_PUBLIC_KEY=' + publicKeyHex);
  console.log('OPERATOR_PRIVATE_KEY=' + privateKeyHex);
  console.log('\n⚠️  IMPORTANT: Keep your private key secure! Never share it or commit it to version control.\n');

  // Optionally write to .env file
  const envPath = path.join(process.cwd(), '.env');
  if (fs.existsSync(envPath)) {
    console.log('Found existing .env file. Please manually update it with the keys above.\n');
  } else {
    console.log('Creating .env file with generated keys...\n');
    const envContent = `# Operator Identity (generated ${new Date().toISOString()})
OPERATOR_ID=${operatorId}
OPERATOR_PUBLIC_KEY=${publicKeyHex}
OPERATOR_PRIVATE_KEY=${privateKeyHex}

# Bitcoin Configuration
OPERATOR_BTC_ADDRESS=bc1q...
BITCOIN_NETWORK=testnet

# Main Node Seed
MAIN_SEED_URL=wss://autho.pinkmahi.com:4001

# API Configuration
PORT=3000
WS_PORT=4001

# Data Storage
DATA_DIR=/data
`;
    fs.writeFileSync(envPath, envContent);
    console.log('✅ Created .env file with generated keys');
    console.log('⚠️  Please update OPERATOR_BTC_ADDRESS with your Bitcoin address\n');
  }

  console.log('Next steps:');
  console.log('1. Update OPERATOR_BTC_ADDRESS in your .env file');
  console.log('2. Start your operator node: npm start');
  console.log('3. Apply for operator status at https://autho.pinkmahi.com/dashboard\n');
}

generateOperatorKeys();
