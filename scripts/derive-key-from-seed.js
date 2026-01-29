/**
 * Derive Bitcoin private key and address from a BIP39 seed phrase
 * Usage: node scripts/derive-key-from-seed.js "your seed phrase here"
 */

const bip39 = require('bip39');
const { BIP32Factory } = require('bip32');
const ecc = require('tiny-secp256k1');
const bitcoin = require('bitcoinjs-lib');

const bip32 = BIP32Factory(ecc);
bitcoin.initEccLib(ecc);

const seedPhrase = process.argv.slice(2).join(' ').trim();

if (!seedPhrase) {
  console.error('Usage: node scripts/derive-key-from-seed.js "your seed phrase here"');
  process.exit(1);
}

if (!bip39.validateMnemonic(seedPhrase)) {
  console.error('Invalid seed phrase!');
  process.exit(1);
}

async function deriveKeys() {
  const seed = await bip39.mnemonicToSeed(seedPhrase);
  const root = bip32.fromSeed(seed);
  
  // BIP84 path for native SegWit (bc1q addresses): m/84'/0'/0'/0/0
  const path = "m/84'/0'/0'/0/0";
  const child = root.derivePath(path);
  
  // Convert Uint8Array to Buffer for bitcoinjs-lib compatibility
  const privateKeyBuf = Buffer.from(child.privateKey);
  const publicKeyBuf = Buffer.from(child.publicKey);
  
  const privateKeyHex = privateKeyBuf.toString('hex');
  
  const { address } = bitcoin.payments.p2wpkh({
    pubkey: publicKeyBuf,
    network: bitcoin.networks.bitcoin,
  });
  
  const publicKeyHex = publicKeyBuf.toString('hex');

  console.log('\n=== Derived Bitcoin Keys (BIP84 - Native SegWit) ===\n');
  console.log('Derivation Path:', path);
  console.log('\nOPERATOR_PRIVATE_KEY=' + privateKeyHex);
  console.log('OPERATOR_PUBLIC_KEY=' + publicKeyHex);
  console.log('OPERATOR_BTC_ADDRESS=' + address);
  console.log('\n=== Copy these values to your Coolify environment variables ===\n');
}

deriveKeys().catch(console.error);
