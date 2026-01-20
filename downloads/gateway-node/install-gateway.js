#!/usr/bin/env node

/**
 * Autho Gateway Node Installer
 * 
 * This script installs and sets up the Autho Gateway Node
 * with hardcoded seed configuration.
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const os = require('os');

console.log('🌐 Autho Gateway Node Installer');
console.log('================================');

// Check Node.js version
const nodeVersion = process.version;
const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0]);

if (majorVersion < 18) {
  console.error('❌ Node.js 18 or higher is required');
  console.error(`   Current version: ${nodeVersion}`);
  process.exit(1);
}

console.log(`✅ Node.js version: ${nodeVersion}`);

// Create installation directory
const installDir = path.join(os.homedir(), 'autho-gateway-node');
console.log(`📁 Installing to: ${installDir}`);

if (!fs.existsSync(installDir)) {
  fs.mkdirSync(installDir, { recursive: true });
  console.log('✅ Created installation directory');
}

// Copy files
const filesToCopy = [
  'gateway-package.js',
  'package.json',
  'README.md'
];

const currentDir = __dirname;

filesToCopy.forEach(file => {
  const source = path.join(currentDir, file);
  const dest = path.join(installDir, file);
  
  if (fs.existsSync(source)) {
    fs.copyFileSync(source, dest);
    console.log(`✅ Copied ${file}`);
  } else {
    console.log(`⚠️  File not found: ${file}`);
  }
});

// Install dependencies
console.log('📦 Installing dependencies...');
try {
  process.chdir(installDir);
  execSync('npm install', { stdio: 'inherit' });
  console.log('✅ Dependencies installed');
} catch (error) {
  console.error('❌ Failed to install dependencies');
  console.error('   You may need to install them manually:');
  console.error(`   cd ${installDir}`);
  console.error('   npm install');
}

// Create start script
const startScript = os.platform() === 'win32' ? 'start.bat' : 'start.sh';
const startScriptPath = path.join(installDir, startScript);

if (os.platform() === 'win32') {
  fs.writeFileSync(startScriptPath, `@echo off
cd /d "%~dp0"
node gateway-package.js
pause`);
} else {
  fs.writeFileSync(startScriptPath, `#!/bin/bash
cd "$(dirname "$0")"
node gateway-package.js`);
  
  // Make executable on Unix systems
  try {
    execSync(`chmod +x "${startScriptPath}"`);
  } catch (error) {
    // Ignore chmod errors
  }
}

console.log(`✅ Created start script: ${startScript}`);

// Create configuration
const config = {
  port: 3001,
  host: '0.0.0.0',
  seedNodes: ['autho.pinkmahi.com:3000'],
  dataDir: './gateway-data'
};

fs.writeFileSync(
  path.join(installDir, 'config.json'),
  JSON.stringify(config, null, 2)
);
console.log('✅ Created configuration file');

console.log('');
console.log('🎉 Installation complete!');
console.log('');
console.log('🚀 To start the gateway node:');
if (os.platform() === 'win32') {
  console.log(`   cd ${installDir}`);
  console.log('   start.bat');
} else {
  console.log(`   cd ${installDir}`);
  console.log(`./${startScript}`);
}
console.log('');
console.log('🌐 Gateway will be available at:');
console.log('   http://localhost:3001');
console.log('');
console.log('📊 Check status:');
console.log('   http://localhost:3001/health');
console.log('');
console.log('🔒 Seed nodes are hardcoded to autho.pinkmahi.com');
console.log('🎯 Connected to the Autho network!');
console.log('');
console.log('📖 For more information, see:');
console.log(`   ${path.join(installDir, 'README.md')}`);
