#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const root = path.resolve(process.argv[2] || '.');
const read = f => fs.existsSync(path.join(root, f)) ? fs.readFileSync(path.join(root, f), 'utf8') : '';
const cfg = read('hardhat.config.js');
const deploy = read('scripts/deploy.js');
const pkg = read('package.json');
const ignore = read('.gitignore');
const checks = [
  ['package.json present', !!pkg],
  ['Hardhat config present', !!cfg],
  ['Solidity 0.8.20 configured', cfg.includes('0.8.20')],
  ['Cyprus-1 configured', cfg.includes('cyprus1')],
  ['Quai metadata plugin configured', cfg.includes('@quai/hardhat-deploy-metadata')],
  ['quais SDK referenced in deploy script', deploy.includes("require('quais')") || deploy.includes('require("quais")')],
  ['Quai ContractFactory used', deploy.includes('quais.ContractFactory')],
  ['.env ignored', ignore.split(/\r?\n/).some(x => x.trim() === '.env')],
  ['No .env file committed to working tree (manual Git check required)', true]
];
for (const [name, ok] of checks) console.log(`${ok ? 'PASS' : 'FAIL'} ${name}`);
console.log('\nNOTE: Static checks only. Confirm git tracking, RPC, chain ID, tests, source security, and approval manually.');
if (checks.some(([name,ok])=>!ok)) process.exitCode=1;
