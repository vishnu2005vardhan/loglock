// Shared helpers for the SakshyaLog Quai scripts.
const fs = require('fs')
const path = require('path')
const quais = require('quais')

const ROOT = path.join(__dirname, '..')
const ENV_PATH = path.join(ROOT, '.env')
const DEPLOY_PATH = path.join(ROOT, 'deployments', 'orchard-cyprus1.json')
const ARTIFACT_PATH = path.join(ROOT, 'artifacts', 'contracts', 'LogAnchor.sol', 'LogAnchor.json')
// Official Orchard values from https://docs.qu.ai/build/networks (checked 20 Nov 2026).
const ORCHARD = {
  name: 'Quai Orchard testnet, Cyprus-1',
  chainId: 15000n,
  rpc: 'https://orchard.rpc.quai.network', // base URL: quais usePathing adds /cyprus1 itself
  explorer: 'https://orchard.quaiscan.io',
  faucet: 'https://orchard.faucet.quai.network',
}

function loadEnv() {
  require('dotenv').config({ path: ENV_PATH })
  return {
    rpc: process.env.RPC_URL || ORCHARD.rpc,
    key: process.env.CYPRUS1_PK,
    chainId: BigInt(process.env.CHAIN_ID || 15000),
  }
}

function setEnvValues(values) {
  const lines = fs.existsSync(ENV_PATH) ? fs.readFileSync(ENV_PATH, 'utf8').split(/\r?\n/) : []
  const keep = lines.filter((l) => l.trim() && !Object.keys(values).includes(l.split('=')[0].trim()))
  fs.writeFileSync(ENV_PATH, [...keep, ...Object.entries(values).map(([k, v]) => `${k}=${v}`)].join('\n') + '\n')
}

function provider(rpc) {
  return new quais.JsonRpcProvider(rpc, undefined, { usePathing: true })
}

function loadArtifact() {
  if (!fs.existsSync(ARTIFACT_PATH)) throw new Error('Contract not compiled. Run: npx hardhat compile')
  return JSON.parse(fs.readFileSync(ARTIFACT_PATH, 'utf8'))
}

function loadDeployment() {
  if (!fs.existsSync(DEPLOY_PATH)) throw new Error('No deployment found. Run the deploy step first (see QUAI.md).')
  return JSON.parse(fs.readFileSync(DEPLOY_PATH, 'utf8'))
}

function describeAddress(addr) {
  const zone = quais.getZoneForAddress(addr)
  return { zone, isCyprus1: zone === quais.Zone.Cyprus1, isQuaiLedger: quais.isQuaiAddress(addr) }
}

module.exports = { quais, ROOT, ENV_PATH, DEPLOY_PATH, ARTIFACT_PATH, ORCHARD, loadEnv, setEnvValues, provider,
  loadArtifact, loadDeployment, describeAddress }
