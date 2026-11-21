// Read-only checks before any Orchard transaction. Sends NOTHING.
//   node scripts/preflight.js
const fs = require('fs')
const path = require('path')
const { quais, ROOT, ORCHARD, ARTIFACT_PATH, loadEnv, provider, describeAddress } = require('./common')

const withTimeout = (promise, ms, what) => Promise.race([promise,
  new Promise((_, rej) => setTimeout(() => rej(new Error(`${what} timed out after ${ms / 1000}s (check internet / RPC URL)`)), ms))])

async function preflight({ quiet = false } = {}) {
  const env = loadEnv()
  const results = []
  const check = (name, ok, detail = '') => { results.push({ name, ok, detail }); if (!quiet) console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  ' + detail : ''}`) }

  const ignored = fs.existsSync(path.join(ROOT, '.gitignore')) &&
    fs.readFileSync(path.join(ROOT, '.gitignore'), 'utf8').split(/\r?\n/).some((l) => l.trim() === '.env')
  check('.env is git-ignored', ignored)
  check('Wallet key present in quai/.env', !!env.key, env.key ? '' : 'run: node scripts/new-wallet.js')
  check('Contract compiled (Solidity 0.8.20, london)', fs.existsSync(ARTIFACT_PATH), fs.existsSync(ARTIFACT_PATH) ? '' : 'run: npx hardhat compile')
  check('CHAIN_ID setting is 15000 (Orchard)', env.chainId === ORCHARD.chainId, `got ${env.chainId}`)
  if (!env.key) return { ok: false, results }

  const wallet = new quais.Wallet(env.key)
  const where = describeAddress(wallet.address)
  check('Wallet is a Cyprus-1 address', where.isCyprus1, `${wallet.address} (zone ${where.zone})`)
  check('Wallet is on the Quai ledger (not Qi)', where.isQuaiLedger)

  let p
  try {
    p = provider(env.rpc)
    const net = await withTimeout(p.getNetwork(), 20000, 'Connecting to RPC')
    check('RPC reachable', true, env.rpc)
    check('Connected chain is Orchard (15000)', net.chainId === ORCHARD.chainId, `chain id ${net.chainId}`)
    const bal = await withTimeout(p.getBalance(wallet.address), 20000, 'Reading balance')
    check('Wallet has testnet QUAI', bal > 0n, `${quais.formatQuai(bal)} QUAI` + (bal > 0n ? '' : `  -> faucet: ${ORCHARD.faucet}`))
  } catch (e) {
    check('RPC reachable', false, `${env.rpc}: ${e.shortMessage || e.message}`)
  }
  const ok = results.every((r) => r.ok)
  if (!quiet) console.log(ok ? '\nAll preflight checks passed.' : '\nFix the FAIL lines above before deploying.')
  return { ok, results, wallet: wallet.address, rpc: env.rpc }
}

module.exports = { preflight }
module.exports.withTimeout = withTimeout
if (require.main === module) preflight().then((r) => process.exit(r.ok ? 0 : 1))
