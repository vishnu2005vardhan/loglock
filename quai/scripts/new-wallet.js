// Create a NEW, dedicated Orchard testnet wallet in the Cyprus-1 zone (Quai ledger).
// The private key is written straight into quai/.env (git-ignored) and is NEVER printed.
//   node scripts/new-wallet.js
const fs = require('fs')
const { quais, ENV_PATH, ORCHARD, setEnvValues, describeAddress } = require('./common')

if (fs.existsSync(ENV_PATH) && /^CYPRUS1_PK=/m.test(fs.readFileSync(ENV_PATH, 'utf8')) && !process.argv.includes('--force')) {
  console.log('quai/.env already has a wallet key. Not overwriting it. (Use --force to replace it.)')
  process.exit(0)
}

let wallet, tries = 0
do { // Quai addresses are sharded: keep generating until the address is a Cyprus-1, Quai-ledger address
  wallet = new quais.Wallet(quais.hexlify(quais.randomBytes(32)))
  tries++
} while (!(describeAddress(wallet.address).isCyprus1 && describeAddress(wallet.address).isQuaiLedger))

setEnvValues({ RPC_URL: ORCHARD.rpc, CHAIN_ID: '15000', CYPRUS1_PK: wallet.privateKey })
console.log(`New Orchard Cyprus-1 testnet wallet created (${tries} tries).`)
console.log(`Address: ${wallet.address}`)
console.log(`The private key was saved to quai/.env only. Never share it, paste it in chat, or commit it.`)
console.log(`\nNext: get free testnet QUAI for this address at ${ORCHARD.faucet}`)
console.log('Then run:  npm run preflight')
