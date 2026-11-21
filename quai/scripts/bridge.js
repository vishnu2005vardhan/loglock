// SakshyaLog <-> Quai bridge. The Python vault cannot sign Quai transactions (Quai uses
// its own transaction format), so it asks this small local service, which uses the
// official quais SDK. Listens on 127.0.0.1 only.
//
//   node scripts/bridge.js          (run_demo.py --quai starts it for you)
//
// POST /send  {fn, args}  -> sends one contract transaction (queued, one at a time)
// POST /read  {fn, args}  -> read-only contract call
// GET  /info              -> network, contract, wallet, balance
// GET  /anchors           -> Anchored events (for the evidence pack)
const http = require('http')
const { quais, ORCHARD, loadEnv, loadDeployment, provider } = require('./common')

const PORT = Number(process.env.QUAI_BRIDGE_PORT || 8600)

// A network hiccup with the Quai RPC (timeout, dropped connection) must not kill the bridge.
// Log it and keep serving; the vault retries on the next seal.
const why = (e) => (e && (e.shortMessage || e.code || e.message)) || String(e)
process.on('unhandledRejection', (e) => console.error(`[quai-bridge] network warning, still running: ${why(e)}`))
process.on('uncaughtException', (e) => console.error(`[quai-bridge] error, still running: ${why(e)}`))
const env = loadEnv()
if (!env.key) { console.error('No wallet key in quai/.env. Run: node scripts/new-wallet.js'); process.exit(1) }
const dep = loadDeployment()
const p = provider(env.rpc)
const wallet = new quais.Wallet(env.key, p)
const abi = require('../deployments/LogAnchor.abi.json').abi
const contract = new quais.Contract(dep.address, abi, wallet)

const toJSON = (v) => JSON.parse(JSON.stringify(v, (_, x) => (typeof x === 'bigint' ? x.toString() : x)))
const plain = (r) => {
  if (r && typeof r.toObject === 'function') { try { return toJSON(r.toObject()) } catch (_) { /* fall through */ } }
  if (Array.isArray(r)) return r.map(plain)
  return toJSON(r)
}

// {"keccak": "text"} in args -> bytes32 keccak256 of the text (for per-stream mappings)
const prep = (args) => (args || []).map((a) => (a && typeof a === 'object' && 'keccak' in a ? quais.id(a.keccak) : a))

let queue = Promise.resolve() // one transaction at a time = no nonce clashes
function send(fn, args) {
  const job = queue.then(async () => {
    const tx = await contract[fn](...args)
    const rc = await tx.wait()
    if (!rc || rc.status !== 1) throw new Error(`transaction ${tx.hash} reverted`)
    return { tx: tx.hash, gasUsed: rc.gasUsed.toString(), block: Number(rc.blockNumber) }
  })
  queue = job.catch(() => {})
  return job
}

const routes = {
  'POST /send': async (b) => send(b.fn, prep(b.args)),
  'POST /read': async (b) => ({ result: plain(await contract[b.fn](...prep(b.args))) }),
  'GET /info': async () => {
    const [net, bal, block] = await Promise.all([p.getNetwork(), p.getBalance(wallet.address), p.getBlockNumber()])
    return { name: ORCHARD.name, chainId: Number(net.chainId), contract: dep.address, wallet: wallet.address,
             balance: quais.formatQuai(bal), blockNumber: block, explorer: ORCHARD.explorer,
             deployTx: dep.transactionHash }
  },
  'GET /anchors': async () => {
    const evs = await contract.queryFilter(contract.filters.Anchored(), dep.blockNumber || 0)
    return evs.map((e) => ({ root: e.args.root.slice(2), ts: Number(e.args.timestamp), tx: e.transactionHash }))
  },
}

http.createServer((req, res) => {
  let body = ''
  req.on('data', (d) => (body += d))
  req.on('end', async () => {
    const route = routes[`${req.method} ${req.url}`]
    res.setHeader('Content-Type', 'application/json')
    if (!route) { res.statusCode = 404; return res.end('{"error":"not found"}') }
    try {
      res.end(JSON.stringify(await route(body ? JSON.parse(body) : {})))
    } catch (e) {
      res.statusCode = 500
      res.end(JSON.stringify({ error: (e.shortMessage || e.reason || e.message || String(e)).slice(0, 400) }))
    }
  })
}).on('error', (e) => {
  if (e.code === 'EADDRINUSE') {
    console.error(`[quai-bridge] port ${PORT} is already in use: an old bridge is still running.`)
    console.error('[quai-bridge] Close all CMD windows of the old demo (or run: taskkill /F /IM node.exe) and start again.')
  } else console.error(`[quai-bridge] could not start: ${why(e)}`)
  process.exit(1)
}).listen(PORT, '127.0.0.1', () => {
  console.log(`[quai-bridge] ${ORCHARD.name}, contract ${dep.address}, wallet ${wallet.address}`)
  console.log(`[quai-bridge] listening on http://127.0.0.1:${PORT}`)
})
