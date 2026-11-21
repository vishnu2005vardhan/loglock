// Serves the built React app (dist/) and forwards /api/* to the SakshyaLog vault.
// No npm packages needed:   node ui/serve.cjs      then open http://localhost:5173
const http = require('http')
const fs = require('fs')
const path = require('path')

const PORT = Number(process.env.UI_PORT || 5173)
const VAULT = process.env.VAULT_URL || 'http://127.0.0.1:8000'
const DIST = path.join(__dirname, 'dist')
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2', '.woff': 'font/woff', '.png': 'image/png', '.json': 'application/json' }

http.createServer((req, res) => {
  if (req.url.startsWith('/api/')) {
    const target = new URL(req.url.slice(4), VAULT)
    const up = http.request(target, { method: req.method, headers: { ...req.headers, host: target.host } }, (r) => {
      res.writeHead(r.statusCode, r.headers)
      r.pipe(res)
    })
    up.on('error', () => { res.writeHead(502, { 'Content-Type': 'application/json' }); res.end('{"error":"vault not reachable on port 8000. Start run_demo.py first."}') })
    return req.pipe(up)
  }
  let file = path.join(DIST, decodeURIComponent(req.url.split('?')[0]))
  if (!file.startsWith(DIST) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) file = path.join(DIST, 'index.html')
  res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream' })
  fs.createReadStream(file).pipe(res)
}).on('error', (e) => {
  if (e.code === 'EADDRINUSE') {
    console.log(`SakshyaLog website is already running. Open http://localhost:${PORT}`)
    setInterval(() => {}, 1 << 30) // stay quiet; the other copy serves the site
  } else { console.error('website could not start:', e.message); process.exit(1) }
}).listen(PORT, () => console.log(`SakshyaLog UI on http://localhost:${PORT}  (vault: ${VAULT})`))
