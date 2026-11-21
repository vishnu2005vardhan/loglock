import { useEffect, useRef, useState, useCallback } from 'react'

const API = '/api'

export const SLOW = "The vault or the blockchain didn't answer in time. Your evidence is safe. Try again in a few seconds."

export async function api(path, { method = 'GET', body, params, text = false } = {}) {
  const url = new URL(API + path, window.location.origin)
  if (params) Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v))
  const ctl = new AbortController()
  const timer = setTimeout(() => ctl.abort(), 90000)
  let res
  try {
    res = await fetch(url, {
      method, signal: ctl.signal,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    })
  } catch {
    throw new Error(SLOW)
  } finally { clearTimeout(timer) }
  if (!res.ok) {
    let msg = ''
    try { const j = await res.json(); msg = typeof j.detail === 'string' ? j.detail : (j.error || '') } catch { /* not json */ }
    if (!msg || msg === 'Internal Server Error' || res.status >= 500) msg = res.status === 502 && msg.startsWith('vault not reachable') ? msg : (msg && res.status === 502 ? `The blockchain didn't accept this yet: ${msg}` : SLOW)
    throw new Error(msg)
  }
  return text ? res.text() : res.json()
}

export async function download(path, filename, opts) {
  const url = new URL(API + path, window.location.origin)
  let res
  try { res = await fetch(url, opts) } catch { throw new Error(SLOW) }
  if (!res.ok) throw new Error(SLOW)
  const blob = await res.blob()
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = filename
  a.click()
  URL.revokeObjectURL(a.href)
}

export function saveText(text, filename, type = 'text/html') {
  const a = document.createElement('a')
  a.href = URL.createObjectURL(new Blob([text], { type }))
  a.download = filename
  a.click()
}

/** Poll an async function every `ms` while mounted. Returns {data, error, refresh}. */
export function usePoll(fn, ms, deps = []) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const fnRef = useRef(fn)
  fnRef.current = fn
  const refresh = useCallback(async () => {
    try { setData(await fnRef.current()); setError(null) } catch (e) { setError(e.message) }
  }, [])
  useEffect(() => {
    let alive = true
    let t
    const tick = async () => {
      try { const d = await fnRef.current(); if (alive) { setData(d); setError(null) } } catch (e) { if (alive) setError(e.message) }
      if (alive && ms) t = setTimeout(tick, ms)
    }
    tick()
    return () => { alive = false; clearTimeout(t) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
  return { data, error, refresh }
}

export const short = (h, n = 10) => (h ? `${h.slice(0, n)}…` : '')
export const clock = (ts) => { try { return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) } catch { return '' } }
export const dateTime = (ts) => { try { return new Date(ts).toLocaleString([], { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) } catch { return '' } }
export const fromUnix = (t) => (t ? new Date(t * 1000).toLocaleString([], { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) : 'not found on chain')
export const ago = (s) => (s == null ? 'never' : s < 60 ? `${Math.round(s)} s ago` : `${Math.round(s / 60)} min ago`)
export const human = (s) => (s < 3600 ? `${Math.floor(s / 60)} min ${Math.floor(s % 60)} s` : s < 86400 ? `${(s / 3600).toFixed(1)} hours` : `${(s / 86400).toFixed(1)} days`)

// ---- Browser-side proof check (same public algorithms as the vault) ----------
const enc = new TextEncoder()
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('')
const fromHex = (h) => new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16)))
async function sha256Bytes(bytes) { return hex(await crypto.subtle.digest('SHA-256', bytes)) }
// Python json.dumps(..., separators=(",",":")) with ensure_ascii=True
const pyJson = (v) => JSON.stringify(v).replace(/[\u0080-￿]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'))

export async function entryHash(e) {
  return sha256Bytes(enc.encode(pyJson([e.seq, e.ts, e.host, e.line, e.prev_hash])))
}

/** Recompute leaf -> root in the browser. Returns the list of steps for the visual. */
export async function walkProof(leaf, proof) {
  const steps = [{ hash: leaf, label: 'This line' }]
  let h = leaf
  for (const [sib, side] of proof) {
    const a = side === 'L' ? sib : h
    const b = side === 'L' ? h : sib
    const joined = new Uint8Array([...fromHex(a), ...fromHex(b)])
    h = await sha256Bytes(joined)
    steps.push({ hash: h, sibling: sib, side })
  }
  return steps
}
