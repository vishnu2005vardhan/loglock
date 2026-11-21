import { useEffect, useMemo, useState } from 'react'
import { DiffLine, ProvenanceCard } from './Views2.jsx'
import { api, download, saveText, usePoll, clock, dateTime, fromUnix, short, human, entryHash, walkProof } from './lib.js'

/* ------------------------------------------------------------ Timeline --- */
export function Timeline({ host }) {
  const { data } = usePoll(() => api(`/timeline/${host}`), 3000, [host])
  const events = data?.events || []
  return (
    <section className="view">
      <header className="view__head">
        <h1>What happened, in order</h1>
        <p>Rebuilt from the sealed copy, so it still shows the steps the attacker deleted from the machine.</p>
        {data?.attacker_ips?.length > 0 && <p className="callout callout--breach">Suspected source: <strong>{data.attacker_ips.join(', ')}</strong></p>}
      </header>
      {events.length === 0 ? <p className="quiet">Nothing suspicious yet. Run <code>py -3.14 demo\attack.py</code> in a second window.</p> : (
        <ol className="tl">
          {events.map((e, i) => (
            <li key={i} className={`tl__item tl__item--${e.severity} ${e.title.startsWith('Self-healed') ? 'tl__item--heal' : ''}`}>
              <time>{clock(e.ts)}</time>
              <div>
                <h3>{e.title}</h3>
                <p>{e.detail}</p>
              </div>
            </li>
          ))}
        </ol>
      )}
    </section>
  )
}

/* -------------------------------------------------------------- Verify --- */
export function Verify({ host, s }) {
  const [r, setR] = useState(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const run = async () => {
    setBusy(true); setErr('')
    try { setR(await api('/verify-live', { method: 'POST', params: { host } })) } catch (e) { setErr(e.message) }
    setBusy(false)
  }
  useEffect(() => { setR(null); run() /* eslint-disable-next-line */ }, [host])
  const findings = (r?.findings || []).filter((f) => f.status !== 'NOT-YET-SEALED')
  const report = async () => saveText(await api('/report/evidence', { method: 'POST', body: r, text: true }), `SakshyaLog_evidence_${host}.html`)

  return (
    <section className="view">
      <header className="view__head">
        <h1>Compare the machine with the sealed copy</h1>
        <p>Reads the log as it is right now and checks every line against the vault and the blockchain fingerprint.</p>
        <div className="row">
          <button className="btn btn--seal" onClick={run} disabled={busy}>{busy ? 'Checking…' : 'Check again'}</button>
          {r && <button className="btn" onClick={report}>Download evidence report</button>}
        </div>
      </header>
      {err && <p className="callout">{err}{r ? ' Showing the last result.' : ''}</p>}
      {r?.chain_unreachable && <p className="callout">The blockchain isn't answering right now, so seal times come from the vault's own record. The comparison itself is complete.</p>}
      {r && (
        <div className={`verdict verdict--${r.verdict === 'INTACT' ? 'ok' : 'bad'}`}>
          <strong>{r.verdict === 'INTACT' ? 'Intact' : 'Tampered'}</strong>
          <span>{r.matching} of {r.vault_entries} sealed lines are unchanged on the machine{r.healed ? `. ${r.healed} restored by self-healing` : ''}{r.authorized ? `. ${r.authorized} changed under an approved ticket` : ''}.</span>
        </div>
      )}
      <div className="exhibits">
        {findings.map((f, i) => (
          <article key={i} className={`exhibit exhibit--${f.status.toLowerCase()}`}>
            <header>
              <span className="exhibit__no">{f.seq ? `Line #${f.seq}` : 'Unsealed line'}</span>
              <span className="exhibit__status">{f.status === 'DELETED' ? 'Erased on the machine' : f.status === 'MODIFIED' ? 'Altered on the machine' : 'Never sealed'}</span>
              {f.healed && <span className="exhibit__healed">Restored by self-healing</span>}
              {f.authorized && <span className="exhibit__authorized">Approved change · {f.authorized.ticket}</span>}
              {f.authorization_mismatch && <span className="exhibit__mismatch">Differs from approved {f.authorization_mismatch.ticket}</span>}
            </header>
            {f.vault_line && <p className="exhibit__line"><em>Sealed original</em><code>{f.vault_line}</code></p>}
            {f.server_line && <p className="exhibit__line"><em>On the machine now</em><code>{f.server_line}</code></p>}
            {f.diff && <DiffLine diff={f.diff} />}
            {f.proof?.anchored && (
              <footer>
                Merkle proof {f.proof.proof_valid ? 'valid' : 'invalid'} · fingerprinted {fromUnix(f.proof.on_chain_since)}
                {f.proof.tx_url && <> · <a href={f.proof.tx_url} target="_blank" rel="noreferrer">view transaction</a></>}
              </footer>
            )}
          </article>
        ))}
      </div>
    </section>
  )
}

/* --------------------------------------------------------------- Prove --- */
export function Prove({ host, s }) {
  const [search, setSearch] = useState('')
  const [rows, setRows] = useState([])
  const [pick, setPick] = useState(null)
  const [reveal, setReveal] = useState([])
  const [proof, setProof] = useState(null)
  const [walk, setWalk] = useState(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    const t = setTimeout(() => api(`/entries/${host}`, { params: { search, limit: 40 } })
      .then((r) => setRows(r.filter((e) => !e.line.startsWith('[SAKSHYALOG RESTORED')))).catch(() => {}), 250)
    return () => clearTimeout(t)
  }, [host, search])
  useEffect(() => { setPick(null); setProof(null); setWalk(null) }, [host])

  const hostInfo = (s?.hosts || []).find((x) => x.host === host)
  const sealedTo = hostInfo?.sealed_seq ?? Math.max(0, ...(s?.batches || []).filter((b) => b.host === host).map((b) => b.end_seq))
  const ready = sealedTo > 0 ? rows.filter((e) => e.seq <= sealedTo) : rows
  const waiting = rows.length - ready.length

  const make = async () => {
    if (!pick) return
    setErr(''); setWalk(null)
    try {
      const p = await api(`/proof/${host}/${pick.seq}`, { params: { reveal: reveal.join(',') } })
      setProof(p)
      const leaf = await entryHash(p.entry)
      const steps = await walkProof(leaf, p.proof)
      setWalk({ leafOk: leaf === p.leaf, steps, rootOk: steps[steps.length - 1].hash === p.root })
    } catch (e) { setErr(e.message) }
  }

  return (
    <section className="view">
      <header className="view__head">
        <h1>Prove one line, keep the rest private</h1>
        <p>A court gets one line and a few hashes. Your browser recomputes the path to the fingerprint on the blockchain, without trusting our server.</p>
      </header>
      <div className="prove">
        <div className="prove__pick">
          <input className="field" placeholder="Search sealed lines, e.g. root, TXN, KYC" value={search} onChange={(e) => setSearch(e.target.value)} aria-label="Search sealed lines" />
          {waiting > 0 && <p className="prove__note">{waiting === 1 ? '1 newer line is' : `${waiting} newer lines are`} still waiting for a seal, so {waiting === 1 ? "it isn't" : "they aren't"} listed yet.</p>}
          <ul className="picklist">
            {ready.map((e) => (
              <li key={e.seq}>
                <button className={pick?.seq === e.seq ? 'is-on' : ''} onClick={() => { setPick(e); setReveal([]); setProof(null); setWalk(null) }}>
                  <span>#{e.seq}</span><code>{e.line.slice(0, 120)}</code>
                </button>
              </li>
            ))}
          </ul>
        </div>
        <div className="prove__out">
          {!pick ? <p className="quiet">Choose a line on the left.</p> : (
            <>
              <code className="prove__line">{pick.line}</code>
              {pick.tokens.length > 0 && (
                <fieldset className="reveal">
                  <legend>Personal data in this line is hidden. Reveal any of it to the court?</legend>
                  {pick.tokens.map((t) => (
                    <label key={t}><input type="checkbox" checked={reveal.includes(t)} onChange={(e) => setReveal(e.target.checked ? [...reveal, t] : reveal.filter((x) => x !== t))} /> {t.split(':')[0].slice(2)} <code>{t}</code></label>
                  ))}
                </fieldset>
              )}
              <button className="btn btn--seal" onClick={make}>Create and check the proof</button>
              {err && <p className="callout callout--breach">{err}</p>}
              {proof && walk && (
                <div className="merkle">
                  <ol className="merkle__path">
                    {walk.steps.map((st, i) => (
                      <li key={i} style={{ '--d': `${i * 260}ms` }} className={i === walk.steps.length - 1 ? 'is-root' : ''}>
                        {i === 0 ? <span className="merkle__label">This line</span> : <span className="merkle__label">combined with <code>{short(st.sibling, 8)}</code></span>}
                        <code className="merkle__hash">{short(st.hash, 18)}</code>
                      </li>
                    ))}
                  </ol>
                  <div className={`verdict verdict--${walk.leafOk && walk.rootOk ? 'ok' : 'bad'}`}>
                    <strong>{walk.leafOk && walk.rootOk ? 'Verified by your browser' : 'Does not match'}</strong>
                    <span>
                      Matches the fingerprint on the blockchain, recorded {fromUnix(proof.on_chain_since)}. {proof.batch_size - 1 === 1 ? '1 other line stays' : `${proof.batch_size - 1} other lines stay`} hidden; {proof.hidden_personal_fields === 1 ? '1 personal field' : `${proof.hidden_personal_fields} personal fields`} hidden.
                      {proof.tx_url && <> <a href={proof.tx_url} target="_blank" rel="noreferrer">View transaction</a>.</>}
                    </span>
                  </div>
                  {proof.disclosed.map((d) => <p key={d.token} className="callout">Revealed {d.kind}: <strong>{d.value}</strong>. The salt proves it matches the sealed hash.</p>)}
                  <button className="btn" onClick={() => saveText(JSON.stringify(proof, null, 1), `proof_line_${proof.entry.seq}.json`, 'application/json')}>Download proof file</button>
                </div>
              )}
            </>
          )}
        </div>
      </div>
      {proof && walk && <ProvenanceCard host={host} seq={proof.entry.seq} />}
    </section>
  )
}

/* ------------------------------------------------------------- UPI case --- */
const TXN = /TXN (T\d+) \| FROM (ACC-\w+) \(([^)]*)\) \| TO (ACC-\w+) \(([^)]*)\) \| INR (\d+)/
const LAYER = { Victim: 0, 'Account A': 1, 'Account B': 2, 'Account C': 2, 'Account D': 3 }

export function UpiCase({ s }) {
  const CASE = 'case-UPI-001'
  const known = s.hosts.some((h) => h.host === CASE)
  const { data: entries } = usePoll(() => (known ? api(`/entries/${CASE}`, { params: { limit: 200 } }) : Promise.resolve([])), 4000, [known])
  const { data: live } = usePoll(() => (known ? api('/verify-live', { method: 'POST', params: { host: CASE } }) : Promise.resolve(null)), 4000, [known])
  const sealed = useMemo(() => (entries || []).filter((e) => !e.line.startsWith('[SAKSHYALOG RESTORED')).sort((a, b) => a.seq - b.seq), [entries])
  const bad = useMemo(() => new Map((live?.findings || []).filter((f) => f.seq).map((f) => [f.seq, f])), [live])

  const graph = useMemo(() => {
    const nodes = new Map(); const edges = []
    for (const e of sealed) {
      const m = e.line.match(TXN); if (!m) continue
      const [, id, fa, fr, ta, tr, amt] = m
      nodes.set(fa, fr); nodes.set(ta, tr)
      edges.push({ id, from: fa, to: ta, amt: +amt, f: bad.get(e.seq) })
    }
    const cols = {}
    const pos = {}
    ;[...nodes].forEach(([acc, role]) => {
      const c = LAYER[role] ?? 1; cols[c] = (cols[c] || 0) + 1
      pos[acc] = { x: 100 + c * 260, slot: cols[c] - 1, role, c }
    })
    Object.values(pos).forEach((p) => { const n = cols[p.c]; p.y = 130 + (p.slot - (n - 1) / 2) * 150 })
    return { pos, edges }
  }, [sealed, bad])

  if (!known) return <section className="view"><p className="quiet">The case file is being written and sealed. It appears about 30 seconds after start.</p></section>
  const tampered = live && live.verdict !== 'INTACT'

  return (
    <section className="view">
      <header className="view__head">
        <h1>Case UPI-001: a ₹50,000 phishing loss</h1>
        <p>The investigation file is sealed line by line and fingerprinted on the same contract as the server logs. All data is synthetic; accounts are pseudonyms and the complainant’s mobile and UPI ID are hidden. SakshyaLog doesn’t decide guilt or freeze accounts. It proves the record wasn’t secretly changed.</p>
      </header>
      <div className={`verdict verdict--${tampered ? 'bad' : 'ok'}`}>
        <strong>{tampered ? 'Case file tampered' : 'Case file intact'}</strong>
        <span>{sealed.length} records sealed{tampered ? `. ${bad.size} changed on the investigation server${live.healed ? `, ${live.healed} restored by self-healing` : ''}.` : '.'} Run <code>py -3.14 demo\attack_case.py</code> to try a cover-up.</span>
      </div>

      <figure className="flow">
        <svg viewBox="0 0 980 270" role="img" aria-label="Money flow from the victim through accounts A to D">
          <defs>
            <marker id="arr-ok" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path d="M0,0L10,5L0,10z" fill="#3b82c4" /></marker>
            <marker id="arr-bad" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path d="M0,0L10,5L0,10z" fill="#111827" /></marker>
          </defs>
          {graph.edges.map((e) => {
            const a = graph.pos[e.from], b = graph.pos[e.to]
            const p0 = [a.x + 70, a.y], p1 = [a.x + 140, a.y], p2 = [b.x - 140, b.y], p3 = [b.x - 72, b.y]
            const d = `M${p0} C${p1} ${p2} ${p3}`
            const mx = (p0[0] + 3 * p1[0] + 3 * p2[0] + p3[0]) / 8, my = (p0[1] + 3 * p1[1] + 3 * p2[1] + p3[1]) / 8
            return (
              <g key={e.id} className={e.f ? 'flow__edge is-bad' : 'flow__edge'}>
                <path d={d} markerEnd={`url(#${e.f ? 'arr-bad' : 'arr-ok'})`} />
                <text x={mx} y={my - 8} textAnchor="middle">{e.id} ₹{e.amt.toLocaleString('en-IN')}</text>
                {e.f && <text x={mx} y={my + 12} textAnchor="middle">{e.f.healed ? 'erased on the server, restored' : 'erased on the server'}</text>}
              </g>
            )
          })}
          {Object.entries(graph.pos).map(([acc, p]) => (
            <g key={acc} className={`flow__node ${p.role === 'Victim' ? 'is-victim' : ''}`} transform={`translate(${p.x - 70},${p.y - 26})`}>
              <rect width="140" height="52" rx="6" />
              <text x="70" y="22" textAnchor="middle" className="flow__role">{p.role}</text>
              <text x="70" y="40" textAnchor="middle" className="flow__acc">{acc}</text>
            </g>
          ))}
        </svg>
        <figcaption>Drawn from the sealed originals, so a deleted transfer still appears, in black.</figcaption>
      </figure>

      <ol className="records">
        {sealed.map((e) => {
          const f = bad.get(e.seq)
          const kind = (e.line.split(' | ')[2] || '').split(' ')[0]
          return (
            <li key={e.seq} className={f ? 'is-bad' : ''}>
              <span className="records__kind">{kind.toLowerCase()}</span>
              <code>{e.line.split(' | ').slice(2).join(' | ')}</code>
              {f && <span className="records__flag">{f.status === 'MODIFIED' ? 'altered' : 'erased'} on the server{f.healed ? ', restored' : ''}{f.server_line ? `: now reads “${f.server_line.split(' | ').slice(3).join(' | ').slice(0, 90)}”` : ''}</span>}
            </li>
          )
        })}
      </ol>
    </section>
  )
}

/* ---------------------------------------------------------- CERT-In ------ */
export function CertIn({ s, host, h }) {
  const [busy, setBusy] = useState('')
  const [form, setForm] = useState({ org: 'Demo Bank Ltd', sector: 'Banking', contact: 'A. Kumar, CISO', contact_details: 'ciso@demobank.example', actions: 'Server isolated, root password rotated, attacker IP blocked' })
  const [now, setNow] = useState(Date.now())
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(t) }, [])
  const incidents = s.incidents.filter((i) => i.host === host)
  const ret = h.retention || {}
  const act = async (label, fn) => { setBusy(label); try { await fn() } catch (e) { alert(e.message) } setBusy('') }

  return (
    <section className="view">
      <header className="view__head">
        <h1>Report within six hours, prove it forever</h1>
        <p>Freezing evidence writes the incident to the smart contract. The contract fixes the six-hour CERT-In deadline and later records whether the report was on time.</p>
      </header>
      <div className="split">
        <div className="panel">
          <h2>Incident</h2>
          <button className="btn btn--seal" disabled={!!busy} onClick={() => act('freeze', () => api('/incident', { method: 'POST', body: { host, note: `Evidence tampering on ${host}` } }))}>
            {busy === 'freeze' ? 'Freezing on-chain…' : 'Freeze evidence and start the clock'}
          </button>
          {incidents.slice(0, 3).map((i) => {
            const left = Math.max(0, (new Date(i.deadline).getTime() - now) / 1000)
            const hh = String(Math.floor(left / 3600)).padStart(2, '0'), mm = String(Math.floor((left % 3600) / 60)).padStart(2, '0'), ss = String(Math.floor(left % 60)).padStart(2, '0')
            return (
              <div key={i.id} className="incident">
                <p className="incident__clock" aria-label="Time left to report to CERT-In">{hh}:{mm}:{ss}</p>
                <p>Incident {i.id} · frozen {dateTime(i.declared_at)} · on-chain incident {i.chain_id}</p>
                {i.reported_at ? (
                  <p className={`verdict verdict--${i.on_time ? 'ok' : 'bad'}`}><strong>{i.on_time ? 'Reported on time' : 'Reported late'}</strong><span>Decided by the smart contract at {dateTime(i.reported_at)}. It can’t be changed.</span></p>
                ) : (
                  <button className="btn" disabled={!!busy} onClick={() => act('report', async () => {
                    const html = await api(`/report/certin/${host}`, { method: 'POST', body: form, text: true })
                    await api(`/incident/${i.id}/reported`, { method: 'POST', body: { report: html } })
                  })}>{busy === 'report' ? 'Recording…' : 'Mark as reported to CERT-In'}</button>
                )}
              </div>
            )
          })}
        </div>
        <div className="panel">
          <h2>Report and court evidence</h2>
          <div className="form">
            {[['org', 'Organisation'], ['contact', 'Point of contact'], ['contact_details', 'Phone or email'], ['actions', 'Containment actions']].map(([k, l]) => (
              <label key={k}>{l}<input className="field" value={form[k]} onChange={(e) => setForm({ ...form, [k]: e.target.value })} /></label>
            ))}
          </div>
          <div className="row">
            <button className="btn" onClick={() => act('certin', async () => saveText(await api(`/report/certin/${host}`, { method: 'POST', body: form, text: true }), `CERT-In_incident_report_${host}.html`))}>Download CERT-In report</button>
            <button className="btn" onClick={() => act('pack', () => download(`/evidence-pack/${host}`, `sakshyalog_evidence_${host}.zip`))}>{busy === 'pack' ? 'Building…' : 'Download court evidence pack'}</button>
          </div>
          <p className="quiet">Anyone can check the pack without trusting us: <code>python verify_pack.py pack.zip</code></p>
          <h2>180-day retention</h2>
          <p>Kept safely for <strong>{ret.kept_seconds != null ? human(ret.kept_seconds) : '–'}</strong>. Newest line locked until {ret.locked_until ? dateTime(ret.locked_until) : '–'}.</p>
          <div className="meter" aria-hidden="true"><span style={{ width: `${Math.min(100, ((ret.kept_days || 0) / s.retention_days) * 100)}%` }} /></div>
        </div>
      </div>
    </section>
  )
}

/* -------------------------------------------------------------- Chain ---- */
export function Chain({ s, ci, h }) {
  const [gwei, setGwei] = useState(30)
  const [price, setPrice] = useState(20)
  const anchors = Object.entries(s.gas || {}).filter(([k]) => k.startsWith('anchor'))
  const n = anchors.reduce((a, [, v]) => a + v.count, 0)
  const avg = n ? Math.round(anchors.reduce((a, [, v]) => a + v.avg_gas * v.count, 0) / n) : 0
  const perDay = avg ? ((86400 / 60) * avg + (86400 / 300) * (s.gas?.heartbeat?.avg_gas || 0)) * gwei * 1e-9 : 0
  const cur = ci.mode === 'quai' ? 'QUAI' : 'token'
  return (
    <section className="view">
      <header className="view__head">
        <h1>The blockchain is the notary</h1>
        <p>The company controls its servers and its vault, but not the chain. Only 32-byte fingerprints go on-chain: no log text, no personal data.</p>
      </header>
      <div className={`verdict verdict--${ci.simulated ? 'bad' : 'ok'}`}>
        <strong>{ci.mode === 'quai' ? 'Quai Network · Orchard testnet, Cyprus-1' : ci.name}</strong>
        <span>
          {ci.contract && <>Contract <a href={ci.explorer_address || undefined} target="_blank" rel="noreferrer"><code>{ci.contract}</code></a> · block {ci.block_number}</>}
          {ci.simulated && ' Simulated offline ledger: say so if you demo it.'}
        </span>
      </div>
      <ul className="rules">
        <li><strong>No skipped lines.</strong> Each batch must start where the last ended, or the chain rejects it.</li>
        <li><strong>Public heartbeat.</strong> Last on-chain heartbeat {h.chain_heartbeat_age_s != null ? `${h.chain_heartbeat_age_s} s ago` : '–'}. Silence is visible to anyone.</li>
        <li><strong>Agent attestation.</strong> The logger’s code hash is on-chain{h.attestation?.changed ? ', and it has changed.' : ' and matches.'}</li>
        <li><strong>Incident registry.</strong> The contract sets the six-hour deadline and the on-time verdict.</li>
      </ul>
      <div className="split">
        <div className="panel">
          <h2>Latest transactions</h2>
          <ol className="txs">
            {s.chain_txs.map((t) => (
              <li key={t.id}>
                <time>{clock(t.ts)}</time>
                <span className="txs__kind">{t.kind.replace('anchor-', 'seal · ')}</span>
                {t.tx_url ? <a href={t.tx_url} target="_blank" rel="noreferrer"><code>{short(t.tx, 14)}</code></a> : <code>{short(t.tx, 14)}</code>}
                <span className="txs__gas">{t.gas ? t.gas.toLocaleString() : ''}</span>
              </li>
            ))}
          </ol>
        </div>
        <div className="panel">
          <h2>What it costs per server</h2>
          <div className="form form--row">
            <label>Gas price (gwei)<input className="field" type="number" value={gwei} onChange={(e) => setGwei(+e.target.value)} /></label>
            <label>{cur} price (₹)<input className="field" type="number" value={price} onChange={(e) => setPrice(+e.target.value)} /></label>
          </div>
          {avg ? (
            <dl className="facts">
              <dt>Gas per seal (measured)</dt><dd>{avg.toLocaleString()}</dd>
              <dt>Per day, sealing every minute</dt><dd>₹{(perDay * price).toFixed(2)} ({perDay.toFixed(4)} {cur})</dd>
              <dt>Per month</dt><dd>₹{(perDay * price * 30).toFixed(0)}</dd>
            </dl>
          ) : <p className="quiet">Measuring gas from the first seals…</p>}
          <p className="quiet">Assumed prices. Update them to today’s values before quoting a number.</p>
        </div>
      </div>
    </section>
  )
}
