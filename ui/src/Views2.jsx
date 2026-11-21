/* SakshyaLog 2.0 pages: fleet, attack lab, change control, auditor portal, hardening,
   plus the exact-diff and provenance pieces reused by Verify and Prove. */
import { useEffect, useMemo, useState } from 'react'
import { api, usePoll, ago, dateTime, short, entryHash, walkProof, saveText } from './lib.js'

export const hostLabel = (x) =>
  x === 'server-01' ? 'Server logs · server-01' : x === 'server-02' ? 'Server logs · server-02'
    : x === 'case-UPI-001' ? 'UPI fraud case file · UPI-001' : x

/* ---------------------------------------------------- ① exact diff ---- */
export function DiffLine({ diff }) {
  if (!diff) return null
  return (
    <div className="diff">
      <p className="diff__summary">{diff.summary}</p>
      <code className="diff__line" aria-label="Character-level difference">
        {diff.segments.map((g, i) => g.op === 'eq' ? <span key={i}>{g.text}</span>
          : g.op === 'del' ? <del key={i} title="removed">{g.text}</del> : <ins key={i} title="added">{g.text}</ins>)}
      </code>
      {diff.fields.length > 0 && (
        <ul className="diff__fields">
          {diff.fields.slice(0, 4).map((f, i) => (
            <li key={i}><b>{f.field}</b> {f.from || '∅'} → {f.to || '∅'}</li>
          ))}
        </ul>
      )}
    </div>
  )
}

/* ----------------------------------------------- ⑪ provenance card ---- */
const MARK = { pass: '✓', fail: '✗', warn: '!', pending: '…' }
export function ProvenanceCard({ host, seq }) {
  const [p, setP] = useState(null)
  const [err, setErr] = useState('')
  useEffect(() => {
    setP(null); setErr('')
    if (!seq) return
    api(`/provenance/${host}/${seq}`).then(setP).catch((e) => setErr(e.message))
  }, [host, seq])
  if (!seq) return null
  if (err) return <p className="callout">{err}</p>
  if (!p) return <p className="quiet">Checking where this line came from…</p>
  const tone = p.machine === 'same' ? 'ok' : p.machine === 'changed' ? 'bad' : 'warn'
  return (
    <section className={`prov prov--${tone}`} aria-label="Evidence provenance">
      <header>
        <h3>Provenance of line #{p.seq}</h3>
        <p>{p.verdict}</p>
      </header>
      <ol className="prov__checks">
        {p.checks.map((c) => (
          <li key={c.name} className={`is-${c.status}`}>
            <span className="prov__mark" aria-label={c.status}>{MARK[c.status]}</span>
            <div><b>{c.name}</b><span>{c.detail}</span></div>
          </li>
        ))}
      </ol>
      {p.diff && <DiffLine diff={p.diff} />}
      <div className="prov__agree">
        {['vault', 'read-only copy', 'blockchain', 'machine'].map((src) => (
          <span key={src} className={p.agree.includes(src) ? 'is-on' : ''}>{src}</span>
        ))}
      </div>
      <ul className="prov__story">
        {p.story.map((s, i) => <li key={i}><time>{dateTime(s.ts)}</time>{s.what}</li>)}
      </ul>
    </section>
  )
}

/* ----------------------------------------------------- ⑤ fleet ---- */
export function Fleet({ setHost, setView, ci }) {
  const { data } = usePoll(() => api('/fleet'), 3000)
  const servers = data?.servers || []
  const H = Math.max(220, servers.length * 92 + 40)
  const tone = (x) => (!x.agent_alive ? 'down' : x.verdict === 'TAMPERED' ? 'bad' : x.high_alert ? 'watch' : 'ok')
  return (
    <section className="view">
      <header className="view__head">
        <h1>Every machine, one evidence network</h1>
        <p>Each server runs its own agent. All of them feed the same off-machine vault and the same smart contract, so one compromised machine can't hide its tracks.</p>
      </header>
      <figure className="net">
        <svg viewBox={`0 0 980 ${H}`} role="img" aria-label="Agents on each machine send sealed lines to the vault, which seals them on the blockchain">
          {servers.map((x, i) => {
            const y = 40 + i * 92 + 32
            return (
              <g key={x.host} className={`net__node net__node--${tone(x)}`}>
                <path className="net__wire" d={`M290,${y} C380,${y} 380,${H / 2} 450,${H / 2}`} />
                <rect x="40" y={y - 32} width="250" height="64" rx="8" />
                <text x="58" y={y - 6} className="net__name">{x.host}</text>
                <text x="58" y={y + 16} className="net__meta">
                  {!x.agent_alive ? 'agent silent' : x.verdict === 'TAMPERED' ? `${x.bad} line(s) tampered` : `${x.entries} lines sealed`}
                </text>
                <circle cx="268" cy={y - 12} r="6" className="net__dot" />
              </g>
            )
          })}
          <path className="net__wire net__wire--chain" d={`M610,${H / 2} L720,${H / 2}`} />
          <g className="net__hub">
            <rect x="450" y={H / 2 - 40} width="160" height="80" rx="10" />
            <text x="530" y={H / 2 - 6} textAnchor="middle" className="net__name">Vault</text>
            <text x="530" y={H / 2 + 16} textAnchor="middle" className="net__meta">off-machine, append-only</text>
          </g>
          <g className="net__chain">
            <circle cx="790" cy={H / 2} r="58" />
            <text x="790" y={H / 2 - 4} textAnchor="middle" className="net__name">{ci.mode === 'quai' ? 'Quai' : 'Blockchain'}</text>
            <text x="790" y={H / 2 + 16} textAnchor="middle" className="net__meta">smart contract</text>
          </g>
        </svg>
      </figure>
      <div className="fleet">
        {servers.map((x) => (
          <article key={x.host} className={`fleet__card fleet__card--${tone(x)}`}>
            <header>
              <h3>{x.host}</h3>
              <span className="fleet__state">{!x.agent_alive ? 'Agent silent' : x.verdict === 'TAMPERED' ? 'Tampering found' : x.high_alert ? 'High alert' : 'Protected'}</span>
            </header>
            <dl>
              <dt>Lines sealed</dt><dd>{x.entries ?? 0}</dd>
              <dt>Seals on chain</dt><dd>{x.seals ?? 0}</dd>
              <dt>Agent heartbeat</dt><dd>{x.heartbeat_age_s != null ? ago(x.heartbeat_age_s) : '–'}</dd>
              <dt>Live tamper signals</dt><dd>{x.live_signals}</dd>
              <dt>Restored lines</dt><dd>{x.healed}</dd>
              <dt>Key custody</dt><dd>{x.custody?.mode || '–'}</dd>
            </dl>
            <button className="btn" onClick={() => { setHost(x.host); setView('overview') }}>Open {x.host}</button>
          </article>
        ))}
      </div>
    </section>
  )
}

/* ----------------------------------------------- ⑩ attack lab ---- */
export function Lab({ host, hosts }) {
  const { data: meta } = usePoll(() => api('/lab/scenarios'), 0)
  const { data: runs } = usePoll(() => api('/lab/runs'), 1500)
  const [target, setTarget] = useState(host)
  const [busy, setBusy] = useState('')
  const [err, setErr] = useState('')
  useEffect(() => setTarget(host), [host])
  const fire = async (id) => {
    setBusy(id); setErr('')
    try { await api('/lab/run', { method: 'POST', body: { host: target, scenario: id } }) } catch (e) { setErr(e.message) }
    setBusy('')
  }
  const done = (runs || []).filter((r) => r.detected_s != null)
  const avg = done.length ? (done.reduce((a, r) => a + r.detected_s, 0) / done.length).toFixed(1) : null
  const targets = meta?.targets || hosts
  return (
    <section className="view">
      <header className="view__head">
        <h1>Attack it yourself</h1>
        <p>Pick a machine, launch a real attack on its log file, and watch SakshyaLog catch it, name exactly what changed, and put the original back. Demo logs only.</p>
      </header>
      {meta && !meta.enabled && <p className="callout">The attack lab runs only in demo mode. Start with run_demo.py.</p>}
      <div className="lab__bar">
        <label className="source">
          <span>Target</span>
          <select value={target} onChange={(e) => setTarget(e.target.value)}>
            {targets.map((x) => <option key={x} value={x}>{hostLabel(x)}</option>)}
          </select>
        </label>
        {runs && runs.length > 0 && (
          <p className="lab__score"><b>{done.length}</b> of <b>{runs.length}</b> attacks caught{avg && <> · average <b>{avg} s</b> to detect</>}</p>
        )}
      </div>
      <div className="lab__grid">
        {(meta?.scenarios || []).map((sc) => (
          <button key={sc.id} className={`lab__card ${sc.id === 'authorized_change' ? 'lab__card--ok' : ''}`} disabled={!!busy || meta?.enabled === false} onClick={() => fire(sc.id)}>
            <b>{busy === sc.id ? 'Launching…' : sc.title}</b>
            <span>{sc.what}</span>
          </button>
        ))}
      </div>
      {err && <p className="callout">{err}</p>}
      <table className="lab__runs">
        <thead><tr><th>Attack</th><th>What changed</th><th>Detected</th><th>Restored</th><th>Result</th></tr></thead>
        <tbody>
          {(runs || []).map((r, i) => (
            <tr key={r.id} className={i === 0 ? 'is-new' : ''}>
              <td><b>{r.title}</b><small>{r.host}{r.seq ? ` · line #${r.seq}` : ''}</small></td>
              <td>{r.diff ? <DiffLine diff={r.diff} /> : r.scenario === 'fake_insert' ? <code className="lab__fake">+ {r.after}</code>
                : r.scenario === 'delete_line' ? <code className="lab__del">{r.before}</code> : <span className="quiet">{r.note}</span>}</td>
              <td className="num">{r.detected_s != null ? <><b>{r.detected_s.toFixed(1)} s</b><small>{r.detected_by}</small></> : <span className="lab__wait">watching</span>}</td>
              <td className="num">{r.recovered_s != null ? <b>{r.recovered_s.toFixed(1)} s</b> : '–'}</td>
              <td className={`lab__out ${/Allowed/.test(r.outcome) ? 'is-ok' : r.detected_s != null ? 'is-caught' : ''}`}>{r.outcome}</td>
            </tr>
          ))}
          {runs && !runs.length && <tr><td colSpan="5" className="quiet">No attacks yet. Launch one above.</td></tr>}
        </tbody>
      </table>
    </section>
  )
}

/* ------------------------------------------ ② change control ---- */
export function Changes({ host }) {
  const [search, setSearch] = useState('')
  const [rows, setRows] = useState([])
  const [pick, setPick] = useState(null)
  const [form, setForm] = useState({ new_line: '', ticket: '', reason: '', approver: '' })
  const [msg, setMsg] = useState('')
  const { data: reqs, refresh } = usePoll(() => api('/change-requests', { params: { host } }), 4000, [host])
  useEffect(() => {
    const t = setTimeout(() => api(`/entries/${host}`, { params: { search, limit: 25 } })
      .then((r) => setRows(r.filter((e) => !e.line.startsWith('[SAKSHYALOG')))).catch(() => {}), 250)
    return () => clearTimeout(t)
  }, [host, search])
  useEffect(() => { setPick(null); setMsg('') }, [host])
  const choose = (e) => { setPick(e); setForm((f) => ({ ...f, new_line: e.line })); setMsg('') }
  const submit = async () => {
    setMsg('')
    try {
      await api('/change-request', { method: 'POST', body: { host, seq: pick.seq, ...form } })
      setMsg(`Approved. Line #${pick.seq}'s original is preserved. Now only this exact new text is allowed.`)
      refresh()
    } catch (e) { setMsg(e.message) }
  }
  const ok = pick && form.ticket.trim() && form.reason.trim() && form.approver.trim()
  return (
    <section className="view">
      <header className="view__head">
        <h1>Approve a change before it happens</h1>
        <p>Sometimes a log must change for a real reason. Register the change first: the original stays preserved, the exact allowed text is recorded, and any other edit is flagged as tampering and reverted.</p>
      </header>
      <div className="split">
        <div className="panel">
          <h2>1. Pick the line</h2>
          <input className="field" placeholder="Search sealed lines" value={search} onChange={(e) => setSearch(e.target.value)} aria-label="Search sealed lines" />
          <ul className="picklist picklist--short">
            {rows.map((e) => (
              <li key={e.seq}><button className={pick?.seq === e.seq ? 'is-on' : ''} onClick={() => choose(e)}><span>#{e.seq}</span><code>{e.line.slice(0, 110)}</code></button></li>
            ))}
          </ul>
        </div>
        <div className="panel">
          <h2>2. Describe the approved change</h2>
          {!pick ? <p className="quiet">Pick a line on the left first.</p> : (
            <div className="form">
              <label>New text (leave as is and delete the line to approve a deletion)
                <textarea className="field" rows="3" value={form.new_line} onChange={(e) => setForm({ ...form, new_line: e.target.value })} />
              </label>
              <label>Change ticket<input className="field" placeholder="CHG-2041" value={form.ticket} onChange={(e) => setForm({ ...form, ticket: e.target.value })} /></label>
              <label>Reason<input className="field" placeholder="Correct a misspelt customer name" value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} /></label>
              <label>Approved by<input className="field" placeholder="A. Kumar, CISO" value={form.approver} onChange={(e) => setForm({ ...form, approver: e.target.value })} /></label>
              <button className="btn btn--seal" disabled={!ok} onClick={submit}>Approve this change</button>
              {msg && <p className="callout">{msg}</p>}
            </div>
          )}
        </div>
      </div>
      <h2 className="section">Approved changes</h2>
      <ul className="changes">
        {(reqs || []).map((r) => (
          <li key={r.id} className={`changes__item is-${r.state}`}>
            <header><b>{r.ticket}</b> · line #{r.seq} · {r.approver}<span className="changes__state">{r.state_text}</span></header>
            <p className="quiet">{r.reason}</p>
            <DiffLine diff={r.original_line && r.new_line ? diffOf(r.original_line, r.new_line) : null} />
            {r.state === 'flagged' && r.actual && <p className="changes__actual">Actually written: <code>{r.actual}</code></p>}
          </li>
        ))}
        {reqs && !reqs.length && <li className="quiet">No approved changes yet.</li>}
      </ul>
    </section>
  )
}

/* tiny client-side diff for the approved-change preview (same idea as the server's) */
function diffOf(a, b) {
  let i = 0; while (i < a.length && i < b.length && a[i] === b[i]) i++
  let j = 0; while (j < a.length - i && j < b.length - i && a[a.length - 1 - j] === b[b.length - 1 - j]) j++
  const del = a.slice(i, a.length - j), ins = b.slice(i, b.length - j)
  if (!del && !ins) return { summary: 'No change in the text (approves a deletion)', segments: [{ op: 'eq', text: a }], fields: [] }
  return { summary: `Allowed change: ${del || '∅'} → ${ins || '∅'}`, fields: [],
    segments: [{ op: 'eq', text: a.slice(0, i) }, ...(del ? [{ op: 'del', text: del }] : []), ...(ins ? [{ op: 'ins', text: ins }] : []), { op: 'eq', text: a.slice(a.length - j) }] }
}

/* ------------------------------------------ ⑦ auditor portal ---- */
export function Auditor({ host }) {
  const [proof, setProof] = useState(null)
  const [check, setCheck] = useState(null)
  const [err, setErr] = useState('')
  const [lookup, setLookup] = useState('')
  const [seq, setSeq] = useState(null)
  const read = async (file) => {
    setErr(''); setCheck(null); setProof(null)
    try {
      const p = JSON.parse(await file.text())
      if (p.format !== 'sakshyalog-line-proof-v1') throw new Error('This is not a SakshyaLog line proof file.')
      const leaf = await entryHash(p.entry)
      const steps = await walkProof(leaf, p.proof)
      setProof(p)
      setCheck({ leafOk: leaf === p.leaf, rootOk: steps[steps.length - 1].hash === p.root, steps: steps.length })
    } catch (e) { setErr(e.message || 'Could not read that file.') }
  }
  return (
    <section className="view">
      <header className="view__head">
        <span className="readonly">Read-only</span>
        <h1>Auditor portal</h1>
        <p>For auditors, regulators and courts. Nothing here can change evidence. Check a proof file entirely in your own browser, or look up any sealed line and see where it came from.</p>
      </header>
      <div className="split">
        <div className="panel">
          <h2>Check a proof file</h2>
          <p className="quiet">Use the file from “Prove one line” (Download proof file). The check runs in this browser, with no help from our server.</p>
          <label className="drop">
            <input type="file" accept=".json,application/json" onChange={(e) => e.target.files[0] && read(e.target.files[0])} />
            <span>Choose a proof file</span>
          </label>
          {err && <p className="callout">{err}</p>}
          {proof && check && (
            <div className={`verdict verdict--${check.leafOk && check.rootOk ? 'ok' : 'bad'}`}>
              <strong>{check.leafOk && check.rootOk ? 'Proof is valid' : 'Proof does not match'}</strong>
              <span>
                Line #{proof.entry.seq} from {proof.entry.host}. Recomputed {check.steps} hashes up to the fingerprint {short(proof.root, 10)}
                {proof.tx_url && <> · <a href={proof.tx_url} target="_blank" rel="noreferrer">see it on the blockchain</a></>}.
              </span>
            </div>
          )}
          {proof && <code className="auditor__line">{proof.entry.line}</code>}
        </div>
        <div className="panel">
          <h2>Look up a sealed line</h2>
          <p className="quiet">Source: {hostLabel(host)} (change it at the top).</p>
          <div className="row">
            <input className="field" inputMode="numeric" placeholder="Line number, e.g. 42" value={lookup} onChange={(e) => setLookup(e.target.value.replace(/\D/g, ''))} aria-label="Line number" />
            <button className="btn btn--seal" disabled={!lookup} onClick={() => setSeq(Number(lookup))}>Check provenance</button>
          </div>
        </div>
      </div>
      {seq && <ProvenanceCard host={host} seq={seq} />}
    </section>
  )
}

/* -------------------------------- ⑥ ⑧ ⑨ hardening ---- */
export function Hardening({ hosts }) {
  const { data: custody } = usePoll(() => api('/custody'), 10000)
  const { data: siem } = usePoll(() => api('/siem/status'), 5000)
  const [fmt, setFmt] = useState('cef')
  const { data: sample } = usePoll(() => api('/siem/events', { params: { format: fmt, limit: 6 }, text: fmt !== 'json' }), 5000, [fmt])
  const [worm, setWorm] = useState({})
  const checkAll = async () => {
    const out = {}
    for (const h of hosts) { try { out[h] = await api(`/worm/${h}`) } catch (e) { out[h] = { error: e.message } } }
    setWorm(out)
  }
  useEffect(() => { checkAll() /* eslint-disable-next-line */ }, [hosts.join()])
  const download = async () => saveText(await api('/siem/events', { params: { format: fmt, limit: 500 }, text: fmt !== 'json' }).then((x) => typeof x === 'string' ? x : JSON.stringify(x, null, 1)), `sakshyalog_siem.${fmt === 'json' ? 'json' : 'log'}`)
  return (
    <section className="view">
      <header className="view__head">
        <h1>Hardened like a real deployment</h1>
        <p>Where the keys live, where the immutable copies live, and how alerts reach the security team's existing tools.</p>
      </header>
      <h2 className="section">Key custody</h2>
      <div className="harden">
        {hosts.map((h) => {
          const c = custody?.[h]
          return (
            <article key={h} className="panel harden__card">
              <h3>{h}</h3>
              <p><b>{c?.label || 'Waiting for the agent…'}</b></p>
              <p className="quiet">The sealing key is stored sealed at rest and rotated every minute; each old key is destroyed. {c?.production ? `Production: ${c.production}.` : ''}</p>
              {c?.note && <p className="quiet">{c.note}</p>}
            </article>
          )
        })}
      </div>
      <h2 className="section">Write-once evidence copies (WORM)</h2>
      <div className="row"><button className="btn" onClick={checkAll}>Verify all copies again</button></div>
      <div className="harden">
        {hosts.map((h) => {
          const w = worm[h]
          return (
            <article key={h} className={`panel harden__card ${w?.ok === false ? 'is-bad' : w?.ok ? 'is-ok' : ''}`}>
              <h3>{h}</h3>
              {!w ? <p className="quiet">Checking…</p> : w.error ? <p className="callout">{w.error}</p> : (
                <>
                  <p><b>{w.ok ? 'All copies intact' : 'Copies were tampered with'}</b></p>
                  <p className="quiet">{w.files} read-only files covering {w.entries} lines (up to #{w.covers_to_seq}). Each file holds the fingerprint of the one before it, so deleting or editing any copy is detected.{w.s3_object_lock ? ' Also stored in S3 Object Lock (compliance mode).' : ''}</p>
                  {w.problems.map((p, i) => <p key={i} className="callout">{p}</p>)}
                </>
              )}
            </article>
          )
        })}
      </div>
      <h2 className="section">SIEM integration</h2>
      <div className="panel">
        <p>Every alert is forwarded as it happens: <b>{siem?.forwarded ?? 0}</b> sent so far{siem?.last_error ? `, last error: ${siem.last_error}` : ''}.</p>
        <ul className="siem__targets">
          <li><b>JSON lines file</b> for Splunk, Elastic or Wazuh to tail: <code>{siem?.targets?.file}</code></li>
          <li><b>Webhook</b> (Splunk HEC, Microsoft Sentinel, Elastic): {siem?.targets?.webhook ? <code>{siem.targets.webhook}</code> : <span className="quiet">set SIEM_WEBHOOK to enable</span>}</li>
          <li><b>Syslog with CEF</b> (QRadar, ArcSight): {siem?.targets?.syslog ? <code>{siem.targets.syslog}</code> : <span className="quiet">set SIEM_SYSLOG=host:port to enable</span>}</li>
        </ul>
        <div className="row">
          {['cef', 'syslog', 'json'].map((f) => <button key={f} className={`btn ${fmt === f ? 'btn--seal' : ''}`} onClick={() => setFmt(f)}>{f.toUpperCase()}</button>)}
          <button className="btn" onClick={download}>Download feed</button>
        </div>
        <pre className="siem__sample">{typeof sample === 'string' ? sample : JSON.stringify(sample, null, 1)}</pre>
      </div>
    </section>
  )
}

export function useHosts(s) {
  return useMemo(() => (s?.hosts || []).map((h) => h.host), [s])
}
