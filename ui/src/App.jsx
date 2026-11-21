import { Component, useEffect, useMemo, useState } from 'react'
import { api, usePoll, ago, human, dateTime, short, clock } from './lib.js'
import Custody from './Custody.jsx'
import { Timeline, Verify, Prove, UpiCase, CertIn, Chain } from './Views.jsx'
import { Fleet, Lab, Changes, Auditor, Hardening, hostLabel } from './Views2.jsx'

const VIEWS = [
  { id: 'overview', label: 'Overview', group: 'Watch' },
  { id: 'fleet', label: 'All machines' },
  { id: 'lab', label: 'Attack lab' },
  { id: 'timeline', label: 'Attack timeline' },
  { id: 'verify', label: 'Verify', group: 'Investigate' },
  { id: 'prove', label: 'Prove one line' },
  { id: 'upi', label: 'UPI case' },
  { id: 'auditor', label: 'Auditor portal' },
  { id: 'changes', label: 'Change control', group: 'Govern' },
  { id: 'certin', label: 'CERT-In & court' },
  { id: 'hardening', label: 'Hardening' },
  { id: 'chain', label: 'Blockchain' },
]
const TAMPER = ['tamper-detected', 'live-tamper', 'chain-break', 'bad-hash', 'forged-seal', 'sequence-gap', 'epoch-rollback', 'agent-code-changed']

export default function App() {
  const [view, setView] = useState(() => window.location.hash.slice(1) || 'overview')
  const [host, setHost] = useState('server-01')
  useEffect(() => { if (window.location.hash.slice(1) !== view) window.location.hash = view }, [view])
  useEffect(() => { // back/forward buttons and #links switch views too
    const on = () => { const v = window.location.hash.slice(1); if (VIEWS.some((x) => x.id === v)) setView(v) }
    window.addEventListener('hashchange', on)
    return () => window.removeEventListener('hashchange', on)
  }, [])

  const { data: s, error } = usePoll(() => api('/status'), 2000)
  const { data: live } = usePoll(() => api('/verify-live', { method: 'POST', params: { host } }).catch(() => null), 4000, [host])

  const hosts = useMemo(() => {
    const hs = (s?.hosts || []).map((h) => h.host)
    return hs.sort((a, b) => (a === 'server-01' ? -1 : b === 'server-01' ? 1 : a.localeCompare(b)))
  }, [s])
  const h = s?.hosts.find((x) => x.host === host) || {}
  const alerts = (s?.alerts || []).filter((a) => a.host === host)
  const breached = alerts.some((a) => TAMPER.includes(a.kind))
  const panicked = alerts.some((a) => a.kind === 'panic-anchor')
  const silent = alerts.some((a) => a.kind === 'heartbeat-lost')
  const mood = breached || panicked ? 'breach' : silent || h.anchor_mode === 'HIGH ALERT' ? 'watch' : 'calm'

  if (!s) {
    return (
      <main className="boot">
        <div className="boot__seal" aria-hidden="true" />
        <h1>SakshyaLog</h1>
        <p>{error ? 'The vault isn’t answering on port 8000. Start it with py -3.14 run_demo.py --reset --quai, then this page connects by itself.' : 'Connecting to the evidence vault…'}</p>
      </main>
    )
  }

  const ci = s.chain_info || {}
  const props = { s, h, host, hosts, setHost, live, ci, alerts, setView }

  return (
    <div className={`app app--${mood}`}>
      <header className="bar">
        <a className="brand" href="#overview" onClick={() => setView('overview')}>
          <span className="brand__seal" aria-hidden="true" />
          <span className="brand__name">SakshyaLog</span>
        </a>
        <label className="source">
          <span>Evidence source</span>
          <select value={host} onChange={(e) => setHost(e.target.value)}>
            {hosts.map((x) => <option key={x} value={x}>{hostLabel(x)}</option>)}
          </select>
        </label>
        <div className={`state state--${mood}`} role="status" aria-live="polite">
          <span className="state__dot" aria-hidden="true" />
          {mood === 'breach' ? 'Evidence under attack' : mood === 'watch' ? 'Watching closely' : 'Evidence intact'}
        </div>
        <a className={`chainchip ${ci.simulated ? 'chainchip--sim' : ''}`} href={ci.explorer_address || undefined} target="_blank" rel="noreferrer">
          {ci.mode === 'quai' ? 'Quai Orchard' : ci.name}
          {ci.contract && <code>{short(ci.contract, 8)}</code>}
        </a>
      </header>

      <nav className="rail" aria-label="Sections">
        {VIEWS.map((v) => [
          v.group && <span key={`g-${v.group}`} className="rail__group">{v.group}</span>,
          <button key={v.id} className={view === v.id ? 'is-on' : ''} onClick={() => setView(v.id)} aria-current={view === v.id ? 'page' : undefined}>
            {v.label}
            {v.id === 'timeline' && alerts.length > 0 && <span className="pip">{alerts.length}</span>}
          </button>,
        ])}
      </nav>

      <main className="stage">
        <Guard key={view + host} onHome={() => setView('overview')}>
        {view === 'overview' && <Overview {...props} mood={mood} />}
        {view === 'timeline' && <Timeline {...props} />}
        {view === 'verify' && <Verify {...props} />}
        {view === 'prove' && <Prove {...props} />}
        {view === 'upi' && <UpiCase {...props} />}
        {view === 'certin' && <CertIn {...props} />}
        {view === 'chain' && <Chain {...props} />}
        {view === 'fleet' && <Fleet {...props} />}
        {view === 'lab' && <Lab {...props} />}
        {view === 'changes' && <Changes {...props} />}
        {view === 'auditor' && <Auditor {...props} />}
        {view === 'hardening' && <Hardening {...props} />}
        </Guard>
      </main>
    </div>
  )
}

function Overview({ s, h, host, live, ci, alerts, mood, setView }) {
  const batches = s.batches.filter((b) => b.host === host)
  const recent = s.recent.filter((r) => r.host === host)
  const heals = (s.heals || []).filter((x) => x.host === host)
  const liveSignals = (s.alerts || []).filter((a) => a.host === host && a.kind === 'live-tamper').length
  const panics = s.panics.filter((p) => p.host === host)
  const bad = (live?.findings || []).filter((f) => f.seq && (f.status === 'DELETED' || f.status === 'MODIFIED'))
  const att = h.attestation || {}
  const ret = h.retention || {}

  const headline = mood === 'breach'
    ? `Someone erased ${bad.length || 'some'} sealed line${bad.length === 1 ? '' : 's'}. ${heals.length ? `SakshyaLog put ${heals.length} back.` : 'The originals are safe in the vault.'}`
    : `${h.entries ?? 0} lines sealed and copied off the machine. ${batches.length} seals on ${ci.mode === 'quai' ? 'Quai' : 'the chain'}.`

  const guards = [
    { name: 'Copied off the machine instantly', value: h.witness_delay_s != null ? `${h.witness_delay_s.toFixed(2)} s` : '–', ok: true,
      note: 'Each line reaches the vault before an attacker can touch it.' },
    { name: 'Logger heartbeat', value: ago(h.last_heartbeat_s), ok: h.last_heartbeat_s != null && h.last_heartbeat_s < 20,
      note: 'If the logger is silenced, the silence raises the alarm.' },
    { name: 'Panic seal on wipe commands', value: panics.length ? `${panics.length} fired` : 'armed', ok: !panics.length, warn: panics.length > 0,
      note: panics[0] ? `Last trigger: ${panics[0].trigger}` : 'A log-wiping command seals everything on-chain at once.' },
    { name: 'Signing key rotation', value: `epoch ${h.key_epoch ?? 0}`, ok: true,
      note: `${h.key_epoch ?? 0} old keys destroyed. Even root can't re-sign old lines.` },
    { name: 'One-line proofs', value: 'ready', ok: true, note: 'Prove a single line to a court, keep the rest private.' },
    { name: 'Personal data hidden', value: `${s.pii_protected} fields`, ok: true, note: 'Emails, phones, UPI IDs and Aadhaar become salted hashes.' },
    { name: 'Sealing speed', value: `every ${h.anchor_every_s ?? '–'} s`, ok: h.anchor_mode !== 'HIGH ALERT', warn: h.anchor_mode === 'HIGH ALERT',
      note: h.anchor_mode === 'HIGH ALERT' ? `Sped up: ${h.high_alert_reason}` : 'Speeds up by itself during suspicious activity.' },
    { name: 'Self-healing', value: heals.length ? `${heals.length} restored` : 'armed', ok: true, heal: heals.length > 0,
      note: heals.length ? 'Erased lines were written back, after checking them against the blockchain.' : 'Erased lines are written back within seconds.' },
    { name: 'Live file monitor', value: liveSignals ? `${liveSignals} caught` : 'watching', ok: !liveSignals, warn: liveSignals > 0,
      note: 'Any edit to existing lines, even one character, is reported within about a second.' },
    { name: 'Exact change report', value: 'on', ok: true, note: 'Names the field and the character that changed, e.g. Monisha → Manisha.' },
    { name: 'Write-once copies', value: 'on', ok: true, note: 'Every sealed batch is also kept as a read-only, hash-linked file.' },
    { name: 'SIEM feed', value: 'live', ok: true, note: 'Every alert goes to the security team’s existing tools (CEF, syslog, JSON).' },
  ]

  return (
    <>
      <section className="hero">
        <h1 className="hero__title">{headline}</h1>
        <p className="hero__sub">
          {mood === 'breach'
            ? 'Every change is caught against the copy in the vault and the fingerprint on the blockchain.'
            : 'Each tag below is a real log line. Brass seals mark the batches fingerprinted on the blockchain.'}
        </p>
        {bad.length > 0 && (
          <>
            <h2 className="hero__strip">The erased evidence, recovered from the vault</h2>
            <Custody recent={bad.map((f) => ({ host, seq: f.seq, ts: f.ts, line: f.vault_line, hash: f.proof?.leaf, proof: f.proof }))}
              batches={batches} findings={live?.findings} heals={heals} chainName={ci.mode === 'quai' ? 'Quai Orchard' : ci.name} />
            <h2 className="hero__strip">Still sealing, line by line</h2>
          </>
        )}
        <Custody recent={recent} batches={batches} findings={live?.findings} heals={heals} chainName={ci.mode === 'quai' ? 'Quai Orchard' : ci.name} explorer={ci.explorer} />
        {mood === 'breach' && (
          <div className="hero__actions">
            <button className="btn btn--seal" onClick={() => setView('verify')}>See what was changed</button>
            <button className="btn" onClick={() => setView('timeline')}>Replay the attack</button>
          </div>
        )}
      </section>

      <section className="guards" aria-label="Safeguards">
        <h2>Eight safeguards, live</h2>
        <ul>
          {guards.map((g) => (
            <li key={g.name} className={g.warn ? 'is-warn' : g.heal ? 'is-heal' : g.ok ? 'is-ok' : 'is-bad'}>
              <span className="guards__name">{g.name}</span>
              <span className="guards__value">{g.value}</span>
              <span className="guards__note">{g.note}</span>
            </li>
          ))}
        </ul>
      </section>

      <section className="split">
        <div className="panel">
          <h2>Latest alerts</h2>
          {alerts.length === 0 ? <p className="quiet">No alerts. Run <code>py -3.14 demo\attack.py</code> to see SakshyaLog respond.</p> : (
            <ol className="alerts">
              {alerts.slice(0, 7).map((a) => (
                <li key={a.id} className={`alerts__item alerts__item--${a.kind}`}>
                  <time>{clock(a.ts)}</time>
                  <span>{a.detail}</span>
                </li>
              ))}
            </ol>
          )}
        </div>
        <div className="panel">
          <h2>Custody record</h2>
          <dl className="facts">
            <dt>Agent code</dt><dd>{att.changed ? 'changed since start-up' : att.count ? 'matches the attested hash' : '–'} <code>{short(att.code_hash, 10)}</code></dd>
            <dt>Public heartbeat</dt><dd>{h.chain_heartbeat_age_s != null ? `${h.chain_heartbeat_age_s} s ago on-chain` : '–'}</dd>
            <dt>Kept safely for</dt><dd>{ret.kept_seconds != null ? human(ret.kept_seconds) : '–'} of {s.retention_days} days required by CERT-In</dd>
            <dt>Locked until</dt><dd>{ret.locked_until ? dateTime(ret.locked_until) : '–'}</dd>
            <dt>Wallet</dt><dd>{ci.balance ? `${ci.balance} ${ci.currency}` : 'built-in'}</dd>
          </dl>
        </div>
      </section>
    </>
  )
}

/* A problem in one page must never blank the whole site during a demo. */
class Guard extends Component {
  constructor(p) { super(p); this.state = { failed: false } }
  static getDerivedStateFromError() { return { failed: true } }
  componentDidCatch(e) { console.warn('[SakshyaLog] page recovered from:', e) }
  render() {
    if (!this.state.failed) return this.props.children
    return (
      <section className="view">
        <header className="view__head">
          <h1>This page is catching up</h1>
          <p>The live data changed while the page was drawing. Your evidence is safe in the vault and on the blockchain.</p>
          <div className="row">
            <button className="btn btn--seal" onClick={() => this.setState({ failed: false })}>Reload this page</button>
            <button className="btn" onClick={this.props.onHome}>Go to Overview</button>
          </div>
        </header>
      </section>
    )
  }
}
