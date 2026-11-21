import { useEffect, useMemo, useRef } from 'react'
import { clock, short } from './lib.js'

/**
 * The hero: a live chain of custody. Each sealed log line is a paper exhibit tag,
 * tied to the previous one (its hash links to the last). Every blockchain anchor
 * is a brass seal stamped over the batch of tags it covers. Deleted or altered
 * tags show torn and red; restored ones carry a restored stamp.
 */
export default function Custody({ recent, batches, findings, heals, chainName, explorer }) {
  const tags = useMemo(() => [...recent].sort((a, b) => a.seq - b.seq).slice(-14), [recent])
  const bad = useMemo(() => new Map((findings || []).filter((f) => f.seq).map((f) => [f.seq, f])), [findings])
  const healed = useMemo(() => new Set((heals || []).map((h) => h.seq)), [heals])
  const sealFor = (seq, t) => batches.find((b) => b.start_seq <= seq && b.end_seq >= seq) ||
    (t?.proof?.anchored ? { start_seq: t.proof.batch[0], end_seq: t.proof.batch[1], root: t.proof.root, tx_url: t.proof.tx_url, mode: 'normal' } : null)
  const strip = useRef(null)
  const newest = tags.length ? tags[tags.length - 1].seq : 0
  useEffect(() => { // keep the newest tag in view as lines are sealed
    const el = strip.current
    if (el) el.scrollTo({ left: el.scrollWidth, behavior: 'smooth' })
  }, [newest])

  if (!tags.length) {
    return (
      <div className="custody custody--empty">
        <p>Waiting for the first sealed lines. Start the system with <code>py -3.14 run_demo.py --reset --quai</code>.</p>
      </div>
    )
  }

  return (
    <div className="custody" role="list" aria-label="Newest sealed log lines" ref={strip}>
      <div className="custody__thread" aria-hidden="true" />
      {tags.map((t, i) => {
        const f = bad.get(t.seq)
        const restoredLine = t.line.startsWith('[SAKSHYALOG RESTORED')
        const seal = sealFor(t.seq, t)
        const next = tags[i + 1]
        const sealHere = seal && (!next || !(seal.start_seq <= next.seq && seal.end_seq >= next.seq))
        const state = f ? (healed.has(t.seq) || f.healed ? 'torn healed' : 'torn') : restoredLine ? 'restored' : ''
        return (
          <article key={`${t.host}-${t.seq}`} className={`tag ${state}`} role="listitem" style={{ '--i': i }}>
            <div className="tag__paper">
            <header className="tag__head">
              <span className="tag__no">#{t.seq}</span>
              <span className="tag__time">{clock(t.ts)}</span>
            </header>
            <p className="tag__line">{restoredLine ? t.line.replace(/^\[SAKSHYALOG RESTORED[^\]]*\]\s*/, '') : t.line.slice(16)}</p>
            {f || restoredLine ? (
              <footer className="tag__stamps">
                {f && <span className="tag__stamp tag__stamp--breach">{f.status === 'MODIFIED' ? 'altered' : 'erased'}</span>}
                {(restoredLine || (f && (f.healed || healed.has(t.seq)))) && <span className="tag__stamp tag__stamp--restored">restored</span>}
              </footer>
            ) : <footer className="tag__hash" title={t.hash}>{short(t.hash, 12)}</footer>}
            </div>
            {sealHere && (
              <a className="seal" href={seal.tx_url || undefined} target="_blank" rel="noreferrer"
                 title={`Lines ${seal.start_seq}–${seal.end_seq} sealed on ${chainName}. Root ${seal.root}`}>
                <span className="seal__ring">
                  <span className="seal__range">{seal.start_seq}–{seal.end_seq}</span>
                  <span className="seal__mode">{seal.mode === 'normal' ? 'sealed' : seal.mode}</span>
                </span>
              </a>
            )}
          </article>
        )
      })}
      {explorer && <span className="custody__note">Seals link to the transaction on {chainName}</span>}
    </div>
  )
}
