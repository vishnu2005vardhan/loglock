"""HTML reports: court evidence report and CERT-In incident report draft.
Open in a browser and use Print -> Save as PDF."""
import html
from datetime import datetime, timezone

esc = html.escape
CSS = """<style>body{font-family:Arial,sans-serif;max-width:1000px;margin:30px auto;color:#111;font-size:13px}
h1{margin-bottom:2px;color:#0f2a4a}h2{color:#0f2a4a;border-bottom:2px solid #0f2a4a;padding-bottom:3px;margin-top:26px}
table{border-collapse:collapse;width:100%;margin:10px 0}td,th{border:1px solid #999;padding:6px;vertical-align:top;
word-break:break-word}th{background:#eef3f8;text-align:left;width:28%}code{font-size:11px;word-break:break-all}
.v{font-size:22px;font-weight:bold}.box{border:1px solid #333;padding:12px;margin-top:20px}
.crit{color:#b91c1c;font-weight:bold}.high{color:#c2410c;font-weight:bold}.note{font-size:11px;color:#555}</style>"""


def local(ts):
    try:
        return datetime.fromisoformat(ts).astimezone().strftime("%d %b %Y, %H:%M:%S %Z")
    except Exception:
        return ts or "-"


def fmt_unix(t):
    return datetime.fromtimestamp(t, timezone.utc).astimezone().strftime("%d %b %Y %H:%M:%S %Z") if t else "NOT FOUND"


def timeline_table(events):
    rows = "".join(f"<tr><td>{local(e['ts'])}</td><td class='{e['severity']}'>{esc(e['severity'].upper())}</td>"
                   f"<td><b>{esc(e['title'])}</b><br>{esc(e['detail'])}</td></tr>" for e in events)
    return f"<table><tr><th>Time</th><th>Severity</th><th>Event</th></tr>{rows or '<tr><td colspan=3>No events</td></tr>'}</table>"


def evidence_report(r, timeline=None, retention=None):
    rows = ""
    for f in r["findings"]:
        if f["status"] == "NOT-YET-SEALED":
            continue
        p = f.get("proof") or {}
        proof = (f"Merkle proof {'VALID' if p.get('proof_valid') else 'INVALID'}<br>root <code>{p['root']}</code><br>"
                 f"tx <code>{p['tx']}</code><br>on {esc(p['chain'])} since {fmt_unix(p.get('on_chain_since'))}"
                 if p.get("anchored") else "awaiting anchor" if f["seq"] else "n/a")
        rows += (f"<tr><td>{f['seq'] or '-'}</td><td><b>{f['status']}</b></td><td>{esc(f['vault_line'] or '-')}</td>"
                 f"<td>{esc(f['server_line'] or '-')}</td><td>{proof}</td></tr>")
    color = "#15803d" if r["verdict"] == "INTACT" else "#b91c1c"
    ret = ""
    if retention:
        ret = (f"<tr><th>Retention</th><td colspan=3>{retention['entries']} entries kept since "
               f"{local(retention['oldest'])}; each locked for {retention['required_days']} days (CERT-In). "
               f"{retention['anchors_on_chain']}/{retention['anchors']} anchors confirmed on blockchain.</td></tr>")
    tl = f"<h2>Attack timeline</h2>{timeline_table(timeline)}" if timeline else ""
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>SakshyaLog Evidence Report</title>{CSS}</head><body>
<h1>SakshyaLog: Log Integrity Evidence Report</h1><p>Generated {local(r['checked_at'])}</p>
<p class="v" style="color:{color}">Verdict: {r['verdict']}</p>
<table><tr><th>Server</th><td>{esc(r['host'])}</td><th>Source checked</th><td>{esc(str(r.get('source')))}</td></tr>
<tr><th>Entries sealed in vault</th><td>{r['vault_entries']}</td><th>Lines unchanged on server</th><td>{r['matching']}</td></tr>
<tr><th>Blockchain</th><td colspan=3>{esc(r['chain'])}</td></tr>{ret}</table>
<h2>Findings</h2><table><tr><th>Seq</th><th>Status</th><th>Original (sealed)</th><th>Found on server</th><th>Blockchain proof</th></tr>
{rows or '<tr><td colspan=5>No discrepancies found.</td></tr>'}</table>{tl}
<h2>Method</h2><p>Each log line was sealed on the source server at write time (sequence number, SHA-256 hash chain,
forward-secure HMAC). Personal data was replaced by salted-hash commitments before sealing. Lines were sent to an
off-host append-only vault within about one second and batched into Merkle trees whose roots were anchored on a
blockchain, immediately when evidence-destroying commands were seen. Anyone can re-check every value with the
open-source <code>verify_pack.py</code> tool included in the court evidence pack.</p>
<div class="box"><b>Certificate regarding electronic records (draft for Section 63, Bharatiya Sakshya Adhiniyam, 2023)</b>
<p>I, ______________________ (name, designation), state that the electronic records described above were produced by
the computer systems identified, which were operating properly during the relevant period, that the records were stored
and verified by the process described, and that the hash values stated are true to the best of my knowledge.</p>
<p>Signature: ____________ &nbsp;&nbsp; Date: ____________ &nbsp;&nbsp; Place: ____________</p>
<p class="note">Prototype output. To be completed and signed by the responsible person and checked by a legal
professional before filing.</p></div></body></html>"""


def certin_report(d):
    """Pre-filled draft of an incident report to CERT-In (6-hour rule, CERT-In Directions of 28 April 2022)."""
    ev = d.get("timeline", [])
    first = next((e for e in ev if e["severity"] in ("high", "crit")), ev[0] if ev else None)
    detected = next((e for e in ev if e["source"] == "alert"), None)
    rows = lambda pairs: "".join(f"<tr><th>{esc(k)}</th><td>{v}</td></tr>" for k, v in pairs)
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>CERT-In Incident Report (draft)</title>{CSS}</head><body>
<h1>Cyber Security Incident Report: DRAFT for CERT-In</h1>
<p>Auto-filled by SakshyaLog on {local(d['generated_at'])}. Report within <b>6 hours</b> of noticing the incident
(CERT-In Directions under Section 70B(6) of the IT Act, 28 April 2022).</p>
<p class="note">Send to CERT-In by email (incident@cert-in.org.in) or through its incident reporting portal, using the
current official format. Check every field before sending.</p>
<h2>1. Reporting organisation</h2><table>{rows([
        ("Organisation name", esc(d.get('org') or '')),
        ("Sector", esc(d.get('sector') or '')),
        ("Point of contact (name, designation)", esc(d.get('contact') or '')),
        ("Phone / email", esc(d.get('contact_details') or '')),
    ])}</table>
<h2>2. Incident details</h2><table>{rows([
        ("Type of incident (CERT-In categories)", esc(", ".join(d['categories']))),
        ("Date and time of occurrence", local(first['ts']) if first else "-"),
        ("Date and time incident was detected", local(detected['ts']) if detected else "-"),
        ("Reporting deadline (detection + 6 h)", esc(d.get('deadline_local') or '-')),
        ("Affected system(s)", esc(d['host']) + " (Linux server, auth/system logs)"),
        ("Suspected source IP address(es)", esc(", ".join(d['attacker_ips']) or 'unknown')),
        ("Brief description", esc(d['summary'])),
        ("Indicators of compromise", "<br>".join(esc(x) for x in d['iocs']) or "-"),
    ])}</table>
<h2>3. Timeline of events</h2>{timeline_table(ev)}
<h2>4. Actions taken</h2><table>{rows([
        ("Evidence preserved", "Logs sealed off-host in append-only vault; 180-day retention lock"),
        ("Blockchain evidence anchors", f"{d['anchors']} Merkle roots anchored on {esc(d['chain'])}; "
                                         f"latest root <code>{esc(d['latest_root'])}</code>"),
        ("Incident evidence snapshot", f"<code>{esc(d.get('snapshot_root') or 'not frozen yet')}</code> "
                                       f"tx <code>{esc(d.get('snapshot_tx') or '-')}</code>"),
        ("Containment / remediation", esc(d.get('actions') or '')),
    ])}</table>
<p class="note">Log retention: CERT-In requires ICT system logs to be maintained securely for a rolling period of
180 days within Indian jurisdiction and provided to CERT-In on request.</p></body></html>"""
