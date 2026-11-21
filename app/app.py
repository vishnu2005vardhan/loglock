"""SakshyaLog dashboard (Streamlit).

Run:  streamlit run app/app.py      (or just: python run_demo.py)
"""
import os
import time
from datetime import datetime, timezone

import requests
import streamlit as st

VAULT = os.getenv("VAULT_URL", "http://localhost:8000")
st.set_page_config(page_title="SakshyaLog", page_icon="🔏", layout="wide")
SEV = {"crit": "🔴", "high": "🟠", "med": "🟡", "info": "🔵"}


def get(path, **params):
    try:
        r = requests.get(VAULT + path, params=params, timeout=30)
        return r.json() if r.ok else None
    except requests.RequestException:
        return None


def local(ts, fmt="%H:%M:%S"):
    try:
        return datetime.fromisoformat(ts).astimezone().strftime(fmt)
    except Exception:
        return "-"


def fmt_unix(t):
    return datetime.fromtimestamp(t, timezone.utc).astimezone().strftime("%d %b %Y %H:%M:%S") if t else "NOT FOUND ON CHAIN"


def human(seconds):
    if seconds < 3600:
        return f"{int(seconds // 60)} min {int(seconds % 60)} s"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    return f"{seconds / 86400:.1f} days"


st.title("🔏 SakshyaLog")
st.caption("Logs the attacker can't erase · tamper-evident security logs anchored on blockchain · CERT-In ready")

s = get("/status")
if s is None:
    st.error(f"Vault not reachable at {VAULT}. Start everything with `python run_demo.py --reset`.")
    st.stop()

auto = st.sidebar.toggle("Live auto-refresh (3 s)", value=True,
                         help="Turn off while filling in the CERT-In form")
hosts = [h["host"] for h in s["hosts"]] or ["server-01"]
hosts = sorted(hosts, key=lambda x: (x != "server-01", x))  # the protected server first, then use cases
host = st.sidebar.selectbox("Evidence source", hosts, help="server-01 = server logs; case-UPI-001 = UPI fraud case file")
h = next((x for x in s["hosts"] if x["host"] == host), {})
ci = s["chain_info"]
st.sidebar.markdown(f"**Blockchain:** {ci['name']}")
if ci.get("contract"):
    st.sidebar.caption(f"Contract `{ci['contract']}` · block #{ci.get('block_number')}")
if ci.get("mode") == "quai":
    st.sidebar.markdown(f"[Contract on Quaiscan ↗]({ci['explorer_address']})")
    st.sidebar.caption(f"Vault wallet `{ci['wallet']}` · {ci['balance']} QUAI")
if ci.get("simulated"):
    st.sidebar.warning("Simulated offline ledger. Install requirements-blockchain.txt for a real chain.")
st.sidebar.markdown("**Demo:** run `python demo\\attack.py` in a second window, then watch this page.")

tabs = st.tabs(["📊 Live", "🕵️ Attack timeline", "✅ Verify", "🔎 Prove one line", "🇮🇳 CERT-In & Court",
                "⛓️ Blockchain", "🏦 UPI Case (use case)"])

# =============================================================== LIVE ========
with tabs[0]:
    kinds = {a["kind"] for a in s["alerts"]}
    if kinds & {"tamper-detected", "chain-break", "bad-hash", "forged-seal", "sequence-gap", "epoch-rollback"}:
        st.error(f"🔴 TAMPERING DETECTED: {len(s['alerts'])} alert(s). See the Attack timeline tab.")
    elif "panic-anchor" in kinds:
        st.error("🚨 EVIDENCE-DESTRUCTION ATTEMPT: panic anchor fired")
    elif "heartbeat-lost" in kinds:
        st.warning("🟠 Agent heartbeat lost: logging may have been stopped")
    elif h.get("anchor_mode") == "HIGH ALERT":
        st.warning(f"🟠 Suspicious activity: {h.get('high_alert_reason')}")
    else:
        st.success("🟢 All logs intact")

    c = st.columns(4)
    c[0].metric("Sealed log lines", h.get("entries", 0))
    c[1].metric("Blockchain anchors", len(s["batches"]))
    c[2].metric("Alerts", len(s["alerts"]))
    c[3].metric("Personal-data fields protected", s["pii_protected"])

    st.subheader("🛡️ Defences (live)")
    hb, wd = h.get("last_heartbeat_s"), h.get("witness_delay_s")
    row1, row2 = st.columns(4), st.columns(4)
    with row1[0].container(border=True):
        st.markdown("**⭐1 Instant off-box copy**")
        st.metric("Copy reaches vault in", f"{wd:.2f} s" if wd is not None else "–")
        st.caption("Copied off the server before an attacker can edit it")
    with row1[1].container(border=True):
        alive = hb is not None and hb < 20
        st.markdown("**⭐2 Heartbeat**")
        st.metric("Last heartbeat", f"{hb:.0f} s ago" if hb is not None else "never",
                  "alive 💓" if alive else "SILENT 💀", delta_color="normal" if alive else "inverse")
        st.caption("Silence itself raises the alarm")
    with row1[2].container(border=True):
        st.markdown("**⭐3 Panic anchor**")
        st.metric("Panic anchors fired", len(s["panics"]), s["panics"][0]["trigger"] if s["panics"] else "armed",
                  delta_color="inverse" if s["panics"] else "off")
        st.caption("Wipe commands trigger an instant anchor")
    with row1[3].container(border=True):
        st.markdown("**⭐4 Forward-secure keys**")
        st.metric("Current key epoch", f"#{h.get('key_epoch', 0)}", f"{h.get('key_epoch', 0)} old keys destroyed",
                  delta_color="off")
        st.caption("Even root can't re-sign old lines")
    with row2[0].container(border=True):
        st.markdown("**⭐5 Show one page only**")
        st.metric("Proof size for one line", "1 line + a few hashes")
        st.caption("Prove a single line to a court; the rest stays hidden (tab 🔎)")
    with row2[1].container(border=True):
        st.markdown("**⭐6 Privacy-safe redaction**")
        st.metric("Personal fields hidden", s["pii_protected"], f"{s['pii_erased_events']} erasure(s) done",
                  delta_color="off")
        st.caption("Emails, phones, Aadhaar → salted hashes (DPDP-friendly)")
    with row2[2].container(border=True):
        high = h.get("anchor_mode") == "HIGH ALERT"
        st.markdown("**⭐7 Adaptive anchoring**")
        st.metric("Anchoring every", f"{h.get('anchor_every_s', '–')} s",
                  f"HIGH ALERT ({h.get('high_alert_left_s')} s left)" if high else "normal",
                  delta_color="inverse" if high else "off")
        st.caption("Speeds up automatically during suspicious activity")
    with row2[3].container(border=True):
        ret = h.get("retention") or {}
        st.markdown("**🇮🇳 180-day retention**")
        st.metric("Logs kept safely for", human(ret.get("kept_seconds", 0)),
                  f"locked until {local(ret['locked_until'], '%d %b %Y')}" if ret else "", delta_color="off")
        st.progress(min(1.0, ret.get("kept_days", 0) / s["retention_days"]) if ret else 0.0)
    heals_here = [x for x in s.get("heals", []) if x["host"] == host]
    with st.container(border=True):
        c8a, c8b = st.columns([1, 3])
        c8a.markdown("**⭐8 Self-healing logs**")
        c8a.metric("Lines restored at source", len(heals_here))
        if heals_here:
            c8b.markdown("The attacker erased or changed lines, and SakshyaLog **put the originals back by itself**, "
                         "marked `[SAKSHYALOG RESTORED …]` with their blockchain proof:")
            for x in heals_here[:4]:
                link = f" · [tx]({x['tx_url']})" if x["tx_url"] else ""
                c8b.caption(f"♻️ {local(x['ts'])} · #{x['seq']} {x['status'].lower()} → restored · "
                            f"root `{(x['root'] or 'pending')[:14]}…`{link}")
        else:
            c8b.caption("Armed. If an attacker deletes or edits sealed lines, the originals are written back into the "
                        "log within seconds, clearly marked as restored, never disguised as untouched.")

    left, right = st.columns([3, 2])
    with left:
        st.subheader("Alerts")
        if s["alerts"]:
            st.dataframe([{"time": local(a["ts"]), "kind": a["kind"], "detail": a["detail"]} for a in s["alerts"]],
                         width="stretch", hide_index=True)
        else:
            st.write("None")
        st.subheader("Latest sealed lines (personal data hidden)")
        st.dataframe([{"seq": e["seq"], "time": local(e["ts"]), "line": e["line"], "fingerprint": e["hash"][:14] + "…"}
                      for e in s["recent"]], width="stretch", hide_index=True)
    with right:
        if s["panics"]:
            st.subheader("🚨 Panic anchors")
            for pa in s["panics"]:
                link = f" · [view tx]({pa['tx_url']})" if pa["tx_url"] else ""
                st.markdown(f"**{local(pa['ts'])}** · {pa['trigger']} (line #{pa['seq']})  \n"
                            f"`{(pa['line'] or '(log file wiped on disk)')[-70:]}`{link}")
        st.subheader("⛓️ Blockchain anchors")
        if st.button("Anchor now"):
            requests.post(VAULT + "/anchor-now", timeout=150)
            st.rerun()
        icon = {"high-alert": "⚡", "panic": "🚨", "manual": "👆", "normal": "⏱️"}
        for b in s["batches"][:12]:
            link = f" · [tx]({b['tx_url']})" if b["tx_url"] else ""
            st.markdown(f"{icon.get(b['mode'], '⏱️')} **#{b['start_seq']}–{b['end_seq']}** · {local(b['created_at'])} · "
                        f"{b['mode']}  \nroot `{b['root'][:18]}…`{link}")

# ========================================================= TIMELINE ==========
with tabs[1]:
    t = get(f"/timeline/{host}") or {"events": [], "attacker_ips": []}
    st.subheader("🕵️ What happened, step by step")
    if t["attacker_ips"]:
        st.error(f"Suspected attacker IP(s): **{', '.join(t['attacker_ips'])}**")
    if not t["events"]:
        st.info("No suspicious events yet. Run the attack: `python demo\\attack.py`")
    for e in t["events"]:
        st.markdown(f"`{local(e['ts'])}` {SEV.get(e['severity'], '⚪')} **{e['title']}**  \n"
                    f"<span style='color:gray;font-size:0.9em'>{e['detail']}</span>", unsafe_allow_html=True)
    st.caption("Built from the sealed vault copy, so it still shows the steps the attacker deleted from the server.")

# =========================================================== VERIFY ==========
with tabs[2]:
    st.write("Compare the server's log **as it is now** with the sealed copy in the vault. Every finding is "
             "proved against the blockchain anchor.")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Option 1: auditor pulls the live server log**")
        if st.button("🔍 Verify live server log", type="primary"):
            r = requests.post(VAULT + "/verify-live", params={"host": host}, timeout=120)
            st.session_state["result"] = r.json() if r.ok else {"error": r.text}
            st.session_state.pop("report_html", None)
    with c2:
        st.markdown("**Option 2: upload a log file**")
        up = st.file_uploader("Log file", type=None, label_visibility="collapsed")
        if up and st.button("🔍 Verify uploaded file"):
            st.session_state["result"] = requests.post(VAULT + "/verify", data={"host": host},
                                                       files={"file": (up.name, up.getvalue())}, timeout=120).json()
            st.session_state.pop("report_html", None)

    r = st.session_state.get("result")
    if r and "error" in r:
        st.error(r["error"])
    elif r:
        st.divider()
        if r["verdict"] == "INTACT":
            st.success(f"✅ INTACT: all {r['matching']} sealed lines match the vault and the blockchain.")
        else:
            st.error(f"❌ TAMPERED: only {r['matching']} of {r['vault_entries']} sealed lines are unchanged on the server.")
        if st.button("📄 Prepare evidence report"):
            st.session_state["report_html"] = requests.post(VAULT + "/report/evidence", json=r, timeout=120).text
        if st.session_state.get("report_html"):
            st.download_button("⬇️ Download evidence report (open → Print → Save as PDF)", st.session_state["report_html"],
                               file_name=f"SakshyaLog_evidence_{r['host']}.html", mime="text/html")
        unsealed = sum(f["status"] == "NOT-YET-SEALED" for f in r["findings"])
        if unsealed:
            st.caption(f"ℹ️ {unsealed} newest line(s) are not sealed yet (written in the last second, or after the agent stopped).")
        for f in r["findings"]:
            if f["status"] == "NOT-YET-SEALED":
                continue
            with st.container(border=True):
                if f["status"] == "DELETED":
                    st.markdown(f"🗑️ **DELETED from server**: line #{f['seq']} sealed at {local(f['ts'])}")
                    st.code(f["vault_line"], language=None)
                    st.caption("↑ original recovered from the vault" +
                               (" · ♻️ **self-healed**: already written back into the server log" if f.get("healed") else ""))
                elif f["status"] == "MODIFIED":
                    st.markdown(f"✏️ **MODIFIED on server**: line #{f['seq']}")
                    st.code(f"server now: {f['server_line']}\noriginal  : {f['vault_line']}", language=None)
                else:
                    st.markdown("➕ **INJECTED**: line on server was never sealed by the agent")
                    st.code(f["server_line"], language=None)
                p = f.get("proof") or {}
                if p.get("anchored"):
                    link = f" · [blockchain tx]({p['tx_url']})" if p["tx_url"] else ""
                    st.caption(f"Merkle proof {'✅ valid' if p['proof_valid'] else '❌ invalid'} · root `{p['root'][:16]}…` "
                               f"on {p['chain']} since {fmt_unix(p.get('on_chain_since'))}{link}")
                elif f["seq"]:
                    st.caption("⏳ sealed in vault, waiting for next blockchain anchor")

# ==================================================== PROVE ONE LINE =========
with tabs[3]:
    st.subheader("🔎 ⭐5 Prove ONE line without revealing the rest")
    st.write("Give a court proof of a single log line. It can check the line against the blockchain using only a few "
             "hashes, and **sees none of the other lines**. ⭐6 Personal data stays hidden unless you choose to reveal it.")
    search = st.text_input("Search sealed lines", placeholder="e.g. root, 45.33, KYC, password reset")
    # snapshot the list so live refresh doesn't change the choices under you
    if st.session_state.get("rows_key") != (host, search) or st.button("↻ Refresh list"):
        st.session_state["rows"] = get(f"/entries/{host}", search=search, limit=60) or []
        st.session_state["rows_key"] = (host, search)
    rows = st.session_state["rows"]
    if rows:
        by_seq = {e["seq"]: e for e in rows}
        pick = by_seq[st.selectbox("Choose the line to prove", list(by_seq), key="pick_seq",
                                   format_func=lambda q: f"#{q}  {by_seq[q]['line'][16:120]}")]
        reveal = []
        if pick["tokens"]:
            st.markdown("**Personal data in this line** (hidden by default, as salted hashes):")
            for tok in pick["tokens"]:
                if st.checkbox(f"Reveal {tok.split(':')[0][2:]} `{tok}` to the court", key=f"rv{pick['seq']}{tok}"):
                    reveal.append(tok)
        if st.button("🔐 Create one-line proof", type="primary"):
            r = requests.get(f"{VAULT}/proof/{host}/{pick['seq']}", params={"reveal": ",".join(reveal)}, timeout=60)
            st.session_state["line_proof"] = r.json() if r.ok else {"error": r.json().get("detail", r.text)}
        lp = st.session_state.get("line_proof")
        if lp and "error" in lp:
            st.warning(lp["error"])
        elif lp:
            import json as _json
            with st.container(border=True):
                st.markdown(f"**Line #{lp['entry']['seq']}** sealed at {local(lp['entry']['ts'], '%d %b %Y %H:%M:%S')}")
                st.code(lp["entry"]["line"], language=None)
                a, b, c = st.columns(3)
                a.metric("Other lines revealed", 0, f"{lp['batch_size'] - 1} stay hidden", delta_color="off")
                b.metric("Hashes needed", len(lp["proof"]))
                c.metric("Personal fields", f"{len(lp['disclosed'])} revealed",
                         f"{lp['hidden_personal_fields']} hidden", delta_color="off")
                for d in lp["disclosed"]:
                    st.markdown(f"🔓 {d['kind']}: **{d['value']}** (salt `{d['salt'][:12]}…` proves it matches the sealed hash)")
                st.caption(f"On blockchain since {fmt_unix(lp['on_chain_since'])} · root `{lp['root'][:20]}…`")
                st.download_button("⬇️ Download proof file (.json)", _json.dumps(lp, indent=1),
                                   file_name=f"proof_line_{lp['entry']['seq']}.json", mime="application/json")
                st.caption("Anyone can check it: `python tools/verify_pack.py proof_line_N.json`")
    else:
        st.info("No matching lines.")

    st.divider()
    st.subheader("🧹 DPDP right to erasure")
    st.write("A customer asks you to delete their data. We delete it from the private store. The sealed log keeps "
             "only a salted hash, so **the hash chain and every blockchain proof stay valid**.")
    ps = get("/pii-summary") or {"by_kind": [], "people": []}
    if ps["by_kind"]:
        st.caption("Protected: " + ", ".join(f"{k['n']} {k['kind']} field(s)" for k in ps["by_kind"]))
    who = st.selectbox("Erase all data for", ["-"] + ps["people"])
    if who != "-" and st.button(f"Erase {who}"):
        res = requests.post(VAULT + "/erase-pii", json={"value": who}, timeout=30).json()
        st.success(f"Erased {res['erased_fields']} field(s). Run Verify again: the chain is still valid.")

# ====================================================== CERT-IN & COURT ======
with tabs[4]:
    a, b = st.columns(2)
    with a:
        st.subheader("⏱️ Freeze evidence & start the 6-hour clock")
        note = st.text_input("Incident note", "Unauthorised root login and data exfiltration on server-01")
        if st.button("🧊 Freeze evidence", type="primary"):
            requests.post(VAULT + "/incident", json={"host": host, "note": note}, timeout=150)
            st.rerun()
        for i in s["incidents"][:3]:
            left = datetime.fromisoformat(i["deadline"]) - datetime.now(timezone.utc)
            with st.container(border=True):
                st.markdown(f"**Incident #{i['id']}**: {i['note']}")
                if left.total_seconds() > 0:
                    hh, rem = divmod(int(left.total_seconds()), 3600)
                    st.metric("Time left to report to CERT-In", f"{hh:02d}:{rem // 60:02d}:{rem % 60:02d}")
                else:
                    st.error("CERT-In 6-hour deadline passed")
                st.caption(f"Frozen {local(i['declared_at'], '%d %b %H:%M:%S')} · snapshot `{i['snapshot_root'][:20]}…` · "
                           f"⛓️ on-chain incident #{i.get('chain_id')}, deadline set by the smart contract")
                if i.get("reported_at"):
                    (st.success if i["on_time"] else st.error)(
                        f"Reported to CERT-In at {local(i['reported_at'])}: "
                        f"{'✅ ON TIME' if i['on_time'] else '❌ LATE'} (decided on-chain, can't be changed)")
                elif st.button("✅ Mark as reported to CERT-In (on-chain)", key=f"rep{i['id']}"):
                    html = st.session_state.get("certin") or requests.post(
                        f"{VAULT}/report/certin/{host}", json={}, timeout=60).text
                    requests.post(f"{VAULT}/incident/{i['id']}/reported", json={"report": html}, timeout=180)
                    st.rerun()
    with b:
        st.subheader("🇮🇳 180-day retention tracker")
        rt = get(f"/retention/{host}")
        if rt:
            st.metric("Logs kept safely for", human(rt["kept_seconds"]),
                      f"{rt['required_days']}-day requirement met on {local(rt['requirement_met_on'], '%d %b %Y')}",
                      delta_color="off")
            st.progress(min(1.0, rt["kept_days"] / rt["required_days"]))
            st.markdown(f"- **{rt['entries']}** lines since {local(rt['oldest'], '%d %b %Y %H:%M')}\n"
                        f"- Newest line locked until **{local(rt['locked_until'], '%d %b %Y')}**\n"
                        f"- Storage: {rt['storage']}\n"
                        f"- Proof: **{rt['anchors_on_chain']}/{rt['anchors_checked']}** recent anchors confirmed on blockchain")

    st.divider()
    st.subheader("📝 CERT-In incident report (one click)")
    st.caption("Pre-filled from the timeline and the blockchain evidence. Check it, then send it to CERT-In.")
    f1, f2 = st.columns(2)
    form = {"org": f1.text_input("Organisation", "Demo Bank Ltd"),
            "sector": f2.text_input("Sector", "Banking / Financial services"),
            "contact": f1.text_input("Point of contact", "A. Kumar, CISO"),
            "contact_details": f2.text_input("Phone / email", "+91 80 0000 0000 · ciso@demobank.example"),
            "actions": st.text_input("Containment actions", "Server isolated, root password rotated, attacker IP blocked")}
    if st.button("📝 Generate CERT-In report"):
        st.session_state["certin"] = requests.post(f"{VAULT}/report/certin/{host}", json=form, timeout=60).text
    if st.session_state.get("certin"):
        st.download_button("⬇️ Download CERT-In report (open → Print → Save as PDF)", st.session_state["certin"],
                           file_name=f"CERT-In_incident_report_{host}.html", mime="text/html")

    st.divider()
    st.subheader("⚖️ Court-ready evidence pack + “Don't trust us” verifier")
    st.write("A ZIP with the sealed logs (personal data hidden), fingerprints, Merkle roots, blockchain transaction "
             "IDs, proofs, timeline, retention record, evidence report, and **`verify_pack.py`**, an open-source checker "
             "that uses only standard Python. A court can verify everything **without trusting us**.")
    if st.button("📦 Build evidence pack"):
        z = requests.get(f"{VAULT}/evidence-pack/{host}", timeout=180)
        st.session_state["pack"] = (z.content, z.headers.get("content-disposition", "").split('"')[1])
    if st.session_state.get("pack"):
        data, name = st.session_state["pack"]
        st.download_button(f"⬇️ Download {name}", data, file_name=name, mime="application/zip")
        st.code(f"python verify_pack.py {name}", language=None)

# ======================================================= BLOCKCHAIN =========
with tabs[5]:
    st.subheader("⛓️ The blockchain is our neutral notary")
    st.write("The company controls its servers **and** its vault. Only the blockchain is outside its control, so it "
             "is the one place an auditor or court can check without trusting the company. We put **only fingerprints** "
             "on-chain: no log text, no personal data, about one small transaction a minute.")
    if ci.get("simulated"):
        st.warning("⚠️ Running on the SIMULATED offline ledger. Say so openly in a demo, or install the blockchain "
                   "engine (requirements-blockchain.txt) to use a real EVM.")
    elif ci.get("mode") == "quai":
        st.success(f"⛓️ **Quai Network**: {ci['name']} · chain id {ci.get('chain_id')} · block #{ci.get('block_number')}  \n"
                   f"Smart contract `LogAnchor` at [`{ci.get('contract')}`]({ci['explorer_address']}) · "
                   f"deployed with Hardhat + quais (Solidity 0.8.20)  \nVault wallet `{ci['wallet']}` · balance {ci['balance']} QUAI")
    else:
        st.success(f"Real blockchain: **{ci['name']}** · chain id {ci.get('chain_id')} · block #{ci.get('block_number')}  \n"
                   f"Smart contract `LogAnchor` at `{ci.get('contract')}`")
        st.info("For the hackathon, the contract runs on **Quai Network Orchard**: see QUAI.md, then `python run_demo.py --reset --quai`.")
    st.markdown("**What the smart contract enforces (rules even the company can't break):**")
    att = h.get("attestation") or {}
    cha = h.get("chain_heartbeat_age_s")
    r1, r2, r3, r4 = st.columns(4)
    with r1.container(border=True):
        st.markdown("**🔗 Continuous batches**")
        st.metric("Batches anchored", len(s["batches"]))
        st.caption("Each batch must start where the last ended. Skipping lines is rejected on-chain.")
    with r2.container(border=True):
        st.markdown("**💓 Public heartbeat**")
        st.metric("Last on-chain heartbeat", f"{cha} s ago" if cha is not None else "–",
                  "alive" if cha is not None and cha < 2 * s["chain_heartbeat_seconds"] + 15 else "SILENT",
                  delta_color="normal" if cha is not None and cha < 2 * s["chain_heartbeat_seconds"] + 15 else "inverse")
        st.caption("If the logger is killed, the silence is visible to anyone on the chain.")
    with r3.container(border=True):
        st.markdown("**🪪 Agent attestation**")
        st.metric("Agent code", "CHANGED ⚠️" if att.get("changed") else ("verified ✅" if att.get("count") else "–"),
                  f"hash {att['code_hash'][:10]}…" if att.get("code_hash") else "", delta_color="off")
        st.caption("Hash of the agent's code recorded at start-up. A swapped agent is detected.")
    with r4.container(border=True):
        st.markdown("**🚨 Incident registry**")
        st.metric("Incidents on-chain", len(s["incidents"]))
        st.caption("Declared time + 6 h CERT-In deadline + on-time flag, fixed by the contract.")

    st.markdown("**💰 What it costs** (measured gas × your assumptions)")
    g = s["gas"]
    avg_anchor = round(sum(v["avg_gas"] * v["count"] for k, v in g.items() if k.startswith("anchor")) /
                       max(1, sum(v["count"] for k, v in g.items() if k.startswith("anchor")))) if g else 0
    avg_hb = g.get("heartbeat", {}).get("avg_gas", 0)
    k1, k2, k3 = st.columns(3)
    cur = "QUAI" if ci.get("mode") == "quai" else "token"
    gwei = k1.number_input("Gas price (gwei)", value=30.0, min_value=0.0, help="Check today's gas price on the explorer")
    pol_inr = k2.number_input(f"{cur} price (₹)", value=20.0, min_value=0.0, help="Assumption: update to today's price")
    every = k3.number_input("Anchor every (s), production", value=60, min_value=1)
    if avg_anchor:
        per_day = (86400 / every) * avg_anchor + (86400 / 300) * (avg_hb or 0)  # heartbeat every 5 min in production
        pol_day = per_day * gwei * 1e-9
        c1, c2, c3 = st.columns(3)
        c1.metric("Gas per anchor (measured)", f"{avg_anchor:,}")
        c2.metric("Cost per server per day", f"₹{pol_day * pol_inr:,.2f}", f"{pol_day:.4f} {cur}", delta_color="off")
        c3.metric("Cost per server per month", f"₹{pol_day * pol_inr * 30:,.0f}")
        st.caption("The cost is the same however many log lines there are, because one Merkle root covers the whole batch.")
    else:
        st.caption("Waiting for the first anchors to measure gas…")

    st.markdown("**Latest blockchain transactions**")
    if s["chain_txs"]:
        st.dataframe([{"time": local(t["ts"]), "type": t["kind"], "gas": f"{t['gas']:,}" if t["gas"] else "-", "transaction": t["tx"]}
                      for t in s["chain_txs"]], width="stretch", hide_index=True)
        links = [t for t in s["chain_txs"] if t["tx_url"]][:3]
        for t in links:
            st.markdown(f"🔗 [{t['kind']} on block explorer]({t['tx_url']})")
    with st.expander("Why not put more on the blockchain?"):
        st.write("Putting log lines on-chain would leak private data (DPDP Act) and cost a fortune. We use the "
                 "blockchain only for what nothing else can do: be a neutral, permanent notary of *what existed, when*, "
                 "*whether the logger was alive*, *which agent code ran*, and *when the company knew*. No tokens, no NFTs.")

# ===================================================== UPI CASE (use case) ===
with tabs[6]:
    import re as _re
    CASE = "case-UPI-001"
    st.subheader("🏦 Use case: protecting a UPI fraud case file")
    st.caption("Same SakshyaLog engine, different evidence. Every line of the investigation file is sealed, copied "
               "off the investigation server and anchored on the blockchain, exactly like server logs. "
               "**All data is synthetic.** Account numbers are pseudonymised (ACC-…); the complainant's mobile and "
               "UPI ID are hidden by privacy redaction (⭐6). SakshyaLog does not decide who is guilty and never "
               "freezes accounts: it only proves the investigation record was not secretly changed.")
    if CASE not in [h["host"] for h in s["hosts"]]:
        st.info("The case file is being written and sealed. Wait ~30 seconds after start.")
    else:
        sealed = get(f"/entries/{CASE}", limit=200) or []
        sealed = sorted([e for e in sealed if not e["line"].lstrip().startswith("[SAKSHYALOG RESTORED")],
                        key=lambda e: e["seq"])
        res = requests.post(f"{VAULT}/verify-live", params={"host": CASE}, timeout=120)
        res = res.json() if res.ok else None
        bad = {f["seq"]: f for f in (res or {}).get("findings", []) if f.get("seq")}
        intact = res and res["verdict"] == "INTACT"

        m = st.columns(4)
        m[0].metric("Case records sealed", len(sealed))
        m[1].metric("Case file on server", "INTACT ✅" if intact else "TAMPERED ❌" if res else "–")
        m[2].metric("Records deleted / changed", len(bad))
        cb = [b for b in s["batches"] if b["host"] == CASE]
        m[3].metric("Blockchain anchors (case)", len(cb))
        if res and not intact:
            st.error("🔴 Someone changed the case file on the investigation server. The originals below are "
                     "recovered from the vault and proven against the blockchain anchor.")

        # money flow, drawn from the SEALED originals, so deletions can't hide a transfer
        rx = _re.compile(r"TXN (T\d+) \| FROM (ACC-\w+) \(([^)]*)\) \| TO (ACC-\w+) \(([^)]*)\) \| INR (\d+)")
        dot = ['digraph G { rankdir=LR; bgcolor="transparent"; node [shape=box, style="rounded,filled", '
               'fillcolor="#eef3f8", fontname="Helvetica"]; edge [fontname="Helvetica"];']
        for e in sealed:
            mm = rx.search(e["line"])
            if not mm:
                continue
            tid, fa, fr, ta, tr, amt = mm.groups()
            dot.append(f'"{fa}" [label="{fr}\\n{fa}"]; "{ta}" [label="{tr}\\n{ta}"];')
            if e["seq"] in bad:
                dot.append(f'"{fa}" -> "{ta}" [label="{tid}: ₹{int(amt):,}\\n{bad[e["seq"]]["status"]} on server, '
                           f'{"recovered + restored" if bad[e["seq"]].get("healed") else "recovered"}", color="#b91c1c", '
                           f'fontcolor="#b91c1c", style=dashed, penwidth=2];')
            else:
                dot.append(f'"{fa}" -> "{ta}" [label="{tid}: ₹{int(amt):,}"];')
        dot.append("}")
        st.markdown("**Money flow in the sealed case file**  ·  red dashed = removed or altered on the server, recovered by SakshyaLog")
        st.graphviz_chart("\n".join(dot))

        st.markdown("**Case file: sealed record vs. what is on the server now**")
        for e in sealed:
            f = bad.get(e["seq"])
            kind = (e["line"].split(" | ")[2] if e["line"].count(" | ") >= 2 else "").split(" ")[0]
            if f:
                with st.container(border=True):
                    st.markdown(f"❌ **#{e['seq']} {kind}: {f['status']} on the investigation server**" +
                                (" · ♻️ **self-healed** (original written back)" if f.get("healed") else ""))
                    st.code(f"sealed original : {e['line']}" +
                            (f"\nserver now      : {f['server_line']}" if f.get("server_line") else ""), language=None)
                    p = f.get("proof") or {}
                    if p.get("anchored"):
                        link = f" · [blockchain tx]({p['tx_url']})" if p.get("tx_url") else ""
                        st.caption(f"Merkle proof {'✅ valid' if p['proof_valid'] else '❌ invalid'} · anchored "
                                   f"{fmt_unix(p.get('on_chain_since'))}{link}")
            else:
                st.markdown(f"✅ `#{e['seq']}` {e['line'][:160]}")
        st.caption("To prove one transaction to a bank or court without sharing the rest of the case, choose "
                   "**case-UPI-001** in the sidebar and use the 🔎 Prove one line tab. Demo attack: "
                   "`py -3.14 demo\\attack_case.py` (insider deletes transfer T2 and rewrites the report).")

if auto:
    time.sleep(3)
    st.rerun()
