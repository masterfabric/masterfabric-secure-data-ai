"""Audit dashboard: one self-contained HTML file (inline CSS and SVG, no JavaScript, no network) built from
results/audit_sim.json. Open docs/audit-dashboard.html in any browser; viz/screenshot_dashboard.py renders the
PNG used in the README.
"""
from __future__ import annotations

import html
import json

from mfviz import DOCS, HEX, RESULTS

C = HEX


def esc(s) -> str:
    return html.escape(str(s))


def kpi(label, value, sub, color):
    return (f'<div class="kpi"><div class="kl">{esc(label)}</div><div class="kv" style="color:{color}">{esc(value)}</div>'
            f'<div class="ks">{esc(sub)}</div></div>')


def bars_per_hour(per_hour):
    hours = sorted(per_hour, key=int)
    w, h, pad = 600, 220, 34
    mx = max(v["allow"] + v["deny"] + v["error"] for v in per_hour.values())
    bw = (w - pad - 10) / len(hours)
    out = [f'<svg viewBox="0 0 {w} {h}" class="chart">']
    for i in range(5):
        y = h - 26 - (h - 50) * i / 4
        out.append(f'<line x1="{pad}" x2="{w - 6}" y1="{y:.1f}" y2="{y:.1f}" stroke="{C["LINE"]}" stroke-width="1"/>'
                   f'<text x="{pad - 6}" y="{y + 4:.1f}" class="ax" text-anchor="end">{round(mx * i / 4)}</text>')
    for i, hr in enumerate(hours):
        v = per_hour[hr]
        x = pad + i * bw + 4
        ha = (h - 50) * v["allow"] / mx
        hd = (h - 50) * (v["deny"] + v["error"]) / mx
        y0 = h - 26
        out.append(f'<rect x="{x:.1f}" y="{y0 - ha:.1f}" width="{bw - 8:.1f}" height="{ha:.1f}" fill="{C["ICE"]}" rx="2"/>')
        out.append(f'<rect x="{x:.1f}" y="{y0 - ha - hd:.1f}" width="{bw - 8:.1f}" height="{hd:.1f}" fill="{C["RED"]}" rx="2"/>')
        out.append(f'<text x="{x + (bw - 8) / 2:.1f}" y="{h - 10}" class="ax" text-anchor="middle">{int(hr):02d}</text>')
    out.append("</svg>")
    return "".join(out)


def hbars(d, color):
    mx = max(d.values()) if d else 1
    rows = []
    for k, v in d.items():
        rows.append(f'<div class="hb"><span class="hl">{esc(k)}</span><span class="track"><span class="fill" '
                    f'style="width:{100 * v / mx:.0f}%;background:{color}"></span></span><span class="hv">{v}</span></div>')
    return "".join(rows)


def main():
    d = json.loads((RESULTS / "audit_sim.json").read_text())
    total = d["entries"]
    deny = sum(v.get("deny", 0) for v in d["by_action"].values())
    sql = d["by_action"]["sql.query"]; chat = d["by_action"]["llm.input"]
    chain_ok = d["chain"]["verified"]
    drills = d["tamper_drills"]
    caught = sum(v["detected"] for v in drills.values())
    kpis = "".join([
        kpi("Audit entries", f"{total:,}", "08:00-20:00, simulated clock", C["WHITE"]),
        kpi("Denied", f"{deny}", f"{100 * deny / total:.1f}% of all entries", C["RED"]),
        kpi("SQL denied", f'{sql.get("deny", 0)} / {sum(sql.values())}', "policy engine", C["ORANGE"]),
        kpi("Chat blocked", f'{chat.get("deny", 0)} / {sum(chat.values())}', "guard rule layer", C["PURPLE"]),
        kpi("Erasures", f'{len(d["erasures"])}', "KVKK art. 7 requests", C["GREEN"]),
        kpi("Chain", "intact" if chain_ok else "BROKEN", f'head {d["chain"]["head"]}', C["GREEN"] if chain_ok else C["RED"]),
    ])
    recent = "".join(
        f'<tr><td class="m">{esc(r["time"])}</td><td class="m">#{r["seq"]}</td><td>{esc(r["actor"])}</td><td>{esc(r["role"])}</td>'
        f'<td>{esc(r["reason"])}</td><td class="m q">{esc(r["what"])}</td></tr>' for r in reversed(d["recent_denied"]))
    eras = "".join(
        f'<tr><td class="m">{esc(e["time"])}</td><td class="m">{esc(e["subject_ref"])}</td><td>{e["rows_deleted"]}</td>'
        f'<td>{e["notes_redacted"]}</td><td>{e["rag_docs_removed"]}</td><td>{e["retained_rows"]} invoices</td>'
        f'<td>{esc(", ".join(e["review"]) or "none")}</td></tr>' for e in d["erasures"])
    drill_rows = "".join(
        f'<tr><td>{esc(k)}</td><td style="color:{C["GREEN"] if v["detected"] else C["RED"]}">'
        f'{"detected" if v["detected"] else "missed"}</td><td class="m">#{v["first_bad_seq"]}</td><td>{esc(v["problem"])}</td></tr>'
        for k, v in drills.items())
    tp = d["throughput"]
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Audit log, MasterFabric Secure Data AI</title>
<style>
:root{{color-scheme:dark}}
body{{margin:0;background:{C["BG"]};color:{C["WHITE"]};font:14px/1.45 Inter,-apple-system,"Segoe UI",sans-serif}}
.wrap{{max-width:1280px;margin:0 auto;padding:28px 32px}}
h1{{font-size:22px;margin:0}} .sub{{color:{C["GREY"]};margin:4px 0 20px}}
.kpis{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:16px}}
.kpi,.card{{background:{C["PANEL"]};border:1px solid {C["LINE"]};border-radius:10px}}
.kpi{{padding:14px 16px}} .kl{{color:{C["GREY"]};font-size:12px;text-transform:uppercase;letter-spacing:.06em}}
.kv{{font-size:26px;font-weight:700;margin:4px 0}} .ks{{color:{C["GREY"]};font-size:12px}}
.grid{{display:grid;grid-template-columns:3fr 2fr;gap:16px;margin-bottom:16px}}
.card{{padding:16px 18px}} .card h2{{font-size:14px;margin:0 0 12px;color:{C["GREY"]};font-weight:600}}
.chart{{width:100%;height:auto}} .ax{{fill:{C["GREY"]};font-size:11px;font-family:"JetBrains Mono",monospace}}
.legend span{{display:inline-block;width:10px;height:10px;border-radius:2px;margin:0 6px 0 14px;vertical-align:-1px}}
.hb{{display:grid;grid-template-columns:170px 1fr 36px;align-items:center;gap:10px;margin:7px 0}}
.hl{{color:{C["WHITE"]};font-size:13px}} .hv{{text-align:right;font-family:"JetBrains Mono",monospace}}
.track{{background:{C["BG"]};height:12px;border-radius:6px;overflow:hidden}} .fill{{display:block;height:100%;border-radius:6px}}
table{{width:100%;border-collapse:collapse;font-size:13px}} th{{text-align:left;color:{C["GREY"]};font-weight:600;padding:6px 8px;border-bottom:1px solid {C["LINE"]}}}
td{{padding:6px 8px;border-bottom:1px solid {C["LINE"]}55}} .m{{font-family:"JetBrains Mono",monospace;font-size:12px}}
.q{{color:{C["GREY"]};max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.foot{{color:{C["GREY"]};font-size:12px;margin-top:10px}}
</style></head><body><div class="wrap">
<h1>Audit log</h1>
<div class="sub">{esc(d["day"])} · policy engine, guard, RAG and erasure service writing to one SHA-256 hash-chained log · free text PII-masked before writing</div>
<div class="kpis">{kpis}</div>
<div class="grid">
 <div class="card"><h2>Entries per hour <span class="legend"><span style="background:{C["ICE"]}"></span>allowed<span style="background:{C["RED"]}"></span>denied</span></h2>{bars_per_hour(d["per_hour"])}</div>
 <div class="card"><h2>Denials by reason</h2>{hbars(d["denials_by_reason"], C["RED"])}<h2 style="margin-top:18px">Denials by role</h2>{hbars(d["denials_by_role"], C["ORANGE"])}</div>
</div>
<div class="card" style="margin-bottom:16px"><h2>Most recent denials</h2>
<table><tr><th>Time</th><th>Entry</th><th>Actor</th><th>Role</th><th>Reason</th><th>Request (masked)</th></tr>{recent}</table></div>
<div class="grid">
 <div class="card"><h2>KVKK erasure requests</h2>
 <table><tr><th>Time</th><th>Subject (keyed hash)</th><th>Rows deleted</th><th>Notes redacted</th><th>RAG docs</th><th>Retained</th><th>Review</th></tr>{eras}</table></div>
 <div class="card"><h2>Integrity: {caught} of {len(drills)} tamper drills detected</h2>
 <table><tr><th>Drill (on a copy)</th><th>Result</th><th>At</th><th>Verifier says</th></tr>{drill_rows}</table>
 <div class="foot">Append {tp["append_us_per_entry"]} µs per entry · verify 20,000 entries in {tp["verify_20k_s"]} s · tail cuts are caught by the anchor file, not the chain</div></div>
</div>
<div class="foot">Generated by viz/audit_dashboard.py from results/audit_sim.json. Synthetic data; the timestamps come from a simulated clock, the decisions from the real components. The chat panel shows the rule layer only; the classifier layer is evaluated in results/injection_l2.json.</div>
</div></body></html>
"""
    (DOCS / "audit-dashboard.html").write_text(page)
    print("wrote", DOCS / "audit-dashboard.html")


if __name__ == "__main__":
    main()
