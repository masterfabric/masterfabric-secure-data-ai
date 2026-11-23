"""Charts and the role-view table from results/*.json."""
from __future__ import annotations

import json

from mfviz import GREEN, GREY, HEX, ICE, IMG, ORANGE, PANEL, PURPLE, RED, RESULTS, WHITE, YELLOW, canvas, font, mpl_setup

plt = mpl_setup()


def J(n):
    return json.loads((RESULTS / f"{n}.json").read_text())


def pii():
    d = J("pii_eval")
    kinds = ["TCKN", "IBAN", "CARD", "PHONE", "EMAIL", "ALL"]
    fig, a = plt.subplots(figsize=(11, 4.6))
    x = range(len(kinds))
    for off, mode, col, lab in ((-0.2, "pattern_only", HEX["ORANGE"], "pattern only"), (0.2, "with_checksum", HEX["GREEN"], "pattern + checksum")):
        vals = [d[mode][k]["precision"] for k in kinds]
        a.bar([i + off for i in x], vals, 0.38, color=col, label=lab)
        for i, v in zip(x, vals):
            a.text(i + off, v + 0.01, f"{v:.2f}", ha="center", fontsize=9)
    a.set_xticks(list(x), kinds)
    a.set_ylim(0, 1.12)
    a.set_ylabel("precision (recall = 1.00 in both)")
    a.set_title(f"PII detection on {d['notes']:,} labelled synthetic notes ({d['entities']:,} entities + decoys)", loc="left")
    a.legend(loc="lower right")
    fig.tight_layout(); fig.savefig(IMG / "pii_precision.png"); plt.close(fig)


def rag():
    d = J("rag_eval")["modes"]
    who = ["public_chatbot", "support_istanbul", "business_desk", "fraud_team"]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(15, 4.8))
    modes = [("none_masked", "no filter", HEX["RED"]), ("post_masked", "post-filter top-5", HEX["YELLOW"]), ("pre_masked", "pre-filter (ACL before ranking)", HEX["GREEN"])]
    for j, (m, lab, col) in enumerate(modes):
        xs = [i + (j - 1) * 0.27 for i in range(4)]
        u = [d[m][w]["unauthorized_rate"] * 100 for w in who]
        r = [d[m][w]["avg_results"] for w in who]
        a1.bar(xs, u, 0.26, color=col, label=lab)
        a2.bar(xs, r, 0.26, color=col, label=lab)
        for x, v in zip(xs, u):
            a1.text(x, v + 1.5, f"{v:.0f}%", ha="center", fontsize=8)
        for x, v in zip(xs, r):
            a2.text(x, v + 0.08, f"{v:.2f}", ha="center", fontsize=8)
    for a in (a1, a2):
        a.set_xticks(range(4), [w.replace("_", "\n") for w in who])
    a1.set_ylabel("% of returned chunks the caller may not read"); a1.set_ylim(0, 112)
    a1.set_title("Leakage: unauthorised chunks in top-5", loc="left")
    a2.set_ylabel("chunks returned (of 5)"); a2.set_ylim(0, 5.8)
    a2.set_title("Usefulness: results left after filtering", loc="left")
    a1.legend(fontsize=9, loc="upper right")
    fig.tight_layout(); fig.savefig(IMG / "rag_leakage.png"); plt.close(fig)


def owasp():
    s = J("owasp_llm")["summary"]
    cats = [c for c in s if c != "benign"]
    fig, a = plt.subplots(figsize=(11, 4.6))
    for off, p, col in ((-0.2, "baseline", HEX["RED"]), (0.2, "guarded", HEX["GREEN"])):
        vals = [s[c][p]["succeeded"] / s[c][p]["attacks"] * 100 for c in cats]
        a.bar([i + off for i in range(len(cats))], vals, 0.38, color=col, label=p)
        for i, c in enumerate(cats):
            a.text(i + off, vals[i] + 2, f"{s[c][p]['succeeded']}/{s[c][p]['attacks']}", ha="center", fontsize=10)
    a.set_xticks(range(len(cats)), cats)
    a.set_ylim(0, 100); a.set_ylabel("attacks that succeeded (%)")
    b = s["benign"]["guarded"]
    a.set_title(f"Qwen2.5-1.5B on llama.cpp, temperature 0 · benign questions blocked: {b['blocked']}/{b['questions']}", loc="left")
    a.legend()
    fig.tight_layout(); fig.savefig(IMG / "owasp_attacks.png"); plt.close(fig)


def role_views():
    d = J("policy_eval")["roles"]
    im, dr = canvas(1600, 720)
    dr.text((50, 30), "One table, five roles: the first synthetic customer each role can see", font=font(30, 800), fill=WHITE)
    dr.text((50, 74), "Actual query output from eval/policy_eval.py. Missing cells: the column does not exist for that role (default deny).",
            font=font(18, 450), fill=GREY)
    cols = ["customer_id", "full_name", "tckn", "phone", "email", "iban", "birth_date"]
    widths = [210, 150, 170, 190, 180, 240, 230, 130]
    x0, y = 50, 130
    hdr = ["role"] + cols
    x = x0
    for h, w in zip(hdr, widths):
        dr.text((x, y), h, font=font(18, 750), fill=ICE); x += w
    accents = {"dpo": RED, "fraud_analyst": ORANGE, "data_scientist": PURPLE, "marketing": GREEN, "support_istanbul": YELLOW}
    for role, v in d.items():
        y += 100
        row = dict(zip(v["columns"], v["sample"][0]))
        dr.rounded_rectangle((x0 - 14, y - 22, 1560, y + 52), radius=12, fill=PANEL)
        dr.rounded_rectangle((x0 - 14, y - 22, x0 - 6, y + 52), radius=3, fill=accents[role])
        x = x0
        dr.text((x, y), role, font=font(18, 700), fill=WHITE); x += widths[0]
        for c, w in zip(cols, widths[1:]):
            val = row.get(c, "—")
            val = "NULL" if val == "None" else val
            dr.text((x, y), str(val)[:22], font=font(16, 500, mono=True), fill=WHITE if c in row else GREY); x += w
        dr.text((x0, y + 26), f"{v['rows_visible']:,} rows visible" + (" (row filter)" if v["rows_visible"] < 200000 else ""),
                font=font(14, 450), fill=GREY)
    im.save(IMG / "role_views.png", optimize=True)


def injection_layers():
    d = J("injection_l2")
    s, lat = d["summary"], d["latency"]
    names = [("baseline", "no guard", HEX["RED"]), ("guard_v1", "v1: rules", HEX["YELLOW"]), ("guard_v2", "v2: rules + classifier", HEX["GREEN"])]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(15, 4.9), gridspec_kw={"width_ratios": [1.15, 1]})
    groups = [("dev", "direct"), ("held-out", "direct")]
    for j, (p, lab, col) in enumerate(names):
        xs = [i + (j - 1) * 0.27 for i in range(len(groups))]
        vals = [s[g][k][p]["succeeded"] / s[g][k][p]["n"] * 100 for g, k in groups]
        a1.bar(xs, vals, 0.26, color=col, label=lab)
        for x, (g, k), v in zip(xs, groups, vals):
            a1.text(x, v + 2, f"{s[g][k][p]['succeeded']}/{s[g][k][p]['n']}", ha="center", fontsize=10)
    a1.set_xticks(range(len(groups)), ["development set\n(10 direct attacks)", "held-out set\n(12 direct attacks)"])
    a1.set_ylim(0, 100); a1.set_ylabel("attacks that succeeded (%)")
    a1.set_title("Direct injection: answer contains PWNED", loc="left")
    a1.legend(loc="upper left", fontsize=9)
    groups = [("dev", "benign"), ("held-out", "benign")]
    for j, (p, lab, col) in enumerate(names):
        xs = [i + (j - 1) * 0.27 for i in range(len(groups))]
        vals = [s[g][k][p]["blocked"] for g, k in groups]
        a2.bar(xs, vals, 0.26, color=col)
        for x, (g, k), v in zip(xs, groups, vals):
            a2.text(x, v + 0.1, f"{v}/{s[g][k][p]['n']}", ha="center", fontsize=10)
    a2.set_xticks(range(2), ["development benign\n(10 questions)", "held-out hard benign\n(12 questions)"])
    a2.set_ylim(0, 4); a2.set_ylabel("legitimate questions blocked")
    a2.set_title(f"Cost: false blocks · classifier call p50 {lat['classifier_call']['p50_ms']:.0f} ms", loc="left")
    fig.suptitle("Qwen2.5-1.5B answers, Granite Guardian 3.2 3B-A800M classifies (threshold frozen on the development set) · "
                 "poisoned documents dropped: 16/16, clean: 0/2", x=0.01, ha="left", fontsize=11, color=HEX["GREY"])
    fig.tight_layout(); fig.savefig(IMG / "injection_layers.png"); plt.close(fig)


def erasure():
    d = J("erasure_eval")
    stores = ["crm.customers", "care.call_notes", "analytics.customer_snapshot", "marketing.contact_list", "rag.index", "billing.invoices"]
    labels = ["CRM master", "call notes", "analytics copy", "marketing export", "RAG index", "invoices\n(retained)"]
    before = [d["found_before_total"][k] for k in stores]
    after = [0, 0, 0, 0, 0, d["retained_invoice_rows"]]
    fig, a = plt.subplots(figsize=(12, 4.8))
    xs = range(len(stores))
    a.bar([x - 0.2 for x in xs], before, 0.38, color=HEX["ORANGE"], label="found before the request")
    a.bar([x + 0.2 for x in xs], after, 0.38, color=[HEX["GREEN"]] * 5 + [HEX["PURPLE"]], label="left after (residual scan)")
    for x, b, f in zip(xs, before, after):
        a.text(x - 0.2, b + 1.5, str(b), ha="center", fontsize=10)
        a.text(x + 0.2, f + 1.5, str(f), ha="center", fontsize=10)
    a.set_xticks(list(xs), labels)
    a.set_ylabel("rows or documents, 50 subjects"); a.set_ylim(0, max(before) * 1.35)
    lat = d["latency_ms"]
    a.set_title(f"KVKK erasure: 50 requests over {d['customers']:,} customers · p50 {lat['p50']:.0f} ms, p95 {lat['p95']:.0f} ms · "
                f"other customers' rows unchanged", loc="left")
    from matplotlib.patches import Patch
    a.legend(handles=[Patch(color=HEX["ORANGE"], label="found before the request"),
                      Patch(color=HEX["GREEN"], label="left after (residual scan)"),
                      Patch(color=HEX["PURPLE"], label="kept under a legal retention period")], loc="upper left", ncol=3)
    fig.tight_layout(); fig.savefig(IMG / "erasure.png"); plt.close(fig)


def clarify_eval():
    d = J("clarify_eval")
    s = d["summary"]
    splits = [("dev", "development\n10 + 10"), ("held-out v1", "held-out v1\n12 + 12"),
              ("held-out v2", "held-out v2 (fresh)\n12 + 12")]
    modes = [("v2", "v2: block what the classifier flags", HEX["ORANGE"]),
             ("v3", "v3: clarify, then answer the rewrite", HEX["GREEN"])]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(15, 4.9))
    for ax, key, n_key, title in ((a1, "benign_blocked", "benign", "Legitimate questions blocked"),
                                  (a2, "attacks_succeeded", "attacks", "Direct attacks that got PWNED shown")):
        for j, (m, lab, col) in enumerate(modes):
            xs = [i + (j - 0.5) * 0.36 for i in range(len(splits))]
            vals = [s[sp][m][key] for sp, _ in splits]
            ax.bar(xs, vals, 0.34, color=col, label=lab)
            for x, sp, v in zip(xs, splits, vals):
                ax.text(x, v + 0.08, f"{v}/{s[sp[0]][m][n_key]}", ha="center", fontsize=10)
        ax.set_xticks(range(len(splits)), [l for _, l in splits])
        ax.set_ylim(0, 4.2)
        ax.set_title(title, loc="left")
    a1.set_ylabel("count"); a1.legend(loc="upper left", fontsize=9)
    clar = sum(s[sp]["v3"]["attacks_clarified"] for sp, _ in splits)
    a2.text(0.99, 0.97, f"{clar} attacks reached a clarification (user confirms every time);\n"
            "their rewrites carried no instruction and none showed PWNED", transform=a2.transAxes, ha="right", va="top",
            fontsize=9, color=HEX["GREY"])
    fig.suptitle("Guard v3 (sdai/clarify.py) on the answering path · Qwen2.5-1.5B rewrites, Granite Guardian re-checks "
                 f"the rewrite at {d['threshold']} · clarified path p50 {d['clarified_path_ms_p50']:.0f} ms",
                 x=0.01, ha="left", fontsize=11, color=HEX["GREY"])
    fig.tight_layout(); fig.savefig(IMG / "clarify_eval.png"); plt.close(fig)


def clarify_examples():
    d = J("clarify_eval")
    rows = [r for r in d["rows"] if r["mode"] == "v3" and "classifier (" in r["reason"]]
    rows.sort(key=lambda r: (r["kind"] != "benign", r["status"] != "clarified", r["split"]))
    W, rh, top = 1900, 46, 118
    img, dr = canvas(W, top + rh * (len(rows) + 1) + 40)
    dr.text((40, 30), "Every question the classifier flagged, and what guard v3 did with it", font=font(30, 700), fill=WHITE)
    dr.text((40, 72), "Original message → the model's rewrite → outcome. Rewrites are re-checked by the rules and the "
            "classifier; a rewrite that repeats a capitalised code word is not offered.", font=font(17), fill=GREY)
    cols = [(40, "set"), (210, "kind"), (300, "original message (score)"), (950, "rewrite"), (1440, "outcome")]
    y = top
    for x, h in cols:
        dr.text((x, y), h, font=font(16, 700), fill=GREY)
    y += rh
    for r in rows:
        dr.rectangle([30, y - 8, W - 30, y + rh - 14], fill=PANEL)
        score = r["reason"].split("(")[1].split(")")[0]
        rw = (r.get("rewrite") or "")[:52]
        if r["status"] == "clarified":
            out, col = "offered, answered: " + r["shown"].split("\n---\n")[-1][:34], GREEN
        else:
            out, col = "blocked: " + r["reason"].split("; ", 1)[-1][:40], (ORANGE if r["kind"] == "benign" else GREY)
        vals = [r["split"], r["kind"], f"{r['prompt'][:62]} ({score})", rw, out]
        for (x, _), v in zip(cols, vals):
            dr.text((x, y), v, font=font(15, mono=(x in (300, 950))), fill=col if x == 1440 else WHITE)
        y += rh
    img.save(IMG / "clarify_examples.png")


def dsr_latency():
    d = J("dsr_bench")
    lat, sc = d["latency_ms"], d["scale"]
    types = [("access", "access", HEX["ICE"]), ("consent_withdrawal", "consent withdrawal\n(CCPA: opt-out)", HEX["GREEN"]),
             ("erasure", "erasure", HEX["ORANGE"])]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(15, 4.9), gridspec_kw={"width_ratios": [1, 1.15]})
    for off, q, alpha in ((-0.2, "p50", 1.0), (0.2, "p95", 0.55)):
        for i, (t, _, col) in enumerate(types):
            v = lat["by_request_type"][t]["total"][q]
            a1.bar(i + off, v, 0.38, color=col, alpha=alpha)
            a1.text(i + off, v * 1.12, f"{v:.1f}", ha="center", fontsize=10)
    a1.set_yscale("log"); a1.set_ylim(0.5, 600)
    a1.set_xticks(range(3), [lab for _, lab, _ in types])
    a1.set_ylabel("end-to-end time per request (ms, log scale)")
    a1.set_title("Per request type: p50 (solid) and p95 (light)", loc="left")
    laws = ["gdpr", "ccpa", "kvkk"]
    for j, (t, lab, col) in enumerate(types):
        xs = [i + (j - 1) * 0.27 for i in range(3)]
        vals = [lat["by_law_and_type"][f"{lw}/{t}"]["total"]["p50"] for lw in laws]
        a2.bar(xs, vals, 0.26, color=col, label=lab.replace("\n", " "))
        for x, v in zip(xs, vals):
            a2.text(x, v * 1.12, f"{v:.1f}", ha="center", fontsize=9)
    a2.set_yscale("log"); a2.set_ylim(0.5, 600)
    a2.set_xticks(range(3), [lw.upper() for lw in laws])
    a2.set_ylabel("p50 (ms, log scale)")
    a2.set_title("Per law and type: p50", loc="left")
    a2.legend(loc="upper right", fontsize=9, ncol=3)
    fig.suptitle(f"DSR workflow: intake, identity check, processing, response · {sc['requests_total']} requests "
                 f"({sc['requests_per_law_and_type']} per law and type) over {sc['customers']:,} customers · {d['environment']['cpu_brand']}",
                 x=0.01, ha="left", fontsize=11, color=HEX["GREY"])
    fig.tight_layout(); fig.savefig(IMG / "dsr_latency.png"); plt.close(fig)


def dsr_deadlines():
    import matplotlib.dates as mdates
    from datetime import date
    d = J("dsr_bench")["deadlines"]
    rows = [("GDPR, 1 month (+2 ext.)", "gdpr/access", HEX["GREEN"]), ("CCPA, 45 days (+45 ext.)", "ccpa/access", HEX["ICE"]),
            ("CCPA opt-out, 15 business days", "ccpa/consent_withdrawal", HEX["PURPLE"]), ("KVKK, 30 days", "kvkk/access", HEX["ORANGE"])]
    fig = plt.figure(figsize=(14, 9.2))
    gs = fig.add_gridspec(3, 1, height_ratios=[1, 1, 0.9], hspace=0.55)
    for k, rec in enumerate(("2028-01-31", "2027-11-15")):
        a = fig.add_subplot(gs[k])
        r0 = date.fromisoformat(rec); x0 = mdates.date2num(r0)
        for i, (lab, key, col) in enumerate(rows):
            y = len(rows) - 1 - i
            base = date.fromisoformat(d["samples"][rec][key + "/base"])
            a.barh(y, (base - r0).days, left=x0, height=0.55, color=col)
            a.text(mdates.date2num(base) + 1, y, f"{base:%a %d %b %Y}", va="center", fontsize=10)
            if key + "/extended" in d["samples"][rec]:
                ext = date.fromisoformat(d["samples"][rec][key + "/extended"])
                a.barh(y, (ext - base).days, left=mdates.date2num(base), height=0.55, color=col, alpha=0.35, hatch="//", edgecolor=HEX["PANEL"])
                a.text(mdates.date2num(ext) + 1, y, f"{ext:%a %d %b %Y} (extended)", va="center", fontsize=10, color=HEX["GREY"])
        a.axvline(x0, color=HEX["WHITE"], lw=1.2)
        a.set_yticks(range(len(rows)), [r[0] for r in reversed(rows)])
        a.xaxis_date(); a.xaxis.set_major_formatter(mdates.DateFormatter("%d %b %Y"))
        a.set_xlim(x0 - 3, x0 + 115); a.set_ylim(-0.6, len(rows) - 0.4)
        a.set_title(f"Request received {r0:%a %d %b %Y}: due dates by rule (solid = first period, hatched = extension)", loc="left")
    a = fig.add_subplot(gs[2])
    days = d["gdpr_base_days_to_due_by_receipt_2028"]
    start = mdates.date2num(date(2028, 1, 1))
    a.step([start + i for i in range(len(days))], days, where="post", color=HEX["GREEN"], lw=2)
    a.xaxis_date(); a.xaxis.set_major_formatter(mdates.DateFormatter("%b"))
    a.set_yticks([28, 29, 30, 31]); a.set_ylim(27.5, 31.6)
    a.set_ylabel("calendar days to due")
    g = d["rules"]["gdpr/access/base"]
    a.set_title(f"GDPR one month, by receipt date in 2028: {g['min_days_to_due']} to {g['max_days_to_due']} calendar days "
                f"(2027 and 2028 together: {g['month_end_clamps']} of {g['receipt_dates']} receipt dates clamp to a month end)", loc="left")
    fig.suptitle("Response deadlines from sdai/deadlines.py (day of receipt not counted; weekends and holidays not modelled)",
                 x=0.01, y=0.97, ha="left", fontsize=11, color=HEX["GREY"])
    fig.savefig(IMG / "dsr_deadlines.png"); plt.close(fig)


def dsr_verification():
    import numpy as np
    v = J("dsr_bench")["verification"]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(15, 5.4), gridspec_kw={"width_ratios": [0.8, 1.6]})
    m = np.array([[v["TA"], v["FR"]], [v["FA"], v["TR"]]])
    a1.imshow(m, cmap="Blues", vmin=0, vmax=m.max() * 1.6)
    a1.grid(False)
    names = [["true accept", "false reject"], ["false accept", "true reject"]]
    for i in range(2):
        for j in range(2):
            a1.text(j, i, f"{m[i, j]}\n{names[i][j]}", ha="center", va="center", fontsize=14,
                    color=HEX["BG"])  # light cells: dark text
    a1.set_xticks([0, 1], ["accepted", "rejected"]); a1.set_yticks([0, 1], ["should accept", "should reject"])
    a1.set_title(f"{v['attempts']} labelled attempts · accuracy {v['accuracy']:.3f}\nFAR {v['FAR']:.3f} · FRR {v['FRR']:.3f}", loc="left")
    cats = sorted(v["by_category"].items(), key=lambda kv: (kv[1]["expected"] != "accept", kv[0]))
    for i, (c, x) in enumerate(cats):
        right = x["accepted"] if x["expected"] == "accept" else x["attempts"] - x["accepted"]
        col = HEX["GREEN"] if x["expected"] == "accept" else HEX["ORANGE"]
        a2.barh(i, x["attempts"], color=col, alpha=0.35)
        a2.barh(i, right, color=col)
        a2.text(x["attempts"] + 1, i, f"{right}/{x['attempts']}", va="center", fontsize=9)
    a2.set_yticks(range(len(cats)), [c for c, _ in cats], fontsize=9); a2.invert_yaxis()
    a2.set_xlabel("attempts (solid: decided as expected)")
    a2.set_title("By category: genuine (green) must be accepted, impostors (orange) rejected", loc="left")
    fig.suptitle("Identity check: two matching factors (CCPA opt-out: one, identification only) against crm.customers; "
                 "phone formats and e-mail case are normalised", x=0.01, ha="left", fontsize=11, color=HEX["GREY"])
    fig.tight_layout(); fig.savefig(IMG / "dsr_verification.png"); plt.close(fig)


CHARTS = (pii, rag, owasp, role_views, injection_layers, erasure, clarify_eval, clarify_examples,
          dsr_latency, dsr_deadlines, dsr_verification)

if __name__ == "__main__":
    import sys
    IMG.mkdir(parents=True, exist_ok=True)
    by_name = {f.__name__: f for f in CHARTS}
    wanted = sys.argv[1:] or list(by_name)  # `make_charts.py dsr_latency dsr_deadlines` builds only those
    for n in wanted:
        by_name[n]()
    print("charts written:", ", ".join(wanted))
