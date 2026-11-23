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


if __name__ == "__main__":
    IMG.mkdir(parents=True, exist_ok=True)
    for f in (pii, rag, owasp, role_views, injection_layers, erasure, clarify_eval, clarify_examples):
        f()
    print("charts written")
