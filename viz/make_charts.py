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


if __name__ == "__main__":
    IMG.mkdir(parents=True, exist_ok=True)
    for f in (pii, rag, owasp, role_views):
        f()
    print("charts written")
