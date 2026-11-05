"""Compare on a test file: plain model vs rules vs checklist+rules vs final hybrid.

Usage: python eval_compare.py <model-id> [tests.csv]
Writes per-message results to results/<file>_<model>.csv and prints a summary.
Failed model calls are counted and reported, never treated as a pass.
"""
import csv
import os
import sys
import time

import pipeline
from rules import evaluate, lexicon_features, merge_features

model = sys.argv[1]
test_file = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else "tests.csv"
pipeline.LLM_MODEL = model
pipeline.FALLBACK_MODELS = []  # every score must come from the named model
PAUSE = float(os.getenv("EVAL_PAUSE", "3"))
BASELINE = "--baseline" in sys.argv  # extra call per message: ask the model with no guidance

out, errors = [], 0
for r in csv.DictReader(open(test_file, encoding="utf-8")):
    lex, _ = lexicon_features(r["text"])
    res = pipeline.analyze_text(r["text"], use_llm=True)
    if not res["llm_used"]:
        errors += 1
        print("model error", r["id"], res["llm_error"], file=sys.stderr)
    ok = res["llm_used"]
    out.append({
        "id": r["id"], "language": r["language"], "label": r["label"], "kind": r["kind"], "text": r["text"],
        **({"form": r["form"]} if "form" in r else {}),
        "plain_model": (pipeline.raw_verdict(r["text"]) if BASELINE else res["model_verdict"]) if ok else "error",
        "rules_only": evaluate(lex)["verdict"],
        "checklist_rules": evaluate(res["merged_features"])["verdict"] if ok else "error",
        "final": res["verdict"] if ok else "error",
        "llm_features": "|".join(res["llm_features"]),
    })
    time.sleep(PAUSE)

os.makedirs("results", exist_ok=True)
stem = os.path.splitext(os.path.basename(test_file))[0]
path = f"results/{stem}_{model.replace('/', '_')}.csv"
with open(path, "w", encoding="utf-8", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
    w.writeheader()
    w.writerows(out)

STRONG = {"scam", "likely_scam"}
WARN = {"scam", "likely_scam", "unsure", "not_sure"}
print(f"model: {model}  file: {test_file}  messages: {len(out)}  failed calls: {errors}")
for lang in sorted({o["language"] for o in out}) + ["ALL"]:
    sub = [o for o in out if lang == "ALL" or o["language"] == lang]
    scams = [o for o in sub if o["label"] == "scam"]
    legit = [o for o in sub if o["label"] == "legit"]
    print(f"[{lang}] scams={len(scams)} legit={len(legit)}")
    for s in ["plain_model", "rules_only", "checklist_rules", "final"]:
        print(f"  {s:16} scam called scam {sum(o[s] in STRONG for o in scams)}/{len(scams)}"
              f"  scam warned {sum(o[s] in WARN for o in scams)}/{len(scams)}"
              f"  legit called scam {sum(o[s] in STRONG for o in legit)}/{len(legit)}"
              f"  legit warned {sum(o[s] in WARN for o in legit)}/{len(legit)}")
if "form" in out[0]:
    for form in sorted({o["form"] for o in out}):
        sub = [o for o in out if o["form"] == form]
        sc = [o for o in sub if o["label"] == "scam"]
        le = [o for o in sub if o["label"] == "legit"]
        print(f"[form={form}] final: scam called scam {sum(o['final'] in STRONG for o in sc)}/{len(sc)}"
              f"  scam warned {sum(o['final'] in WARN for o in sc)}/{len(sc)}"
              f"  legit called scam {sum(o['final'] in STRONG for o in le)}/{len(le)}"
              f"  legit warned {sum(o['final'] in WARN for o in le)}/{len(le)}")
print("scams given no warning, and genuine called scam:")
for o in out:
    if (o["label"] == "scam" and o["final"] == "likely_fine") or (o["label"] == "legit" and o["final"] == "likely_scam"):
        print("  ", o["id"], o["language"], o["label"], o.get("form", ""), o["kind"], "final=", o["final"], "model=", o["plain_model"], "|", o["llm_features"], "|", o["text"][:90])
print("saved", path)
