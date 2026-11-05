"""Score the phrase-list rules on tests.csv (no AI model, no network)."""
import csv
from collections import defaultdict
from rules import lexicon_features, evaluate

rows = list(csv.DictReader(open("tests.csv", encoding="utf-8")))
stats = defaultdict(lambda: {"scam": 0, "caught_strict": 0, "caught_warn": 0,
                             "legit": 0, "false_strict": 0, "false_warn": 0})
misses, false_alarms = [], []

for r in rows:
    feats, _ = lexicon_features(r["text"])
    out = evaluate(feats)
    verdict = out["verdict"]
    for key in (r["language"], "ALL"):
        s = stats[key]
        if r["label"] == "scam":
            s["scam"] += 1
            s["caught_strict"] += verdict == "likely_scam"
            s["caught_warn"] += verdict in ("likely_scam", "not_sure")
        else:
            s["legit"] += 1
            s["false_strict"] += verdict == "likely_scam"
            s["false_warn"] += verdict in ("likely_scam", "not_sure")
    if r["label"] == "scam" and verdict != "likely_scam":
        misses.append((r["id"], r["language"], r["kind"], verdict, out["hard_hits"] + out["soft_hits"]))
    if r["label"] == "legit" and verdict != "likely_fine":
        false_alarms.append((r["id"], r["language"], r["kind"], verdict, out["hard_hits"] + out["soft_hits"]))

print(f"{'lang':9} {'scams caught (strict)':>22} {'scams warned':>14} {'legit flagged scam':>20} {'legit warned':>14}")
for key in ["en", "ta", "tanglish", "ALL"]:
    s = stats[key]
    print(f"{key:9} {s['caught_strict']:>3}/{s['scam']:<18} {s['caught_warn']:>3}/{s['scam']:<10} "
          f"{s['false_strict']:>3}/{s['legit']:<16} {s['false_warn']:>3}/{s['legit']:<10}")
print("\nScams not called 'likely scam':")
for m in misses:
    print("  ", m)
print("\nLegit messages not called 'no scam signs':")
for m in false_alarms:
    print("  ", m)
