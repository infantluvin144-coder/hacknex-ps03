#!/usr/bin/env python3
"""One command to reproduce every demonstrated result:  python evaluate.py"""
import json
import os

import detector
import simulator


def main():
    os.makedirs("data", exist_ok=True)
    os.makedirs("outputs", exist_ok=True)
    n1 = simulator.gen(42, True, "data/attack_logs.csv", "data/ground_truth.json")
    n2 = simulator.gen(42, False, "data/clean_logs.csv", "data/ground_truth_clean.json")
    rep_a = detector.run("data/attack_logs.csv", "outputs/report_attack.json", "outputs/report_attack.html")
    rep_c = detector.run("data/clean_logs.csv", "outputs/report_clean.json", "outputs/report_clean.html")
    truth = json.load(open("data/ground_truth.json"))

    matched, details = set(), []
    for t in truth["attacks"]:
        hit = [a for a in rep_a["alerts"] if t["user"] in a["users"]]
        if hit:
            a = hit[0]
            matched.add(a["id"])
            got = [s["stage"] for s in a["stages"]]
            details.append(dict(attack=t["id"], user=t["user"], detected=True,
                                stage_recall=round(len(set(got) & set(t["stages"])) / len(t["stages"]), 2),
                                stages_found=got, risk=a["risk"], severity=a["severity"],
                                first_event=a["start"], true_start=t["start"],
                                order_correct=got == sorted(got, key=detector.STAGES.index)))
        else:
            details.append(dict(attack=t["id"], user=t["user"], detected=False))
    tp = sum(d["detected"] for d in details)
    fp = [a["id"] for a in rep_a["alerts"] if a["id"] not in matched]
    fn = len(details) - tp
    prec = tp / (tp + len(fp)) if tp + len(fp) else 1.0
    rec = tp / len(details) if details else 1.0
    weird_users = {w["user"] for w in truth["benign_weird"]}
    weird_alerts = [a["id"] for a in rep_a["alerts"] if set(a["users"]) & weird_users]

    metrics = dict(attack_dataset=dict(log_lines=n1, attacks_injected=len(details), true_positives=tp,
                                       false_negatives=fn, false_positive_alerts=len(fp),
                                       precision=round(prec, 2), recall=round(rec, 2), per_attack=details),
                   clean_dataset=dict(log_lines=n2, benign_but_weird_cases=len(truth["benign_weird"]),
                                      alerts_raised=rep_c["summary"]["alerts"],
                                      flagged_single_events=rep_c["summary"]["flagged_events"],
                                      watchlisted=rep_c["summary"]["watchlist"]),
                   benign_weird_users_alerted=weird_alerts)
    json.dump(metrics, open("outputs/metrics.json", "w"), indent=2)

    print("=" * 66)
    print(f"ATTACK DATASET  ({n1} logs, {len(details)} injected attacks)")
    for d in details:
        if d["detected"]:
            print(f"  {d['attack']} {d['user']}: DETECTED  risk={d['risk']} {d['severity']:<8} "
                  f"stages={d['stage_recall'] * 100:.0f}% order_ok={d['order_correct']}")
            print(f"       {' -> '.join(d['stages_found'])}")
        else:
            print(f"  {d['attack']} {d['user']}: MISSED")
    print(f"  precision={prec:.2f}  recall={rec:.2f}  false-positive alerts={len(fp)}")
    print(f"CLEAN DATASET   ({n2} logs, incl. {len(truth['benign_weird'])} benign-but-weird cases)")
    print(f"  alerts raised = {rep_c['summary']['alerts']}   (single odd events seen: "
          f"{rep_c['summary']['flagged_events']}, all suppressed)")
    print(f"  weird users alerted in attack run: {weird_alerts or 'none'}")
    print("=" * 66)


if __name__ == "__main__":
    main()
