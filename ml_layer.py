#!/usr/bin/env python3
"""ROUGH PROTOTYPE - Isolation Forest 'second opinion' for Attack Story Builder.

Rules stay the decision-maker (explainable). The ML model scores every
user-day on how unusual it is versus *that user's own* history and ranks it.

    rules alert + ML unusual  -> CONFIRMED   (higher trust)
    rules alert + ML normal   -> RULES-ONLY
    no alert    + ML unusual  -> ML-ONLY     (watch-list, analyst review, NOT an alert)

Run:  python ml_layer.py --logs data/attack_logs.csv
"""
import argparse
import json
from collections import defaultdict

import numpy as np
from sklearn.ensemble import IsolationForest

import detector

FEATURES = ["events", "logins_ok", "logins_fail", "new_geo", "new_device", "offhours",
            "sens_reads", "usb_copies", "uploads", "upload_mb", "priv_esc", "list_share"]
ML_PERCENTILE = 97   # top 3% most unusual user-days are "unusual"


def build_features(rows):
    """One feature vector per (user, day). 'new_*' is vs what the user had seen before."""
    seen_geo, seen_dev = defaultdict(set), defaultdict(set)
    feats, ids = {}, {}
    for r in rows:                      # rows are already time-sorted
        key = (r["user"], r["ts"].date().isoformat())
        f = feats.setdefault(key, dict.fromkeys(FEATURES, 0.0))
        ids.setdefault(key, []).append(r["log_id"])
        f["events"] += 1
        a, obj = r["action"], r["object"]
        if a == "login":
            f["logins_ok" if r["status"] == "ok" else "logins_fail"] += 1
            if r["status"] == "ok":
                if seen_geo[r["user"]] and r["geo"] not in seen_geo[r["user"]]:
                    f["new_geo"] += 1
                if seen_dev[r["user"]] and r["device"] not in seen_dev[r["user"]]:
                    f["new_device"] += 1
                seen_geo[r["user"]].add(r["geo"])
                seen_dev[r["user"]].add(r["device"])
        if r["ts"].hour < 5 or r["ts"].hour >= 23:
            f["offhours"] += 1
        if a == "file_read" and obj.startswith(detector.SENSITIVE):
            f["sens_reads"] += 1
        elif a == "usb_copy":
            f["usb_copies"] += 1
        elif a == "upload":
            f["uploads"] += 1
            f["upload_mb"] += r["bytes"] / 1e6
        elif a == "priv_escalate":
            f["priv_esc"] += 1
        elif a == "list_share":
            f["list_share"] += 1
    return feats, ids


def personalise(feats):
    """Replace raw counts with 'how far above this user's own typical day' (robust z)."""
    by_user = defaultdict(list)
    for (u, _), f in feats.items():
        by_user[u].append(f)
    out = {}
    for key, f in feats.items():
        hist = by_user[key[0]]
        vec = []
        for n in FEATURES:
            col = np.array([h[n] for h in hist])
            med, mad = np.median(col), np.median(np.abs(col - np.median(col)))
            vec.append((f[n] - med) / max(mad * 1.4826, 1.0))   # floor of 1 avoids blow-ups
        out[key] = vec
    return out


def ml_scores(rows, seed=42):
    feats, ids = build_features(rows)
    X_map = personalise(feats)
    keys = sorted(X_map)
    X = np.array([X_map[k] for k in keys])
    model = IsolationForest(n_estimators=300, contamination="auto", random_state=seed).fit(X)
    raw = -model.score_samples(X)                      # higher = more unusual
    thr = np.percentile(raw, ML_PERCENTILE)
    res = {}
    for k, s, x in zip(keys, raw, X):
        top = sorted(zip(FEATURES, x), key=lambda t: -t[1])[:3]
        res[k] = dict(user=k[0], day=k[1], score=round(float(s), 3), unusual=bool(s >= thr),
                      drivers=[f"{n} (+{v:.0f} vs own normal)" for n, v in top if v > 0],
                      log_ids=ids[k][:5])
    return res, thr


def second_opinion(logs_path):
    rows = detector.load_logs(logs_path)
    rep = detector.run(logs_path)
    scores, thr = ml_scores(rows)
    unusual = {k: v for k, v in scores.items() if v["unusual"]}
    alert_days = set()
    for a in rep["alerts"]:
        a["ml_verdict"], a["ml_support"] = "RULES-ONLY", []
        for u in a["users"]:
            days = {s["first_ts"][:10] for s in a["stages"]} | {s["last_ts"][:10] for s in a["stages"]}
            hits = [scores[(u, d)] for d in days if (u, d) in scores and scores[(u, d)]["unusual"]]
            alert_days |= {(u, d) for d in days}
            if hits:
                a["ml_verdict"], a["ml_support"] = "CONFIRMED", hits
    ml_only = sorted((v for k, v in unusual.items() if k not in alert_days),
                     key=lambda v: -v["score"])
    return dict(rules=rep, ml_only=ml_only, threshold=round(float(thr), 3))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", required=True)
    a = ap.parse_args()
    out = second_opinion(a.logs)
    print(f"ML threshold (top {100 - ML_PERCENTILE}%): {out['threshold']}")
    for al in out["rules"]["alerts"]:
        print(f"{al['id']} {al['severity']} risk={al['risk']} users={al['users']} -> {al['ml_verdict']}")
        for h in al["ml_support"]:
            print(f"     ML {h['day']} score={h['score']} drivers: {', '.join(h['drivers'])}")
    print(f"ML-only (watch-list, not alerts): {len(out['ml_only'])}")
    for v in out["ml_only"][:8]:
        print(f"  {v['user']} {v['day']} score={v['score']} {', '.join(v['drivers'])}")
