#!/usr/bin/env python3
"""Attack Story Builder - PS03 core logic.

Pipeline:  logs -> per-user baselines -> stage-tagged suspicious events
           -> entity-linked chains (user / external IP) -> ordered kill-chain check
           -> risk score -> evidence-cited incident report

Design rule against false positives: a single odd event is NEVER an alert.
An alert needs >= 2 distinct kill-chain stages, in chronological order, linked
through shared entities, and a combined risk >= RISK_ALERT.
"""
import argparse
import csv
import json
import os
from collections import defaultdict, deque
from datetime import datetime, timedelta

STAGES = ["Initial Access", "Privilege Escalation", "Discovery", "Collection", "Exfiltration"]
SENSITIVE = ("fin/", "hr/", "secrets/")
WARMUP_DAYS = 2          # learn-only period (nothing is flagged)
GAP_HOURS = 48           # max silence between linked events (supports low-and-slow)
RISK_ALERT = 0.70
MIN_STAGES = 2

ACTIONS = {
    "Initial Access": "Force password reset + revoke active sessions for {users}; block IP(s) {ips}",
    "Privilege Escalation": "Review and roll back privilege/group changes made by {users}",
    "Discovery": "Review share-enumeration activity; tighten share permissions for {users}",
    "Collection": "Audit access to sensitive folders; check DLP logs for {users}",
    "Exfiltration": "Isolate device(s) {devices}; block outbound destination(s) {dests}; inspect removable media / uploaded data",
}


class UserState:
    def __init__(self):
        self.geos, self.ips, self.devs = set(), set(), set()
        self.folders, self.dests = set(), set()
        self.usb = self.priv = self.disc = False
        self.fails, self.sens, self.lists = deque(), deque(), deque()
        self.disc_until = datetime.min


def load_logs(path):
    rows = []
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            r["ts"] = datetime.fromisoformat(r["timestamp"])
            r["bytes"] = int(r["bytes"] or 0)
            rows.append(r)
    rows.sort(key=lambda r: (r["ts"], r["log_id"]))
    return rows


def _trim(dq, ts, minutes, key=lambda x: x):
    while dq and ts - key(dq[0]) > timedelta(minutes=minutes):
        dq.popleft()


def detect(r, st, warm):
    """Return (stage, score, reason) if the event is suspicious for this user."""
    ts, a, obj = r["ts"], r["action"], r["object"]
    folder = obj.split("/")[0]
    sens = obj.startswith(SENSITIVE)
    off = ts.hour < 5 or ts.hour >= 23
    out = None

    if a == "login":
        if r["status"] == "fail":
            st.fails.append((ts, r["ip"]))
            return None
        _trim(st.fails, ts, 15, key=lambda x: x[0])
        n = sum(1 for _, ip in st.fails if ip == r["ip"])
        if n >= 5 and r["ip"] not in st.ips:
            out = ("Initial Access", 0.70,
                   f"{n} failed logins from new IP {r['ip']} followed by a success (brute force)")
        elif r["geo"] not in st.geos:
            s, why = 0.45, [f"first login from new geo {r['geo']} ({r['ip']})"]
            if r["device"] not in st.devs:
                s += 0.15
                why.append(f"unrecognised device {r['device']}")
            if off:
                s += 0.10
                why.append("off-hours")
            out = ("Initial Access", round(s, 2), ", ".join(why))

    elif a == "priv_escalate":
        if not st.priv:
            out = ("Privilege Escalation", round(0.6 + (0.1 if off else 0), 2),
                   "first privilege escalation ever seen for this user" + (", off-hours" if off else ""))

    elif a == "list_share":
        st.lists.append((ts, obj))
        _trim(st.lists, ts, 10, key=lambda x: x[0])
        distinct = len({o for _, o in st.lists})
        if ts <= st.disc_until:
            out = ("Discovery", 0.40, f"share enumeration burst ({distinct} objects in 10 min)")
        elif distinct >= 20:
            if warm or st.disc:
                st.disc = True          # this user normally does this (e.g. admin)
            else:
                st.disc_until = ts + timedelta(minutes=10)
                out = ("Discovery", 0.40, f"share enumeration burst ({distinct} objects in 10 min), never seen for this user")

    elif a == "file_read":
        if sens:
            st.sens.append(ts)
            _trim(st.sens, ts, 10)
            if folder not in st.folders:
                s, why = 0.35, f"first-ever access to sensitive folder '{folder}/'"
                if len(st.sens) >= 10:
                    s += 0.20
                    why += f", {len(st.sens)} sensitive reads in 10 min"
                out = ("Collection", round(s, 2), why)

    elif a == "usb_copy":
        if not st.usb:
            out = ("Exfiltration", round(0.4 + (0.3 if sens else 0), 2),
                   "first removable-media copy ever seen for this user" + (" - sensitive data" if sens else ""))
        elif sens and folder not in st.folders:
            out = ("Exfiltration", 0.50, f"USB copy from sensitive folder '{folder}/' never accessed before")

    elif a == "upload":
        if r["dest"] not in st.dests:
            big = r["bytes"] >= 100_000_000
            out = ("Exfiltration", round(0.3 + (0.3 if big else 0), 2),
                   f"upload of {r['bytes'] / 1e6:.0f} MB to never-seen destination {r['dest']}")

    return None if warm else out


def learn(r, st):
    a, folder = r["action"], r["object"].split("/")[0]
    if a == "login" and r["status"] == "ok":
        st.geos.add(r["geo"]); st.ips.add(r["ip"]); st.devs.add(r["device"])
    elif a == "file_read":
        st.folders.add(folder)
    elif a == "usb_copy":
        st.usb = True
    elif a == "upload":
        st.dests.add(r["dest"])
    elif a == "priv_escalate":
        st.priv = True


def score_events(rows):
    day0 = rows[0]["ts"].replace(hour=0, minute=0, second=0)
    warm_end = day0 + timedelta(days=WARMUP_DAYS)
    states, flags = defaultdict(UserState), []
    for r in rows:
        st = states[r["user"]]
        res = detect(r, st, r["ts"] < warm_end)
        if res:   # flagged events never update the baseline (attacker can't "become normal")
            flags.append(dict(log_id=r["log_id"], ts=r["ts"], user=r["user"], device=r["device"],
                              ip=r["ip"], app=r["app"], geo=r["geo"], action=r["action"],
                              object=r["object"], dest=r["dest"], stage=res[0], score=res[1], reason=res[2]))
        else:
            learn(r, st)
    return flags


def build_incidents(flags):
    """Link flagged events that share a user or an external IP; split on long silences."""
    parent = list(range(len(flags)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    first = {}
    for i, f in enumerate(flags):
        keys = [("user", f["user"])]
        if not f["ip"].startswith("10."):
            keys.append(("ip", f["ip"]))
        for k in keys:
            if k in first:
                parent[find(i)] = find(first[k])
            else:
                first[k] = i
    comps = defaultdict(list)
    for i, f in enumerate(flags):
        comps[find(i)].append(f)
    clusters = []
    for fl in comps.values():
        fl.sort(key=lambda f: f["ts"])
        cur = [fl[0]]
        for f in fl[1:]:
            if f["ts"] - cur[-1]["ts"] > timedelta(hours=GAP_HOURS):
                clusters.append(cur)
                cur = [f]
            else:
                cur.append(f)
        clusters.append(cur)
    return clusters


def summarize(cluster):
    by = defaultdict(list)
    for f in cluster:
        by[f["stage"]].append(f)
    out = []
    for s in STAGES:
        if s in by:
            ev = by[s]
            best = max(ev, key=lambda f: f["score"])
            out.append(dict(stage=s, first_ts=ev[0]["ts"], last_ts=ev[-1]["ts"], n_events=len(ev),
                            score=best["score"], why=best["reason"], evidence=[f["log_id"] for f in ev]))
    return out


def ordered_chain(stages):
    """Longest set of stages whose first occurrences respect kill-chain order in time."""
    dp = [[s] for s in stages]
    for i in range(len(stages)):
        for j in range(i):
            if stages[j]["first_ts"] <= stages[i]["first_ts"] and len(dp[j]) + 1 > len(dp[i]):
                dp[i] = dp[j] + [stages[i]]
    return max(dp, key=len) if dp else []


def noisy_or(scores):
    p = 1.0
    for s in scores:
        p *= (1 - s)
    return round(min(0.99, 1 - p), 2)


def severity(risk):
    return "CRITICAL" if risk >= 0.90 else "HIGH" if risk >= 0.80 else "MEDIUM"


def fmt(ts):
    return ts.isoformat(timespec="seconds")


def run(logs_path, out_json=None, out_html=None):
    rows = load_logs(logs_path)
    rowmap = {r["log_id"]: r for r in rows}
    flags = score_events(rows)
    alerts, watch = [], []

    for cluster in build_incidents(flags):
        stages = summarize(cluster)
        chain = ordered_chain(stages)
        risk = noisy_or([s["score"] for s in chain])
        users = sorted({f["user"] for f in cluster})
        base = dict(users=users, risk=risk, stages=[s["stage"] for s in chain],
                    evidence=[e for s in chain for e in s["evidence"]][:20])
        if len(chain) < MIN_STAGES:
            watch.append(dict(base, suppressed_because="only one kill-chain stage - not enough to call an attack"))
            continue
        if risk < RISK_ALERT:
            watch.append(dict(base, suppressed_because=f"combined risk {risk} below alert threshold {RISK_ALERT}"))
            continue

        devices = sorted({f["device"] for f in cluster})
        ips = sorted({f["ip"] for f in cluster if not f["ip"].startswith("10.")})
        apps = sorted({f["app"] for f in cluster})
        dests = sorted({f["dest"] for f in cluster if f["dest"]})
        st_out, narrative = [], []
        for s in chain:
            sample = []
            for lid in s["evidence"][:3]:
                r = rowmap[lid]
                sample.append(dict(log_id=lid, timestamp=r["timestamp"], user=r["user"], device=r["device"],
                                   ip=r["ip"], action=r["action"], object=r["object"] or r["dest"]))
            st_out.append(dict(stage=s["stage"], first_ts=fmt(s["first_ts"]), last_ts=fmt(s["last_ts"]),
                               n_events=s["n_events"], score=s["score"], why=s["why"],
                               evidence=s["evidence"], sample_rows=sample))
            cite = ", ".join(s["evidence"][:4]) + (f" (+{s['n_events'] - 4} more)" if s["n_events"] > 4 else "")
            narrative.append(f"{fmt(s['first_ts'])} [{s['stage']}] {s['why']}. Evidence: {cite}.")
        sev = severity(risk)
        actions = []
        if risk >= 0.80:
            actions.append(f"Disable account(s) {', '.join(users)} pending investigation")
        for s in chain:
            actions.append(ACTIONS[s["stage"]].format(users=", ".join(users), ips=", ".join(ips) or "n/a",
                                                      devices=", ".join(devices), dests=", ".join(dests) or "n/a"))
        edges, kinds = set(), {}
        for f in cluster:
            for kind, val in (("device", f["device"]), ("ip", f["ip"]), ("app", f["app"])):
                edges.add((f["user"], val)); kinds[val] = kind
            kinds[f["user"]] = "user"
        alerts.append(dict(
            severity=sev, risk=risk, users=users, devices=devices, ips=ips, apps=apps,
            start=st_out[0]["first_ts"], end=max(s["last_ts"] for s in st_out),
            stages=st_out,
            headline=f"{sev} multi-stage intrusion involving {', '.join(users)}: "
                     + " -> ".join(s["stage"] for s in chain),
            narrative=narrative,
            why_flagged=(f"{len(chain)} kill-chain stages linked through shared entities, in chronological order. "
                         f"Each stage is individually weak; risk = noisy-OR of stage scores = {risk}. "
                         "Every statement above cites the log IDs it is based on."),
            actions=actions, graph=dict(edges=sorted(edges), kinds=kinds)))

    alerts.sort(key=lambda a: -a["risk"])
    for i, a in enumerate(alerts, 1):
        a["id"] = f"ALERT-{i:02d}"
    report = dict(summary=dict(logs_processed=len(rows), flagged_events=len(flags),
                               alerts=len(alerts), watchlist=len(watch)),
                  alerts=alerts, watchlist=watch)
    if out_json:
        os.makedirs(os.path.dirname(out_json) or ".", exist_ok=True)
        with open(out_json, "w") as fh:
            json.dump(report, fh, indent=2)
    if out_html:
        import report as html_report
        with open(out_html, "w") as fh:
            fh.write(html_report.render(report))
    return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="PS03 Attack Story Builder")
    ap.add_argument("--logs", required=True)
    ap.add_argument("--out", default="outputs/report.json")
    ap.add_argument("--html", default="outputs/report.html")
    a = ap.parse_args()
    rep = run(a.logs, a.out, a.html)
    print(json.dumps(rep["summary"]))
    for al in rep["alerts"]:
        print(f"{al['id']} {al['severity']} risk={al['risk']} {al['headline']}")
