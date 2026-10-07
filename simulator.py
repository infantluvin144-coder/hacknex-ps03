#!/usr/bin/env python3
"""Synthetic log simulator for PS03.

Generates 7 days of enterprise logs for 40 users:
  * benign routine activity
  * "benign-but-weird" cases (must NOT raise an alert)
  * 3 injected multi-stage attacks (A1 insider/stolen-credential USB theft,
    A2 brute force -> priv-esc -> discovery -> exfil, A3 low-and-slow over 4 days)
Ground truth is written to JSON so precision/recall can be measured.
"""
import argparse
import csv
import json
import os
import random
from datetime import datetime, timedelta

START = datetime(2026, 9, 1)
DAYS = 7
DEPTS = ["eng", "fin", "hr", "ops"]
USB_USERS = {3, 10, 17, 25}
ADMINS = {8, 16}
FIELDS = ["log_id", "timestamp", "user", "device", "ip", "geo", "app",
          "action", "object", "status", "bytes", "dest"]
DEFAULT_APP = {"login": "sso", "file_read": "fileserver", "list_share": "fileserver",
               "usb_copy": "endpoint-agent", "upload": "cloud-gateway",
               "priv_escalate": "active-directory"}


def T(d, h, m=0, s=0):
    return START + timedelta(days=d, hours=h, minutes=m, seconds=s)


def gen(seed=42, attacks=True, out_csv="data/logs.csv", out_truth="data/ground_truth.json"):
    rng = random.Random(seed)
    users = {}
    for i in range(40):
        users[f"user{i:02d}"] = dict(i=i, dept=DEPTS[i % 4], dev=f"LAP-{i:02d}",
                                     ip=f"10.0.{i}.{rng.randint(10, 200)}")
    rows = []

    def add(t, user, action, obj="", status="ok", nbytes=0, dest="", ip=None,
            dev=None, geo="IN", app=None):
        u = users[user]
        rows.append(dict(timestamp=t.isoformat(timespec="seconds"), user=user,
                         device=dev or u["dev"], ip=ip or u["ip"], geo=geo,
                         app=app or DEFAULT_APP[action], action=action, object=obj,
                         status=status, bytes=nbytes, dest=dest))

    # ---------------- benign routine ----------------
    for name, u in users.items():
        i = u["i"]
        for d in range(DAYS):
            day = START + timedelta(days=d)
            t0 = day + timedelta(hours=rng.choice([8, 9, 9, 10]), minutes=rng.randint(0, 59))
            if rng.random() < 0.15:
                add(t0 - timedelta(minutes=1), name, "login", status="fail")
            add(t0, name, "login", app=rng.choice(["sso", "vpn"]))
            for _ in range(rng.randint(10, 30)):
                t = day + timedelta(hours=rng.uniform(9, 18))
                r = rng.random()
                folder = u["dept"] if r < 0.93 else ("public" if r < 0.97 else "eng")
                add(t, name, "file_read", f"{folder}/file_{rng.randint(1, 200)}")
            if i in USB_USERS:
                add(day + timedelta(hours=17, minutes=rng.randint(0, 30)), name, "usb_copy",
                    f"{u['dept']}/file_{rng.randint(1, 200)}", nbytes=rng.randint(1, 20) * 1_000_000)
            if i in ADMINS:
                add(day + timedelta(hours=rng.randint(8, 22), minutes=rng.randint(0, 59)),
                    name, "priv_escalate")
                base = day + timedelta(hours=14)
                for k in range(25):
                    add(base + timedelta(seconds=10 * k), name, "list_share", f"shares/dir_{k}")
            if u["dept"] == "eng":
                for _ in range(rng.randint(1, 3)):
                    add(day + timedelta(hours=rng.uniform(10, 17)), name, "upload",
                        nbytes=rng.randint(5, 50) * 1_000_000, dest="140.82.112.3")

    # ---------------- benign-but-weird (must stay quiet) ----------------
    weird = [
        dict(id="W1", user="user20", note="traveller logs in from a new country (1 stage only)"),
        dict(id="W2", user="user21", note="finance user works at 1 AM on familiar finance files"),
        dict(id="W3", user="user22", note="first-ever USB copy, but of a public handbook"),
        dict(id="W4", user="user24", note="engineer uploads 300 MB to a new cloud service"),
        dict(id="W5", user="user26", note="forgot password: 6 failed logins from usual IP, then success"),
        dict(id="W6", user="user28", note="traveller (new country) + first USB copy of a public file"),
        dict(id="W7", user="user30", note="HR user opens one finance file"),
    ]
    for d in (4, 5):
        add(T(d, 10, 5), "user20", "login", geo="US", ip="73.12.5.9", app="vpn")
    for k in range(25):
        add(T(3, 1, k * 2), "user21", "file_read", f"fin/file_{rng.randint(1, 200)}")
    add(T(5, 17, 40), "user22", "usb_copy", "public/handbook.pdf", nbytes=2_000_000)
    add(T(5, 15, 0), "user24", "upload", nbytes=300_000_000, dest="52.95.110.1")
    for k in range(6):
        add(T(4, 8, k), "user26", "login", status="fail")
    add(T(4, 8, 10), "user26", "login")
    add(T(5, 9, 30), "user28", "login", geo="DE", ip="88.198.4.7", app="vpn")
    add(T(5, 16, 45), "user28", "usb_copy", "public/slides.pdf", nbytes=8_000_000)
    add(T(5, 11, 15), "user30", "file_read", "fin/file_77")

    truth = {"attacks": [], "benign_weird": weird}

    # ---------------- injected attacks ----------------
    if attacks:
        # A1: stolen credentials -> bulk read of sensitive files -> USB copy
        a, ip, dev = "user04", "185.220.101.4", "UNK-7731"
        add(T(4, 2, 10), a, "login", ip=ip, dev=dev, geo="RO", app="vpn")
        for k in range(15):
            add(T(4, 2, 20, 30 * k), a, "file_read", f"{'fin' if k % 2 else 'hr'}/records_{k}",
                ip=ip, dev=dev, geo="RO")
        for k in range(12):
            add(T(4, 2, 55, 30 * k), a, "usb_copy", f"fin/payroll_{k}", nbytes=15_000_000,
                ip=ip, dev=dev, geo="RO")
        truth["attacks"].append(dict(id="A1", user=a, start=T(4, 2, 10).isoformat(),
                                     stages=["Initial Access", "Collection", "Exfiltration"]))

        # A2: brute force -> priv-esc -> share discovery -> big upload
        a, ip, dev = "user13", "203.0.113.77", "UNK-5521"
        for k in range(8):
            add(T(5, 2, 50, 75 * k), a, "login", status="fail", ip=ip, dev=dev, geo="NG")
        add(T(5, 3, 1), a, "login", ip=ip, dev=dev, geo="NG")
        add(T(5, 3, 5), a, "priv_escalate", ip=ip, dev=dev, geo="NG")
        for k in range(45):
            add(T(5, 3, 10, 6 * k), a, "list_share", f"shares/dir_{k}", ip=ip, dev=dev, geo="NG")
        add(T(5, 3, 30), a, "upload", nbytes=800_000_000, dest="198.51.100.9",
            ip=ip, dev=dev, geo="NG")
        truth["attacks"].append(dict(id="A2", user=a, start=T(5, 2, 50).isoformat(),
                                     stages=["Initial Access", "Privilege Escalation",
                                             "Discovery", "Exfiltration"]))

        # A3: low-and-slow over ~4 days, every step looks small on its own
        a, ip = "user07", "91.108.4.20"
        add(T(2, 14, 5), a, "login", ip=ip, geo="BR", app="vpn")
        add(T(3, 16, 20), a, "file_read", "fin/payroll_2026.xlsx", ip=ip, geo="BR")
        add(T(4, 22, 30), a, "file_read", "hr/salaries.csv", ip=ip, geo="BR")
        add(T(5, 1, 10), a, "upload", nbytes=20_000_000, dest="45.9.148.22", ip=ip, geo="BR")
        truth["attacks"].append(dict(id="A3", user=a, start=T(2, 14, 5).isoformat(),
                                     stages=["Initial Access", "Collection", "Exfiltration"]))

    rows.sort(key=lambda r: r["timestamp"])
    for n, r in enumerate(rows, 1):
        r["log_id"] = f"L{n:06d}"
    os.makedirs(os.path.dirname(out_csv) or ".", exist_ok=True)
    with open(out_csv, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    with open(out_truth, "w") as fh:
        json.dump(truth, fh, indent=2)
    return len(rows)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--no-attacks", action="store_true", help="benign + benign-but-weird only")
    ap.add_argument("--out", default="data/logs.csv")
    ap.add_argument("--truth", default="data/ground_truth.json")
    a = ap.parse_args()
    print("wrote", gen(a.seed, not a.no_attacks, a.out, a.truth), "log lines ->", a.out)
