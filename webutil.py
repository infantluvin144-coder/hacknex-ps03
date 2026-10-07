"""Pure-Python helpers used by app.py (no Streamlit import, so they can be unit-tested)."""
import re

from detector import noisy_or


def replay_steps(alert):
    """One step per kill-chain stage: cumulative risk grows as weak signals add up."""
    steps, scores = [], []
    for st in alert["stages"]:
        scores.append(st["score"])
        steps.append(dict(stage=st["stage"], time=st["first_ts"], why=st["why"], score=st["score"],
                          n_events=st["n_events"], evidence=st["evidence"],
                          cumulative_risk=noisy_or(scores),
                          would_alert=len(scores) >= 2 and noisy_or(scores) >= 0.70))
    return steps


def timeline_rows(alert):
    return [dict(Stage=s["stage"], Start=s["first_ts"], End=s["last_ts"], Events=s["n_events"],
                 Score=s["score"], Why=s["why"], Evidence=", ".join(s["evidence"][:5])
                 + (f" (+{s['n_events'] - 5} more)" if s["n_events"] > 5 else ""))
            for s in alert["stages"]]


def alert_table(report):
    return [dict(ID=a["id"], Severity=a["severity"], Risk=a["risk"], Users=", ".join(a["users"]),
                 Stages=" -> ".join(s["stage"] for s in a["stages"]), Start=a["start"], End=a["end"])
            for a in report["alerts"]]


def watchlist_table(report):
    return [dict(Users=", ".join(w["users"]), StagesSeen=" + ".join(w["stages"]), Risk=w["risk"],
                 WhyNotAnAlert=w["suppressed_because"], Evidence=", ".join(w["evidence"][:5]))
            for w in report["watchlist"]]


def answer_question(report, question):
    """Template Q&A over the report. Every answer cites log IDs; no LLM, so no hallucination."""
    q = question.lower()
    m = re.search(r"user\s*0*(\d+)", q)
    target = f"user{int(m.group(1)):02d}" if m else None
    if target is None:
        return ("Ask about a user, for example: *Why did you flag user04?* or *Why was user20 not flagged?* "
                f"Alerts: {', '.join(a['id'] for a in report['alerts']) or 'none'}.")
    for a in report["alerts"]:
        if target in a["users"]:
            lines = [f"**{target} is in {a['id']} ({a['severity']}, risk {a['risk']}).** "
                     f"{len(a['stages'])} linked stages in order: " + " -> ".join(s["stage"] for s in a["stages"]) + "."]
            lines += [f"- {n}" for n in a["narrative"]]
            lines.append(f"**Why it is an attack:** {a['why_flagged']}")
            return "\n".join(lines)
    for w in report["watchlist"]:
        if target in w["users"]:
            return (f"**{target} was NOT raised as an alert.** Seen: {' + '.join(w['stages'])} (risk {w['risk']}). "
                    f"Reason: {w['suppressed_because']}. Evidence: {', '.join(w['evidence'][:5])}.")
    return f"{target} has no suspicious events at all in these logs."
