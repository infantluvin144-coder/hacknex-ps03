"""Self-contained HTML report (no external assets)."""
import math
from html import escape as e

COLORS = {"user": "#2563eb", "device": "#f59e0b", "ip": "#dc2626", "app": "#16a34a"}

CSS = """
body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:0;background:#f1f5f9;color:#0f172a}
header{background:#0f172a;color:#fff;padding:18px 28px}
main{max-width:1100px;margin:0 auto;padding:20px}
.card{background:#fff;border-radius:10px;padding:18px 22px;margin-bottom:20px;box-shadow:0 1px 3px #0002}
.sev{display:inline-block;padding:2px 10px;border-radius:99px;color:#fff;font-weight:700;font-size:12px}
.CRITICAL{background:#b91c1c}.HIGH{background:#ea580c}.MEDIUM{background:#ca8a04}
.bar{height:10px;background:#e2e8f0;border-radius:6px;overflow:hidden;width:240px;display:inline-block}
.bar i{display:block;height:100%;background:linear-gradient(90deg,#f59e0b,#dc2626)}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border-bottom:1px solid #e2e8f0;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#f8fafc}code{background:#f1f5f9;padding:1px 4px;border-radius:4px;font-size:12px}
.chip{display:inline-block;background:#e2e8f0;border-radius:6px;padding:1px 7px;margin:1px;font-size:12px}
.row{display:flex;gap:20px;flex-wrap:wrap}.muted{color:#64748b;font-size:13px}
"""


def graph_svg(g):
    edges, kinds = g["edges"], g["kinds"]
    nodes = sorted(kinds)
    pos = {}
    for i, n in enumerate(nodes):
        a = 2 * math.pi * i / max(1, len(nodes))
        pos[n] = (190 + 130 * math.cos(a), 135 + 100 * math.sin(a))
    s = ['<svg width="380" height="270" style="background:#f8fafc;border-radius:8px">']
    for u, v in edges:
        s.append(f'<line x1="{pos[u][0]:.0f}" y1="{pos[u][1]:.0f}" x2="{pos[v][0]:.0f}" y2="{pos[v][1]:.0f}" stroke="#94a3b8"/>')
    for n in nodes:
        x, y = pos[n]
        s.append(f'<circle cx="{x:.0f}" cy="{y:.0f}" r="7" fill="{COLORS[kinds[n]]}"/>'
                 f'<text x="{x:.0f}" y="{y - 10:.0f}" font-size="9" text-anchor="middle">{e(n)}</text>')
    s.append("</svg>")
    legend = " ".join(f'<span class="chip" style="border-left:8px solid {c}">{k}</span>' for k, c in COLORS.items())
    return "".join(s) + f"<div>{legend}</div>"


def render(rep):
    s = rep["summary"]
    h = [f"<html><head><meta charset='utf-8'><title>Attack Story Report</title><style>{CSS}</style></head><body>",
         "<header><h2 style='margin:0'>Attack Story Builder - Incident Report</h2>"
         f"<div class='muted' style='color:#cbd5e1'>{s['logs_processed']:,} logs processed - "
         f"{s['flagged_events']} suspicious events - <b>{s['alerts']} alerts</b> - "
         f"{s['watchlist']} watch-listed (suppressed)</div></header><main>"]
    if not rep["alerts"]:
        h.append("<div class='card'><h3>No attacks detected</h3><p class='muted'>Every suspicious event was "
                 "isolated (single stage) or below the risk threshold, so no alert was raised.</p></div>")
    for a in rep["alerts"]:
        h.append(f"<div class='card'><h3>{a['id']} <span class='sev {a['severity']}'>{a['severity']}</span> "
                 f"{e(a['headline'])}</h3>")
        h.append(f"<div>Risk <b>{a['risk']}</b> <span class='bar'><i style='width:{int(a['risk'] * 100)}%'></i></span>"
                 f" &nbsp; <span class='muted'>{a['start']} &rarr; {a['end']}</span></div>")
        chips = lambda lab, xs: f"<div><b>{lab}:</b> " + " ".join(f"<span class='chip'>{e(x)}</span>" for x in xs) + "</div>"
        h.append("<div class='row'><div>" + chips("Users", a["users"]) + chips("Devices", a["devices"]) +
                 chips("External IPs", a["ips"]) + chips("Apps", a["apps"]) + "</div><div>" + graph_svg(a["graph"]) + "</div></div>")
        h.append("<h4>Attack timeline &amp; proof</h4><table><tr><th>Stage</th><th>Time window</th><th>Events</th>"
                 "<th>Score</th><th>Why</th><th>Evidence (log IDs)</th></tr>")
        for st in a["stages"]:
            ev = ", ".join(f"<code>{x}</code>" for x in st["evidence"][:5]) + (f" +{st['n_events'] - 5} more" if st["n_events"] > 5 else "")
            h.append(f"<tr><td><b>{st['stage']}</b></td><td>{st['first_ts']}<br>{st['last_ts']}</td><td>{st['n_events']}</td>"
                     f"<td>{st['score']}</td><td>{e(st['why'])}</td><td>{ev}</td></tr>")
        h.append("</table><h4>Sample raw log lines</h4><table><tr><th>log_id</th><th>timestamp</th><th>user</th><th>device</th><th>ip</th><th>action</th><th>object / dest</th></tr>")
        for st in a["stages"]:
            for r in st["sample_rows"]:
                h.append("<tr>" + "".join(f"<td>{e(str(r[k]))}</td>" for k in
                         ("log_id", "timestamp", "user", "device", "ip", "action", "object")) + "</tr>")
        h.append("</table><h4>Narrative (every line cites log IDs)</h4><ul>" +
                 "".join(f"<li>{e(n)}</li>" for n in a["narrative"]) + "</ul>")
        h.append(f"<h4>Why this is an attack</h4><p>{e(a['why_flagged'])}</p>")
        h.append("<h4>Recommended actions</h4><ol>" + "".join(f"<li>{e(x)}</li>" for x in a["actions"]) + "</ol></div>")
    if rep["watchlist"]:
        h.append("<div class='card'><h3>Watch-list (suppressed - NOT alerts)</h3><table><tr><th>Users</th><th>Stages seen</th>"
                 "<th>Risk</th><th>Why suppressed</th></tr>")
        for w in rep["watchlist"]:
            h.append(f"<tr><td>{e(', '.join(w['users']))}</td><td>{e(' + '.join(w['stages']))}</td><td>{w['risk']}</td>"
                     f"<td>{e(w['suppressed_because'])}</td></tr>")
        h.append("</table></div>")
    h.append("</main></body></html>")
    return "".join(h)
