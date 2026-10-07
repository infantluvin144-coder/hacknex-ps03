# Attack Story Builder — HackNex 2026 PS03 (AI-Powered Cyber Threat Intelligence)

## What the project does
Takes raw security logs (logins, file access, share listing, USB, uploads, privilege changes) and
reconstructs **multi-stage attacks**: attack timeline, entities involved (users, devices, IPs, apps),
kill-chain stages, **log-line proof for every stage**, risk score, and recommended actions.
Single odd events are never alerts — they go to a *watch-list*, which is how false positives are controlled.

## Pipeline (data → decision)
```
Logs (CSV) → normalise → per-user baselines (learn-only warm-up)
          → stage-tagged suspicious events (rules + rarity vs. baseline)
          → entity linking (shared user / external IP, 48 h gap window)
          → kill-chain order check (longest chronologically ordered stage chain)
          → risk = noisy-OR of stage scores → ALERT only if ≥2 stages AND risk ≥ 0.70
          → report.json + report.html (timeline, graph, evidence, actions)
```
Schema: `log_id, timestamp, user, device, ip, geo, app, action, object, status, bytes, dest`

## Core model / reasoning
* **Baselines** per user: known geos, IPs, devices, folders, USB usage, upload destinations, privilege use, share-listing behaviour. First 2 days are learn-only. Flagged events never update the baseline (an attacker cannot "become normal").
* **Stages** (MITRE-ATT&CK style): Initial Access (new geo/device, brute force), Privilege Escalation, Discovery (share enumeration burst), Collection (first access to sensitive folders, bursts), Exfiltration (first USB copy, upload to never-seen destination, large size).
* **Chaining**: flagged events are linked via shared user or external IP, split on >48 h silence (supports low-and-slow), and kept only if stages follow kill-chain order in time.
* **False-positive control**: ≥2 stages + risk ≥ 0.70. Explainable scores, no black box.

## ML second opinion (Isolation Forest)
Rules decide and explain every alert. On top, an Isolation Forest scores each
user-day against **that user's own normal** (12 features: new geo/device,
off-hours, sensitive reads, USB, uploads, privilege changes...).

| Rules say | ML says | Result |
|---|---|---|
| Alert | Unusual | **CONFIRMED** (higher trust) |
| Alert | Normal | RULES-ONLY |
| No alert | Unusual | ML-ONLY: watch-list, **never an alert** |

On our test logs all 3 attacks are CONFIRMED. ML never raises an alert alone,
so false-alarm control is unchanged.

Run: `python3 ml_layer.py --logs data/attack_logs.csv`

**Limit:** the top 3% percentile is fixed, so clean logs also show a few
ML-only watch-list rows (no alerts). Tuned on self-generated data only.

## Evidence & explanation
Every stage lists its `log_id`s, the reason string, and its score; sample raw log lines are embedded; the narrative
cites log IDs in every sentence. See `outputs/report_attack.html`.

## Technologies
Core detection: Python 3.9+ standard library only (rule-based, explainable). ML second opinion: scikit-learn (Isolation Forest, trained on the input logs themselves, no pre-trained models). Web dashboard: Streamlit + pandas (+ optional Plotly). No external APIs or external datasets.


## Install, configure, run
```bash
git clone https://github.com/infantluvin144-coder/hacknex-ps03.git && cd hacknex-ps03
pip install -r requirements.txt      # only needed for the web app
streamlit run app.py                 # web dashboard at http://localhost:8501
python evaluate.py                      # generates data, runs detector, prints precision/recall
python ml_layer.py --logs data/attack_logs.csv   # ML second opinion
# or step by step:
python simulator.py --out data/logs.csv
python detector.py --logs data/logs.csv --out outputs/report.json --html outputs/report.html
python simulator.py --no-attacks --out data/clean.csv --truth data/gt_clean.json   # clean-log test
python detector.py --logs data/clean.csv --out outputs/clean.json --html outputs/clean.html
```
Bring your own logs: use a CSV with the schema above. Thresholds are constants at the top of `detector.py`.

## Reproduce demonstrated results
`python evaluate.py` (seed 42) prints and saves `outputs/metrics.json`:

| Dataset | Result |
|---|---|
| 6,499 logs, 3 injected attacks | 3/3 detected, precision 1.00, recall 1.00, 0 false alerts |
| 6,411 clean logs incl. 7 benign-but-weird cases | **0 alerts** |

Injected attacks: **A1** stolen credentials → bulk sensitive reads → USB copy; **A2** brute force → privilege escalation → share discovery → 800 MB upload; **A3** low-and-slow over 4 days.
Benign-but-weird (stay quiet): traveller in a new country, 1 AM work on familiar files, first USB copy of a public file, large upload to a new cloud, forgotten password, traveller + USB (watch-listed, risk 0.67 < 0.70), HR opening one finance file.

## Sample input / output
`docs/sample_input.csv` (excerpt of attack A1 logs) and `docs/sample_output.json` (matching alert).

## Scope note
**MVP implemented:** simulator, baselines, 5-stage tagging, entity-linked ordered chaining, risk score, evidence-cited timeline, HTML+JSON report, graph view, recommended actions, false-positive tests, precision/recall evaluation.
**Stretch NOT implemented (future):** LLM-written narrative (current narrative is template-based so every claim is guaranteed to cite a log ID), Isolation-Forest / GNN for unseen attacks, live streaming dashboard, real public datasets (CERT / LANL).
**Known limitations:** thresholds are hand-tuned on simulated data; real logs would need re-tuning.

## Declared resources
Self-generated synthetic data. No external APIs, pre-trained models or datasets. AI assistance (Claude) was used to help write the code; all team members must be able to explain it.
