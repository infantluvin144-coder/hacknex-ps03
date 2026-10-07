"""Attack Story Builder - web dashboard.   Run:  streamlit run app.py"""
import os
import tempfile

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

import detector
import report as html_report
import simulator
import webutil

try:
    import plotly.express as px
except Exception:           # plotly is optional; fall back to a table
    px = None

st.set_page_config(page_title="Attack Story Builder", page_icon="🛡️", layout="wide")
st.title("🛡️ Attack Story Builder")
st.caption("Logs in, attack story out. Every claim carries log-line proof. Single odd events never raise an alert.")

os.makedirs("data", exist_ok=True)

# ---------------- sidebar: data source ----------------
st.sidebar.header("1. Choose logs")
source = st.sidebar.radio("Data source", ["Demo: logs with attacks", "Demo: clean logs (should give 0 alerts)",
                                          "Upload my own CSV"])
path = None
if source.startswith("Demo: logs"):
    path = "data/attack_logs.csv"
    if not os.path.exists(path):
        simulator.gen(42, True, path, "data/ground_truth.json")
elif source.startswith("Demo: clean"):
    path = "data/clean_logs.csv"
    if not os.path.exists(path):
        simulator.gen(42, False, path, "data/ground_truth_clean.json")
else:
    up = st.sidebar.file_uploader("CSV with columns: log_id,timestamp,user,device,ip,geo,app,action,object,status,bytes,dest", type="csv")
    if up is not None:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".csv")
        tmp.write(up.getvalue())
        tmp.close()
        path = tmp.name

st.sidebar.header("2. Analyse")
go = st.sidebar.button("Analyze logs", type="primary")
if go and path:
    try:
        with st.spinner("Building baselines, linking events, scoring risk..."):
            st.session_state["report"] = detector.run(path)
            st.session_state["source"] = source
    except Exception as exc:
        st.sidebar.error(f"Could not analyse this file: {exc}")
elif go:
    st.sidebar.warning("Upload a CSV first.")

page = st.sidebar.radio("Page", ["Overview", "Attack Story", "Attack Replay", "Why NOT flagged", "Ask the Analyst"])

rep = st.session_state.get("report")
if rep is None:
    st.info("👈 Pick a data source and click **Analyze logs**. Start with the clean logs (0 alerts), then the attack logs.")
    st.stop()

st.sidebar.success(f"Showing: {st.session_state['source']}")

# ---------------- pages ----------------
if page == "Overview":
    s = rep["summary"]
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Logs processed", f"{s['logs_processed']:,}")
    c2.metric("Suspicious events", s["flagged_events"])
    c3.metric("🚨 Alerts", s["alerts"])
    c4.metric("Watch-listed (suppressed)", s["watchlist"])
    if not rep["alerts"]:
        st.success("No attack chains found. Every odd event was isolated (single stage) or below the risk threshold.")
    else:
        df = pd.DataFrame(webutil.alert_table(rep))
        st.subheader("Alerts")
        st.dataframe(df, use_container_width=True, hide_index=True)
        if px is not None:
            fig = px.bar(df, x="ID", y="Risk", color="Severity", hover_data=["Users", "Stages"],
                         color_discrete_map={"CRITICAL": "#b91c1c", "HIGH": "#ea580c", "MEDIUM": "#ca8a04"},
                         range_y=[0, 1])
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.bar_chart(df.set_index("ID")["Risk"])
    with st.expander("How alerting works"):
        st.markdown("An alert needs **>= 2 kill-chain stages**, linked through a shared user or external IP, "
                    f"in **chronological order**, with combined risk **>= {detector.RISK_ALERT}** "
                    "(noisy-OR of stage scores).")

elif page == "Attack Story":
    if not rep["alerts"]:
        st.success("No alerts to show.")
        st.stop()
    pick = st.selectbox("Alert", [f"{a['id']} - {a['severity']} - {', '.join(a['users'])}" for a in rep["alerts"]])
    a = rep["alerts"][[f"{x['id']} - {x['severity']} - {', '.join(x['users'])}" for x in rep["alerts"]].index(pick)]
    st.subheader(a["headline"])
    c1, c2 = st.columns([1, 2])
    c1.metric("Risk", a["risk"])
    c1.progress(min(1.0, a["risk"]))
    c1.write(f"**Window:** {a['start']} → {a['end']}")
    c1.write(f"**Users:** {', '.join(a['users'])}")
    c1.write(f"**Devices:** {', '.join(a['devices'])}")
    c1.write(f"**External IPs:** {', '.join(a['ips']) or '-'}")
    c1.write(f"**Apps:** {', '.join(a['apps'])}")
    with c2:
        components.html(html_report.graph_svg(a["graph"]), height=320)
    st.markdown("#### Attack timeline and proof")
    st.dataframe(pd.DataFrame(webutil.timeline_rows(a)), use_container_width=True, hide_index=True)
    st.markdown("#### Raw log lines behind each stage")
    sample = [dict(Stage=s["stage"], **r) for s in a["stages"] for r in s["sample_rows"]]
    st.dataframe(pd.DataFrame(sample), use_container_width=True, hide_index=True)
    st.markdown("#### Narrative (every line cites log IDs)")
    for n in a["narrative"]:
        st.markdown(f"- {n}")
    st.markdown("#### Why this is an attack")
    st.write(a["why_flagged"])
    st.markdown("#### Recommended actions")
    for i, act in enumerate(a["actions"], 1):
        st.markdown(f"{i}. {act}")
    st.download_button("Download this alert (JSON)", data=pd.Series(a).to_json(indent=2),
                       file_name=f"{a['id']}.json", mime="application/json")

elif page == "Attack Replay":
    if not rep["alerts"]:
        st.success("No alerts to replay.")
        st.stop()
    labels = [f"{x['id']} - {', '.join(x['users'])}" for x in rep["alerts"]]
    a = rep["alerts"][labels.index(st.selectbox("Alert to replay", labels))]
    steps = webutil.replay_steps(a)
    st.caption("Drag the slider: watch weak signals add up until the system is sure it is an attack.")
    k = st.slider("Step", 1, len(steps), 1)
    cur = steps[k - 1]
    st.metric("Combined risk so far", cur["cumulative_risk"])
    st.progress(min(1.0, cur["cumulative_risk"]))
    if cur["would_alert"]:
        st.error(f"🚨 ALERT RAISED at this point: {k} linked stages and risk ≥ {detector.RISK_ALERT}")
    else:
        st.warning("Not an alert yet: one odd event alone is never enough." if k == 1
                   else "Still below the alert threshold, watching...")
    for i, s in enumerate(steps[:k], 1):
        st.markdown(f"**Step {i} · {s['stage']}** · `{s['time']}` · score {s['score']} · {s['n_events']} event(s)  \n"
                    f"{s['why']}  \nProof: {', '.join(s['evidence'][:4])}")

elif page == "Why NOT flagged":
    st.subheader("Suspicious but NOT alerts (false-positive control)")
    st.caption("These events looked odd, but a lone odd event or a low combined risk is not an attack.")
    if rep["watchlist"]:
        st.dataframe(pd.DataFrame(webutil.watchlist_table(rep)), use_container_width=True, hide_index=True)
    else:
        st.info("Nothing was watch-listed.")

elif page == "Ask the Analyst":
    st.subheader("Ask the Analyst")
    st.caption("Template-based answers built only from the report, so every answer cites log IDs.")
    q = st.text_input("Question", placeholder="Why did you flag user04?   /   Why was user20 not flagged?")
    if q:
        st.markdown(webutil.answer_question(rep, q))
