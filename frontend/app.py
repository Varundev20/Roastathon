"""Node Sentinel - Streamlit dashboard (frontend).

Run from the repository root:  streamlit run frontend/app.py
The dark theme lives in .streamlit/config.toml (also at the repository root).
"""
import sys
from pathlib import Path

# Streamlit only puts frontend/ on the import path; add the repository root
# so the backend/ and agent/ packages can be imported.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import altair as alt  # noqa: E402
import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from agent import investigator  # noqa: E402
from backend import config, evaluation, storage  # noqa: E402
from backend.data_loader import DataLoadError, list_datasets, load_flows  # noqa: E402
from backend.detector import detect  # noqa: E402

st.set_page_config(page_title="Node Sentinel", page_icon="🛡️", layout="wide")

# Colours match the dark theme in .streamlit/config.toml.
TEXT = "#ECEAE4"
RED = "#E24B4A"
GREEN = "#639922"
BLUE = "#378ADD"
BLUE_LIGHT = "#85B7EB"

st.markdown("""
<style>
.block-container {padding-top: 1.6rem; max-width: 1250px;}
.ns-badge {display:inline-block; padding:3px 10px; border-radius:8px; font-size:0.8rem; margin-left:6px;}
.ns-ok {background:#173404; color:#C0DD97;}
.ns-info {background:#0C2A4A; color:#B5D4F4;}
.ns-warn {background:#412402; color:#FAC775;}
.ns-bad {background:#501313; color:#F7C1C1;}
.ns-muted {color:#9A9993; font-size:0.85rem;}
.ns-summary {font-family: Georgia, serif; font-size:1.08rem; line-height:1.6; color:#ECEAE4;}
div[data-testid="stMetric"] {background:#1B1F27; border:1px solid #2A2F3A; border-radius:10px; padding:10px 14px;}
div[data-testid="stVerticalBlockBorderWrapper"] {border-color:#2A2F3A !important;}
</style>""", unsafe_allow_html=True)

RULES = {  # rule -> (icon, label, unit of the measured value)
    "connection_burst": ("👥", "Connection burst", "connections per minute"),
    "port_spread": ("🚪", "Port spread", "service ports (<1024) per minute"),
}


def badge(text: str, kind: str = "info") -> str:
    return f'<span class="ns-badge ns-{kind}">{text}</span>'


def over(alert) -> float:
    """How many times over its threshold an alert is."""
    return alert.measured_value / alert.threshold


def bullet_list(items) -> str:
    return "\n".join(f"- {x}" for x in items)


# --- Header -------------------------------------------------------------------

status = investigator.model_status()
hosted = status["provider"] == "gemini"
ai_name = "Gemini" if hosted else "local AI"
datasets = list_datasets(config.SAMPLE_DIR, config.INPUT_DIR)
if not datasets:
    st.error(f"No CSV files found in {config.SAMPLE_DIR} or {config.INPUT_DIR}.")
    st.stop()
names = list(datasets)

left, right = st.columns([3, 2], vertical_alignment="center")
with left:
    st.markdown("## 🛡️ Node Sentinel")
    st.markdown(f'<span class="ns-muted">Rules spot unusual traffic. {"Gemini" if hosted else "A local AI"} '
                'explains it.</span>', unsafe_allow_html=True)
with right:
    if hosted:
        runtime = badge(f"☁️ {config.GEMINI_MODEL} · Gemini API", "ok") if status["running"] \
            else badge("GEMINI_API_KEY not set · fallback mode", "warn")
        privacy = badge("🔒 Only alert summaries are sent", "info")
    else:
        runtime = badge(f"🖥️ {config.OLLAMA_MODEL} · local", "ok") if status["running"] \
            else badge("Local model offline · fallback mode", "warn")
        privacy = badge("🔒 No cloud calls", "info")
    st.markdown(f'<div style="text-align:right">{runtime}{privacy}</div>', unsafe_allow_html=True)

with st.container(border=True):
    c1, c2, c3 = st.columns([3, 1.2, 2], vertical_alignment="bottom")
    default = "sample_data/portscan_sample.csv"
    dataset = c1.selectbox("Traffic file", names, index=names.index(default) if default in names else 0,
                           help="data/sample_data/ ships with the repo. Full CICIDS2017 files are listed if "
                                "NODE_SENTINEL_INPUT_DIR points at them (large files take a minute).")
    run = c2.button("▶ Run detection", type="primary", width="stretch")
    if hosted:
        choices = status["models"]
    else:
        choices = [m for m in config.FALLBACK_MODELS if m in status["models"]] or status["models"] \
            or [config.OLLAMA_MODEL]
    default_model = config.default_model()
    model = c3.selectbox("AI model" if hosted else "Local model", choices,
                         index=choices.index(default_model) if default_model in choices else 0)

if run:
    with st.spinner("Loading flows and running rules..."):
        try:
            flows, report = load_flows(datasets[dataset], name=dataset)
            new_alerts = detect(flows)
            storage.save_analysis(dataset, flows, new_alerts, report.__dict__)
            st.session_state.pop("selected", None)
            st.toast(f"Detection complete: {len(new_alerts)} alert(s) in {report.rows_kept:,} flows", icon="🛡️")
        except DataLoadError as exc:
            st.error(f"Couldn't load that file. {exc}")

info = storage.get_dataset_info(dataset)
if info is None:
    st.markdown("### How it works")
    for col, (icon, title, text) in zip(st.columns(3), [
        ("📄", "1 · Load traffic", "Read network flow records from a CSV file."),
        ("🚨", "2 · Rules flag", "Two transparent rules check every source, minute by minute."),
        ("🧠", "3 · AI explains", f"{'Gemini' if hosted else 'A local model'} investigates with read-only tools."),
    ]):
        with col.container(border=True):
            st.markdown(f"### {icon}\n**{title}**\n\n{text}")
    st.info("Choose a traffic file and press **Run detection**.")
    st.stop()

alerts = storage.list_alerts(dataset)
by_id = {a.alert_id: a for a in alerts}
per_window = storage.flows_per_window(dataset)

tab_overview, tab_investigate, tab_accuracy = st.tabs(["📊 Overview", "🔍 Investigate", "🎯 Accuracy"])

# --- Overview -------------------------------------------------------------------

with tab_overview:
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Flows analysed", f"{info['rows_kept']:,}")
    m2.metric("Alerts", len(alerts))
    m3.metric("Needing review", sum(a.status != "reviewed" for a in alerts))
    if not per_window.empty:
        times = pd.to_datetime(per_window["window_start"])
        minutes = int((times.max() - times.min()).total_seconds() // 60) + 1
        m4.metric("Time span", f"{minutes} min", help=f"{times.min():%Y-%m-%d %H:%M}–{times.max():%H:%M}")

        with st.container(border=True):
            st.markdown("**Flows per minute** <span class='ns-muted'>· red bands = alert windows</span>",
                        unsafe_allow_html=True)
            area = alt.Chart(per_window.assign(window_start=times)).mark_area(
                line={"color": BLUE_LIGHT}, color=BLUE, opacity=0.25).encode(
                x=alt.X("window_start:T", title="Time (24 h)", axis=alt.Axis(format="%H:%M")),
                y=alt.Y("flows:Q", title="Flows"),
                tooltip=[alt.Tooltip("window_start:T", format="%H:%M"), "flows"])
            layers = [area]
            if alerts:
                bands = pd.DataFrame([{
                    "start": pd.to_datetime(a.window_start), "end": pd.to_datetime(a.window_end),
                    "alert": f"{RULES[a.rule_name][1]} · {a.source}"} for a in alerts])
                layers.insert(0, alt.Chart(bands).mark_rect(color=RED, opacity=0.22).encode(
                    x="start:T", x2="end:T", tooltip=["alert"]))
            st.altair_chart(alt.layer(*layers).properties(height=260), width="stretch")

    load_report = info["load_report"]
    for note in load_report.get("assumptions", []):
        st.caption(f"Assumption: {note}")
    if load_report.get("dropped"):
        st.caption(f"Dropped rows: {load_report['dropped']}")

# --- Investigate ----------------------------------------------------------------

with tab_investigate:
    if not alerts:
        st.success("✅ No alerts. No source crossed a rule threshold in this file.")
    else:
        if st.session_state.get("selected") not in by_id:
            st.session_state.selected = max(alerts, key=over).alert_id
        list_col, detail_col = st.columns([1, 2.2])

        with list_col:
            st.markdown("**Alerts** <span class='ns-muted'>· most severe first</span>", unsafe_allow_html=True)
            for a in sorted(alerts, key=over, reverse=True):
                icon, label, _ = RULES[a.rule_name]
                reviewed = badge("reviewed", "ok") if a.status == "reviewed" else ""
                with st.container(border=True):
                    st.markdown(f"{icon} **{label}** {badge(f'{over(a):.1f}× over', 'bad' if over(a) >= 3 else 'warn')}"
                                f"{reviewed}<br><span class='ns-muted'>{a.source} · "
                                f"{a.window_start[11:16]}–{a.window_end[11:16]}</span>", unsafe_allow_html=True)
                    selected = st.session_state.selected == a.alert_id
                    if st.button("Selected" if selected else "Open", key=f"open{a.alert_id}",
                                 type="primary" if selected else "secondary", width="stretch"):
                        st.session_state.selected = a.alert_id
                        st.rerun()

        alert = by_id[st.session_state.selected]
        icon, label, unit = RULES[alert.rule_name]
        with detail_col:
            with st.container(border=True):
                st.markdown(f"#### {icon} {label} · `{alert.source}`")
                st.markdown(f"<span class='ns-muted'>{config.RULE_DESCRIPTIONS[alert.rule_name]}</span>",
                            unsafe_allow_html=True)

                # Gauge: allowed vs measured, with the threshold as a dashed line.
                gauge = pd.DataFrame([
                    {"what": "Allowed", "value": alert.threshold, "color": GREEN},
                    {"what": "Measured", "value": alert.measured_value, "color": RED},
                ])
                bars = alt.Chart(gauge).mark_bar(size=22, cornerRadiusEnd=6).encode(
                    x=alt.X("value:Q", title=unit,
                            scale=alt.Scale(domain=[0, max(alert.measured_value, alert.threshold) * 1.15])),
                    y=alt.Y("what:N", title=None, sort=["Allowed", "Measured"]),
                    color=alt.Color("color:N", scale=None), tooltip=["what", "value"])
                values = bars.mark_text(align="left", dx=6, fontSize=13, fontWeight="bold").encode(
                    text=alt.Text("value:Q", format=","), color=alt.value(TEXT))
                limit = alt.Chart(pd.DataFrame([{"t": alert.threshold}])).mark_rule(
                    color=TEXT, strokeDash=[4, 3], strokeWidth=1.5).encode(x="t:Q")
                st.altair_chart((bars + limit + values).properties(height=110), width="stretch")

                st.markdown(f"**{alert.measured_value:,}** measured vs **{alert.threshold:,}** allowed → "
                            f"{badge(f'{over(alert):.1f}× over', 'bad')} "
                            f"<span class='ns-muted'>over {alert.window_count} minute(s), "
                            f"{alert.window_start[11:16]}–{alert.window_end[11:16]}</span>", unsafe_allow_html=True)
                with st.expander("Per-minute values"):
                    st.dataframe(pd.DataFrame(alert.evidence["per_window"]), hide_index=True, width="stretch")

                b1, b2 = st.columns(2)
                investigate = b1.button(f"✨ Investigate with {ai_name}", type="primary", width="stretch")
                if alert.status != "reviewed":
                    if b2.button("✓ Mark reviewed", width="stretch"):
                        storage.set_alert_status(alert.alert_id, "reviewed")
                        st.rerun()
                else:
                    b2.markdown(badge("✓ Reviewed", "ok"), unsafe_allow_html=True)

            if investigate:
                with st.status(f"Agent is investigating with {model}…", expanded=True) as box:
                    def show_step(call):
                        who = "" if call.requested_by == "model" else " (supplied by the app)"
                        ok = "error" not in call.result
                        box.markdown(f"{'✅' if ok else '⚠️'} `{call.name}({call.arguments.get('alert_id')})`{who}")
                        box.update(label=f"Agent ran `{call.name}` · thinking…")

                    inv = investigator.investigate(alert.alert_id, model=model, on_tool_call=show_step)
                    storage.save_investigation(inv)
                    if inv.status == "ok":
                        box.markdown("🛡️ Guardrails passed: schema, wording, numbers")
                        box.update(label=f"Investigation complete · {inv.duration_seconds}s · "
                                         f"{inv.tokens_per_second} tokens/s", state="complete", expanded=False)
                    else:
                        box.update(label="Model unavailable or answer rejected · showing fallback report",
                                   state="error", expanded=False)

            history = storage.list_investigations(alert.alert_id)
            if not history:
                st.caption("Not investigated yet. " + ("Gemini usually answers in under a minute." if hosted
                           else "The AI takes about a minute on a laptop CPU."))
            else:
                latest = history[0]
                report = latest["report"]
                with st.container(border=True):
                    if latest["status"] == "fallback":
                        head = badge("Fallback report · not AI", "warn")
                        st.markdown(f"**Explanation** {head}", unsafe_allow_html=True)
                        st.warning(f"The model was unavailable or its answer failed validation. "
                                   f"Reason: {latest['error']}")
                    else:
                        conf = str(report.get("confidence", "?")).capitalize()
                        head = badge(f"{conf} confidence · hypothesis, not a verdict", "warn")
                        st.markdown(f"**AI explanation** {head} <span class='ns-muted'>· {latest['model']}, "
                                    f"{latest['duration_seconds']}s, {latest['tokens_per_second']} tokens/s</span>",
                                    unsafe_allow_html=True)
                    st.markdown(f"<div class='ns-summary'>{report.get('summary', '')}</div>", unsafe_allow_html=True)
                    causes, checks = st.columns(2)
                    with causes.container(border=True):
                        st.markdown("**🤔 Possible causes**")
                        st.markdown(bullet_list(report.get("possible_explanations", [])))
                    with checks.container(border=True):
                        st.markdown("**🧭 Check next**")
                        st.markdown(bullet_list(report.get("recommended_checks", [])))
                    with st.expander("📏 Observed evidence and uncertainty"):
                        st.markdown(bullet_list(report.get("observed_evidence", [])))
                        st.caption(f"Uncertainty: {report.get('uncertainty', '')}")
                        st.caption("Missing information: " + "; ".join(report.get("missing_information", [])))
                    with st.expander(f"🛠️ Agent steps ({len(latest['tool_calls'])} tool calls)"):
                        for tc in latest["tool_calls"]:
                            who = "model" if tc["requested_by"] == "model" else "app (model skipped it)"
                            st.markdown(f"✅ `{tc['name']}({tc['arguments'].get('alert_id')})` "
                                        f"<span class='ns-muted'>requested by {who}</span>", unsafe_allow_html=True)
                            st.json(tc["result"], expanded=False)
                    for w in latest["warnings"]:
                        st.caption(f"Guardrail note: {w}")

                if len(history) > 1:
                    with st.expander(f"Investigation history ({len(history)} runs)"):
                        st.dataframe(pd.DataFrame([{
                            "Run": h["investigation_id"], "Started": h["started_at"], "Model": h["model"],
                            "Status": h["status"], "Seconds": h["duration_seconds"],
                            "Tokens/s": h["tokens_per_second"], "Confidence": h["report"].get("confidence"),
                            "Tools": len(h["tool_calls"]),
                        } for h in history]), hide_index=True, width="stretch")

# --- Accuracy -------------------------------------------------------------------

with tab_accuracy:
    st.caption("Scored against the dataset's ground-truth labels. The AI never sees these labels.")
    result = evaluation.evaluate(dataset, alerts)
    if not result["available"]:
        st.info("This file has no labels.")
    else:
        a1, a2, a3 = st.columns(3)
        a1.metric("Attack flows in file", f"{result['attack_flows']:,}")
        a2.metric("Caught (recall)", "–" if result["recall"] is None else f"{result['recall']:.2%}",
                  help="Share of labelled attack flows that fell inside an alert.")
        a3.metric("Alerts that were real (precision)",
                  "–" if result["precision"] is None else f"{result['precision']:.2%}",
                  help="Share of flows inside alerts that really were attacks.")
        if result["by_label"]:
            with st.container(border=True):
                st.markdown("**By attack type**")
                st.dataframe(pd.DataFrame(result["by_label"]), hide_index=True, width="stretch")
        if result["per_alert"]:
            with st.container(border=True):
                st.markdown("**By alert**")
                st.dataframe(pd.DataFrame(result["per_alert"]), hide_index=True, width="stretch")
