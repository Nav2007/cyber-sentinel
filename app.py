"""SentinelAI Streamlit investigation dashboard."""

from __future__ import annotations

from datetime import date, datetime, timezone
from ipaddress import ip_address
from typing import Any

import pandas as pd
import plotly.express as px
import streamlit as st

from detector import analyze_logs
from log_generator import (
    DEFAULT_ATTACK_EPISODES,
    DEFAULT_EVENT_COUNTS,
    LOG_COLUMNS,
    MAX_EVENT_COUNT,
    MIN_DASHBOARD_EVENT_COUNT,
    PERIOD_OPTIONS,
    SCENARIOS,
    generate_logs,
)


SEVERITY_ORDER = ["critical", "high", "medium", "low"]
SEVERITY_COLORS = {"critical": "#bd4a55", "high": "#d47b36", "medium": "#b08b27", "low": "#587765"}
REQUIRED_COLUMNS = LOG_COLUMNS
GENERATOR_VERSION = 2


def validate_logs(raw: pd.DataFrame) -> tuple[pd.DataFrame | None, int, str | None]:
    """Validate an uploaded or generated login table without mutating it."""
    if not isinstance(raw, pd.DataFrame):
        return None, 1, "Input must be a CSV table."
    if raw.columns.duplicated().any():
        return None, len(raw), "Duplicate column names are not allowed."
    missing = [column for column in REQUIRED_COLUMNS if column not in raw.columns]
    if missing:
        return None, len(raw), "Missing required column(s): " + ", ".join(missing)

    clean = raw.loc[:, REQUIRED_COLUMNS].copy()
    stamps = pd.to_datetime(clean["timestamp"], utc=True, errors="coerce")
    clean["timestamp"] = stamps
    for column in ["username", "source_ip", "event_type", "status"]:
        clean[column] = clean[column].astype("string").str.strip()
    clean["username"] = clean["username"].fillna("")
    clean["event_type"] = clean["event_type"].str.lower()
    clean["status"] = clean["status"].str.lower()

    def valid_ip(value: Any) -> bool:
        try:
            ip_address(str(value))
            return True
        except ValueError:
            return False

    valid = (stamps.notna().astype(bool)
             & clean["source_ip"].map(valid_ip).fillna(False).astype(bool)
             & clean["event_type"].eq("login").fillna(False).astype(bool)
             & clean["status"].isin(["success", "failure"]).fillna(False).astype(bool))
    clean = clean.loc[valid].copy()
    clean["timestamp"] = clean["timestamp"].dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    clean = clean.reset_index(drop=True)
    return clean, int(len(raw) - len(clean)), None


@st.cache_data(show_spinner=False, max_entries=8)
def _cached_analysis(logs: pd.DataFrame) -> list[dict[str, Any]]:
    """Cache pure detector output by DataFrame content for rerun efficiency."""
    return analyze_logs(logs)


def get_alerts(logs: pd.DataFrame) -> list[dict[str, Any]]:
    """Single detector integration point; attach source rows for the timeline."""
    alerts = _cached_analysis(logs)
    enriched: list[dict[str, Any]] = []
    for alert in alerts:
        item = dict(alert)
        positions = [int(pos) for pos in item.get("related_event_indices", []) if 0 <= int(pos) < len(logs)]
        events = logs.iloc[positions].copy()
        events["input_row"] = positions
        item["related_event_indices"] = positions
        item["_events"] = events
        item["event_count"] = len(events)
        item["simulated"] = False
        enriched.append(item)
    enriched.sort(key=lambda a: (SEVERITY_ORDER.index(a.get("severity", "low")), -a.get("risk_score", 0), a.get("timestamp", "")))
    return enriched


def filter_alerts(
    alerts: list[dict[str, Any]], *, query: str = "", severities: list[str] | None = None,
    rules: list[str] | None = None, start_date: date | None = None, end_date: date | None = None,
) -> list[dict[str, Any]]:
    """Filter incidents by searchable fields, severity, rule, and date range."""
    # Empty selections mean no restriction. This lets users begin with an
    # unfiltered queue and apply each filter only when they choose values.
    allowed_severities = set(severities) if severities else set(SEVERITY_ORDER)
    allowed_rules = set(rules) if rules else {signal for a in alerts for signal in _alert_rules(a)}
    q = query.strip().casefold()
    result = []
    for alert in alerts:
        if alert.get("severity") not in allowed_severities or not _alert_rules(alert).intersection(allowed_rules):
            continue
        timestamp = pd.to_datetime(alert.get("timestamp"), utc=True, errors="coerce")
        if pd.isna(timestamp):
            continue
        if start_date and timestamp.date() < start_date:
            continue
        if end_date and timestamp.date() > end_date:
            continue
        searchable = " ".join(str(alert.get(key, "")) for key in (
            "id", "timestamp", "rule_name", "signals", "severity", "username", "affected_usernames",
            "source_ip", "evidence", "explanation", "recommended_action",
        )).casefold()
        if q and q not in searchable:
            continue
        result.append(alert)
    return result


def _alert_rules(alert: dict[str, Any]) -> set[str]:
    return {rule for rule in [alert.get("rule_name"), *alert.get("signals", [])] if rule}


def sort_alerts(alerts: list[dict[str, Any]], sort_by: str) -> list[dict[str, Any]]:
    """Return a stable queue ordering without changing the alert objects."""
    if sort_by == "Highest risk":
        key = lambda alert: (-int(alert.get("risk_score", 0)), alert.get("timestamp", ""))
        reverse = False
    elif sort_by == "Severity":
        key = lambda alert: (SEVERITY_ORDER.index(alert.get("severity", "low")), -int(alert.get("risk_score", 0)), alert.get("timestamp", ""))
        reverse = False
    else:
        key = lambda alert: alert.get("timestamp", "")
        reverse = True
    return sorted(alerts, key=key, reverse=reverse)


def dataset_date_bounds(logs: pd.DataFrame) -> tuple[date, date] | None:
    """Return the full UTC date range of valid event timestamps, if available."""
    if logs.empty or "timestamp" not in logs:
        return None
    timestamps = pd.to_datetime(logs["timestamp"], utc=True, errors="coerce").dropna()
    if timestamps.empty:
        return None
    return timestamps.dt.date.min(), timestamps.dt.date.max()


def severity_counts(alerts: list[dict[str, Any]]) -> pd.DataFrame:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for alert in alerts:
        if alert.get("severity") in counts:
            counts[alert["severity"]] += 1
    return pd.DataFrame({"severity": SEVERITY_ORDER, "incidents": [counts[key] for key in SEVERITY_ORDER]})


def _severity_cell_style(value: str) -> str:
    colors = {"Critical": "#a93645", "High": "#ad5b25", "Medium": "#886a13", "Low": "#315f49"}
    return f"color: {colors.get(value, '#29332E')}; font-weight: 600"


def _theme() -> None:
    st.markdown("""
    <style>
    :root { color-scheme: dark; }
    .stApp { background: #15191c; color: #e6eaec; }
    [data-testid="stHeader"] { background: #15191c; }
    [data-testid="stSidebar"] { background: #1b2024; border-right: 1px solid #343b40; }
    [data-testid="stMainBlockContainer"] { padding-top: 1.5rem; padding-bottom: 2rem; max-width: 1500px; }
    body, button, input, textarea { font-family: "DM Sans", "Segoe UI", sans-serif; }
    h1, h2, h3 { color: #f1f3f4; font-family: "Space Grotesk", "Segoe UI", sans-serif; letter-spacing: -.02em; }
    h1 { font-size: 1.8rem !important; font-weight: 600 !important; }
    h2 { font-size: 1.25rem !important; font-weight: 600 !important; }
    h3 { font-size: 1rem !important; font-weight: 600 !important; }
    p, label, [data-testid="stCaptionContainer"] { color: #aab3b8; }
    [data-testid="stMetric"] { background: #1d2327; border: 1px solid #343c41; padding: 10px 13px; border-radius: 4px; }
    [data-testid="stMetricLabel"] { color: #aab3b8 !important; }
    [data-testid="stMetricValue"] { color: #f1f3f4 !important; font-size: 1.65rem !important; }
    [data-testid="stDataFrame"] { border: 1px solid #343c41; border-radius: 3px; }
    [data-testid="stTextInput"] input, [data-testid="stNumberInput"] input { background: #20272b; color: #edf1f2; border-color: #414a50; }
    [data-baseweb="select"] > div { background: #20272b; border-color: #414a50; }
    button[kind="primary"] { background: #147d80; border-color: #147d80; color: white; }
    button[kind="primary"]:hover { background: #199094; border-color: #199094; }
    hr { border-color: #343c41; }
    </style>
    """, unsafe_allow_html=True)


def _evidence_summary(alert: dict[str, Any], limit: int = 120) -> str:
    text = " ".join(str(alert.get("evidence", "")).split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _incident_table(alerts: list[dict[str, Any]], *, height: int = 390) -> None:
    table = pd.DataFrame([{
        "Severity": alert["severity"].title(),
        "Risk": alert["risk_score"],
        "Detection": alert["rule_name"],
        "Source IP": alert["source_ip"],
        "Accounts": alert.get("affected_account_count", 0),
        "Last seen (UTC)": alert["timestamp"],
        "Evidence summary": _evidence_summary(alert),
    } for alert in alerts])
    st.dataframe(
        table.style.map(_severity_cell_style, subset=["Severity"]),
        width="stretch", hide_index=True, height=min(height, 38 + len(table) * 38),
        column_config={
            "Severity": st.column_config.TextColumn(width="small"),
            "Risk": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%d", width="small"),
            "Detection": st.column_config.TextColumn(width="medium"),
            "Source IP": st.column_config.TextColumn(width="small"),
            "Accounts": st.column_config.NumberColumn(width="small"),
            "Last seen (UTC)": st.column_config.TextColumn(width="medium"),
            "Evidence summary": st.column_config.TextColumn(width="large"),
        },
    )


def _open_queue() -> None:
    st.session_state.active_page = "Alert Queue"


def _open_inspect() -> None:
    st.session_state.active_page = "Inspect Alert"


def _mark_event_count_custom() -> None:
    st.session_state.event_count_custom = True
    _clamp_attack_episodes()


def _mark_episode_count_custom() -> None:
    st.session_state.attack_episodes_custom = True


def _scenario_changed() -> None:
    # Scenario widgets invoke this callback before the script recreates widgets,
    # so dependent episode-count state can be safely constrained here.
    _clamp_attack_episodes()
    _regenerate_synthetic_dataset()


def _episode_limit() -> int:
    scenario_label = st.session_state.get("scenario_selector", "Normal activity")
    pattern_max = {"brute_force": 20, "password_spraying": 18, "failed_then_success": 13}.get(
        SCENARIOS.get(scenario_label), 1
    )
    return min(500, max(0, (int(st.session_state.get("event_count", DEFAULT_EVENT_COUNTS[30])) - 1) // pattern_max))


def _clamp_attack_episodes() -> None:
    st.session_state.attack_episodes = min(
        int(st.session_state.get("attack_episodes", DEFAULT_ATTACK_EPISODES[30])), _episode_limit()
    )


def _period_changed() -> None:
    period = int(st.session_state.period_days)
    if not st.session_state.get("event_count_custom", False):
        st.session_state.event_count = DEFAULT_EVENT_COUNTS[period]
    if not st.session_state.get("attack_episodes_custom", False):
        st.session_state.attack_episodes = DEFAULT_ATTACK_EPISODES[period]
    _clamp_attack_episodes()


def _regenerate_synthetic_dataset() -> None:
    """Load the current sidebar scenario/configuration and invalidate UI state."""
    scenario_label = st.session_state.get("scenario_selector", "Normal activity")
    scenario = SCENARIOS.get(scenario_label)
    if scenario is None:
        st.session_state.scenario_error = f"Unknown scenario: {scenario_label}"
        return
    generation_config = (
        GENERATOR_VERSION,
        scenario_label,
        int(st.session_state.get("random_seed", 42)),
        int(st.session_state.get("event_count", DEFAULT_EVENT_COUNTS[30])),
        int(st.session_state.get("period_days", 30)),
        int(st.session_state.get("attack_episodes", DEFAULT_ATTACK_EPISODES[30])),
        st.session_state.get("historical_end_time"),
    )
    if st.session_state.get("synthetic_generation_config") == generation_config:
        st.session_state.scenario_error = ""
        return
    try:
        raw = generate_logs(
            scenario,
            seed=int(st.session_state.get("random_seed", 42)),
            count=int(st.session_state.get("event_count", DEFAULT_EVENT_COUNTS[30])),
            period_days=int(st.session_state.get("period_days", 30)),
            attack_episodes=int(st.session_state.get("attack_episodes", DEFAULT_ATTACK_EPISODES[30])),
            end_time=st.session_state.get("historical_end_time"),
        )
        logs, rejected, error = validate_logs(raw)
        if error:
            st.session_state.scenario_error = error
            return
    except (TypeError, ValueError) as exc:
        st.session_state.scenario_error = str(exc)
        return

    st.session_state.logs = logs
    st.session_state.data_source = f"Synthetic demonstration | {scenario_label} | {st.session_state.period_days}-day period"
    st.session_state.scenario_label = scenario_label
    st.session_state.rejected_rows = rejected
    st.session_state.synthetic_generation_config = generation_config
    st.session_state.dataset_revision = int(st.session_state.get("dataset_revision", 0)) + 1
    st.session_state.selected_alert_id = None
    st.session_state.scenario_error = ""


def _render_monitoring(logs: pd.DataFrame, alerts: list[dict[str, Any]]) -> None:
    st.title("Threat Monitoring")
    critical = sum(alert.get("severity") == "critical" for alert in alerts)
    suspicious_sources = len({alert.get("source_ip") for alert in alerts if alert.get("source_ip")})
    metrics = st.columns(4)
    metrics[0].metric("Events analysed", f"{len(logs):,}")
    metrics[1].metric("Incidents", f"{len(alerts):,}")
    metrics[2].metric("Critical", f"{critical:,}")
    metrics[3].metric("Suspicious sources", f"{suspicious_sources:,}")

    left, right = st.columns([1.65, 1], gap="medium")
    with left:
        st.subheader("Authentication activity")
        if logs.empty:
            st.info("No valid events in the selected dataset.")
        else:
            activity = logs.copy()
            activity["timestamp"] = pd.to_datetime(activity["timestamp"], utc=True)
            span = activity["timestamp"].max() - activity["timestamp"].min()
            bucket = "D" if span >= pd.Timedelta(days=2) else "5min"
            activity["interval"] = activity["timestamp"].dt.floor(bucket)
            volume = activity.groupby(["interval", "status"], as_index=False).size()
            fig = px.line(volume, x="interval", y="size", color="status", markers=True,
                          color_discrete_map={"success": "#39a59c", "failure": "#dc7787"},
                          labels={"interval": "Time (UTC)", "size": "Events", "status": "Outcome"})
            fig.update_layout(template="plotly_dark", height=270, paper_bgcolor="rgba(0,0,0,0)",
                              plot_bgcolor="rgba(0,0,0,0)", font_color="#b8c1c5",
                              margin=dict(l=10, r=10, t=12, b=8), legend_title_text="",
                              legend=dict(orientation="h", y=1.12, x=0))
            fig.update_xaxes(gridcolor="#30383d", zerolinecolor="#30383d")
            fig.update_yaxes(gridcolor="#30383d", zerolinecolor="#30383d")
            if bucket == "D":
                fig.update_xaxes(tickformat="%b %d", nticks=8)
            st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})
    with right:
        st.subheader("Incident severity")
        counts = severity_counts(alerts)
        fig = px.bar(counts, x="incidents", y="severity", orientation="h", text="incidents",
                     color="severity", color_discrete_map=SEVERITY_COLORS,
                     category_orders={"severity": list(reversed(SEVERITY_ORDER))},
                     labels={"incidents": "Incidents", "severity": ""})
        fig.update_layout(template="plotly_dark", height=270, paper_bgcolor="rgba(0,0,0,0)",
                          plot_bgcolor="rgba(0,0,0,0)", font_color="#b8c1c5",
                          margin=dict(l=10, r=14, t=12, b=8), showlegend=False)
        fig.update_xaxes(gridcolor="#30383d", zerolinecolor="#30383d", rangemode="tozero")
        fig.update_yaxes(showgrid=False)
        st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})

    st.subheader("Recent incidents")
    if alerts:
        recent = sorted(alerts, key=lambda alert: alert["timestamp"], reverse=True)[:5]
        _incident_table(recent, height=235)
        st.button("Open alert queue", key="monitor_open_queue", on_click=_open_queue)
    else:
        st.info("No incidents matched the configured detection rules.")


def _render_queue(alerts: list[dict[str, Any]], logs: pd.DataFrame, dataset_revision: int) -> None:
    st.title("Alert Queue")
    if not alerts:
        st.caption("0 incidents total · 0 shown")
        st.info("There are no incidents to review for this dataset.")
        return

    search, severity_col, rule_col, sort_col = st.columns([2.2, 1, 1.4, 1.2], gap="small")
    query = search.text_input("Search", placeholder="Rule, IP, account, evidence", key=f"queue_search_{dataset_revision}")
    severities = severity_col.multiselect("Severity", SEVERITY_ORDER, default=[],
                                          key=f"queue_severity_{dataset_revision}")
    rules = sorted({signal for alert in alerts for signal in _alert_rules(alert)})
    selected_rules = rule_col.multiselect("Detection", rules, default=[],
                                          key=f"queue_rules_{dataset_revision}")
    sort_by = sort_col.selectbox("Sort by", ["Newest", "Highest risk", "Severity"],
                                 key=f"queue_sort_{dataset_revision}")
    bounds = dataset_date_bounds(logs)
    if bounds is not None:
        date_range = st.date_input("Detection date (UTC)", value=bounds,
                                   key=f"queue_dates_{dataset_revision}")
        start_date = date_range[0] if isinstance(date_range, (tuple, list)) and date_range else bounds[0]
        end_date = date_range[-1] if isinstance(date_range, (tuple, list)) and len(date_range) > 1 else start_date
    else:
        st.caption("Date range unavailable: this dataset contains no valid event timestamps.")
        start_date = end_date = None
    filtered = filter_alerts(alerts, query=query, severities=severities, rules=selected_rules,
                             start_date=start_date, end_date=end_date)
    filtered = sort_alerts(filtered, sort_by)
    st.caption(f"{len(alerts)} incidents total · {len(filtered)} shown")
    if not filtered:
        st.info("No incidents match the current search and filters.")
        return

    _incident_table(filtered)
    ids = [alert["id"] for alert in filtered]
    selection_key = f"selected_alert_id_{dataset_revision}"
    current = st.session_state.get(selection_key)
    if current not in ids:
        current = ids[0]
    selected = st.selectbox("Selected incident", ids, index=ids.index(current),
                            format_func=lambda incident_id: next(
                                f"{alert['severity'].upper()} · {alert['rule_name']} · {alert['source_ip']} · {alert['timestamp']}"
                                for alert in filtered if alert["id"] == incident_id), key=selection_key)
    st.session_state.selected_alert_id = selected
    st.button("Inspect selected alert", type="primary", key="inspect_from_queue", on_click=_open_inspect)


def _render_inspect(alerts: list[dict[str, Any]], dataset_revision: int) -> None:
    st.title("Inspect Alert")
    if not alerts:
        st.info("No alert details are available. Load a scenario or upload events that produce an incident.")
        return
    ids = [alert["id"] for alert in alerts]
    active_id = st.session_state.get("selected_alert_id")
    if active_id not in ids:
        active_id = st.session_state.get(f"selected_alert_id_{dataset_revision}")
    if active_id not in ids:
        active_id = ids[0]
    selected_id = st.selectbox("Incident", ids, index=ids.index(active_id),
                               format_func=lambda incident_id: next(
                                   f"{alert['rule_name']} · {alert['source_ip']} · {alert['timestamp']}"
                                   for alert in alerts if alert["id"] == incident_id),
                               key=f"inspect_alert_id_{dataset_revision}")
    alert = next(item for item in alerts if item["id"] == selected_id)

    st.subheader(alert["rule_name"])
    st.caption(f"Incident {alert['id']}  ·  {alert['severity'].upper()}  ·  {alert['timestamp']} (UTC)  ·  Risk {alert['risk_score']}/100")
    top_left, top_right = st.columns([1.35, 1], gap="large")
    with top_left:
        st.markdown("#### Explanation")
        st.write(alert["explanation"])
        st.markdown("#### Recommended action")
        st.write(alert["recommended_action"])
    with top_right:
        st.markdown("#### Affected entity")
        accounts = alert.get("affected_usernames", [])
        st.write("**Account(s):** " + (", ".join(accounts) if accounts else "Not provided"))
        st.write(f"**Source IP:** `{alert['source_ip']}`")
        st.write(f"**Observed:** {alert.get('first_seen', alert['timestamp'])} → {alert['timestamp']} (UTC)")
        st.write(f"**Supporting events:** {alert['event_count']}")

    st.markdown("#### Evidence")
    st.write(alert["evidence"])
    if len(alert.get("signals", [])) > 1:
        st.caption("Corroborating rules: " + " · ".join(alert["signals"][1:]))
    st.markdown("#### Supporting events · chronological")
    events = alert["_events"].copy()
    events["timestamp"] = pd.to_datetime(events["timestamp"], utc=True, errors="coerce")
    events = events.sort_values(["timestamp", "input_row"])
    with st.expander(f"View all {len(events)} supporting events", expanded=True):
        st.dataframe(events[["timestamp", "username", "source_ip", "event_type", "status", "input_row"]],
                     width="stretch", hide_index=True, height=min(420, 42 + len(events) * 36),
                     column_config={
                         "timestamp": st.column_config.DatetimeColumn("Timestamp (UTC)", format="YYYY-MM-DD HH:mm:ss UTC"),
                         "input_row": st.column_config.NumberColumn("Input row", help="Zero-based position in the validated dataset"),
                     })


def main() -> None:
    st.set_page_config(page_title="SentinelAI | Security Operations", page_icon="S", layout="wide", initial_sidebar_state="expanded")
    _theme()

    # Initialize persistent controls once. Dataset changes use a revisioned
    # queue-widget key so user filters survive ordinary Streamlit reruns.
    defaults = {
        "event_count": DEFAULT_EVENT_COUNTS[30],
        "event_count_custom": False,
        "random_seed": 42,
        "period_days": 30,
        "attack_episodes": DEFAULT_ATTACK_EPISODES[30],
        "attack_episodes_custom": False,
        "scenario_selector": "Brute-force attempts",
        "active_page": "Threat Monitoring",
        "dataset_revision": 0,
        "historical_end_time": datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0),
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

    # If Streamlit hot-reloads updated generator/detection defaults while an
    # older synthetic dataset is still in session state, rebuild that dataset
    # once. Uploaded CSVs are left untouched.
    previous_config = st.session_state.get("synthetic_generation_config")
    if ("logs" in st.session_state
            and str(st.session_state.get("data_source", "")).startswith("Synthetic demonstration")
            and (not isinstance(previous_config, tuple)
                 or not previous_config
                 or previous_config[0] != GENERATOR_VERSION)):
        st.session_state.synthetic_generation_config = None
        _clamp_attack_episodes()
        _regenerate_synthetic_dataset()

    if "logs" not in st.session_state:
        initial_raw = generate_logs(
            SCENARIOS[st.session_state.scenario_selector],
            seed=int(st.session_state.random_seed),
            count=int(st.session_state.event_count),
            period_days=int(st.session_state.period_days),
            attack_episodes=int(st.session_state.attack_episodes),
            end_time=st.session_state.historical_end_time,
        )
        initial, _, _ = validate_logs(initial_raw)
        st.session_state.logs = initial
        st.session_state.data_source = (
            f"Synthetic demonstration | {st.session_state.scenario_selector} | "
            f"{st.session_state.period_days}-day period"
        )
        st.session_state.scenario_label = st.session_state.scenario_selector
        st.session_state.synthetic_generation_config = (
            GENERATOR_VERSION,
            st.session_state.scenario_selector,
            int(st.session_state.random_seed),
            int(st.session_state.event_count),
            int(st.session_state.period_days),
            int(st.session_state.attack_episodes),
            st.session_state.historical_end_time,
        )

    with st.sidebar:
        st.markdown("## SENTINELAI")
        st.caption("SECURITY OPERATIONS")
        st.radio("Workspace", ["Threat Monitoring", "Alert Queue", "Inspect Alert"],
                 key="active_page", label_visibility="collapsed")
        st.divider()
        st.markdown("**Event source**")
        st.selectbox("Synthetic scenario", list(SCENARIOS), key="scenario_selector",
                     on_change=_scenario_changed)
        st.number_input("Event count", min_value=MIN_DASHBOARD_EVENT_COUNT, max_value=MAX_EVENT_COUNT, step=1000,
                        key="event_count", on_change=_mark_event_count_custom)
        st.number_input("Attack episodes", min_value=0, max_value=_episode_limit(), step=1,
                        key="attack_episodes", on_change=_mark_episode_count_custom,
                        help="Number of separate episodes in suspicious scenarios; Normal activity remains unplanted.")
        st.number_input("Random seed", min_value=0, max_value=2_147_483_647, step=1, key="random_seed")
        st.selectbox("Historical period", PERIOD_OPTIONS, format_func=lambda days: f"{days} days",
                     key="period_days", on_change=_period_changed)
        st.caption("Scenario changes load immediately. Event count, seed, attack episodes, and period apply with Load scenario.")
        if st.button("Load scenario", width="stretch", type="primary"):
            _regenerate_synthetic_dataset()
            if not st.session_state.scenario_error:
                st.rerun()
        if st.session_state.get("scenario_error"):
            st.error(st.session_state.scenario_error)

        uploaded = st.file_uploader("Upload login events (CSV)", type=["csv"])
        if uploaded is not None:
            try:
                raw = pd.read_csv(uploaded)
                parsed, rejected, error = validate_logs(raw)
                if error:
                    st.error(error)
                elif st.button("Use uploaded CSV", width="stretch"):
                    st.session_state.logs = parsed
                    st.session_state.data_source = f"Uploaded | {uploaded.name}"
                    st.session_state.rejected_rows = rejected
                    st.session_state.synthetic_generation_config = None
                    st.session_state.dataset_revision += 1
                    st.session_state.selected_alert_id = None
                    st.session_state.scenario_error = ""
                    st.rerun()
                st.caption(f"Valid rows: {len(parsed) if parsed is not None else 0} | Rejected: {rejected}")
            except (UnicodeDecodeError, pd.errors.ParserError, OSError) as exc:
                st.error(f"Could not read this CSV: {exc}")
        st.divider()
        st.caption("Synthetic events are demonstrations. No live telemetry is connected.")

    # Alerts are derived from the active DataFrame on each rerun. Nothing in
    # the detection path is cached or reused from a prior scenario.
    logs = st.session_state.logs.copy()
    alerts = get_alerts(logs)
    if not logs.empty:
        event_times = pd.to_datetime(logs["timestamp"], utc=True, errors="coerce").dropna()
        time_range = (
            f"{event_times.min().isoformat(timespec='seconds').replace('+00:00', 'Z')} to "
            f"{event_times.max().isoformat(timespec='seconds').replace('+00:00', 'Z')}"
            if not event_times.empty else "No valid timestamps"
        )
    else:
        time_range = "No events"
    st.caption(f"Source: {st.session_state.data_source} | {len(logs):,} valid events | {time_range}")
    rejected = st.session_state.get("rejected_rows", 0)
    if rejected:
        st.warning(f"{rejected} invalid row(s) excluded from analysis.")

    page = st.session_state.active_page
    if page == "Threat Monitoring":
        _render_monitoring(logs, alerts)
    elif page == "Alert Queue":
        _render_queue(alerts, logs, st.session_state.dataset_revision)
    else:
        _render_inspect(alerts, st.session_state.dataset_revision)

    with st.expander("Validated event data"):
        if logs.empty:
            st.info("No valid rows are available.")
        else:
            st.caption(f"Showing the first {min(len(logs), 500):,} of {len(logs):,} validated events.")
            st.dataframe(logs.head(500), width="stretch", hide_index=True, height=300)


if __name__ == "__main__":
    main()
