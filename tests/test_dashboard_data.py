from datetime import date, datetime, timezone

import pandas as pd

from app import dataset_date_bounds, filter_alerts, get_alerts, severity_counts, sort_alerts, validate_logs
from log_generator import generate_logs


def test_validation_returns_only_analysed_rows_and_reports_rejections_without_mutating_input():
    original = pd.DataFrame([
        {"timestamp": "2026-10-19T09:00:00+02:00", "username": "alice", "source_ip": " 203.0.113.10 ", "event_type": " LOGIN ", "status": " SUCCESS "},
        {"timestamp": "bad", "username": "bob", "source_ip": "203.0.113.11", "event_type": "login", "status": "failure"},
        {"timestamp": "2026-10-19T09:02:00Z", "username": "carol", "source_ip": "not-an-ip", "event_type": "login", "status": "failure"},
        {"timestamp": "2026-10-19T09:03:00Z", "username": "dave", "source_ip": "203.0.113.12", "event_type": "logout", "status": "success"},
        {"timestamp": "2026-10-19T09:04:00Z", "username": "erin", "source_ip": "203.0.113.13", "event_type": "login", "status": "unknown"},
    ])
    original_copy = original.copy(deep=True)
    clean, rejected, error = validate_logs(original)
    assert error is None
    assert rejected == 4
    assert len(clean) == 1
    assert clean.iloc[0]["timestamp"] == "2026-10-19T07:00:00Z"
    assert clean.iloc[0]["source_ip"] == "203.0.113.10"
    pd.testing.assert_frame_equal(original, original_copy)


def test_validation_handles_missing_columns_and_empty_header_only_data():
    missing, rejected, error = validate_logs(pd.DataFrame({"timestamp": ["2026-10-19T09:00:00Z"]}))
    assert missing is None
    assert rejected == 1
    assert "Missing required column" in error

    empty = pd.DataFrame(columns=["timestamp", "username", "source_ip", "event_type", "status"])
    clean, rejected, error = validate_logs(empty)
    assert error is None
    assert rejected == 0
    assert clean.empty

    duplicate = pd.DataFrame([["2026-10-19T09:00:00Z", "alice", "203.0.113.10", "login", "failure", "extra"]], columns=["timestamp", "username", "source_ip", "event_type", "status", "status"])
    _, _, duplicate_error = validate_logs(duplicate)
    assert "Duplicate column" in duplicate_error


def test_dashboard_adapter_attaches_the_actual_detector_rows():
    logs, rejected, error = validate_logs(generate_logs("password_spraying", count=120, attack_episodes=1))
    assert error is None and rejected == 0
    alerts = get_alerts(logs)
    assert len(alerts) == 1
    incident = alerts[0]
    positions = incident["related_event_indices"]
    assert incident["simulated"] is False
    assert incident["event_count"] == len(positions) == len(incident["_events"])
    assert incident["_events"]["input_row"].tolist() == positions
    assert incident["_events"]["status"].eq("failure").all()


def test_severity_counts_and_alert_filters_match_incidents():
    logs, _, _ = validate_logs(generate_logs("normal"))
    alerts = get_alerts(logs)
    counts = severity_counts(alerts)
    assert counts["incidents"].sum() == len(alerts)
    assert counts["severity"].tolist() == ["critical", "high", "medium", "low"]
    assert filter_alerts(alerts) == []

    alerts = get_alerts(validate_logs(generate_logs("password_spraying", count=120, attack_episodes=1))[0])
    assert len(filter_alerts(alerts, severities=[alerts[0]["severity"]])) == 1
    assert len(filter_alerts(alerts, rules=["Repeated login failures"])) == 1
    assert filter_alerts(alerts, query="does not exist") == []
    spray_alert = next(alert for alert in alerts if "Password spraying pattern" in alert["signals"])
    alert_day = pd.to_datetime(spray_alert["timestamp"], utc=True).date()
    assert len(filter_alerts(alerts, start_date=alert_day, end_date=alert_day)) == 1
    assert filter_alerts(alerts, start_date=date(2030, 10, 20), end_date=date(2030, 10, 21)) == []


def test_dashboard_pipeline_preserves_expected_incident_count_for_every_scenario():
    expected = {
        "normal": (0, set()),
        "brute_force": (1, {"Repeated login failures"}),
        "password_spraying": (1, {"Password spraying pattern", "Repeated login failures"}),
        "failed_then_success": (1, {"Failed logins followed by success", "Repeated login failures"}),
    }
    for scenario, (expected_count, expected_signals) in expected.items():
        clean, rejected, error = validate_logs(generate_logs(scenario, seed=42, count=120, attack_episodes=1))
        assert error is None and rejected == 0
        alerts = get_alerts(clean)
        assert len(alerts) == expected_count
        if alerts:
            assert set(alerts[0]["signals"]) == expected_signals
            assert alerts[0]["event_count"] == len(alerts[0]["related_event_indices"])
            assert len(alerts[0]["_events"]) == alerts[0]["event_count"]


def test_queue_filters_compose_and_empty_detection_selection_means_all_rules():
    alerts = []
    for scenario in ("brute_force", "password_spraying", "failed_then_success"):
        clean, _, _ = validate_logs(generate_logs(scenario, seed=42, count=120, attack_episodes=1))
        alerts.extend(get_alerts(clean))

    assert len(alerts) == 3
    assert len(filter_alerts(alerts)) == 3
    assert len(filter_alerts(alerts, rules=[])) == 3
    assert len(filter_alerts(alerts, rules=["Repeated login failures"])) == 3
    assert len(filter_alerts(alerts, rules=["Password spraying pattern"])) == 1
    high_count = sum(alert["severity"] == "high" for alert in alerts)
    assert len(filter_alerts(alerts, severities=["high"])) == high_count
    assert len(filter_alerts(alerts, severities=["critical", "high", "medium", "low"])) == 3
    assert len(filter_alerts(alerts, severities=[])) == 3
    assert len(filter_alerts(alerts, severities=["high"], rules=[])) == high_count
    assert len(filter_alerts(alerts, severities=[], rules=["Password spraying pattern"])) == 1

    assert len(filter_alerts(alerts, query=alerts[0]["source_ip"])) == 1
    username_query = alerts[-1]["affected_usernames"][0]
    assert any(alert["username"] == username_query or username_query in alert["affected_usernames"]
               for alert in filter_alerts(alerts, query=username_query))
    assert len(filter_alerts(alerts, query="Password spraying pattern")) == 1
    assert filter_alerts(alerts, query="no matching user or rule") == []

    spray_alert = next(alert for alert in alerts if "Password spraying pattern" in alert["signals"])
    alert_day = pd.to_datetime(spray_alert["timestamp"], utc=True).date()
    composed = filter_alerts(
        alerts, query=spray_alert["affected_usernames"][0], severities=[spray_alert["severity"]], rules=["Password spraying pattern"],
        start_date=alert_day, end_date=alert_day,
    )
    assert len(composed) == 1
    assert filter_alerts(alerts, start_date=date(2030, 10, 20), end_date=date(2030, 10, 21)) == []


def test_queue_sort_modes_are_deterministic_and_severity_is_implemented():
    alerts = [
        {"id": "low", "severity": "low", "risk_score": 15, "timestamp": "2026-10-19T09:03:00Z"},
        {"id": "critical", "severity": "critical", "risk_score": 90, "timestamp": "2026-10-19T09:01:00Z"},
        {"id": "high", "severity": "high", "risk_score": 70, "timestamp": "2026-10-19T09:02:00Z"},
    ]
    assert [a["id"] for a in sort_alerts(alerts, "Newest")] == ["low", "high", "critical"]
    assert [a["id"] for a in sort_alerts(alerts, "Highest risk")] == ["critical", "high", "low"]
    assert [a["id"] for a in sort_alerts(alerts, "Severity")] == ["critical", "high", "low"]


def test_queue_date_defaults_cover_the_full_dataset_and_empty_data_is_safe():
    logs = pd.DataFrame({"timestamp": [
        "2026-10-18T23:30:00Z", "2026-10-19T09:00:00Z", "invalid",
    ]})
    assert dataset_date_bounds(logs) == (date(2026, 10, 18), date(2026, 10, 19))
    assert dataset_date_bounds(pd.DataFrame(columns=["timestamp"])) is None
    assert dataset_date_bounds(pd.DataFrame({"timestamp": ["invalid"]})) is None


def test_alert_queue_starts_unfiltered_and_filters_can_be_cleared_independently():
    from streamlit.testing.v1 import AppTest

    logs = generate_logs(
        "brute_force", seed=42, count=120, attack_episodes=1,
        start_time=datetime(2026, 10, 18, 22, 0, tzinfo=timezone.utc),
    )
    at = AppTest.from_file("../app.py")
    at.session_state["logs"] = logs
    at.session_state["data_source"] = "Test dataset"
    at.session_state["dataset_revision"] = 7
    at.session_state["active_page"] = "Alert Queue"
    at.session_state["event_count"] = 1_000
    at.session_state["attack_episodes"] = 1
    at.run()

    assert not at.exception
    assert [(widget.label, widget.value) for widget in at.multiselect] == [
        ("Severity", []), ("Detection", []),
    ]
    date_widget = next(widget for widget in at.date_input if widget.label == "Detection date (UTC)")
    assert date_widget.value == dataset_date_bounds(logs)

    def shown_count():
        caption = next(widget.value for widget in at.caption if "incidents total" in widget.value)
        return caption

    assert "1 incidents total" in shown_count() and "1 shown" in shown_count()
    incident_severity = get_alerts(logs)[0]["severity"]
    at.multiselect[0].set_value([incident_severity]).run()
    assert "1 shown" in shown_count()
    at.multiselect[1].set_value(["Repeated login failures"]).run()
    assert "1 shown" in shown_count()
    source_ip = get_alerts(logs)[0]["source_ip"]
    at.text_input[0].set_value(source_ip).run()
    assert "1 shown" in shown_count()

    # Clearing one control removes only that constraint; the other active
    # controls continue to filter the incident list.
    at.multiselect[0].set_value([]).run()
    assert "1 shown" in shown_count()
    at.multiselect[1].set_value([]).run()
    assert "1 shown" in shown_count()
    at.text_input[0].set_value("").run()
    assert "1 shown" in shown_count()

    at.multiselect[0].set_value([incident_severity]).run()
    at.text_input[0].set_value("does not match").run()
    assert "0 shown" in shown_count()
    next(widget for widget in at.selectbox if widget.label == "Synthetic scenario").set_value(
        "Failed login then success"
    ).run()
    assert at.session_state["dataset_revision"] == 8
    assert at.session_state["queue_search_8"] == ""
    assert at.session_state["queue_severity_8"] == []
    assert at.session_state["queue_rules_8"] == []
    refreshed_alerts = get_alerts(at.session_state["logs"])
    assert len(refreshed_alerts) == 1
    assert refreshed_alerts[0]["rule_name"] == "Failed logins followed by success"
    supporting = refreshed_alerts[0]["_events"]
    assert supporting["status"].tolist()[-1] == "success"
    assert supporting["status"].tolist().count("failure") in {3, 4}
    assert "1 incidents total" in shown_count() and "1 shown" in shown_count()
    at.radio[0].set_value("Inspect Alert").run()
    assert not at.exception
    assert any("Failed logins followed by success" in widget.value for widget in at.subheader)


def test_load_scenario_button_updates_data_without_mutating_instantiated_widget_state():
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file("../app.py").run(timeout=15)
    assert not at.exception
    previous_revision = at.session_state["dataset_revision"]
    next(widget for widget in at.number_input if widget.label == "Event count").set_value(11_000).run(timeout=15)
    assert not at.exception
    next(widget for widget in at.button if widget.label == "Load scenario").click().run(timeout=15)
    assert not at.exception
    assert len(at.session_state["logs"]) == 11_000
    assert at.session_state["dataset_revision"] == previous_revision + 1
