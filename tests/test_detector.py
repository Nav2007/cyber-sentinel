from datetime import timedelta

import pandas as pd
import pytest

from detector import DetectionConfig, analyze_logs


def make_logs(rows, *, index=None):
    frame = pd.DataFrame(rows, columns=["timestamp", "username", "source_ip", "event_type", "status"])
    if index is not None:
        frame.index = index
    return frame


def event(minute, username="alice", ip="203.0.113.10", status="failure", *, second=0, event_type="login"):
    return {
        "timestamp": f"2026-10-19T09:{minute:02d}:{second:02d}Z",
        "username": username,
        "source_ip": ip,
        "event_type": event_type,
        "status": status,
    }


def test_brute_force_detection_and_original_positions_survive_sorting():
    rows = [event(4), event(0), event(1), event(2), event(3)]
    alerts = analyze_logs(make_logs(rows, index=[99, 8, 8, -1, 200]))
    brute = [alert for alert in alerts if alert["rule_name"] == "Repeated login failures"]
    assert len(brute) == 1
    assert brute[0]["related_event_indices"] == [1, 2, 3, 4, 0]
    assert brute[0]["evidence"].startswith("5 failed and 0 successful")


def test_password_spraying_detection():
    rows = [event(i, username=user) for i, user in enumerate(["alice", "bob", "carol", "dave", "alice", "bob"])]
    alerts = analyze_logs(make_logs(rows))
    spray = [alert for alert in alerts if alert["rule_name"] == "Password spraying pattern"]
    assert len(spray) == 1
    assert spray[0]["related_event_indices"] == list(range(6))
    assert spray[0]["username"] == ""
    assert spray[0]["severity"] in {"low", "medium", "high", "critical"}


def test_failed_logins_followed_by_success_detection():
    rows = [event(0), event(1), event(2), event(3, status="success")]
    alerts = analyze_logs(make_logs(rows))
    sequence = [alert for alert in alerts if alert["rule_name"] == "Failed logins followed by success"]
    assert len(sequence) == 1
    assert sequence[0]["related_event_indices"] == [0, 1, 2, 3]
    assert sequence[0]["username"] == "alice"
    assert "followed by a success" in sequence[0]["explanation"]


def test_normal_activity_does_not_alert():
    rows = [event(0, "alice", status="success"), event(1, "bob", status="failure"),
            event(2, "carol", status="success"), event(3, "dave", status="failure")]
    assert analyze_logs(make_logs(rows)) == []


def test_window_boundary_is_inclusive_and_one_second_outside_is_not():
    inside = [event(0), event(2), event(4), event(6), event(10)]
    outside = [event(0), event(2), event(4), event(6), event(10, second=1)]
    config = DetectionConfig(brute_force_min_failures=5)
    inside_alerts = [a for a in analyze_logs(make_logs(inside), config=config) if a["rule_name"] == "Repeated login failures"]
    outside_alerts = [a for a in analyze_logs(make_logs(outside), config=config) if a["rule_name"] == "Repeated login failures"]
    assert len(inside_alerts) == 1
    assert outside_alerts == []


def test_repeated_failure_severity_tiers_follow_attempt_count():
    expected = {3: "low", 4: "low", 5: "medium", 7: "medium", 8: "high", 14: "high", 15: "critical"}
    for attempt_count, severity in expected.items():
        rows = [event(index // 60, second=index % 60) for index in range(attempt_count)]
        alert = next(a for a in analyze_logs(make_logs(rows)) if a["rule_name"] == "Repeated login failures")
        assert alert["severity"] == severity


def test_sliding_window_finds_qualifying_group_after_unqualified_early_event():
    rows = [event(0), event(9), event(11), event(12), event(13), event(14)]
    alerts = [a for a in analyze_logs(make_logs(rows)) if a["rule_name"] == "Repeated login failures"]
    assert len(alerts) == 1
    assert alerts[0]["related_event_indices"] == [1, 2, 3, 4, 5]


def test_failed_then_success_boundary_is_inclusive():
    rows = [event(0), event(2), event(4), event(10, status="success")]
    config = DetectionConfig(failed_then_success_window=timedelta(minutes=10))
    sequence = [a for a in analyze_logs(make_logs(rows), config=config) if a["rule_name"] == "Failed logins followed by success"]
    assert len(sequence) == 1
    assert sequence[0]["related_event_indices"] == [0, 1, 2, 3]


def test_invalid_rows_missing_columns_and_empty_frames_are_safe():
    invalid = make_logs([
        event(0, status="unknown"),
        {**event(1), "timestamp": "not-a-timestamp"},
        {**event(2), "source_ip": ""},
        {**event(3), "event_type": "logout"},
        {**event(4), "timestamp": ["2026-10-19T09:04:00Z"]},
        {**event(5), "source_ip": ["203.0.113.10"]},
    ])
    assert analyze_logs(invalid) == []
    assert analyze_logs(pd.DataFrame()) == []
    assert analyze_logs(pd.DataFrame({"timestamp": ["2026-10-19T09:00:00Z"]})) == []
    assert analyze_logs(None) == []


def test_missing_usernames_are_supported_and_excluded_from_spray_and_account_rule():
    logs = pd.DataFrame([
        {"timestamp": event(i)["timestamp"], "source_ip": "203.0.113.10", "event_type": "login", "status": "failure"}
        for i in range(5)
    ])
    alerts = analyze_logs(logs)
    assert [alert["rule_name"] for alert in alerts] == ["Repeated login failures"]


def test_exact_duplicate_events_do_not_inflate_threshold():
    rows = [event(0), event(1), event(1), event(1), event(1)]
    alerts = [a for a in analyze_logs(make_logs(rows)) if a["rule_name"] == "Repeated login failures"]
    assert alerts == []


def test_scores_stay_in_range_and_outputs_are_deterministic():
    rows = [event(i) for i in range(15)]
    logs = make_logs(rows)
    first = analyze_logs(logs)
    second = analyze_logs(logs.copy())
    assert first == second
    assert first
    assert all(0 <= alert["risk_score"] <= 100 for alert in first)
    assert all(alert["severity"] in {"low", "medium", "high", "critical"} for alert in first)
    required = {
        "id", "timestamp", "rule_name", "severity", "risk_score", "username", "source_ip",
        "evidence", "explanation", "recommended_action", "related_event_indices",
    }
    assert all(required.issubset(alert) for alert in first)
    assert all("signals" in alert and "first_seen" in alert and "affected_usernames" in alert for alert in first)


def test_configuration_validation():
    with pytest.raises(ValueError):
        DetectionConfig(brute_force_min_failures=0)
    with pytest.raises(ValueError):
        DetectionConfig(password_spray_window=timedelta(seconds=0))
