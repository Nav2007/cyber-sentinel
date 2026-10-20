from detector import DetectionConfig, analyze_logs
from log_generator import generate_logs


def test_all_builtin_scenarios_have_the_documented_detector_behavior():
    assert analyze_logs(generate_logs("normal", seed=17)) == []

    brute = analyze_logs(generate_logs("brute_force", seed=17, count=120, attack_episodes=1))
    assert len(brute) == 1
    assert brute[0]["rule_name"] == "Repeated login failures"
    assert brute[0]["severity"] in {"low", "medium", "high", "critical"}
    assert len(brute[0]["related_event_indices"]) >= 3

    spray = analyze_logs(generate_logs("password_spraying", seed=17, count=120, attack_episodes=1))
    assert len(spray) == 1
    assert spray[0]["rule_name"] == "Password spraying pattern"
    assert spray[0]["signals"] == ["Password spraying pattern", "Repeated login failures"]
    assert spray[0]["affected_account_count"] >= 4
    assert spray[0]["severity"] in {"medium", "high", "critical"}

    sequence_logs = generate_logs("failed_then_success", seed=17, count=120, attack_episodes=1)
    sequence = analyze_logs(sequence_logs)
    assert len(sequence) == 1
    assert sequence[0]["rule_name"] == "Failed logins followed by success"
    assert sequence[0]["severity"] in {"medium", "high", "critical"}
    supporting = sequence_logs.iloc[sequence[0]["related_event_indices"]]
    assert supporting["status"].tolist()[-1] == "success"
    assert supporting["status"].tolist().count("failure") >= 3


def test_overlapping_rules_for_same_rows_merge_but_distinct_groups_do_not():
    spray = analyze_logs(generate_logs("password_spraying", count=120, attack_episodes=1))
    assert len(spray) == 1
    assert len(spray[0]["signals"]) == 2

    first = [
        {"timestamp": f"2026-10-19T09:0{i}:00Z", "username": "alice", "source_ip": "203.0.113.44", "event_type": "login", "status": "failure"}
        for i in range(5)
    ]
    second = [
        {"timestamp": f"2026-10-19T09:4{i}:00Z", "username": "alice", "source_ip": "203.0.113.44", "event_type": "login", "status": "failure"}
        for i in range(5)
    ]
    import pandas as pd
    separate = analyze_logs(pd.DataFrame(first + second))
    assert len(separate) == 2
    assert separate[0]["source_ip"] == separate[1]["source_ip"]
    assert set(separate[0]["related_event_indices"]).isdisjoint(separate[1]["related_event_indices"])


def test_more_supporting_failures_raise_score_and_severity_without_fixed_distribution():
    import pandas as pd

    def make_burst(size):
        import pandas as pd
        return pd.DataFrame([
            {"timestamp": (pd.Timestamp("2026-10-19T09:00:00Z") + pd.Timedelta(seconds=i * 25)).strftime("%Y-%m-%dT%H:%M:%SZ"), "username": "alice", "source_ip": "203.0.113.55", "event_type": "login", "status": "failure"}
            for i in range(size)
        ])

    low = analyze_logs(make_burst(5))[0]
    strong = analyze_logs(make_burst(15))[0]
    assert low["severity"] == "medium"
    assert strong["severity"] == "critical"
    assert low["risk_score"] < strong["risk_score"]
    assert 0 <= low["risk_score"] <= strong["risk_score"] <= 100


def test_incident_indices_are_the_union_of_the_supporting_rule_events():
    spray = analyze_logs(generate_logs("password_spraying", count=120, attack_episodes=1))[0]
    assert len(spray["related_event_indices"]) == spray["event_count"]
    assert spray["related_event_indices"] == sorted(spray["related_event_indices"])
    assert spray["first_seen"] < spray["timestamp"]


def test_score_and_incident_grouping_settings_are_configurable():
    config = DetectionConfig(
        brute_force_min_failures=4,
        brute_force_high_failures=6,
        brute_force_critical_failures=10,
        brute_force_base_score=30,
        compact_window_fraction=0.5,
        incident_overlap_ratio=0.7,
    )
    assert config.brute_force_min_failures == 4
    assert config.incident_overlap_ratio == 0.7
