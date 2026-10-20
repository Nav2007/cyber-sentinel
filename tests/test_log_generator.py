from datetime import datetime, timedelta, timezone

import pandas as pd

from detector import analyze_logs
from log_generator import DEFAULT_EVENT_COUNTS, LOG_COLUMNS, PERIOD_OPTIONS, generate_logs


def test_generation_is_reproducible_and_uses_the_shared_schema():
    first = generate_logs("normal", seed=202)
    second = generate_logs("normal", seed=202)
    assert first.equals(second)
    assert first.columns.tolist() == LOG_COLUMNS
    assert len(first) == DEFAULT_EVENT_COUNTS[30] == 10_000
    assert first["timestamp"].str.endswith("Z").all()
    assert first["event_type"].eq("login").all()
    assert set(first["status"]).issubset({"success", "failure"})


def test_suspicious_scenario_sizes_are_checked():
    for scenario, minimum in [
        ("brute_force", 8),
        ("password_spraying", 8),
        ("failed_then_success", 5),
    ]:
        assert len(generate_logs(scenario, count=50, attack_episodes=1)) == 50
        try:
            generate_logs(scenario, count=50, attack_episodes=5)
        except ValueError as error:
            assert "can require up to" in str(error)
        else:
            raise AssertionError(f"{scenario} should reject an impossible episode count")


def test_historical_periods_span_the_window_and_are_reproducible_by_seed():
    end = datetime(2026, 10, 19, 18, 0, tzinfo=timezone.utc)
    for period in PERIOD_OPTIONS:
        first = generate_logs("normal", seed=202, count=120, period_days=period, end_time=end)
        again = generate_logs("normal", seed=202, count=120, period_days=period, end_time=end)
        other_seed = generate_logs("normal", seed=203, count=120, period_days=period, end_time=end)
        assert first.equals(again)
        assert not first.equals(other_seed)
        timestamps = pd.to_datetime(first["timestamp"], utc=True)
        assert timestamps.min() >= pd.Timestamp(end - timedelta(days=period))
        assert timestamps.max() <= pd.Timestamp(end)
        assert timestamps.min().date() == (end - timedelta(days=period)).date()
        assert timestamps.max().date() == end.date()
        assert timestamps.dt.date.nunique() >= period


def test_background_activity_is_business_weighted_with_weekend_and_offhours_rows():
    end = datetime(2026, 10, 19, 18, 0, tzinfo=timezone.utc)
    logs = generate_logs("normal", seed=42, count=1000, period_days=30, end_time=end)
    timestamps = pd.to_datetime(logs["timestamp"], utc=True)
    daily = timestamps.dt.date.value_counts()
    weekdays = [count for day, count in daily.items() if day.weekday() < 5]
    weekends = [count for day, count in daily.items() if day.weekday() >= 5]
    assert sum(weekdays) / len(weekdays) > sum(weekends) / len(weekends)
    off_hours = (timestamps.dt.hour < 6) | (timestamps.dt.hour > 21)
    assert off_hours.any()
    assert (timestamps.dt.hour.between(7, 18)).any()


def test_scenario_episodes_are_seeded_but_not_placed_at_one_fixed_time():
    from detector import analyze_logs

    end = datetime(2026, 10, 19, 18, 0, tzinfo=timezone.utc)
    scenarios = ("brute_force", "password_spraying", "failed_then_success")
    first_seen = []
    for scenario in scenarios:
        logs = generate_logs(scenario, seed=42, count=120, attack_episodes=1, period_days=30, end_time=end)
        first_seen.append(analyze_logs(logs)[0]["first_seen"])
    assert len({value[:10] for value in first_seen}) > 1
    assert len({value[11:13] for value in first_seen}) > 1


def test_suspicious_episodes_remain_intact_across_all_historical_periods():
    end = datetime(2026, 10, 19, 18, 0, tzinfo=timezone.utc)
    expected = {
        "brute_force": "Repeated login failures",
        "password_spraying": "Password spraying pattern",
        "failed_then_success": "Failed logins followed by success",
    }
    for period in PERIOD_OPTIONS:
        for scenario, rule_name in expected.items():
            logs = generate_logs(scenario, seed=91, count=120, attack_episodes=1, period_days=period, end_time=end)
            matches = analyze_logs(logs)
            assert any(rule_name in alert["signals"] for alert in matches)
            assert len(logs) == 120


def test_period_defaults_match_requested_large_history_volumes():
    end = datetime(2026, 10, 19, 18, 0, tzinfo=timezone.utc)
    for period, expected_count in DEFAULT_EVENT_COUNTS.items():
        logs = generate_logs("normal", seed=1, period_days=period, end_time=end)
        assert len(logs) == expected_count
        timestamps = pd.to_datetime(logs["timestamp"], utc=True)
        assert timestamps.max() - timestamps.min() >= pd.Timedelta(days=period - 1)


def test_configured_episode_counts_produce_separate_detector_incidents():
    end = datetime(2026, 10, 19, 18, 0, tzinfo=timezone.utc)
    for scenario, count in (("brute_force", 12), ("password_spraying", 12), ("failed_then_success", 12)):
        logs = generate_logs(scenario, seed=29, count=2_000, period_days=30,
                             attack_episodes=count, end_time=end)
        incidents = analyze_logs(logs)
        assert len(incidents) == count
        assert all(incident["related_event_indices"] for incident in incidents)
        assert len({incident["id"] for incident in incidents}) == count
