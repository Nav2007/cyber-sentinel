"""Explainable, deterministic login detection and incident grouping.

Default trigger thresholds (all configurable through ``DetectionConfig``):

* Repeated failures: 3 failures from one source IP in 10 minutes. Three to four
  attempts are low severity; five or more are medium or stronger.
* Password spraying: 6 failures against 4 distinct named accounts in 10 minutes.
* Failed then successful login: 3 failures then a success for one account/IP
  within 10 minutes.

Severity is assigned from rule-specific evidence tiers, independently of the
numeric risk score. Scores estimate the strength of observed evidence, not the
probability of compromise. See ``INTEGRATION_CONTRACT.md`` for formulas.

Incident grouping is deterministic: detections from the same source are merged
only when their supporting-event sets overlap by at least the configured
fraction of the smaller set and their time spans overlap. IP equality alone
never merges alerts. Merged incidents retain all rule signals and the union of
supporting input row positions.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import hashlib
import ipaddress
import json
from typing import Any, Iterator

import pandas as pd


@dataclass(frozen=True)
class DetectionConfig:
    """Detection, severity, score, and incident-correlation configuration."""

    brute_force_min_failures: int = 3
    brute_force_window: timedelta = timedelta(minutes=10)
    brute_force_medium_failures: int = 5
    brute_force_high_failures: int = 8
    brute_force_critical_failures: int = 15
    brute_force_base_score: int = 25
    brute_force_extra_failure_score: int = 5

    password_spray_min_failures: int = 6
    password_spray_min_usernames: int = 4
    password_spray_window: timedelta = timedelta(minutes=10)
    password_spray_high_failures: int = 10
    password_spray_high_usernames: int = 6
    password_spray_critical_failures: int = 16
    password_spray_critical_usernames: int = 8
    password_spray_base_score: int = 45
    password_spray_extra_failure_score: int = 3
    password_spray_extra_username_score: int = 4

    failed_then_success_min_failures: int = 3
    failed_then_success_window: timedelta = timedelta(minutes=10)
    failed_then_success_high_failures: int = 6
    failed_then_success_critical_failures: int = 10
    failed_then_success_base_score: int = 45
    failed_then_success_extra_failure_score: int = 4
    successful_login_score: int = 10

    compact_window_fraction: float = 0.25
    compact_window_score: int = 5
    corroborating_signal_score: int = 5
    incident_overlap_ratio: float = 0.8

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if name.endswith("_window"):
                if not isinstance(value, timedelta) or value.total_seconds() <= 0:
                    raise ValueError(f"{name} must be a positive datetime.timedelta")
            elif name.endswith("_fraction") or name.endswith("_ratio"):
                if not isinstance(value, (int, float)) or not 0 < value <= 1:
                    raise ValueError(f"{name} must be greater than 0 and at most 1")
            elif name.endswith("_score"):
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    raise ValueError(f"{name} must be a non-negative integer")
            elif name.endswith("_failures") or name.endswith("_usernames"):
                if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                    raise ValueError(f"{name} must be a positive integer")
        if self.brute_force_medium_failures < self.brute_force_min_failures:
            raise ValueError("brute_force_medium_failures cannot be below its detection threshold")
        if self.brute_force_high_failures < self.brute_force_medium_failures:
            raise ValueError("brute_force_high_failures cannot be below its medium threshold")
        if self.brute_force_critical_failures < self.brute_force_high_failures:
            raise ValueError("brute_force_critical_failures cannot be below its high threshold")
        if self.password_spray_high_failures < self.password_spray_min_failures:
            raise ValueError("password_spray_high_failures cannot be below its detection threshold")
        if self.password_spray_high_usernames < self.password_spray_min_usernames:
            raise ValueError("password_spray_high_usernames cannot be below its detection threshold")
        if self.password_spray_critical_failures < self.password_spray_high_failures:
            raise ValueError("password_spray_critical_failures cannot be below its high threshold")
        if self.password_spray_critical_usernames < self.password_spray_high_usernames:
            raise ValueError("password_spray_critical_usernames cannot be below its high threshold")
        if self.failed_then_success_high_failures < self.failed_then_success_min_failures:
            raise ValueError("failed_then_success_high_failures cannot be below its detection threshold")
        if self.failed_then_success_critical_failures < self.failed_then_success_high_failures:
            raise ValueError("failed_then_success_critical_failures cannot be below its high threshold")


@dataclass(frozen=True)
class _Event:
    position: int
    timestamp: pd.Timestamp
    username: str
    source_ip: str
    status: str


_REQUIRED_COLUMNS = ("timestamp", "source_ip", "event_type", "status")
_RULE_PRIORITY = {"PS": 0, "FS": 1, "BF": 2}
_RULE_NAMES = {
    "PS": "Password spraying pattern",
    "FS": "Failed logins followed by success",
    "BF": "Repeated login failures",
}


def _clean_text(value: Any) -> str:
    if value is None or isinstance(value, (list, tuple, dict, set)):
        return ""
    try:
        missing = pd.isna(value)
        if isinstance(missing, bool) and missing:
            return ""
    except (TypeError, ValueError):
        return ""
    return str(value).strip()


def _parse_timestamp(value: Any) -> pd.Timestamp | None:
    if isinstance(value, (list, tuple, dict, set)):
        return None
    try:
        stamp = pd.to_datetime(value, utc=True, errors="coerce")
        if pd.isna(stamp):
            return None
        return pd.Timestamp(stamp).tz_convert("UTC")
    except (TypeError, ValueError, OverflowError):
        return None


def _normalized_events(logs: pd.DataFrame) -> list[_Event]:
    if not isinstance(logs, pd.DataFrame) or logs.empty:
        return []
    if any(column not in logs.columns for column in _REQUIRED_COLUMNS):
        return []

    # Parse timestamps in one vectorized pandas operation. Parsing each value
    # inside iterrows() dominated runtime for histories with tens of thousands
    # of records and was repeated on every Streamlit rerun.
    timestamps = pd.to_datetime(logs["timestamp"], utc=True, errors="coerce").array
    columns = list(logs.columns)
    source_index = columns.index("source_ip")
    event_type_index = columns.index("event_type")
    status_index = columns.index("status")
    username_index = columns.index("username") if "username" in logs.columns else None
    events: list[_Event] = []
    seen: set[tuple[int, str, str, str, str]] = set()
    for position, row in enumerate(logs.itertuples(index=False, name=None)):
        timestamp = timestamps[position]
        if pd.isna(timestamp):
            continue
        timestamp = pd.Timestamp(timestamp).tz_convert("UTC")
        username = _clean_text(row[username_index]) if username_index is not None else ""
        source_ip_text = _clean_text(row[source_index])
        try:
            source_ip = str(ipaddress.ip_address(source_ip_text))
        except ValueError:
            source_ip = ""
        event_type = _clean_text(row[event_type_index]).lower()
        status = _clean_text(row[status_index]).lower()
        if not source_ip or event_type != "login" or status not in {"success", "failure"}:
            continue

        dedupe_key = (int(timestamp.value), username, source_ip, event_type, status)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        events.append(_Event(position, timestamp, username, source_ip, status))
    return sorted(events, key=lambda event: (event.timestamp.value, event.position))


def _qualifying_windows(
    events: list[_Event],
    window: timedelta,
    min_events: int,
    min_distinct_usernames: int = 1,
) -> Iterator[list[_Event]]:
    """Yield earliest qualifying, disjoint windows; exact boundaries count."""
    start = end = 0
    usernames: dict[str, int] = {}
    while start < len(events):
        end = max(end, start)
        limit = events[start].timestamp + pd.Timedelta(window)
        while end < len(events) and events[end].timestamp <= limit:
            username = events[end].username
            usernames[username] = usernames.get(username, 0) + 1
            end += 1

        if end - start >= min_events and len(usernames) >= min_distinct_usernames:
            yield events[start:end]
            usernames.clear()
            start = end
            continue

        leaving = events[start].username
        remaining = usernames.get(leaving, 0) - 1
        if remaining > 0:
            usernames[leaving] = remaining
        else:
            usernames.pop(leaving, None)
        start += 1


def _burst_score(
    base: int,
    extra_failures: int,
    per_failure: int,
    events: list[_Event],
    window: timedelta,
    compact_fraction: float,
    compact_bonus: int,
) -> int:
    duration = max(0.0, (events[-1].timestamp - events[0].timestamp).total_seconds())
    is_compact = duration <= window.total_seconds() * compact_fraction
    return min(100, base + max(0, extra_failures) * per_failure + (compact_bonus if is_compact else 0))


def _duration_text(events: list[_Event]) -> str:
    seconds = max(0, int((events[-1].timestamp - events[0].timestamp).total_seconds()))
    minutes, seconds = divmod(seconds, 60)
    if minutes and seconds:
        return f"{minutes} min {seconds} sec"
    if minutes:
        return f"{minutes} min"
    return f"{seconds} sec"


def _candidate(
    code: str,
    events: list[_Event],
    score: int,
    severity: str,
    evidence: str,
    explanation: str,
    action: str,
) -> dict[str, Any]:
    ordered = sorted(events, key=lambda event: (event.timestamp.value, event.position))
    return {
        "code": code,
        "source_ip": ordered[0].source_ip,
        "events": ordered,
        "indices": {event.position for event in ordered},
        "first": ordered[0].timestamp,
        "last": ordered[-1].timestamp,
        "risk_score": max(0, min(100, int(score))),
        "severity": severity,
        "evidence": evidence,
        "explanation": explanation,
        "recommended_action": action,
    }


def _candidates(events: list[_Event], cfg: DetectionConfig) -> list[dict[str, Any]]:
    by_ip_failures: dict[str, list[_Event]] = {}
    by_account: dict[tuple[str, str], list[_Event]] = {}
    for event in events:
        if event.status == "failure":
            by_ip_failures.setdefault(event.source_ip, []).append(event)
        if event.username:
            by_account.setdefault((event.source_ip, event.username), []).append(event)

    candidates: list[dict[str, Any]] = []

    for source_ip in sorted(by_ip_failures):
        for group in _qualifying_windows(
            by_ip_failures[source_ip], cfg.brute_force_window, cfg.brute_force_min_failures
        ):
            count = len(group)
            if count >= cfg.brute_force_critical_failures:
                severity = "critical"
            elif count >= cfg.brute_force_high_failures:
                severity = "high"
            elif count >= cfg.brute_force_medium_failures:
                severity = "medium"
            else:
                severity = "low"
            score = _burst_score(
                cfg.brute_force_base_score,
                count - cfg.brute_force_min_failures,
                cfg.brute_force_extra_failure_score,
                group,
                cfg.brute_force_window,
                cfg.compact_window_fraction,
                cfg.compact_window_score,
            )
            candidates.append(_candidate(
                "BF", group, score, severity,
                f"{count} failed login attempts from {source_ip} within {_duration_text(group)}.",
                f"The source produced at least {cfg.brute_force_min_failures} failures within {cfg.brute_force_window}; this can be consistent with password guessing but may have benign causes.",
                "Review the source and affected accounts. Confirm whether the attempts are expected before applying rate limits or blocking the address.",
            ))

    for source_ip in sorted(by_ip_failures):
        named_failures = [event for event in by_ip_failures[source_ip] if event.username]
        for group in _qualifying_windows(
            named_failures,
            cfg.password_spray_window,
            cfg.password_spray_min_failures,
            cfg.password_spray_min_usernames,
        ):
            count = len(group)
            user_count = len({event.username for event in group})
            if count >= cfg.password_spray_critical_failures and user_count >= cfg.password_spray_critical_usernames:
                severity = "critical"
            elif count >= cfg.password_spray_high_failures and user_count >= cfg.password_spray_high_usernames:
                severity = "high"
            else:
                severity = "medium"
            score = min(100, cfg.password_spray_base_score
                        + max(0, count - cfg.password_spray_min_failures) * cfg.password_spray_extra_failure_score
                        + max(0, user_count - cfg.password_spray_min_usernames) * cfg.password_spray_extra_username_score
                        + (cfg.compact_window_score if (group[-1].timestamp - group[0].timestamp).total_seconds() <= cfg.password_spray_window.total_seconds() * cfg.compact_window_fraction else 0))
            accounts = ", ".join(sorted({event.username for event in group}))
            candidates.append(_candidate(
                "PS", group, score, severity,
                f"{count} failed attempts targeted {user_count} accounts from {source_ip} within {_duration_text(group)}; accounts: {accounts}.",
                f"The source crossed the password-spraying threshold of {cfg.password_spray_min_failures} failures across {cfg.password_spray_min_usernames} named accounts; this pattern may have benign explanations.",
                "Review sign-in context for the affected accounts and confirm whether the source is expected. Consider rate limiting only after validating the activity.",
            ))

    for source_ip, username in sorted(by_account):
        pending_failures: list[_Event] = []
        for event in by_account[(source_ip, username)]:
            if event.status == "failure":
                pending_failures.append(event)
                continue
            window_start = event.timestamp - pd.Timedelta(cfg.failed_then_success_window)
            relevant = [failure for failure in pending_failures if window_start <= failure.timestamp <= event.timestamp]
            pending_failures = []
            if len(relevant) < cfg.failed_then_success_min_failures:
                continue
            group = [*relevant, event]
            count = len(relevant)
            if count >= cfg.failed_then_success_critical_failures:
                severity = "critical"
            elif count >= cfg.failed_then_success_high_failures:
                severity = "high"
            else:
                severity = "medium"
            duration = event.timestamp - relevant[0].timestamp
            is_compact = duration.total_seconds() <= cfg.failed_then_success_window.total_seconds() * cfg.compact_window_fraction
            score = min(100, cfg.failed_then_success_base_score
                        + (count - cfg.failed_then_success_min_failures) * cfg.failed_then_success_extra_failure_score
                        + cfg.successful_login_score
                        + (cfg.compact_window_score if is_compact else 0))
            candidates.append(_candidate(
                "FS", group, score, severity,
                f"{count} failed attempts were followed by a successful login for {username} from {source_ip} within {_duration_text(group)}.",
                f"The account had at least {cfg.failed_then_success_min_failures} failed attempts followed by a success within {cfg.failed_then_success_window}; this alone does not prove compromise.",
                "Confirm the successful sign-in with the account owner and review device, location, and authentication context. This sequence alone does not prove compromise.",
            ))
    return candidates


def _overlaps_substantially(a: dict[str, Any], b: dict[str, Any], ratio: float) -> bool:
    if a["source_ip"] != b["source_ip"]:
        return False
    if a["first"] > b["last"] or b["first"] > a["last"]:
        return False
    smaller_size = min(len(a["indices"]), len(b["indices"]))
    shared = len(a["indices"] & b["indices"])
    return smaller_size > 0 and shared / smaller_size >= ratio


def _incident(alert_candidates: list[dict[str, Any]], cfg: DetectionConfig) -> dict[str, Any]:
    by_priority = sorted(alert_candidates, key=lambda item: _RULE_PRIORITY[item["code"]])
    primary = by_priority[0]
    signals = [_RULE_NAMES[item["code"]] for item in by_priority]
    all_events_by_position = {
        event.position: event
        for candidate in alert_candidates
        for event in candidate["events"]
    }
    ordered_events = sorted(all_events_by_position.values(), key=lambda event: (event.timestamp.value, event.position))
    indices = [event.position for event in ordered_events]
    accounts = sorted({event.username for event in ordered_events if event.username})
    source_ip = primary["source_ip"]
    first_seen, last_seen = ordered_events[0].timestamp, ordered_events[-1].timestamp
    failure_count = sum(event.status == "failure" for event in ordered_events)
    success_count = sum(event.status == "success" for event in ordered_events)
    duration = _duration_text(ordered_events)
    score = min(100, max(item["risk_score"] for item in alert_candidates)
                + cfg.corroborating_signal_score * (len(signals) - 1))
    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    severity = max((item["severity"] for item in alert_candidates), key=severity_order.get)
    evidence = (
        f"{failure_count} failed and {success_count} successful login event(s) from {source_ip} "
        f"across {len(accounts)} named account(s) within {duration}."
    )
    if len(signals) > 1:
        evidence += " Matching signals: " + "; ".join(signals) + "."
    explanation = primary["explanation"]
    if len(signals) > 1:
        explanation += " The same supporting activity also met " + "; ".join(signals[1:]) + "."

    identity = json.dumps([primary["code"], source_ip, indices], separators=(",", ":"), ensure_ascii=True)
    alert_id = f"INC-{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:12]}"
    return {
        "id": alert_id,
        "timestamp": last_seen.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "first_seen": first_seen.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "rule_name": _RULE_NAMES[primary["code"]],
        "signals": signals,
        "severity": severity,
        "risk_score": score,
        "username": accounts[0] if len(accounts) == 1 else "",
        "affected_usernames": accounts,
        "affected_account_count": len(accounts),
        "source_ip": source_ip,
        "evidence": evidence,
        "explanation": explanation,
        "recommended_action": primary["recommended_action"],
        "event_count": len(ordered_events),
        "related_event_indices": indices,
    }


def analyze_logs(
    logs: pd.DataFrame,
    *,
    config: DetectionConfig | None = None,
) -> list[dict[str, Any]]:
    """Analyze login events and return deduplicated, evidence-linked incidents.

    ``username`` is optional. Invalid records and exact duplicate normalized
    rows are ignored (the first duplicate's positional input index is retained).
    Naive timestamps are interpreted as UTC; aware timestamps are converted
    to UTC. Time windows include their exact boundary.

    Candidates merge only if their source IPs match, their time ranges overlap,
    and at least ``incident_overlap_ratio`` of the smaller candidate's event
    set is shared. This joins redundant signals while preserving separate
    non-overlapping event groups from the same address.
    """
    cfg = config or DetectionConfig()
    events = _normalized_events(logs)
    if not events:
        return []
    candidates = _candidates(events, cfg)
    if not candidates:
        return []

    # Deterministic union-find: transitive overlap forms one incident group.
    parents = list(range(len(candidates)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    for left in range(len(candidates)):
        for right in range(left + 1, len(candidates)):
            if _overlaps_substantially(candidates[left], candidates[right], cfg.incident_overlap_ratio):
                root_left, root_right = find(left), find(right)
                if root_left != root_right:
                    parents[root_right] = root_left

    groups: dict[int, list[dict[str, Any]]] = {}
    for index, candidate in enumerate(candidates):
        groups.setdefault(find(index), []).append(candidate)

    incidents = [_incident(group, cfg) for group in groups.values()]
    incidents.sort(key=lambda alert: (alert["timestamp"], alert["rule_name"], alert["source_ip"], alert["related_event_indices"]))
    return incidents


__all__ = ["DetectionConfig", "analyze_logs"]
