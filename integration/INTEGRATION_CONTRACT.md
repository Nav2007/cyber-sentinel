# SentinelAI detection integration contract

The Streamlit dashboard owns presentation, filtering, charting, CSV input, and synthetic data. The detector owns detection logic. The dashboard's `get_alerts(logs)` calls `detector.analyze_logs(logs)` and enriches each result with the related event rows for the UI timeline. Alerts are deterministic rule-based signals for analyst review and do not prove an attack occurred.

## Detector interface

The detection module exposes:

```python
def analyze_logs(logs: pandas.DataFrame) -> list[dict]:
    ...
```

`logs` contains exactly these required columns:

| Column | Type | Meaning |
| --- | --- | --- |
| `timestamp` | UTC ISO 8601 string | Login event time, for example `2026-10-19T09:00:00Z` |
| `username` | string | Account name |
| `source_ip` | string | Source address |
| `event_type` | string | `login` |
| `status` | string | `success` or `failure` |

Return a list of dictionaries with the following fields:

| Field | Meaning |
| --- | --- |
| `id` | Stable identifier for this alert |
| `timestamp` | Alert timestamp in UTC ISO 8601 format |
| `rule_name` | Short detection rule name |
| `severity` | `critical`, `high`, `medium`, or `low` |
| `risk_score` | Numeric risk score from 0 to 100 |
| `username` | Account involved |
| `source_ip` | Source involved |
| `evidence` | Concise observable facts supporting the alert |
| `explanation` | Human-readable reason the activity is concerning |
| `recommended_action` | Action an analyst can consider |
| `related_event_indices` | Zero-based positional row indices into the exact input DataFrame for supporting events; retained in timestamp order |
| `first_seen` | First supporting event time in UTC ISO 8601 format |
| `signals` | Detection rules that identified substantially the same activity |
| `affected_usernames` | Distinct named accounts in the incident |
| `affected_account_count` | Number of distinct named accounts |
| `event_count` | Number of unique supporting rows after incident grouping |

## Detection thresholds and severity tiers

The detector is deterministic and rule-based. It ignores invalid records, collapses exact duplicate normalized events (keeping the first input position), and treats naive timestamps as UTC while converting aware timestamps to UTC. Rule windows include events exactly on the configured time boundary. Current defaults are:

| Rule | Detection threshold | Low | Medium | High | Critical |
| --- | --- | --- | --- | --- | --- |
| Repeated failures from one IP | 3 failures in 10 minutes | 3–4 | 5–7 | 8–14 | 15+ |
| Password spraying | 6 failures against 4 named accounts in 10 minutes | — | Meets trigger | 10+ failures and 6+ accounts | 16+ failures and 8+ accounts |
| Failed logins then success for one account/IP | 3 failures then success in 10 minutes | — | 3–5 failures | 6–9 | 10+ |

`detector.DetectionConfig` exposes trigger thresholds, time windows, severity cutoffs, scoring weights, and incident overlap ratio. `analyze_logs(logs, *, config=None)` keeps the normal `analyze_logs(logs)` integration call and accepts a config when tests or callers need alternate settings.

Severity is assigned from the rule-specific evidence tiers above and is independent of risk score. The repeated-failure rule now emits low-severity findings for three or four failures, then increases severity as the number of attempts rises. When signals merge, the incident receives the strongest severity among its matched rules.

Risk scores use these deterministic formulas, then are capped to 0–100:

* Repeated failures: base 25 + 5 for each failure above the three-failure trigger + 5 when the burst spans at most 25% of its configured window.
* Password spraying: base 45 + 3 for each failure above the trigger + 4 for each named account above the trigger + the same compact-burst bonus.
* Failed then success: base 45 + 4 for each failure above the trigger + 10 for the observed success + the same compact-sequence bonus.
* A grouped incident receives 5 additional score points for each additional distinct matching rule signal.

Scores indicate relative evidence strength for triage. They are not probabilities and do not prove compromise.

## Incident grouping

Candidate detections merge only when they have the same source IP, their supporting time spans overlap, and their supporting event-index sets share at least 80% of the smaller set. This merges repeated-failure and password-spraying signals over the same attempts. The incident retains the union of event positions and all matched signals; the primary rule is selected by specificity (password spraying, then failed-login-then-success, then repeated failures). Events from one IP do not merge solely because the address matches. Separate non-overlapping event groups remain separate incidents.

## Synthetic scenario expectations

`log_generator.generate_logs` accepts `scenario`, `seed`, `count`, `period_days` (7, 30, or 90), and `attack_episodes`. It returns the exact five-column input schema and requested total row count. Default volumes are 3,000 events for 7 days, 10,000 for 30 days, and 30,000 for 90 days, with a configurable 1,000–60,000 event dashboard control. Default suspicious episode counts are 8, 30, and 45 respectively. Timestamps are UTC, generated across the selected historical interval, and weighted toward weekday/business-hour activity while retaining weekends and off-hours. A seed plus fixed settings and end time reproduces the same records. Suspicious scenarios create separate traceable episodes distributed across the selected interval; normal activity does not inject attacks.

| Scenario | Planted pattern | Expected behavior with defaults |
| --- | --- | --- |
| Normal activity | Routine successes and occasional isolated failures | No attack is deliberately planted; alerts occur only if background events meet an actual rule |
| Brute force | 3–20 failures from one IP against one account per episode | One incident per episode, severity based on the observed attempt count |
| Password spraying | 6–18 failures from one IP against 4–9 accounts per episode | One incident per episode with password-spraying and repeated-failure signals; severity follows the stronger signal |
| Failed login then success | 3–12 failures then a success for one account/IP per episode | One incident per episode; severity rises with the number of failures |

## Dashboard handoff

`get_alerts(logs)` is the only integration point the dashboard calls for alert generation. It retains detector fields and adds `_events` (selected with `logs.iloc[related_event_indices]`) and `simulated=False` to distinguish rule-engine output from placeholder alerts. The UI uses `_events` for the chronological timeline. `event_count` comes from the detector's unique supporting-row union. The dataset source is tracked separately so synthetic input remains clearly labeled even though the detector itself is real. The scenario selector regenerates logs on change; filters and selected-incident widgets are keyed to the loaded dataset revision so prior-scenario state cannot leak into the new queue or inspection view.
