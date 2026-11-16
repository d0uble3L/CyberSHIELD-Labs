import argparse
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

WINDOW = timedelta(minutes=10)
FAILURE_THRESHOLD = 5
MFA_DENIAL_THRESHOLD = 3


def _timestamp(event):
    value = event["timestamp"].replace("Z", "+00:00")
    parsed = datetime.fromisoformat(value)
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def _first_burst(timed_events, threshold):
    """Return (start_event, count) for the first WINDOW holding >= threshold events.

    timed_events is a time-sorted list of (timestamp, event) pairs. A two-pointer
    sweep keeps this linear, and each timestamp is parsed only once.
    """
    end = 0
    for start, (start_time, event) in enumerate(timed_events):
        end = max(end, start)
        while end < len(timed_events) and timed_events[end][0] <= start_time + WINDOW:
            end += 1
        if end - start >= threshold:
            return event, end - start
    return None


RULES = (
    ("login_failure", FAILURE_THRESHOLD, "repeated_login_failures"),
    ("mfa_denied", MFA_DENIAL_THRESHOLD, "repeated_mfa_denials"),
)


def hunt_events(events):
    grouped = defaultdict(list)
    for event in events:
        grouped[event.get("user", "unknown")].append((_timestamp(event), event))

    findings = []
    for user, timed_events in grouped.items():
        timed_events.sort(key=lambda pair: pair[0])
        for event_type, threshold, finding_type in RULES:
            matching = [pair for pair in timed_events if pair[1].get("type") == event_type]
            burst = _first_burst(matching, threshold)
            if burst:
                event, count = burst
                findings.append({
                    "user": user,
                    "type": finding_type,
                    "count": count,
                    "start": event["timestamp"],
                })
    return findings


def main():
    parser = argparse.ArgumentParser(description="Hunt patterns in synthetic auth events.")
    parser.add_argument(
        "input", nargs="?", type=Path, default=Path(__file__).with_name("auth_events.json")
    )
    args = parser.parse_args()
    findings = hunt_events(json.loads(args.input.read_text(encoding="utf-8")))
    if not findings:
        print("No configured patterns matched.")
    for finding in findings:
        print(f"[REVIEW] {finding['user']}: {finding['type']} (count={finding['count']})")


if __name__ == "__main__":
    main()
