import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

MAX_RESTORE_AGE = timedelta(days=90)


def _timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def validate_backups(records, now=None):
    now = now or datetime.now(timezone.utc)
    findings = []
    for record in records:
        name = record.get("name", "unnamed")
        if not record.get("encrypted", False):
            findings.append({"backup": name, "type": "encryption_not_confirmed"})
        if not record.get("immutable", False):
            findings.append({"backup": name, "type": "immutability_not_confirmed"})
        restore_test = record.get("last_restore_test")
        if not restore_test:
            findings.append({"backup": name, "type": "restore_test_missing"})
        else:
            tested_at = _timestamp(restore_test)
            if tested_at > now:
                findings.append({"backup": name, "type": "restore_test_in_future"})
            elif now - tested_at > MAX_RESTORE_AGE:
                findings.append({"backup": name, "type": "restore_test_stale"})
    return findings


def main():
    parser = argparse.ArgumentParser(description="Validate simulated backup evidence.")
    parser.add_argument(
        "input", nargs="?", type=Path, default=Path(__file__).with_name("backup_status.json")
    )
    args = parser.parse_args()
    findings = validate_backups(json.loads(args.input.read_text(encoding="utf-8")))
    if not findings:
        print("No configured evidence gaps found.")
    for finding in findings:
        print(f"[REVIEW] {finding['backup']}: {finding['type']}")


if __name__ == "__main__":
    main()
