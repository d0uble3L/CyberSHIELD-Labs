import argparse
import json
from pathlib import Path


def _as_list(value):
    """Policies may give a single string or a list; treat both as a list of entries."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _principal_entries(principal):
    if isinstance(principal, dict):
        return [entry for value in principal.values() for entry in _as_list(value)]
    return _as_list(principal)


def audit_policy(policy):
    findings = []
    for index, statement in enumerate(policy.get("statements", []), start=1):
        if str(statement.get("effect", "")).lower() != "allow":
            continue
        actions = _as_list(statement.get("actions"))
        resources = _as_list(statement.get("resources"))
        if "*" in actions:
            findings.append({
                "statement": index,
                "type": "wildcard_action",
                "detail": "Allow statement grants every action.",
            })
        if "*" in resources:
            findings.append({
                "statement": index,
                "type": "wildcard_resource",
                "detail": "Allow statement applies to every resource.",
            })
        if "*" in _principal_entries(statement.get("principal")):
            findings.append({
                "statement": index,
                "type": "public_principal",
                "detail": "Allow statement names a public or unrestricted principal.",
            })
    return findings


def main():
    parser = argparse.ArgumentParser(description="Statically audit a sample IAM policy.")
    parser.add_argument(
        "input", nargs="?", type=Path, default=Path(__file__).with_name("policy.json")
    )
    args = parser.parse_args()
    findings = audit_policy(json.loads(args.input.read_text(encoding="utf-8")))
    if not findings:
        print("No broad grants matched these simple checks.")
    for finding in findings:
        print(f"[REVIEW] statement {finding['statement']}: {finding['type']} — {finding['detail']}")


if __name__ == "__main__":
    main()
