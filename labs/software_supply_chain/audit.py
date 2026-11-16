import argparse
import json
import re
from pathlib import Path

PINNED_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
SHA256 = re.compile(r"^[A-Fa-f0-9]{64}$")


def _text(component, key):
    """Return a string field, treating JSON null or non-string values as missing."""
    value = component.get(key)
    return value if isinstance(value, str) else ""


def audit_sbom(sbom):
    findings = []
    components = sbom.get("components") or []
    if not components:
        return [{"component": "SBOM", "type": "empty_inventory"}]

    for component in components:
        name = _text(component, "name") or "unnamed"
        if not PINNED_VERSION.fullmatch(_text(component, "version")):
            findings.append({"component": name, "type": "version_not_exact"})
        if not SHA256.fullmatch(_text(component, "sha256")):
            findings.append({"component": name, "type": "hash_missing_or_invalid"})
        if not component.get("source"):
            findings.append({"component": name, "type": "source_missing"})
    return findings


def main():
    parser = argparse.ArgumentParser(description="Check local SBOM inventory completeness.")
    parser.add_argument(
        "input", nargs="?", type=Path, default=Path(__file__).with_name("sbom.json")
    )
    args = parser.parse_args()
    findings = audit_sbom(json.loads(args.input.read_text(encoding="utf-8")))
    if not findings:
        print("No configured inventory gaps found.")
    for finding in findings:
        print(f"[REVIEW] {finding['component']}: {finding['type']}")


if __name__ == "__main__":
    main()
