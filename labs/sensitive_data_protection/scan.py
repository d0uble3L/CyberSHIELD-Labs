import argparse
import re
from pathlib import Path

PATTERNS = (
    ("email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)),
    ("phone", re.compile(
        r"(?<!\w)(?:\+?1[-. ]?)?(?:\(\d{3}\)|\d{3})[-. ]\d{3}[-. ]\d{4}(?!\w)"
    )),
    ("demo_secret", re.compile(r"\bDEMO_API_KEY_[A-Z0-9]{8,}\b")),
)


def redact_text(text):
    findings = []
    redacted = text
    for label, pattern in PATTERNS:
        matches = list(pattern.finditer(redacted))
        for match in reversed(matches):
            findings.append({"type": label, "line": redacted.count("\n", 0, match.start()) + 1})
            redacted = redacted[:match.start()] + f"[REDACTED:{label}]" + redacted[match.end():]
    return redacted, findings


def main():
    parser = argparse.ArgumentParser(description="Find and redact sample sensitive data locally.")
    parser.add_argument(
        "input", nargs="?", type=Path, default=Path(__file__).with_name("sample.txt")
    )
    args = parser.parse_args()
    text = args.input.read_text(encoding="utf-8")
    redacted, findings = redact_text(text)
    print(f"Found {len(findings)} pattern match(es).")
    for finding in findings:
        print(f"[REVIEW] line {finding['line']}: {finding['type']}")
    print("\nRedacted preview:\n" + redacted)


if __name__ == "__main__":
    main()
