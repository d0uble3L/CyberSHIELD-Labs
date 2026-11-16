import argparse
import json
import re
from pathlib import Path

SUSPICIOUS_TEXT = re.compile(
    r"\b(ignore (?:all )?previous instructions|reveal (?:the )?secret|"
    r"send (?:the )?(?:secret|credentials)|override (?:the )?policy)\b",
    re.IGNORECASE,
)


def analyze_events(events):
    findings = []
    for event in events:
        event_id = event.get("id", "unknown")
        source = event.get("source", "")
        text = event.get("text", "")
        if source in {"retrieved_document", "external_content"} and SUSPICIOUS_TEXT.search(text):
            findings.append({
                "event": event_id,
                "type": "untrusted_instruction",
                "detail": "Untrusted content contains an instruction-like request.",
            })

        tool = event.get("tool_requested")
        allowed_tools = event.get("allowed_tools", [])
        if tool and tool not in allowed_tools:
            findings.append({
                "event": event_id,
                "type": "tool_not_allowlisted",
                "detail": f"Requested tool {tool!r} is not in this event's allowlist.",
            })
    return findings


def main():
    parser = argparse.ArgumentParser(description="Review synthetic AI application events.")
    parser.add_argument(
        "input", nargs="?", type=Path, default=Path(__file__).with_name("events.json")
    )
    args = parser.parse_args()
    events = json.loads(args.input.read_text(encoding="utf-8"))
    findings = analyze_events(events)
    if not findings:
        print("No rule matches in the supplied events.")
    for finding in findings:
        print(f"[REVIEW] {finding['event']}: {finding['type']} — {finding['detail']}")


if __name__ == "__main__":
    main()
