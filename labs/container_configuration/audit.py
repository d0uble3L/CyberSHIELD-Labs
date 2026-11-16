import argparse
import re
from pathlib import Path


ROOT_USERS = {"root", "0"}


def _is_floating_image(from_line, stage_names):
    """True when FROM uses ':latest' or no tag/digest at all (which implies latest)."""
    tokens = [token for token in from_line.split()[1:] if not token.startswith("--")]
    if not tokens:
        return False
    image = tokens[0]
    if "$" in image or image.lower() == "scratch" or image.lower() in stage_names:
        return False  # Build args, the empty base, and earlier stages are not registry tags.
    if "@" in image:
        return False  # Pinned by digest.
    name = image.rsplit("/", 1)[-1]  # Ignore a registry port such as host:5000/.
    return ":" not in name or name.lower().endswith(":latest")


def audit_dockerfile(text):
    findings = []
    stage_names = set()
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        upper = line.upper()
        if upper.startswith("FROM "):
            if _is_floating_image(line, stage_names):
                findings.append({"line": line_number, "type": "floating_base_image"})
            alias = re.search(r"\sAS\s+(\S+)\s*$", line, re.IGNORECASE)
            if alias:
                stage_names.add(alias.group(1).lower())
        if upper.startswith("USER ") and len(line.split()) > 1:
            user = line.split(maxsplit=1)[1].split(":", 1)[0].strip().lower()
            if user in ROOT_USERS:
                findings.append({"line": line_number, "type": "root_user"})
        if upper.startswith("ENV ") and re.search(
            r"(?:PASSWORD|TOKEN|SECRET|API_KEY)\s*=", line, re.IGNORECASE
        ):
            findings.append({"line": line_number, "type": "possible_secret_in_env"})
        if upper.startswith("ADD "):
            findings.append({"line": line_number, "type": "review_add_instruction"})
    if not re.search(r"(?m)^\s*USER\s+\S+", text):
        findings.append({"line": 0, "type": "non_root_user_not_declared"})
    return findings


def main():
    parser = argparse.ArgumentParser(description="Statically review a Dockerfile; does not build it.")
    parser.add_argument(
        "input", nargs="?", type=Path, default=Path(__file__).with_name("Dockerfile")
    )
    args = parser.parse_args()
    findings = audit_dockerfile(args.input.read_text(encoding="utf-8"))
    if not findings:
        print("No configured Dockerfile checks matched.")
    for finding in findings:
        print(f"[REVIEW] line {finding['line']}: {finding['type']}")


if __name__ == "__main__":
    main()
