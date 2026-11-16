import argparse
import getpass
from pathlib import Path

# Small teaching list; real checks should use a large breached-password corpus.
COMMON_WORDS = (
    "password", "passw0rd", "letmein", "welcome", "admin", "qwerty", "iloveyou",
    "monkey", "dragon", "football", "baseball", "sunshine", "princess", "master",
    "shadow", "login", "trustno", "superman", "batman", "secret", "changeme",
)

# Adjacent characters in these strings (forwards or backwards) form predictable runs.
SEQUENCES = (
    "0123456789", "1234567890", "abcdefghijklmnopqrstuvwxyz",
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
)

LEET = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i",
})

MIN_RUN = 3


def _is_adjacent(first, second):
    pair = first + second
    return any(pair in sequence or pair in sequence[::-1] for sequence in SEQUENCES)


def _mark_common_words(lowered, predictable, reasons):
    normalized = lowered.translate(LEET)
    for word in COMMON_WORDS:
        for candidate in {lowered, normalized}:
            start = candidate.find(word)
            while start != -1:
                for index in range(start, start + len(word)):
                    predictable[index] = True
                reasons.add("contains a common password word")
                start = candidate.find(word, start + 1)


def _mark_runs(lowered, predictable, reasons):
    start = 0
    while start < len(lowered):
        end = start + 1
        while end < len(lowered) and _is_adjacent(lowered[end - 1], lowered[end]):
            end += 1
        if end - start >= MIN_RUN:
            for index in range(start, end):
                predictable[index] = True
            reasons.add("contains a keyboard or alphabet/number sequence")
        start = end


def _mark_repeated_characters(lowered, predictable, reasons):
    start = 0
    while start < len(lowered):
        end = start
        while end < len(lowered) and lowered[end] == lowered[start]:
            end += 1
        if end - start >= MIN_RUN:
            # Keep one character's worth of credit for the run.
            for index in range(start + 1, end):
                predictable[index] = True
            reasons.add("repeats the same character")
        start = end


def _repeating_unit(lowered):
    """Return the shortest unit that the whole value repeats, or None."""
    if len(lowered) < 2:
        return None
    position = (lowered + lowered).find(lowered, 1)
    return lowered[:position] if position < len(lowered) else None


def analyze_password(password):
    """Return a rough, local-only estimate; this is not an entropy calculation.

    The estimate discounts predictable segments (common words, sequences, and
    repetition) before applying length thresholds. The password is never stored,
    logged, or transmitted.
    """
    lowered = password.lower()
    predictable = [False] * len(lowered)
    reasons = set()

    _mark_common_words(lowered, predictable, reasons)
    _mark_runs(lowered, predictable, reasons)
    _mark_repeated_characters(lowered, predictable, reasons)
    effective_length = predictable.count(False)

    unit = _repeating_unit(lowered)
    if unit is not None:
        effective_length = min(effective_length, len(unit))
        reasons.add("repeats a short pattern")
    if lowered and len(set(lowered)) <= 2:
        effective_length = min(effective_length, len(set(lowered)))
        reasons.add("uses very few distinct characters")

    if effective_length >= 16:
        rating = "Strong"
    elif effective_length >= 12:
        rating = "Good"
    elif effective_length >= 8:
        rating = "Fair"
    else:
        rating = "Weak"
    return {
        "rating": rating,
        "length": len(password),
        "effective_length": effective_length,
        "reasons": sorted(reasons),
    }


def check_password_strength(password):
    return analyze_password(password)["rating"]


def _print_result(label, result):
    print(
        f"{label}: {result['rating']} "
        f"(length {result['length']}, unpredictable length {result['effective_length']})"
    )
    for reason in result["reasons"]:
        print(f"  - {reason}")


def main():
    parser = argparse.ArgumentParser(
        description="Estimate password strength locally; nothing is stored or sent."
    )
    parser.add_argument(
        "--samples", nargs="?", type=Path, const=Path(__file__).with_name("samples.txt"),
        help="rate each line of a file of synthetic examples (default: bundled samples.txt)",
    )
    args = parser.parse_args()

    if args.samples:
        for line in args.samples.read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.startswith("#"):
                _print_result(repr(line), analyze_password(line))
    else:
        password = getpass.getpass("Enter a password to check its strength (input hidden): ")
        _print_result("Estimated strength", analyze_password(password))
    print("Use a unique password stored in a password manager; enable MFA where available.")


if __name__ == "__main__":
    main()
