# Lab 4: Sensitive-Data Protection

**Why it matters:** AI-assisted workflows and routine data sharing can increase the chance that personal data or credentials appear in logs, tickets, and prompts.

## Exercise

Run `python3 -m labs.sensitive_data_protection.scan` from the repository root. This standard-library script checks the bundled synthetic text for email-like values, North American phone numbers, and an explicitly fake demo-key pattern, then prints a redacted preview.

Only use synthetic data for this exercise. Try an input file you create locally with fake values. The checks are deliberately narrow, can miss real sensitive data, and can flag harmless text; do not treat them as a production DLP control.

**Takeaway:** minimize data collection, redact before sharing, and use approved secret-management and DLP systems for real information.
