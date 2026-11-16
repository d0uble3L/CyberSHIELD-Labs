# Lab 1: AI Application Safety

**Why it matters:** AI features increasingly connect models to retrieved content and tools. Treat retrieved text as untrusted input, and keep tool permissions narrow.

## Exercise

From the repository root, run `python3 -m labs.ai_application_safety.analyze`. The script reads only the bundled synthetic `events.json` fixture and flags instruction-like text in untrusted content and requested tools outside each event's allowlist.

Review the findings, then edit a copy of the JSON fixture to test a benign document and a tool that is explicitly allowed. Consider what a rule-based review misses: context, indirect instructions, and policy decisions. The output is a triage hint, not proof of an attack or a full AI risk assessment.

**Takeaway:** enforce authorization outside the model, minimize tool privileges, and keep untrusted content separate from trusted instructions.
