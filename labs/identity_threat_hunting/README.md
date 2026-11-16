# Lab 3: Identity Threat Hunting

**Why it matters:** identity systems remain central to workforce, cloud, and service access. Authentication and MFA telemetry can reveal risk that is otherwise easy to miss.

## Exercise

Run `python3 -m labs.identity_threat_hunting.hunt` from the repository root. The script analyzes the synthetic `auth_events.json` fixture for five or more failed logins for one user within ten minutes and three or more denied MFA prompts for one user within ten minutes (a possible push-fatigue pattern).

Try changing event times to cross a threshold or spread failures over a longer period. Threshold alerts need context and can have false positives; this small example is not an account lockout or automated response system.

**Takeaway:** correlate identity events with organizational context, protect authentication logs, and investigate suspicious activity using your approved incident process.
