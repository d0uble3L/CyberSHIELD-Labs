# Lab 5: Backup Resilience

**Why it matters:** a backup is useful only when it can be recovered. Encryption, deletion resistance, and practiced restore procedures are core resilience controls.

## Exercise

Run `python3 -m labs.backup_resilience.validate` from the repository root. The sample JSON lists simulated backup controls and restore-test dates; the checker reports missing encryption/immutability evidence and restore tests older than 90 days.

Update a copy of the fixture and rerun. The age threshold is a teaching default, not a universal policy. Real recovery objectives should be defined by the system owner, and restore exercises should be performed through approved procedures.

**Takeaway:** test restores, measure recovery objectives, and protect backup administration separately from production access.
