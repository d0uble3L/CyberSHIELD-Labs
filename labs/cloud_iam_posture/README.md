# Lab 2: Cloud IAM Posture

**Why it matters:** cloud identity is a high-impact control plane. Small policy mistakes can grant more access than a workload or person needs.

## Exercise

Run `python3 -m labs.cloud_iam_posture.audit` from the repository root. The static auditor reads the bundled, provider-neutral `policy.json` example and reports wildcard actions, wildcard resources, and unrestricted principals in `Allow` statements.

Edit a copy of the fixture: narrow broad grants to a specific action, resource, and principal. Then rerun the audit. This intentionally small policy format does not model provider-specific conditions, inheritance, or every policy language feature; a clean result is not proof of safety.

**Takeaway:** prefer scoped identities and least privilege; verify effective permissions with the cloud provider's supported tooling before changing a real environment.
