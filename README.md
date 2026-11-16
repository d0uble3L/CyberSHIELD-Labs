# CyberSHIELD Labs

Small, local-first exercises for practical defensive security. The labs focus on capabilities that remain important as organizations adopt AI agents, cloud services, modern identity, and software supply chains through 2026–27, along with password and web-exposure fundamentals.

## Requirements

Python 3.9 or later. Every lab uses only the standard library, so there is nothing to install.

## Learning path

| # | Lab | Focus | Exercise | Run |
| --- | --- | --- | --- | --- |
| 1 | [AI application safety](./labs/ai_application_safety/README.md) | AI agents and untrusted input | Review synthetic assistant/tool events for unsafe requests | `python3 -m labs.ai_application_safety.analyze` |
| 2 | [Cloud IAM posture](./labs/cloud_iam_posture/README.md) | Least privilege | Audit a sample policy for broad or public grants | `python3 -m labs.cloud_iam_posture.audit` |
| 3 | [Identity threat hunting](./labs/identity_threat_hunting/README.md) | Authentication and MFA | Find suspicious patterns in synthetic auth events | `python3 -m labs.identity_threat_hunting.hunt` |
| 4 | [Sensitive-data protection](./labs/sensitive_data_protection/README.md) | DLP and privacy | Detect and redact sample sensitive data locally | `python3 -m labs.sensitive_data_protection.scan` |
| 5 | [Backup resilience](./labs/backup_resilience/README.md) | Recovery readiness | Validate simulated backup and restore evidence | `python3 -m labs.backup_resilience.validate` |
| 6 | [Software supply chain](./labs/software_supply_chain/README.md) | SBOM quality | Check a local SBOM for inventory gaps | `python3 -m labs.software_supply_chain.audit` |
| 7 | [Container configuration](./labs/container_configuration/README.md) | Workload hardening | Review sample container configuration statically | `python3 -m labs.container_configuration.audit` |
| 8 | [Password strength](./labs/password_strength/README.md) | Credential hygiene | Estimate strength after discounting predictable patterns | `python3 -m labs.password_strength.estimate` |
| 9 | [Web exposure](./labs/web_exposure/README.md) | Attack-surface hygiene | Check a local practice server for commonly exposed paths | `python3 -m labs.web_exposure.check --demo` |

Each lab has a short guide, a runnable Python script, and a synthetic fixture (Lab 9 generates its practice site on the fly). Run every command from the repository root. Most scripts also accept a path to your own copy of the fixture; see each guide for details.

Run the tests with:

```sh
python3 -m unittest discover -s tests -v
```

## Repository layout

```text
labs/<lab_name>/README.md   guide for the exercise
labs/<lab_name>/*.py        runnable script (python3 -m labs.<lab_name>.<script>)
labs/<lab_name>/*.json|txt  synthetic fixture
tests/test_labs.py          unit tests for every lab
```

The password and web tools that used to live in `password-strength-checker/` and `web-vulnerability-scanner/` are now Labs 8 and 9.

## Safety and scope

Labs 1–8 work only on bundled or user-selected local files. They do not contact any network service or run payloads. Lab 9 sends HTTP `HEAD` requests, but only to `localhost` or loopback IP addresses. It ignores proxy settings so requests never leave the machine, and its `--demo` mode serves a temporary synthetic site on `127.0.0.1`. Only assess systems you own or are explicitly authorized to test.

These are teaching examples, not production security products. Their checks are intentionally limited. For real environments, rely on organizational policy, current vendor documentation, and qualified review. No lab claims to predict all threats or provide a complete compliance assessment.
