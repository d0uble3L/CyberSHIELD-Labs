# Lab 6: Software Supply-Chain Inventory

**Why it matters:** teams need to know what they build and deploy, where components came from, and how to verify the artifacts they use.

## Exercise

Run `python3 -m labs.software_supply_chain.audit` from the repository root. The checker reads only a local SBOM-like JSON file and reports components without an exact `major.minor.patch` version, well-formed 64-character SHA-256 digest, or source.

Improve a copy of `sbom.json` to resolve the reported inventory gaps. Digests here are placeholder-shaped teaching data, not evidence that an artifact is authentic. The lab does not download packages, consult a vulnerability database, or assert that a component is vulnerable.

**Takeaway:** generate SBOMs from build systems, verify provenance and artifact digests through trusted pipelines, and keep dependency risk data current.
