# Lab 7: Container Configuration

**Why it matters:** container build and runtime settings influence the privileges, repeatability, and exposure of application workloads.

## Exercise

Run `python3 -m labs.container_configuration.audit` from the repository root. It statically reviews the bundled Dockerfile for a floating base image (an explicit `latest` tag, or no tag or digest at all, which implies `latest`), a declared root user (including `root:root` and `0:0`), environment variables that look like embedded secrets, an `ADD` instruction to review, and the absence of an explicit non-root user.

Make a copy of the file and replace the risky teaching examples with safer choices. The fake key is not a credential. The checks are intentionally simplistic and do not parse Dockerfile syntax fully, build images, inspect registries, or assess runtime configuration.

**Takeaway:** pin and verify build inputs, avoid embedding secrets, run with least privilege, and use a maintained image-scanning pipeline.
