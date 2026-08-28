# Security Policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Report them
privately through GitHub's vulnerability reporting for this repository:

https://github.com/slsa-framework/verifier/security/advisories/new

Include what you found, how to reproduce it and, if you can, the impact you
believe it has. You will get an acknowledgement within a few days, and we
will keep you informed as we work on a fix. Please give us a reasonable
window to release one before disclosing the issue publicly.

## Supported versions

Fixes are released on `main` and in the latest tagged release. Older
releases are not patched: upgrade to the latest release to get security
fixes.

## What counts as a vulnerability here

`slsa-verifier` decides whether an attestation should be trusted. Anything
that lets a crafted attestation, envelope or signature produce a `PASS` the
tool's documented semantics say it should not — or that lets the tool be
made to skip a check silently — is in scope. So is anything in the
dependency chain used to verify signatures.

Permissive behavior that the tool documents and that is selected by the
caller is not a vulnerability: see the trust model in the README for what
the defaults do and do not verify.
