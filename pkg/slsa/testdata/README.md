# SLSA test fixtures

Plain in-toto JSON statements and Sigstore bundles used by the verifier
integration tests.

| File | Predicate type |
| --- | --- |
| `plain/v01-build.intoto.json` | `https://slsa.dev/provenance/v0.1` |
| `plain/v02-build.intoto.json` | `https://slsa.dev/provenance/v0.2` |
| `plain/v1-build.intoto.json` | `https://slsa.dev/provenance/v1` |
| `plain/source.intoto.json` | `https://github.com/slsa-framework/slsa-source-poc/source-provenance/v1-draft` |

These are minimal, hand-crafted fixtures — just enough content to round-trip
through the upstream proto definitions and exercise a CEL expression. They are
not intended to look like real-world provenance produced by a builder.

## Sigstore bundles

| File | Predicate type |
| --- | --- |
| `bundle/source-provenance.sigstore.json` | `https://github.com/slsa-framework/slsa-source-poc/source-provenance/v1-draft` |
| `bundle/source-vsa.sigstore.json` | `https://slsa.dev/verification_summary/v1` |

Real-world bundles produced by the official SLSA source-actions workflow for
commit `b797d53` of `github.com/puerco/lab`: the source provenance for
`refs/heads/master` and the VSA the workflow issued for it. Tests parse them
and exercise the statement paths offline; verifying their signatures needs
the Sigstore trust root (TUF) and is left to the signer library's own tests.
