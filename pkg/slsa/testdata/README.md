# SLSA test fixtures

Plain in-toto JSON statements used by the verifier integration tests.

| File | Predicate type |
| --- | --- |
| `plain/v01-build.intoto.json` | `https://slsa.dev/provenance/v0.1` |
| `plain/v02-build.intoto.json` | `https://slsa.dev/provenance/v0.2` |
| `plain/v1-build.intoto.json` | `https://slsa.dev/provenance/v1` |
| `plain/source.intoto.json` | `https://github.com/slsa-framework/slsa-source-poc/source-provenance/v1-draft` |

These are minimal, hand-crafted fixtures — just enough content to round-trip
through the upstream proto definitions and exercise a CEL expression. They are
not intended to look like real-world provenance produced by a builder.

DSSE envelopes and Sigstore bundles aren't fixtured here yet — the signature
verification path will get its own fixtures in a follow-up.
