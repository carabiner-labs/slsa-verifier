# Embedded verifier registry

YAML files in this directory are compiled into the verifier as its
default registry of VSA issuers bound to their signing identity. There
are none yet: verifiers are bound with `--verifier <id>=<signer spec>`
or a registry file passed with `--verifiers`. The file format and the
binding rules are documented in
[docs/verifier-registry.md](../../../../docs/verifier-registry.md),
with an example entry.
