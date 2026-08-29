# The verifier registry

A Verification Summary Attestation names the verifier that issued it in
`verifier.id`. Like a provenance's `builder.id`, that is a claim written
by whoever produced the document: the id means something only once it
is bound to the identity that signed the VSA. The `vsa` command binds
them per invocation — `--verifier <id>=<signer spec>` — and the
**verifier registry** does it once, by name: a `--verifier <id>` given
without a signer takes the signer the registry binds to that id.

It is the counterpart of the [builder registry](builder-registry.md)
for VSAs, with the same file shape. Nothing is embedded yet: the
verifier ships no known VSA issuers, so bindings come from `--verifier`
and from registry files passed with `--verifiers`.

## How a bound verifier is checked

For a VSA whose `verifier.id` is an accepted verifier, the signer check
requires the envelope's verified signature to match an identity
authorized for that verifier: the ones bound with `--verifier id=…`,
the registry's when the id was given bare, plus any wildcard `--signer`.
A registry signer must also have signed at a ref its **ref policy**
allows. A verifier bound nowhere is refused unless
`--allow-unbound-verifier` is passed, in which case only the id is
matched.

## Registry files

```yaml
verifiers:
  # The SLSA source tool's workflow issues a VSA for every commit it
  # attests. Its id is the repository; the certificate names the
  # workflow that ran, from main, so the ref policy stays "any".
  - id: https://github.com/slsa-framework/source-actions
    title: SLSA source-actions
    description: |
      VSAs issued by the SLSA source tool running as the official
      source-actions workflow.
    signer: sigstore(identityMatch=prefix)::https://token.actions.githubusercontent.com::https://github.com/slsa-framework/source-actions/.github/workflows/compute_slsa_source.yml@
    ref: any

  # A verifier of your own, signed with a workload identity.
  - id: https://verify.example.com
    signer: spiffe://example.com/verifier
```

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | The verifier id as VSAs record it in `verifier.id`. |
| `idMatch` | no | `exact` (default) or `prefix`. |
| `title`, `description` | no | For people. |
| `issuer` | one of `issuer`/`signer` | OIDC issuer of the signing certificate. With `signer` unset, the signer is derived as any sigstore identity from `issuer` whose subject starts with `id` followed by `/` — every workflow of the repository the id names. Naming the workflow with `signer` is the stronger binding. |
| `signer` | one of `issuer`/`signer` | A full identity spec: `sigstore::<issuer>::<subject>`, `sigstore(identityMatch=prefix)::…`, `key::<type>::<id>`, `spiffe://…`. |
| `ref` | no | `any` (default) or `semver-tag`: the `@ref` in the signer's subject must be `refs/tags/vX.Y.Z`. Use it for verifiers that run from releases; a workflow invoked from a branch, as source-actions is, needs `any`. |

Later entries with the same `id` and `idMatch` replace earlier ones; a
directory of files merges in path order.

## Command line

```
slsa-verifier vsa --verifiers ci/verifiers.yaml \
    --verifier https://github.com/slsa-framework/source-actions \
    --level SLSA_SOURCE_LEVEL_1 commit.vsa.jsonl
```

`--verifier id=<spec>` still binds explicitly and overrides the
registry for that id. Binding a verifier, by flag or registry, implies
`--require-signatures`.

## Go

```go
reg, err := verifiers.Load("ci/verifiers.yaml")      // or verifiers.LoadEmbedded(), empty today
res, err := attestation.New().VerifyVSA(ctx, env, &attestation.VSAOptions{
    Verifiers: []attestation.VerifierBinding{{ID: "https://github.com/slsa-framework/source-actions"}},
    Registry:  reg,
})
```
