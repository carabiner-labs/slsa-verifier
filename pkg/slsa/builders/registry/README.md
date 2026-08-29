# Embedded builder registry

The YAML files in this directory are compiled into the verifier as its
default builder registry: for each known builder, the signing identity
its provenance must carry for `builder.id` to count as proven. They are
merged in path order at load time.

The file format, the binding rules, and how to extend the registry from
the command line are documented in
[docs/builder-registry.md](../../../../docs/builder-registry.md).
