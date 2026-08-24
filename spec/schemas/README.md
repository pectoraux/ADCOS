# ADCOS Machine-Readable Schemas

## Status

**ACTIVE — Canonical Schema Location**

This directory is the canonical location for ADCOS machine-readable protocol schemas and registries. The location and conventions were established by WORK-001; the vocabulary and registry model by WORK-002; the protocol version line, envelope schema, and compatibility semantics by WORK-003 (versioned protocol envelope and serialization). WORK-003 deliberately implements no wire/protocol runtime behavior beyond the envelope/serialization library in `protocol/`.

## Structure

```text
spec/schemas/
  registries/
    domain-object-registry.json    the 11 frozen architecture nouns → stable IDs + schema references
    access-profile-registry.json   access/technology profiles (5G, LTE, Wi-Fi, ..., future IMT) as registry data
    capability-registry.json       capability identifiers, core- or profile-scoped
    identity-profile-registry.json identity profiles: derivation rules, key roles, algorithms (WORK-004)
  protocol.json                    protocol version line, envelope reference, message-type grammar, codec statuses (WORK-003)
  envelope.schema.json             the frozen §7 protocol envelope schema (WORK-003)
  <noun>.schema.json               one JSON Schema (draft 2020-12) per frozen domain object
```

## Core boundary

```text
ADCOS core nouns (domain-object-registry)
        ↓
stable technology-neutral IDs (adcos.*)
        ↓
access/profile registries (access.*, capability.*)
        ↓
5G / IMT-2030 / future technologies — registry DATA, never core domain types
```

- Core domain object IDs (`adcos.node`, `adcos.identity`, `adcos.adapter`, `adcos.capability`, `adcos.link`, `adcos.path`, `adcos.session`, `adcos.resource`, `adcos.intent`, `adcos.federation`, `adcos.evidence`) never encode an access technology, radio generation, standards body, vendor, or implementation language. `tools/schema_check.py` (SCHEMA-04) rejects any technology token in a core identifier.
- Access technologies — including 5G (`access.3gpp.nr.imt2020`) and the reserved future IMT-2030 path (`access.3gpp.nr.imt2030`) — are entries of the access-profile registry, consumed through the adapter boundary (LOCK-001..LOCK-003). No core state machine may branch on these identifiers (architecture §8).
- The access registry contains all nine frozen technology identifiers from architecture §8 plus a reserved IMT-2030 placeholder (identifier only; no 6G semantics specified or frozen) and the generic experimental profile backing the generic adapter of architecture §10.5.

## Conventions

- Files are UTF-8 JSON in canonical form: sorted keys, 2-space indent, trailing newline (SCHEMA-01). Registry artifacts contain no timestamps, no machine-local paths, and no nondeterministic generated values; ordering is stable wherever ordering is semantically irrelevant. (Note: this repository canonical form is distinct from the *wire* canonical JSON form implemented by `protocol/canonicalization.py`, which is compact and used for encoding/signature input material.)
- Every artifact declares a top-level `schema_version` string (`MAJOR.MINOR`) and the `architecture_version` it is written against (SCHEMA-02; never greater than the Architecture Version declared in `spec/architecture.md` Status). The `architecture_version` field is a written-against reference, not an Architecture Version declaration.
- The **Protocol Version** line is declared in `spec/schemas/protocol.json` (`protocol_version` field, established by WORK-003) — an independent version kind, never conflated with architecture/schema/implementation versions (spec/governance.md §3).
- Registration is additive: appending new entries is a minor `schema_version` bump; removing, renaming, or reinterpreting entries is a breaking change (major bump) and requires an Architecture Change Request (`spec/change-control.md`).
- Domain-object schemas are standard JSON Schema draft 2020-12 documents, referenced from the domain-object registry (`schema_ref` + `schema_id` + matching `schema_version`; SCHEMA-05). Each schema encodes exactly the frozen field lists of architecture §6 with `additionalProperties: true` so the model evolves additively (LOCK-014). Structures the architecture does not freeze (e.g. resource accounting, trust state) are open objects owned by later Work Items.
- The envelope schema (`envelope.schema.json`) is referenced from `protocol.json`; its `message_type` pattern must equal `protocol.json`'s `message_type_grammar` mechanically (SCHEMA-07 — single source of truth).
- Closed `enum`s are used only where the frozen architecture defines a closed set (link state dimensions §11, resource kinds/availability §17, evidence types §6.11). Evolving vocabularies (intent metrics §6.9, capability references, envelope extension entries) are open so future entries never require schema changes.

## Unknown-identifier semantics

Registries with extension surface (access-profile, capability) declare an `unknown_id_policy`. Identifier classification (`tools/schema_check.py: classify_id`):

- **known** — registered in the registry;
- **unknown** — well-formed per the registry's `id_grammar` but not registered. Consumers must preserve unknown identifiers, must not coerce them to any registered identifier, and may reject them only where an explicit consuming contract requires a known identifier. Unknown future capabilities are safely ignorable (architecture §2 P4);
- **invalid** — malformed (fails the `id_grammar`). Rejected by validators.

The architecture's `access.3gpp.future.unknown` example (§8) is realized by this classification rule rather than as a concrete registry entry. These semantics are proven by `tools/schema_selftest.py` (unknown/invalid distinction, no-coercion, pass-through in valid object instances).

## Validation tooling

```bash
python3 tools/spec_check.py       # WORK-001 governance/specification consistency checks
python3 tools/schema_check.py     # WORK-002/003 registry/schema/protocol-artifact consistency checks (SCHEMA-01..07)
python3 tools/schema_selftest.py  # WORK-002/003 registry compatibility + protocol-artifact negative tests
python3 tools/envelope_selftest.py  # WORK-003 envelope/serialization compatibility matrix, golden vectors, property/fuzz
python3 tools/identity_selftest.py   # WORK-004 identity lifecycle, rotation, revocation, secret isolation
python3 tools/capability_selftest.py  # WORK-005 capability statements, negotiation, open-world semantics
python3 tools/discovery_selftest.py   # WORK-006 peer discovery, convergence, replay defense, freshness
```

All are zero-dependency (Python 3 standard library), fully offline, deterministic (byte-identical repeat output), and run in CI on every push and pull request. The check catalogs and test case lists are documented in `tools/README.md`. The envelope implementation itself lives in the `protocol/` package (see `protocol/README.md`), including the provisional compact codec — the production canonicalization profile remains unfrozen until later conformance work.
