# ADCOS Specification System

**Canonical repository entry point for architecture review and implementation handoff.**

ADCOS uses a layered specification system. This page provides navigation and precedence; it does not create a new architecture authority.

## 1. Authority order

### Level 1 — current frozen architecture state
These four artifacts are the normative specification set:

1. `spec/architecture.md` — full architecture and protocol semantics.
2. `spec/architecture-lock.md` — compact enforceable non-negotiable locks. For an overlapping rule, the lock is the enforceable constraint; any contradiction with the full architecture is a blocking specification defect and must not be resolved by an implementation.
3. `spec/dependency-graph.md` — sequencing authority for Work Items.
4. `spec/work-items.md` — the approved implementation backlog and frozen per-Work-Item requirements.

### Level 2 — accepted architecture changes
`spec/acr/ACR-*.md` records the approved reason, impact and decision. An accepted ACR is authoritative through the synchronized frozen artifacts it changes; the ACR record is not an alternate architecture.

### Level 3 — process authorities
`spec/governance.md`, `spec/change-control.md`, and `spec/workflow.md` explain how the frozen architecture is governed and reviewed. They may not silently modify Level-1 semantics.

### Level 4 — derived implementation system
`docs/specification/` and `docs/handoffs/` summarize frozen requirements, authority ownership, invariants, matrices, and implementation instructions. They are intentionally non-authoritative. They must never override a frozen rule.

`spec/prompts/` remains the Architect-authored per-Work-Item prompt surface where present; a prompt is subordinate to the frozen Work Item and architecture.

### Level 5 — accepted implementation precedent and evidence
Merged code, package READMEs, selftests, PR review records, and worklogs are evidence and precedent. They may reveal a resolved interpretation, but they cannot silently override frozen architecture. If implementation conflicts with frozen architecture, the implementation is wrong unless an accepted ACR changed the architecture.

## 2. Architect reading order

```text
spec/README.md
→ relevant frozen architecture sections
→ relevant LOCK-XXX clauses
→ frozen Work Item + frozen DAG
→ docs/specification/authority-model.md
→ docs/specification/invariant-catalog.md
→ docs/specification/semantic-ownership-matrix.md
→ docs/specification/state-ownership-matrix.md
→ docs/specification/minting-authority-registry.md
→ docs/specification/forbidden-dependency-matrix.md
→ docs/handoffs/WORK-XXX.md
→ accepted implementation precedent / review history
```

Then run `docs/specification/architect-review-protocol.md` and the integrity checks.

## 3. Frozen vs derived surface

### Frozen specification surface
```text
spec/architecture.md
spec/architecture-lock.md
spec/work-items.md
spec/dependency-graph.md
spec/schemas/
```

Semantic changes to frozen artifacts follow the existing ACR/schema rules.

### Derived / process surface
```text
spec/README.md
spec/governance.md
spec/change-control.md
spec/workflow.md
spec/acr/
spec/prompts/
docs/specification/
docs/handoffs/
tools/specification_integrity_check.py
tools/specification_integrity_selftest.py
```

Derived artifacts cannot acquire authority merely by being referenced more often.

## 4. Current baseline

At the migration baseline, `main` is `62f5b9d3075871a9f06d9806f51b37658a6995cc`, W029 is merged, and W030 remains under Architect re-review and is not accepted on current `main`. This snapshot must be refreshed when `main` changes.

## 5. Integrity commands

```bash
python3 tools/spec_check.py
python3 tools/specification_integrity_check.py
python3 tools/specification_integrity_selftest.py
```

The first validates existing repository specification mechanics. The second validates the migration's canonical derived artifacts. The third validates the new checker.

## 6. Zero-drift rule

Do not fill an architectural gap by assumption. Resolve from frozen authority and accepted history first. If a genuine contradiction remains, record an **OPEN ARCHITECTURAL QUESTION** and stop the affected semantic decision until the Architect resolves it.
