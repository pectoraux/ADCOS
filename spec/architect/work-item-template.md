# ADCOS Work Item Template

## Status

**ACTIVE — Persistent Governance Authority (template; follows the frozen Architecture Version 1.0)**

Canonical reusable handoff template. Every future Work Item authorization and
handoff is derived from this template. It is a superset of the minimum
prompt contract frozen in `spec/dependency-graph.md` §6 (Work Item ID,
architecture version, relevant sections, lock clauses, dependencies,
acceptance criteria, expected files/modules, out of scope, verification
requirements, required tests, forbidden shortcuts): a handoff that satisfies
this template satisfies §6; a handoff may never drop a §6 field.

---

## Template

```markdown
# WORK-XXX — <title>

## Identity
- Work Item ID: WORK-XXX
- Title: <title from spec/work-items.md>
- Phase: <execution phase from spec/dependency-graph.md §3>
- Critical path: yes | no

## Objective
<one paragraph, from the frozen backlog; never reinterpreted>

## Baseline
- main SHA the branch must be cut from
- architecture version reference (declared only in spec/architecture.md)

## Hard dependencies
<from spec/work-items.md "Dependencies:"> — each with its acceptance
decision (DEC-NNNN) and merge SHA from the execution ledger

## Soft dependencies
<parallel/adapter dependencies, per spec/dependency-graph.md §5>

## Authority consumed
<exact authorities this Work Item composes over, e.g. the W003 envelope,
the W015 FederationStore — with their owning modules>

## Authority created
<new authority this Work Item establishes, and its single owner>

## Authority forbidden
<second authorities, shadow state, bypasses that must not exist>

## Interfaces
<frozen public API surface, exports, schemas, registries>

## State model
<value records, lifecycle states, determinism rules>

## Failure model
<failure classes, fail-closed semantics, cleanup, recovery>

## Security model
<trust boundary, secrets handling (LOCK-023), audit surface>

## Persistence/recovery
<what is persisted, checkpoint/recovery semantics, replay safety>

## Adapter boundary
<what stays behind the adapter seam; vendor/access leakage prohibited>

## Verification
<required battery, CI wiring order (work-item order), determinism,
PYTHONHASHSEED invariance, structural audits, anti-promotion proofs>

## Acceptance gate
<the frozen acceptance criteria and definition of done, mapped to evidence;
evidence classes per criterion (SOFTWARE / PHYSICAL / OPERATIONAL)>

## Evidence classes
<for each external-evidence criterion: class, required environment, honest
statuses (PASS / PARTIAL / NOT-TESTABLE / OPEN); never promote software
evidence to physical>

## Out-of-scope
<explicit forbidden territory>

## Architectural precedents
<accepted implementations whose patterns this item composes (with their
DEC-NNNN records)>

## Known open questions
<questions the Architect must answer before or during implementation>
```

## Usage rules

1. The Architect instantiates this template in the authorization record
   (`spec/architect/authorizations/WORK-XXX.yaml`) and/or the handoff
   document; Z.ai implements from that instantiation only.
2. Objective, acceptance criteria, and definition of done are quoted from
   `spec/work-items.md` — never reinterpreted or simplified.
3. Forbidden shortcuts must be stated explicitly (e.g. "no mocks replacing
   production paths in acceptance evidence").
4. Evidence obligations declared here are registered in
   `spec/architect/evidence-obligations.yaml` at delivery/review time.
