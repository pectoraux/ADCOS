# ADCOS Architect Review Protocol

**Status:** ACTIVE REVIEW PROCESS — subordinate to frozen architecture and change control.

## Gate A — readiness

1. Confirm the Work Item exists in `spec/work-items.md`.
2. Confirm every hard dependency is Architect-accepted, not merely merged.
3. Confirm the Architect explicitly designated this Work Item as execution-ready when the one-item rule applies.
4. Confirm the implementation branch is based on the accepted current `main`.

## Gate B — scope and authority

1. Is the diff limited to the Work Item?
2. Which frozen architecture sections and LOCK identifiers govern it?
3. What authority already owns every consumed semantic?
4. Does the Work Item create any new authority? Why is that authority not already owned?
5. Who can mint each authority-bearing object?
6. Who can mutate each persistent state?
7. Can a caller manufacture a structurally valid substitute?
8. Does the implementation verify provenance rather than only integrity?
9. Does it introduce hidden imports or semantic dependencies?
10. Does it bypass an upstream authority by re-evaluating or reconstructing its result?

## Gate C — adversarial security review

Ask explicitly:

```text
Integrity vs provenance:
    Can a self-consistent but unrecorded object pass?

Authority replacement:
    Can later rebinding/global replacement alter already-established state?

Mutable trust:
    Can attacker-reachable mutable state manufacture authority?

Replay:
    Is security-sensitive replay state changed before authentication/verification?

Cleanup:
    Can cleanup fail while the implementation still reports success?

Recovery:
    Can restart/partition resurrect expired/revoked/superseded authority?

Adapter boundary:
    Can vendor/access-specific semantics leak into core?

Audit:
    Can an unexpected exception escape the intended universal audit boundary?

Discrimination:
    Would the regression fail against the vulnerable implementation?
```

## Gate D — verification

Report separately:
- **Architecture conformance:** architecture/locks/ownership/imports/diff scope.
- **Automated verification:** deterministic tests, negative tests, property/fuzz, replay/failure/recovery as applicable.
- **External evidence:** real implementation/device/lab/pilot requirements. `OPEN` or `BLOCKED` stays visible.

A simulator/reference peer cannot satisfy a frozen independent-evidence gate.

## Gate E — acceptance

The acceptance record must state:

```text
Process state: ACCEPTED
Architecture conformance: PASS
Automated verification: PASS
External evidence: PASS | OPEN | BLOCKED | NOT REQUIRED
Architect: explicit decision
```

Acceptance is not implied by merge, CI, PR closure, or self-assessment.

## Gate F — architecture change trigger

Stop and require an ACR when a frozen rule, frozen dependency, protocol/state meaning, authority ownership, or frozen evidence requirement must change.

Do not repair an architecture conflict by editing only implementation or explanatory documentation.
