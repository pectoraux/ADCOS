# WORK-050 Architect Handoff — Platform Connectivity Sharing Capability & Isolation Matrix

**Authorization:** WORK-050-CORE-001
**Decision:** DEC-0078
**Baseline:** 89ad6ff3d168c59256c3e805539eb9ca22f6b3bc
**Implementer:** Z.ai

> Status: ACTIVE — Architect activation handoff (DEC-0078). This document is
> the governance-authored activation contract frozen by the DEC-0078
> transition. It is not a WORK-050 implementation artifact; the implementation
> delivery updates it from its own delivery PR, exactly one PR, cut from the
> mainline that carries the authorization record.

## Objective

Implement the versioned, deterministic platform capability model for ADCOS
connectivity sharing: which operating systems, device classes, network
configurations, and deployment modes can safely provide or consume leased
connectivity, which isolation primitives are available, and which sharing
modes are unsupported or require additional infrastructure.

WORK-050 is a **capability/isolation declaration authority** — advisory
capability input consumed by WORK-048 (provider sharing runtime) and WORK-049
(provider & buyer client runtime). It is NOT routing, NetworkPath, session,
identity, transport, commercial, usage, payment, marketplace, or enforcement
authority, and it does not implement WORK-048/WORK-049 enforcement.

## Required invariants

1. The registry is descriptive/capability authority only: a capability
   declaration is never confused with proof that a particular physical
   deployment currently works.
2. UNKNOWN is never treated as SUPPORTED; UNSUPPORTED fails closed;
   RESTRICTED yields constrained declarations only; SUPPORTED is a
   declaration that the canonical enforcement owners (W048/W049/NetworkPath)
   may consume, never a bypass of their checks.
3. Never assume a platform can share connectivity merely because of an
   OS/platform label, because it can create a socket, or because it can
   enable tethering.
4. Sharing modes (for example application proxy, OS-level forwarding,
   tether-backed path, gateway/router mode) are capability classes, never
   universal assumptions.
5. Isolation must be based on enforceable platform mechanisms, not
   application declarations alone where stronger isolation is required;
   isolation primitive declarations carry their minimum security/isolation
   properties explicitly.
6. Capability declarations never become enforcement, and no second
   containment authority is created: W048/ACR-012 own containment
   enforcement; the frozen ACR-012 capability vocabulary
   (unsupported/unknown/supported/restricted) is reused, never redefined.
7. Metering capability and byte-counting authority are declared, never
   becoming commercial truth; lease-enforcement capability (time, byte,
   concurrency, emergency stop) is declared, never enforced here.
8. No SOFTWARE evidence is promoted into a PHYSICAL PASS: real platform
   capability/isolation behavior on physical devices and networks remains
   separately governed PHYSICAL evidence (and W040's obligations
   EVID-007/EVID-008 remain W040-owned and open).
9. WORK-050 never becomes a hard dependency that blocks WORK-048 or
   WORK-049: the W050 -> W048/W049 DAG edges are advisory capability-input
   edges sanctioned by ACR-011, not hard gates.
10. ACR-012, WORK-048, and WORK-049 are not altered by WORK-050; their
    accepted contracts are frozen.
11. The registry and evaluation are versioned and auditable: historical
    capability decisions are preserved and never silently rewritten;
    evaluation is deterministic and repeatable (byte-identical repeat output,
    independence from hash iteration ordering / PYTHONHASHSEED where
    applicable).
12. Forbidden implementation territory (enforced by the authorization's
    out_of_scope list): OS firewall/tether/VPN/proxy implementation;
    packet-forwarding implementation; NetworkPath/routing/session/transport
    implementation; commercial/payment/usage authority; W048 containment
    enforcement; W049 client runtime implementation; marketplace
    implementation; physical-evidence claims; and any modification of
    `spec/architect/` from the implementation PR.

## Canonical dependency statement

WORK-050 provides capability declarations consumed by WORK-048/WORK-049 —
but WORK-050 does not implement WORK-048/WORK-049 enforcement.

WORK-050's hard dependencies are exactly the frozen registry declaration
(Dependencies: none). It composes — as advisory input only — the accepted
ACR-009 commercial planning context (DEC-0050/PR #82) under which it is
defined, the ACR-012 frozen capability vocabulary, the ACR-005 NetworkPath
platform boundary, WORK-045 jurisdiction-aware eligibility where applicable,
and the `/adapters` platform family contracts it describes capability for;
it never imports or mutates their enforcement internals.

## Scope

The frozen implementation scope is recorded verbatim in
`spec/architect/authorizations/WORK-050.yaml`: the versioned platform
capability registry; provider/buyer role capability declarations;
sharing-mode capability classes; isolation primitive declarations; minimum
security/isolation properties; metering capability declarations;
lease-enforcement capability declarations; lifecycle/platform constraints;
deterministic compatibility evaluation; explicit
supported/restricted/unsupported/unknown states; versioned, auditable
historical decisions; deterministic software evidence; and
authority/import/source-boundary audits.

The literal repository path surface of the eventual implementation delivery
(the capability-matrix package directory, the dedicated deterministic battery
under `tools/`, `docs/WORK-050-evidence.md`, updates to this handoff, and
additive CI wiring) is pinned by the Architect's implementation directive
before any implementation delta; a DEC-0069-style authorization-scope
reconciliation records the literal path prefixes if needed. Until then no
implementation delta is covered by the authorization (fail closed).

## Verification

The delivery PR must demonstrate:

- deterministic capability evaluation for provider/buyer/platform
  combinations over versioned registries, with explicit supported /
  restricted / unsupported / unknown outcomes;
- negative fail-closed proofs that unknown and unsupported capabilities fail
  closed and that no OS/platform label implies sharing support;
- explicit, testable isolation requirements per sharing mode, with
  minimum security properties stated per isolation primitive;
- metering and lease-enforcement capability declarations that remain
  declarations (never commercial truth, never enforcement);
- versioned, auditable historical capability decisions with deterministic
  replay and hash-seed independence;
- composition with W048/W049 and NetworkPath without bypassing their
  authorities (boundary and forbidden-import audits);
- restart/replay determinism and exact WORK-050-CORE-001 authorization
  provenance.

The delivery PR must not modify `spec/architect/` and must remain within
`WORK-050-CORE-001`. Any required architecture or authorization change is a
separate Architect governance action.

## Acceptance

One implementation PR only, cut from the mainline that carries the
authorization record. The Architect reviews the exact delivery SHA, evidence
manifest, scope audit, CI/provenance condition, authority boundaries,
determinism, honesty of the SOFTWARE/PHYSICAL evidence classification, and
every invariant above before acceptance. W040 remains independent and
in-review; no other Work Item is activated by this handoff.
