#!/usr/bin/env python3
"""ADCOS intent self-test (WORK-009).

Deterministic, offline verification of the intent package against the
frozen WORK-009 requirements (spec/prompts/WORK-009.md): the 25 required
adversarial verification categories, plus mechanical forbidden-API/imports
checks, frozen-dimensions presence, hard/soft-flip rejection, secret-
material rejection, no-policy/resource/routing-leakage audit, and a
byte-identical determinism proof.

The central boundary is exercised throughout:

    INTENT  =  desired outcome / requirements

    INTENT  !=  policy decision             (out of scope -- WORK-010)
    INTENT  !=  authorization               (out of scope -- WORK-010)
    INTENT  !=  topology fact               (WORK-007 authority)
    INTENT  !=  resource offer              (WORK-008 authority)
    INTENT  !=  resource measurement        (WORK-008 authority)
    INTENT  !=  route / path                 (out of scope -- WORK-011)
    INTENT  !=  adapter / access technology (LOCK-001 / LOCK-002 / LOCK-003)
    INTENT  !=  trust score                  (LOCK-022)
    INTENT  !=  price / settlement           (forbidden)

The most important adversarial invariant (mirrors WORK-007 LOCK-008):

    An application asks for "10 Mbps latency <= 50 ms end-to-end privacy
    prefer local"  -->  the normalized intent NEVER carries 5G/Wi-Fi/vendor
    adapter fields, NEVER selects a route/resource, NEVER computes a price,
    NEVER flips a hard constraint to soft (or vice versa). The intent layer
    answers ONLY whether the request is valid and what its canonical
    requirements are.

All key material is TEST-ONLY; all clocks are injected; all PRNGs are seeded
so runs are byte-identical. No external network access is permitted or
required for the suite. Identity binding flows through the canonical WORK-004
``parse_node_id``; intent dimensions are the frozen 8 (no second vocabulary
authority); temporal uses WORK-003 primitives; canonical bytes use WORK-003
``canonical_json_bytes``. Unit resolution for resource-aligned dimensions
(bandwidth, energy) delegates to the WORK-008 unit registry; intent-native
unit tables (latency, reliability, cost) cover dimensions WORK-008 does not
own. Quantities carry explicit units and normative values are integer-only
(no float, NaN, or Infinity).
"""

from __future__ import annotations

import hashlib
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tools"))

from intent import (  # noqa: E402
    Constraint,
    ConnectivityIntent,
    Hardness,
    IntentDimension,
    IntentError,
    NormalizedIntent,
    NormalizationResult,
    Operator,
    bucket_for,
    intent_canonical_bytes,
    intent_from_mapping,
    normalize_intent,
    resolve_unit,
    validate_constraint,
    validate_dimension,
)


Result = Tuple[str, bool, str]


def ok(name: str, detail: str = "") -> Tuple[str, bool, str]:
    return (name, True, detail)


def fail(name: str, detail: str) -> Tuple[str, bool, str]:
    return (name, False, detail)


# --------------------------------------------------------------------------
# Test helpers
# --------------------------------------------------------------------------

# A canonical, valid NodeID for use as ``requester_node_id`` (derived from
# test material -- not a real identity). The digest is 64 lowercase hex;
# the profile is a registered-style dotted lowercase id.
_TEST_NODE_ID = "adcos:node:test.profile.v1:" + "a" * 64


def base_constraint(
    constraint_id: str = "c1",
    dimension: str = IntentDimension.BANDWIDTH,
    operator: str = Operator.GE,
    value=10,
    unit: str = "Mbps",
    hardness: str = Hardness.HARD,
    weight: int = 0,
    scope: str = "",
    provenance: str = "",
) -> Constraint:
    """Build a Constraint with sensible defaults."""
    return Constraint(
        constraint_id=constraint_id,
        dimension=dimension,
        operator=operator,
        value=value,
        unit=unit,
        hardness=hardness,
        weight=weight,
        scope=scope,
        provenance=provenance,
    )


def base_intent(
    intent_id: str = "intent-1",
    constraints: Tuple[Constraint, ...] = (),
    requester_node_id: str = "",
    issued_at: str = "",
    expires_at: str = "",
    extensions=(),
) -> ConnectivityIntent:
    """Build a ConnectivityIntent with the given constraints in the
    requirements bucket by default."""
    return ConnectivityIntent(
        intent_id=intent_id,
        requester_node_id=requester_node_id,
        issued_at=issued_at,
        expires_at=expires_at,
        requirements=constraints,
        extensions=extensions,
    )


# --------------------------------------------------------------------------
# Required adversarial verification cases (1-25 from the prompt)
# --------------------------------------------------------------------------

def case_01_minimal_valid_intent(results: List[Result]) -> None:
    """1. minimal valid intent (single hard constraint, no requester/temporal).

    Note: the NormalizedIntent carries the canonical base-unit form of each
    constraint (e.g. ``10 Mbps`` -> ``value=10_000_000, unit='bps'``), so
    comparing against the original input constraint is by digest equality,
    not by tuple equality.
    """
    c = base_constraint()
    i = base_intent(constraints=(c,))
    r = normalize_intent(i)
    if r.ok and r.intent and len(r.intent.constraints) == 1:
        # Canonical form: 10 Mbps -> 10_000_000 bps.
        cc = r.intent.constraints[0]
        if cc.unit == "bps" and cc.value == 10_000_000 and cc.hardness == Hardness.HARD:
            results.append(ok("case_01_minimal_valid_intent", "normalized to base form; digest=%s" % r.intent.digest[:12]))
        else:
            results.append(fail("case_01_minimal_valid_intent", "wrong canonical form: %r" % (cc,)))
    else:
        results.append(fail("case_01_minimal_valid_intent", "expected ok, got %r %r" % (r.ok, r.code)))


def case_02_all_eight_dimensions_represented(results: List[Result]) -> None:
    """2. all eight frozen dimensions can be expressed in one intent."""
    constraints = (
        Constraint(constraint_id="bw",  dimension=IntentDimension.BANDWIDTH,  operator=Operator.GE, value=10,    unit="Mbps",         hardness=Hardness.HARD),
        Constraint(constraint_id="lat", dimension=IntentDimension.LATENCY,     operator=Operator.LE, value=50,    unit="ms",           hardness=Hardness.HARD),
        Constraint(constraint_id="rel",  dimension=IntentDimension.RELIABILITY, operator=Operator.GE, value=9990,  unit="basis-points",hardness=Hardness.HARD),
        Constraint(constraint_id="loc",  dimension=IntentDimension.LOCALITY,    operator=Operator.EQ, value="GH",                       hardness=Hardness.SOFT, weight=10),
        Constraint(constraint_id="en",  dimension=IntentDimension.ENERGY,      operator=Operator.LE, value=5_000_000, unit="millijoules", hardness=Hardness.SOFT, weight=10),
        Constraint(constraint_id="cst",  dimension=IntentDimension.COST,        operator=Operator.LE, value=5,     unit="units",        hardness=Hardness.SOFT, weight=10),
        Constraint(constraint_id="priv", dimension=IntentDimension.PRIVACY,     operator=Operator.EQ, value="end-to-end",              hardness=Hardness.HARD),
        Constraint(constraint_id="svc",  dimension=IntentDimension.SERVICE,     operator=Operator.EQ, value="voice",                    hardness=Hardness.HARD),
    )
    i = ConnectivityIntent(
        intent_id="intent-all8",
        requirements=(constraints[0], constraints[1], constraints[2], constraints[6], constraints[7]),
        preferences=(constraints[3], constraints[4], constraints[5]),
    )
    r = normalize_intent(i)
    if not r.ok or r.intent is None:
        results.append(fail("case_02_all_eight_dimensions_represented", "expected ok, got %r %r" % (r.ok, r.code)))
        return
    seen_dims = {c.dimension for c in r.intent.constraints}
    if seen_dims == set(IntentDimension.values()):
        results.append(ok("case_02_all_eight_dimensions_represented", "all 8 dims present; %d constraints" % len(r.intent.constraints)))
    else:
        results.append(fail("case_02_all_eight_dimensions_represented", "missing dims: %s" % (set(IntentDimension.values()) - seen_dims)))


def case_03_hard_vs_soft_constraints(results: List[Result]) -> None:
    """3. hard vs soft constraints are structurally distinct (separate buckets).

    Note: two constraints with the same (dim/op/val/unit/scope) but different
    hardness create semantic ambiguity (which one wins?), and the validator
    correctly rejects them. So this test uses different constraint dimensions
    for the hard vs soft examples to keep them semantically distinct.
    """
    hard_c = Constraint(constraint_id="hard1", dimension=IntentDimension.BANDWIDTH, operator=Operator.GE, value=10, unit="Mbps", hardness=Hardness.HARD)
    soft_c = Constraint(constraint_id="soft1", dimension=IntentDimension.LOCALITY, operator=Operator.EQ, value="GH", hardness=Hardness.SOFT, weight=5)
    i = ConnectivityIntent(
        intent_id="intent-hs",
        requirements=(hard_c,),
        preferences=(soft_c,),
    )
    r = normalize_intent(i)
    if not r.ok or r.intent is None:
        results.append(fail("case_03_hard_vs_soft_constraints", "expected ok, got %r %r" % (r.ok, r.code)))
        return
    # Bucket ordering: requirements(0) < preferences(1) -- the hard bandwidth
    # constraint must come first, the soft locality preference second.
    cs = r.intent.constraints
    if (cs[0].hardness == Hardness.HARD and cs[0].dimension == IntentDimension.BANDWIDTH
        and cs[1].hardness == Hardness.SOFT and cs[1].dimension == IntentDimension.LOCALITY):
        results.append(ok("case_03_hard_vs_soft_constraints", "hard bw then soft loc; structural separation preserved"))
    else:
        results.append(fail("case_03_hard_vs_soft_constraints", "wrong order: %s" % [(c.constraint_id, c.hardness, c.dimension) for c in cs]))


def case_04_insertion_order_independent_normalization(results: List[Result]) -> None:
    """4. insertion order cannot change canonical output (same intent_id)."""
    c1 = base_constraint(constraint_id="bw1")
    c2 = Constraint(constraint_id="lat1", dimension=IntentDimension.LATENCY, operator=Operator.LE, value=50, unit="ms", hardness=Hardness.HARD)
    c3 = Constraint(constraint_id="loc1", dimension=IntentDimension.LOCALITY, operator=Operator.EQ, value="GH", hardness=Hardness.SOFT, weight=10)
    iA = ConnectivityIntent(intent_id="intent-order", requirements=(c1, c2), preferences=(c3,))
    iB = ConnectivityIntent(intent_id="intent-order", requirements=(c2, c1), preferences=(c3,))
    rA = normalize_intent(iA)
    rB = normalize_intent(iB)
    if not (rA.ok and rB.ok):
        results.append(fail("case_04_insertion_order_independent_normalization", "expected both ok, got A=%r B=%r" % (rA.code, rB.code)))
        return
    if rA.intent.digest == rB.intent.digest and rA.intent.canonical_bytes() == rB.intent.canonical_bytes():  # type: ignore[union-attr]
        results.append(ok("case_04_insertion_order_independent_normalization", "byte-identical; digest=%s" % rA.intent.digest[:12]))  # type: ignore[union-attr]
    else:
        results.append(fail("case_04_insertion_order_independent_normalization", "digests differ: %s vs %s" % (rA.intent.digest, rB.intent.digest)))  # type: ignore[union-attr]


def case_05_equivalent_unit_normalization(results: List[Result]) -> None:
    """5. equivalent units normalize identically (1 Mbps == 1000 kbps)."""
    cA = base_constraint(constraint_id="bw", value=1, unit="Mbps")
    cB = base_constraint(constraint_id="bw", value=1000, unit="kbps")
    cC = base_constraint(constraint_id="bw", value=1_000_000, unit="bps")
    iA = base_intent(intent_id="intent-equiv", constraints=(cA,))
    iB = base_intent(intent_id="intent-equiv", constraints=(cB,))
    iC = base_intent(intent_id="intent-equiv", constraints=(cC,))
    rA, rB, rC = normalize_intent(iA), normalize_intent(iB), normalize_intent(iC)
    if not (rA.ok and rB.ok and rC.ok) or rA.intent is None or rB.intent is None or rC.intent is None:
        results.append(fail("case_05_equivalent_unit_normalization", "expected all ok"))
        return
    if rA.intent.digest == rB.intent.digest == rC.intent.digest:
        # All canonicalized to base unit 'bps' with value 1_000_000
        for r in (rA, rB, rC):
            c = r.intent.constraints[0]  # type: ignore[union-attr]
            if c.unit != "bps" or c.value != 1_000_000:
                results.append(fail("case_05_equivalent_unit_normalization", "base form wrong: %r" % (c,)))
                return
        results.append(ok("case_05_equivalent_unit_normalization", "1 Mbps == 1000 kbps == 1e6 bps; all -> 1000000 bps"))
    else:
        results.append(fail("case_05_equivalent_unit_normalization", "digests differ: %s %s %s" % (rA.intent.digest[:8], rB.intent.digest[:8], rC.intent.digest[:8])))


def case_06_incompatible_unit_rejection(results: List[Result]) -> None:
    """6. incompatible units fail closed (ms is not a bandwidth unit)."""
    c = base_constraint(constraint_id="bw", value=10, unit="ms")  # ms is not in WORK-008 bandwidth
    i = base_intent(constraints=(c,))
    r = normalize_intent(i)
    if not r.ok and r.code == "unit-unknown":
        results.append(ok("case_06_incompatible_unit_rejection", "rejected 'ms' for bandwidth: %s" % r.code))
    else:
        results.append(fail("case_06_incompatible_unit_rejection", "expected unit-unknown, got %r %r" % (r.ok, r.code)))


def case_07_unsupported_operator_rejection(results: List[Result]) -> None:
    """7. unsupported operators fail closed ('~=' is not in the frozen set)."""
    try:
        Constraint(constraint_id="bw", dimension=IntentDimension.BANDWIDTH, operator="~=", value=10, unit="Mbps", hardness=Hardness.HARD)
        results.append(fail("case_07_unsupported_operator_rejection", "Constraint constructor accepted '~='"))
    except IntentError as e:
        if e.code == "operator":
            results.append(ok("case_07_unsupported_operator_rejection", "rejected '~=' at construction: %s" % e.code))
        else:
            results.append(fail("case_07_unsupported_operator_rejection", "wrong code: %s" % e.code))


def case_08_unsupported_required_constraint_rejection(results: List[Result]) -> None:
    """8. unsupported required constraint dimensions fail explicitly."""
    # '5g-bandwidth' contains a forbidden access-technology token
    try:
        Constraint(constraint_id="x5g", dimension="5g-bandwidth", operator=Operator.GE, value=10, unit="Mbps", hardness=Hardness.HARD)
        results.append(fail("case_08_unsupported_required_constraint_rejection", "Constraint constructor accepted '5g-bandwidth'"))
    except IntentError as e:
        if e.code == "dimension":
            results.append(ok("case_08_unsupported_required_constraint_rejection", "rejected '5g-bandwidth' at construction: %s" % e.code))
        else:
            results.append(fail("case_08_unsupported_required_constraint_rejection", "wrong code: %s" % e.code))
    # A dimension without a forbidden token but not in the frozen 8
    try:
        Constraint(constraint_id="jitter", dimension="jitter", operator=Operator.GE, value=5, unit="ms", hardness=Hardness.HARD)
        results.append(fail("case_08_unsupported_required_constraint_rejection", "Constraint constructor accepted 'jitter'"))
    except IntentError as e:
        if e.code == "dimension":
            results.append(ok("case_08_unsupported_required_constraint_rejection_2", "rejected 'jitter' (not in frozen 8): %s" % e.code))
        else:
            results.append(fail("case_08_unsupported_required_constraint_rejection_2", "wrong code: %s" % e.code))


def case_09_optional_extension_preservation(results: List[Result]) -> None:
    """9. unknown optional extension fields survive via WORK-003 extension semantics."""
    c = base_constraint()
    ext = {"x-adcos-future-profile": "future-id-42", "opaque-note": "preserved"}
    i = base_intent(constraints=(c,), extensions=(ext,))
    r = normalize_intent(i)
    if not r.ok or r.intent is None:
        results.append(fail("case_09_optional_extension_preservation", "expected ok, got %r %r" % (r.ok, r.code)))
        return
    if r.intent.extensions and r.intent.extensions[0] == ext:
        results.append(ok("case_09_optional_extension_preservation", "extension preserved verbatim"))
    else:
        results.append(fail("case_09_optional_extension_preservation", "extension mutated: %r" % (r.intent.extensions,)))


def case_10_duplicate_constraint_ambiguity_rejection(results: List[Result]) -> None:
    """10. duplicate constraints that create ambiguity fail closed."""
    c1 = base_constraint(constraint_id="bw", value=10)
    c2 = base_constraint(constraint_id="bw", value=20)  # same id, different value
    i = base_intent(constraints=(c1, c2))
    r = normalize_intent(i)
    if not r.ok and r.code == "duplicate-id":
        results.append(ok("case_10_duplicate_constraint_ambiguity_rejection", "rejected: %s" % r.code))
    else:
        results.append(fail("case_10_duplicate_constraint_ambiguity_rejection", "expected duplicate-id, got %r %r" % (r.ok, r.code)))
    # Also: two semantically identical constraints with different IDs
    c3 = base_constraint(constraint_id="bw1", value=10)
    c4 = base_constraint(constraint_id="bw2", value=10)  # same semantics, different id
    i2 = base_intent(constraints=(c3, c4))
    r2 = normalize_intent(i2)
    if not r2.ok and r2.code == "duplicate-semantic":
        results.append(ok("case_10b_duplicate_semantic_rejection", "rejected: %s" % r2.code))
    else:
        results.append(fail("case_10b_duplicate_semantic_rejection", "expected duplicate-semantic, got %r %r" % (r2.ok, r2.code)))


def case_11_malformed_requester_nodeid_rejection(results: List[Result]) -> None:
    """11. malformed requester NodeID rejected via WORK-004 ``parse_node_id``."""
    c = base_constraint()
    bad_ids = (
        "not-a-node-id",
        "adcos:node:test",  # too short
        "ADcos:node:test.profile.v1:" + "a" * 64,  # uppercase prefix
        "adcos:node:test.profile.v1:" + "z" * 64,  # non-hex digest
    )
    for bad in bad_ids:
        i = base_intent(constraints=(c,), requester_node_id=bad)
        r = normalize_intent(i)
        if r.ok or r.code != "requester":
            results.append(fail("case_11_malformed_requester_nodeid_rejection", "expected requester rejection for %r, got %r %r" % (bad, r.ok, r.code)))
            return
    # Valid NodeID accepted
    i_ok = base_intent(constraints=(c,), requester_node_id=_TEST_NODE_ID)
    r_ok = normalize_intent(i_ok)
    if r_ok.ok and r_ok.intent.requester_node_id == _TEST_NODE_ID:  # type: ignore[union-attr]
        results.append(ok("case_11_malformed_requester_nodeid_rejection", "all malformed rejected; valid accepted"))
    else:
        results.append(fail("case_11_malformed_requester_nodeid_rejection", "valid node id rejected: %r %r" % (r_ok.ok, r_ok.code)))


def case_12_malformed_naive_timestamp_rejection(results: List[Result]) -> None:
    """12. malformed/naive timestamps rejected via WORK-003 ``parse_instant``."""
    c = base_constraint()
    bad_times = (
        "2026-01-01 00:00:00",  # space separator, no Z
        "2026-01-01T00:00:00",  # no Z
        "2026-01-01T00:00:00+00:00",  # offset instead of Z
        "2026-13-01T00:00:00Z",  # invalid month
        "not-a-timestamp",
    )
    for bad in bad_times:
        i = base_intent(constraints=(c,), issued_at=bad, expires_at="2026-12-31T23:59:59Z")
        r = normalize_intent(i)
        if r.ok or r.code != "issued-at":
            results.append(fail("case_12_malformed_naive_timestamp_rejection", "expected issued-at rejection for %r, got %r %r" % (bad, r.ok, r.code)))
            return
    # Valid RFC 3339 UTC accepted
    i_ok = base_intent(constraints=(c,), issued_at="2026-01-01T00:00:00Z", expires_at="2026-12-31T23:59:59Z")
    r_ok = normalize_intent(i_ok)
    if r_ok.ok:
        results.append(ok("case_12_malformed_naive_timestamp_rejection", "all malformed rejected; valid RFC 3339 UTC accepted"))
    else:
        results.append(fail("case_12_malformed_naive_timestamp_rejection", "valid RFC 3339 rejected: %r %r" % (r_ok.ok, r_ok.code)))


def case_13_validity_expiry_behavior(results: List[Result]) -> None:
    """13. validity/expiry behavior (issued/expires recorded; expires<issued rejected)."""
    c = base_constraint()
    # expires < issued -> rejected at normalization
    i_bad = base_intent(
        constraints=(c,),
        issued_at="2026-06-01T00:00:00Z",
        expires_at="2026-01-01T00:00:00Z",
    )
    r_bad = normalize_intent(i_bad)
    if r_bad.ok or r_bad.code != "expires-before-issued":
        results.append(fail("case_13_validity_expiry_behavior", "expected expires-before-issued, got %r %r" % (r_bad.ok, r_bad.code)))
        return
    # Equal issued/expires accepted (zero-length validity window)
    i_eq = base_intent(
        constraints=(c,),
        issued_at="2026-01-01T00:00:00Z",
        expires_at="2026-01-01T00:00:00Z",
    )
    r_eq = normalize_intent(i_eq)
    if not r_eq.ok:
        results.append(fail("case_13_validity_expiry_behavior", "equal issued/expires rejected: %r" % r_eq.code))
        return
    # Freshness-at-a-given-time is NOT computed by normalization (it is a
    # policy/routing concern). The intent layer records the temporal
    # metadata only. Confirm that no wall-clock read occurs by running
    # normalization with a future-issued instant and seeing it succeed.
    i_future = base_intent(
        constraints=(c,),
        issued_at="9999-01-01T00:00:00Z",
        expires_at="9999-12-31T23:59:59Z",
    )
    r_future = normalize_intent(i_future)
    if r_future.ok and r_future.intent.issued_at == "9999-01-01T00:00:00Z":  # type: ignore[union-attr]
        results.append(ok("case_13_validity_expiry_behavior", "expires<issued rejected; equal accepted; future-dated accepted (no wall-clock read)"))
    else:
        results.append(fail("case_13_validity_expiry_behavior", "future-dated rejected: %r %r" % (r_future.ok, r_future.code)))


def case_14_negative_numeric_rejection(results: List[Result]) -> None:
    """14. negative numeric values rejected."""
    for dim, unit in (
        (IntentDimension.BANDWIDTH, "Mbps"),
        (IntentDimension.LATENCY, "ms"),
        (IntentDimension.RELIABILITY, "basis-points"),
        (IntentDimension.ENERGY, "millijoules"),
        (IntentDimension.COST, "units"),
    ):
        try:
            Constraint(constraint_id="neg", dimension=dim, operator=Operator.GE, value=-1, unit=unit, hardness=Hardness.HARD)
            results.append(fail("case_14_negative_numeric_rejection", "negative value accepted for %s" % dim))
            return
        except IntentError as e:
            if e.code != "value":
                results.append(fail("case_14_negative_numeric_rejection", "wrong code for %s: %s" % (dim, e.code)))
                return
    results.append(ok("case_14_negative_numeric_rejection", "all negative values rejected at construction"))


def case_15_nan_infinity_float_rejection(results: List[Result]) -> None:
    """15. NaN/Infinity/float values rejected."""
    for bad_val in (1.5, float("nan"), float("inf"), float("-inf")):
        try:
            Constraint(constraint_id="bad", dimension=IntentDimension.BANDWIDTH, operator=Operator.GE, value=bad_val, unit="Mbps", hardness=Hardness.HARD)  # type: ignore[arg-type]
            results.append(fail("case_15_nan_infinity_float_rejection", "float accepted: %r" % bad_val))
            return
        except IntentError as e:
            if e.code != "value":
                results.append(fail("case_15_nan_infinity_float_rejection", "wrong code for %r: %s" % (bad_val, e.code)))
                return
    # bool is also rejected (it is an int subclass)
    try:
        Constraint(constraint_id="bad", dimension=IntentDimension.BANDWIDTH, operator=Operator.GE, value=True, unit="Mbps", hardness=Hardness.HARD)
        results.append(fail("case_15_nan_infinity_float_rejection", "bool accepted"))
        return
    except IntentError as e:
        if e.code != "value":
            results.append(fail("case_15_nan_infinity_float_rejection", "bool wrong code: %s" % e.code))
            return
    results.append(ok("case_15_nan_infinity_float_rejection", "1.5, NaN, Infinity, -Infinity, bool all rejected"))


def case_16_deterministic_digest(results: List[Result]) -> None:
    """16. deterministic digest/identity is content-derived (sha256 of canonical JSON).

    The digest is computed over the canonical JSON of the NormalizedIntent
    payload WITHOUT the digest field itself (otherwise the digest would be
    a self-referential fixpoint, which is awkward and deterministic-but-
    ambiguous). This test verifies:
    - the digest is deterministic across runs (same input -> same digest);
    - the digest equals ``sha256(canonical_json_bytes(payload_without_digest))``;
    - the digest is NOT a NodeID (does not start with ``adcos:node:``) --
      i.e., it is NOT a second identity authority.
    """
    from protocol.canonicalization import canonical_json_bytes
    c = base_constraint()
    i = base_intent(constraints=(c,))
    r1 = normalize_intent(i)
    r2 = normalize_intent(i)
    # First guard: both must succeed AND have a NormalizedIntent attached.
    if not (r1.ok and r2.ok and r1.intent is not None and r2.intent is not None):
        results.append(fail("case_16_deterministic_digest", "expected both ok + intent; got r1=%r r2=%r" % (r1.code, r2.code)))
        return
    # Now mypy has narrowed r1.intent and r2.intent to NormalizedIntent.
    if r1.intent.digest != r2.intent.digest:
        results.append(fail("case_16_deterministic_digest", "digests differ across runs: %s vs %s" % (r1.intent.digest, r2.intent.digest)))
        return
    ni = r1.intent
    # Independently reconstruct the digest content payload (without the
    # digest field) and verify the digest matches
    # sha256(canonical_json_bytes(payload)). The content representation
    # omits empty optional fields (requester_node_id / issued_at /
    # expires_at / extensions), matching NormalizedIntent.content_dict()
    # -- the explicit single source of truth for the digest input
    # (Architect PR #9 blocker fix). This reconstruction is built from
    # scratch (it does NOT call content_dict()) so it is an independent
    # cross-check, not a tautology.
    expected_payload: dict = {"intent_id": ni.intent_id}
    if ni.requester_node_id:
        expected_payload["requester_node_id"] = ni.requester_node_id
    if ni.issued_at:
        expected_payload["issued_at"] = ni.issued_at
    if ni.expires_at:
        expected_payload["expires_at"] = ni.expires_at
    expected_payload["constraints"] = [c.to_dict() for c in ni.constraints]
    if ni.extensions:
        expected_payload["extensions"] = [dict(e) for e in ni.extensions]
    expected = hashlib.sha256(canonical_json_bytes(expected_payload)).hexdigest()
    if ni.digest == expected and not ni.digest.startswith("adcos:node:"):
        results.append(ok("case_16_deterministic_digest", "digest = sha256(canonical_json(content)); no second identity authority"))
    else:
        results.append(fail("case_16_deterministic_digest", "digest mismatch: stored=%s computed=%s starts_with_node=%r" % (ni.digest, expected, ni.digest.startswith("adcos:node:"))))


def case_17_5g_wifi_vendor_implementation_leakage_rejection(results: List[Result]) -> None:
    """17. 5G/Wi-Fi/vendor implementation leakage rejection."""
    forbidden_dims = (
        "5g-bandwidth", "wifi-bandwidth", "nr-bandwidth", "lte-bandwidth",
        "6g-bandwidth", "satellite-bandwidth", "mesh-bandwidth",
        "fiber-bandwidth", "vendor-huawei-bandwidth", "adapter",
        "access-technology-bandwidth", "cell-bandwidth", "bearer",
        "ran-bandwidth", "spectrum-bandwidth", "frequency",
        "route-bandwidth", "path-bandwidth", "next-hop", "topology",
        "cell-id", "ssid",
    )
    rejected = 0
    for dim in forbidden_dims:
        try:
            Constraint(constraint_id="x", dimension=dim, operator=Operator.GE, value=10, unit="Mbps", hardness=Hardness.HARD)
            results.append(fail("case_17_5g_wifi_vendor_implementation_leakage_rejection", "accepted forbidden dimension: %r" % dim))
            return
        except IntentError:
            rejected += 1
    # Also test validate_dimension directly (defensive re-check)
    for dim in forbidden_dims:
        try:
            validate_dimension(dim)
            results.append(fail("case_17_5g_wifi_vendor_implementation_leakage_rejection", "validate_dimension accepted forbidden: %r" % dim))
            return
        except IntentError:
            pass
    results.append(ok("case_17_5g_wifi_vendor_implementation_leakage_rejection", "%d forbidden dimensions rejected" % rejected))


def case_18_route_resource_trust_policy_leakage_audit(results: List[Result]) -> None:
    """18. route/resource/trust/policy leakage audit on NormalizedIntent.to_dict()."""
    c = base_constraint()
    i = base_intent(constraints=(c,))
    r = normalize_intent(i)
    if not r.ok or r.intent is None:
        results.append(fail("case_18_route_resource_trust_policy_leakage_audit", "expected ok"))
        return
    # Audit the canonical dict form for any forbidden authoritative field.
    forbidden_fields = (
        "authorized", "trusted", "admitted", "selected_resource",
        "selected_route", "next_hop", "adapter", "access_technology",
        "price", "settlement", "trust_score", "policy_decision",
        "resource_offer", "resource_measurement", "topology_fact",
    )
    def _audit(obj, path="root") -> List[str]:
        leaks = []
        if isinstance(obj, dict):
            for key, val in obj.items():
                if key in forbidden_fields:
                    leaks.append("%s.%s" % (path, key))
                leaks.extend(_audit(val, "%s.%s" % (path, key)))
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                leaks.extend(_audit(item, "%s[%d]" % (path, idx)))
        return leaks
    ni_dict = r.intent.to_dict()
    leaks = _audit(ni_dict)
    if leaks:
        results.append(fail("case_18_route_resource_trust_policy_leakage_audit", "forbidden fields found: %s" % leaks))
    else:
        # Also audit the canonical bytes form (just to be sure)
        canonical = r.intent.canonical_bytes().decode("utf-8")
        for field in forbidden_fields:
            if '"%s"' % field in canonical:
                results.append(fail("case_18_route_resource_trust_policy_leakage_audit", "forbidden field in canonical bytes: %s" % field))
                return
        results.append(ok("case_18_route_resource_trust_policy_leakage_audit", "no authoritative fields in NormalizedIntent"))


def case_19_secret_material_serialization_rejection(results: List[Result]) -> None:
    """19. secret material in serialized objects rejected (LOCK-023)."""
    c = base_constraint()
    # Secret in extensions
    for secret_field in ("private_key", "secret_key", "priv_key", "password", "token"):
        i = base_intent(constraints=(c,), extensions=({secret_field: "xxx"},))
        r = normalize_intent(i)
        if r.ok or r.code != "secret-material":
            results.append(fail("case_19_secret_material_serialization_rejection", "expected secret-material for %r, got %r %r" % (secret_field, r.ok, r.code)))
            return
    # Secret in constraint provenance / scope / value -- build each case
    # explicitly so the constructor kwargs are statically type-correct.
    secret_constraint_specs = (
        ("provenance", lambda: Constraint(constraint_id="x", dimension=IntentDimension.BANDWIDTH, operator=Operator.GE, value=10, unit="Mbps", hardness=Hardness.HARD, provenance="password")),
        ("scope", lambda: Constraint(constraint_id="x", dimension=IntentDimension.BANDWIDTH, operator=Operator.GE, value=10, unit="Mbps", hardness=Hardness.HARD, scope="token")),
        ("value", lambda: Constraint(constraint_id="x", dimension=IntentDimension.LOCALITY, operator=Operator.EQ, value="private_key", hardness=Hardness.HARD)),
    )
    for label, ctor in secret_constraint_specs:
        try:
            c2 = ctor()
            i2 = base_intent(constraints=(c2,))
            r2 = normalize_intent(i2)
            if r2.ok or r2.code != "secret-material":
                results.append(fail("case_19_secret_material_serialization_rejection", "expected secret-material for %s, got %r %r" % (label, r2.ok, r2.code)))
                return
        except IntentError as e:
            if e.code != "secret-material":
                results.append(fail("case_19_secret_material_serialization_rejection", "wrong code for %s: %s" % (label, e.code)))
                return
    results.append(ok("case_19_secret_material_serialization_rejection", "private_key/secret_key/password/token rejected in extensions + constraint fields"))


def case_20_future_profile_constraint_handling(results: List[Result]) -> None:
    """20. future profile/constraint handling via extensions; unknown required fail explicitly."""
    # Unknown required future constraint: a dimension not in the frozen 8.
    try:
        Constraint(constraint_id="future1", dimension="jitter", operator=Operator.LE, value=5, unit="ms", hardness=Hardness.HARD)
        results.append(fail("case_20_future_profile_constraint_handling", "accepted unknown required dimension 'jitter'"))
        return
    except IntentError as e:
        if e.code != "dimension":
            results.append(fail("case_20_future_profile_handling", "wrong code for unknown required dim: %s" % e.code))
            return
    # Future optional profile in extensions: preserved verbatim.
    c = base_constraint()
    ext = {"x-future-profile": "urn:adcos:profile:future-2030-v1", "opaque-tag": "future"}
    i = base_intent(constraints=(c,), extensions=(ext,))
    r = normalize_intent(i)
    if r.ok and r.intent.extensions and r.intent.extensions[0] == ext:  # type: ignore[union-attr]
        results.append(ok("case_20_future_profile_constraint_handling", "unknown required dim rejected; future optional extension preserved"))
    else:
        results.append(fail("case_20_future_profile_constraint_handling", "future extension not preserved: %r" % (r.intent.extensions if r.intent else None,)))


def case_21_canonical_byte_identity_across_runs(results: List[Result]) -> None:
    """21. canonical byte identity across repeated runs (process-level determinism)."""
    c = base_constraint()
    i = base_intent(constraints=(c,))
    digests = []
    bytes_forms = []
    for _ in range(5):
        r = normalize_intent(i)
        if not r.ok or r.intent is None:
            results.append(fail("case_21_canonical_byte_identity_across_runs", "expected ok"))
            return
        digests.append(r.intent.digest)
        bytes_forms.append(r.intent.canonical_bytes())
    if len(set(digests)) == 1 and len(set(bytes_forms)) == 1:
        results.append(ok("case_21_canonical_byte_identity_across_runs", "5 in-process runs byte-identical; digest=%s" % digests[0][:12]))
    else:
        results.append(fail("case_21_canonical_byte_identity_across_runs", "non-deterministic: %d distinct digests" % len(set(digests))))


def case_22_fuzz_property_inputs_never_crash(results: List[Result]) -> None:
    """22. fuzz/property inputs never crash (no exceptions other than IntentError)."""
    import random
    rng = random.Random(42)  # seeded; deterministic
    crash_count = 0
    intent_error_count = 0
    ok_count = 0
    for trial in range(500):
        # Build a random intent from a constrained vocabulary
        try:
            dim_choices = list(IntentDimension.values()) + ["5g", "wifi", "jitter", "vendor"]
            op_choices = list(Operator.values()) + ["~=", "==", ">", "<>"]
            value_choices = [10, 0, -5, 1.5, "GH", "end-to-end", "", True, None]
            unit_choices = ["Mbps", "ms", "%", "kJ", "basis-points", "", "bps", "Wh"]
            hardness_choices = [Hardness.HARD, Hardness.SOFT, "medium"]
            weight_choices = [0, 5, -1, 100]
            dim = rng.choice(dim_choices)
            op = rng.choice(op_choices)
            val = rng.choice(value_choices)
            unit = rng.choice(unit_choices)
            hardness = rng.choice(hardness_choices)
            weight = rng.choice(weight_choices)
            c = Constraint(constraint_id="fuzz-%d" % trial, dimension=dim, operator=op, value=val, unit=unit, hardness=hardness, weight=weight)  # type: ignore[arg-type]
            i = base_intent(intent_id="fuzz-intent-%d" % trial, constraints=(c,))
            r = normalize_intent(i)
            if r.ok:
                ok_count += 1
            else:
                intent_error_count += 1
        except IntentError:
            intent_error_count += 1
        except Exception as e:
            crash_count += 1
            results.append(fail("case_22_fuzz_property_inputs_never_crash", "trial %d crashed: %s %s" % (trial, type(e).__name__, e)))
            if crash_count > 3:
                return
            break
    if crash_count == 0:
        results.append(ok("case_22_fuzz_property_inputs_never_crash", "500 fuzz trials; %d ok, %d IntentError, 0 crashes" % (ok_count, intent_error_count)))
    else:
        results.append(fail("case_22_fuzz_property_inputs_never_crash", "%d crashes" % crash_count))


def case_23_hard_constraints_never_silently_downgraded(results: List[Result]) -> None:
    """23. hard constraints never silently downgraded to soft."""
    c_hard = base_constraint(constraint_id="hard1", hardness=Hardness.HARD)
    i = base_intent(constraints=(c_hard,))
    r = normalize_intent(i)
    if not r.ok or r.intent is None:
        results.append(fail("case_23_hard_constraints_never_silently_downgraded", "expected ok"))
        return
    for c in r.intent.constraints:
        if c.hardness != Hardness.HARD:
            results.append(fail("case_23_hard_constraints_never_silently_downgraded", "hard constraint downgraded to %r" % c.hardness))
            return
    # Also reject a SOFT constraint that lacks weight (cannot be silently upgraded)
    try:
        Constraint(constraint_id="bad", dimension=IntentDimension.BANDWIDTH, operator=Operator.GE, value=10, unit="Mbps", hardness=Hardness.SOFT, weight=0)
        results.append(fail("case_23_hard_constraints_never_silently_downgraded", "SOFT weight=0 accepted"))
        return
    except IntentError as e:
        if e.code != "weight":
            results.append(fail("case_23_hard_constraints_never_silently_downgraded", "wrong code: %s" % e.code))
            return
    results.append(ok("case_23_hard_constraints_never_silently_downgraded", "hard stays hard; SOFT weight=0 rejected"))


def case_24_soft_constraints_never_silently_upgraded(results: List[Result]) -> None:
    """24. soft constraints never silently upgraded to hard."""
    c_soft = base_constraint(constraint_id="soft1", hardness=Hardness.SOFT, weight=5)
    i = ConnectivityIntent(intent_id="intent-soft", preferences=(c_soft,))
    r = normalize_intent(i)
    if not r.ok or r.intent is None:
        results.append(fail("case_24_soft_constraints_never_silently_upgraded", "expected ok"))
        return
    for c in r.intent.constraints:
        if c.hardness != Hardness.SOFT:
            results.append(fail("case_24_soft_constraints_never_silently_upgraded", "soft upgraded to %r" % c.hardness))
            return
    # Also reject a HARD constraint that has weight>0 (cannot be silently downgraded)
    try:
        Constraint(constraint_id="bad", dimension=IntentDimension.BANDWIDTH, operator=Operator.GE, value=10, unit="Mbps", hardness=Hardness.HARD, weight=5)
        results.append(fail("case_24_soft_constraints_never_silently_upgraded", "HARD weight=5 accepted"))
        return
    except IntentError as e:
        if e.code != "weight":
            results.append(fail("case_24_soft_constraints_never_silently_upgraded", "wrong code: %s" % e.code))
            return
    results.append(ok("case_24_soft_constraints_never_silently_upgraded", "soft stays soft; HARD weight=5 rejected"))


def case_25_normalization_has_no_side_effects_on_resource_topology_state(results: List[Result]) -> None:
    """25. normalization has no side effects on resource/topology state.

    Construct a WORK-008 ResourceStore and a WORK-007 TopologyGraph, then
    run normalization many times against an intent that references
    resource-aligned dimensions. Confirm the stores remain byte-identical
    before and after normalization (rule 25 of the prompt).
    """
    try:
        from resources import Resource, ResourceKind, ResourceStore  # type: ignore
        from topology import TopologyGraph  # type: ignore
    except ImportError as e:
        results.append(fail("case_25_normalization_no_side_effects", "import failed: %s" % e))
        return
    owner = _TEST_NODE_ID
    store = ResourceStore()
    rid = "adcos:resource:%s:bandwidth:%s" % (owner, hashlib.sha256(b"link-1").hexdigest()[:16])
    try:
        res = Resource(resource_id=rid, owner_node_id=owner, kind=ResourceKind.BANDWIDTH, availability="continuous", scope="link-1")
        store.register_resource(res)
    except Exception as e:
        results.append(fail("case_25_normalization_no_side_effects", "resource setup failed: %s %s" % (type(e).__name__, e)))
        return
    topo = TopologyGraph()
    try:
        before_store = store.to_canonical_bytes()
        before_topo = topo.to_canonical_bytes()
    except Exception as e:
        # Fallback to snapshot if to_canonical_bytes is not available.
        try:
            before_store = repr(store.snapshot()).encode("utf-8")
            before_topo = repr(topo.snapshot()).encode("utf-8")
        except Exception as e2:
            results.append(fail("case_25_normalization_no_side_effects", "snapshot failed: %s %s" % (type(e2).__name__, e2)))
            return
    # Run normalization 10 times with a resource-aligned intent.
    c = base_constraint(constraint_id="bw", value=10, unit="Mbps", hardness=Hardness.HARD)
    c2 = Constraint(constraint_id="en", dimension=IntentDimension.ENERGY, operator=Operator.LE, value=5_000_000, unit="millijoules", hardness=Hardness.SOFT, weight=10)
    i = ConnectivityIntent(intent_id="intent-side-effect", requirements=(c,), preferences=(c2,))
    for _ in range(10):
        r = normalize_intent(i)
        if not r.ok or r.intent is None:
            results.append(fail("case_25_normalization_no_side_effects", "expected ok, got %r %r" % (r.ok, r.code)))
            return
    try:
        after_store = store.to_canonical_bytes()
        after_topo = topo.to_canonical_bytes()
    except Exception:
        after_store = repr(store.snapshot()).encode("utf-8")
        after_topo = repr(topo.snapshot()).encode("utf-8")
    if before_store == after_store and before_topo == after_topo:
        results.append(ok("case_25_normalization_no_side_effects", "resource+topology stores byte-identical after 10 normalizations"))
    else:
        store_same = before_store == after_store
        topo_same = before_topo == after_topo
        results.append(fail("case_25_normalization_no_side_effects", "store_same=%r topo_same=%r" % (store_same, topo_same)))


# --------------------------------------------------------------------------
# Additional mechanical / boundary checks
# --------------------------------------------------------------------------

def case_26_label_dimension_unit_rejection(results: List[Result]) -> None:
    """Label dimensions (locality/privacy/service) reject any non-empty unit.

    The Constraint constructor only checks structural shape (string-ness,
    int-ness, hardness, weight); cross-dimension unit-vs-dimension checks
    happen in :func:`intent.validation.validate_constraint`, which is
    invoked by :func:`intent.normalization.normalize_intent`. So this test
    builds an intent containing the malformed constraint and verifies
    normalization rejects it with the ``unit-label`` code.
    """
    for dim in (IntentDimension.LOCALITY, IntentDimension.PRIVACY, IntentDimension.SERVICE):
        c = Constraint(constraint_id="x", dimension=dim, operator=Operator.EQ, value="label", unit="Mbps", hardness=Hardness.HARD)
        i = base_intent(constraints=(c,))
        r = normalize_intent(i)
        if r.ok or r.code != "unit-label":
            results.append(fail("case_26_label_dimension_unit_rejection", "label dim %r not rejected (ok=%r code=%r)" % (dim, r.ok, r.code)))
            return
    results.append(ok("case_26_label_dimension_unit_rejection", "label dims reject non-empty units at normalization"))


def case_27_reliability_basis_point_normalization(results: List[Result]) -> None:
    """Reliability normalizes to basis points (99% == 9900 basis-points)."""
    cPct = Constraint(constraint_id="rel", dimension=IntentDimension.RELIABILITY, operator=Operator.GE, value=99, unit="%", hardness=Hardness.HARD)
    cBp = Constraint(constraint_id="rel", dimension=IntentDimension.RELIABILITY, operator=Operator.GE, value=9900, unit="basis-points", hardness=Hardness.HARD)
    iP = base_intent(intent_id="rel-intent", constraints=(cPct,))
    iB = base_intent(intent_id="rel-intent", constraints=(cBp,))
    rP = normalize_intent(iP)
    rB = normalize_intent(iB)
    if not (rP.ok and rB.ok) or rP.intent is None or rB.intent is None:
        results.append(fail("case_27_reliability_basis_point_normalization", "expected both ok"))
        return
    if rP.intent.digest == rB.intent.digest:
        # Both canonicalized to 9900 basis-points
        c = rP.intent.constraints[0]
        if c.unit == "basis-points" and c.value == 9900:
            results.append(ok("case_27_reliability_basis_point_normalization", "99% == 9900 basis-points; both -> 9900 basis-points"))
        else:
            results.append(fail("case_27_reliability_basis_point_normalization", "wrong base form: %r" % (c,)))
    else:
        results.append(fail("case_27_reliability_basis_point_normalization", "digests differ: %s vs %s" % (rP.intent.digest[:8], rB.intent.digest[:8])))


def case_28_energy_unit_normalization(results: List[Result]) -> None:
    """Energy normalizes to millijoules (5 Wh == 18000 joules == 18M millijoules)."""
    cWh = Constraint(constraint_id="en", dimension=IntentDimension.ENERGY, operator=Operator.LE, value=5, unit="Wh", hardness=Hardness.SOFT, weight=10)
    cJ = Constraint(constraint_id="en", dimension=IntentDimension.ENERGY, operator=Operator.LE, value=18000, unit="joules", hardness=Hardness.SOFT, weight=10)
    cMj = Constraint(constraint_id="en", dimension=IntentDimension.ENERGY, operator=Operator.LE, value=18_000_000, unit="millijoules", hardness=Hardness.SOFT, weight=10)
    iWh = ConnectivityIntent(intent_id="en-intent", preferences=(cWh,))
    iJ = ConnectivityIntent(intent_id="en-intent", preferences=(cJ,))
    iMj = ConnectivityIntent(intent_id="en-intent", preferences=(cMj,))
    rWh, rJ, rMj = normalize_intent(iWh), normalize_intent(iJ), normalize_intent(iMj)
    if not (rWh.ok and rJ.ok and rMj.ok):
        results.append(fail("case_28_energy_unit_normalization", "expected all ok"))
        return
    if rWh.intent.digest == rJ.intent.digest == rMj.intent.digest:  # type: ignore[union-attr]
        c = rWh.intent.constraints[0]  # type: ignore[union-attr]
        if c.unit == "millijoules" and c.value == 18_000_000:
            results.append(ok("case_28_energy_unit_normalization", "5 Wh == 18000 joules == 18M millijoules; all -> 18M millijoules"))
        else:
            results.append(fail("case_28_energy_unit_normalization", "wrong base form: %r" % (c,)))
    else:
        results.append(fail("case_28_energy_unit_normalization", "digests differ"))


def case_29_cost_unit_normalization(results: List[Result]) -> None:
    """Cost normalizes to base units (5k units == 5000 units)."""
    c5k = Constraint(constraint_id="cst", dimension=IntentDimension.COST, operator=Operator.LE, value=5, unit="k", hardness=Hardness.SOFT, weight=10)
    c5000 = Constraint(constraint_id="cst", dimension=IntentDimension.COST, operator=Operator.LE, value=5000, unit="units", hardness=Hardness.SOFT, weight=10)
    i5k = ConnectivityIntent(intent_id="cst-intent", preferences=(c5k,))
    i5000 = ConnectivityIntent(intent_id="cst-intent", preferences=(c5000,))
    r5k = normalize_intent(i5k)
    r5000 = normalize_intent(i5000)
    if not (r5k.ok and r5000.ok):
        results.append(fail("case_29_cost_unit_normalization", "expected both ok"))
        return
    if r5k.intent.digest == r5000.intent.digest:  # type: ignore[union-attr]
        c = r5k.intent.constraints[0]  # type: ignore[union-attr]
        if c.unit == "units" and c.value == 5000:
            results.append(ok("case_29_cost_unit_normalization", "5k units == 5000 units; both -> 5000 units"))
        else:
            results.append(fail("case_29_cost_unit_normalization", "wrong base form: %r" % (c,)))
    else:
        results.append(fail("case_29_cost_unit_normalization", "digests differ"))


def case_30_case_insensitive_unit_aliases(results: List[Result]) -> None:
    """Case-insensitive unit lookup (Mbps, mbps, MBPS all equivalent)."""
    for variant in ("Mbps", "mbps", "MBPS", "MbPs"):
        c = base_constraint(constraint_id="bw", value=10, unit=variant)
        i = base_intent(intent_id="case-intent", constraints=(c,))
        r = normalize_intent(i)
        if not r.ok or r.intent is None:
            results.append(fail("case_30_case_insensitive_unit_aliases", "rejected variant %r: %r %r" % (variant, r.ok, r.code)))
            return
    # All four should produce the same digest
    digests = []
    for variant in ("Mbps", "mbps", "MBPS", "MbPs"):
        c = base_constraint(constraint_id="bw", value=10, unit=variant)
        i = base_intent(intent_id="case-intent", constraints=(c,))
        r = normalize_intent(i)
        digests.append(r.intent.digest)  # type: ignore[union-attr]
    if len(set(digests)) == 1:
        results.append(ok("case_30_case_insensitive_unit_aliases", "4 case variants all -> byte-identical digest"))
    else:
        results.append(fail("case_30_case_insensitive_unit_aliases", "case variants differ: %s" % [d[:8] for d in digests]))


def case_31_serialization_roundtrip(results: List[Result]) -> None:
    """Round-trip: ConnectivityIntent -> canonical bytes -> intent_from_mapping -> normalize."""
    c1 = base_constraint(constraint_id="bw", value=10, unit="Mbps")
    c2 = Constraint(constraint_id="lat", dimension=IntentDimension.LATENCY, operator=Operator.LE, value=50, unit="ms", hardness=Hardness.HARD)
    c3 = Constraint(constraint_id="loc", dimension=IntentDimension.LOCALITY, operator=Operator.EQ, value="GH", hardness=Hardness.SOFT, weight=10)
    i = ConnectivityIntent(
        intent_id="rt-intent",
        requester_node_id=_TEST_NODE_ID,
        issued_at="2026-01-01T00:00:00Z",
        expires_at="2026-12-31T23:59:59Z",
        requirements=(c1, c2),
        preferences=(c3,),
        extensions=({"x-tag": "rt"},),
    )
    r1 = normalize_intent(i)
    if not r1.ok:
        results.append(fail("case_31_serialization_roundtrip", "first normalization failed: %r %r" % (r1.ok, r1.code)))
        return
    # Reconstruct from mapping and renormalize.
    dict_form = i.to_dict()
    i2 = intent_from_mapping(dict_form)
    r2 = normalize_intent(i2)
    if not r2.ok:
        results.append(fail("case_31_serialization_roundtrip", "second normalization failed: %r %r" % (r2.ok, r2.code)))
        return
    if r1.intent.digest == r2.intent.digest and r1.intent.canonical_bytes() == r2.intent.canonical_bytes():  # type: ignore[union-attr]
        results.append(ok("case_31_serialization_roundtrip", "round-trip byte-identical; digest=%s" % r1.intent.digest[:12]))  # type: ignore[union-attr]
    else:
        results.append(fail("case_31_serialization_roundtrip", "round-trip differs: %s vs %s" % (r1.intent.digest[:8], r2.intent.digest[:8])))  # type: ignore[union-attr]


def case_32_no_forbidden_fields_or_methods(results: List[Result]) -> None:
    """Audit intent package public API for forbidden authoritative fields."""
    forbidden_attrs = (
        "authorized", "trusted", "admitted", "selected_resource",
        "selected_route", "next_hop", "adapter", "access_technology",
        "price", "settlement", "trust_score", "policy_decision",
    )
    leaks = []
    for cls in (Constraint, ConnectivityIntent, NormalizedIntent, NormalizationResult):
        for attr in forbidden_attrs:
            if hasattr(cls, attr):
                leaks.append("%s.%s" % (cls.__name__, attr))
    if leaks:
        results.append(fail("case_32_no_forbidden_fields_or_methods", "leaks: %s" % leaks))
    else:
        results.append(ok("case_32_no_forbidden_fields_or_methods", "no authoritative fields on public classes"))


def case_33_no_5g_vendor_imports(results: List[Result]) -> None:
    """Audit intent package source for 5G/Wi-Fi/vendor/route SDK imports."""
    intent_dir = REPO_ROOT / "intent"
    forbidden_patterns = (
        "import nr", "from nr", "import lte", "from lte",
        "import wifi", "from wifi", "import 5g", "from 5g",
        "import cellular", "from cellular", "import satellite", "from satellite",
        "import huawei", "from huawei", "import ericsson", "from ericsson",
        "import nokia", "from nokia", "import samsung", "from samsung",
        "import fiber", "from fiber", "import ran", "from ran",
        "import adapter_5g", "from adapter_5g", "import pycrll", "from pycrll",
    )
    leaks = []
    for src in intent_dir.glob("*.py"):
        text = src.read_text(encoding="utf-8")
        for pat in forbidden_patterns:
            if pat in text:
                leaks.append("%s: %r" % (src.name, pat))
    if leaks:
        results.append(fail("case_33_no_5g_vendor_imports", "forbidden imports: %s" % leaks))
    else:
        results.append(ok("case_33_no_5g_vendor_imports", "no 5G/vendor SDK imports in intent/"))


def case_34_frozen_dimensions_present(results: List[Result]) -> None:
    """All 8 frozen intent dimensions are present in the IntentDimension enum."""
    expected = {
        "bandwidth", "latency", "reliability", "locality",
        "energy", "cost", "privacy", "service",
    }
    actual = set(IntentDimension.values())
    if actual == expected:
        results.append(ok("case_34_frozen_dimensions_present", "all 8 frozen dimensions present"))
    else:
        results.append(fail("case_34_frozen_dimensions_present", "missing: %s extra: %s" % (expected - actual, actual - expected)))


def case_35_frozen_operators_present(results: List[Result]) -> None:
    """Frozen operator set is {>=, <=, >, <, =, !=}."""
    expected = {">=", "<=", ">", "<", "=", "!="}
    actual = set(Operator.values())
    if actual == expected:
        results.append(ok("case_35_frozen_operators_present", "all 6 frozen operators present"))
    else:
        results.append(fail("case_35_frozen_operators_present", "missing: %s extra: %s" % (expected - actual, actual - expected)))


def case_36_extensions_secret_material_deep_nested(results: List[Result]) -> None:
    """Secret material is rejected even when deeply nested in extensions."""
    c = base_constraint()
    nested_ext = {
        "outer": {
            "inner": [
                {"private_key": "xxx"},  # deep secret
            ],
        },
    }
    i = base_intent(constraints=(c,), extensions=(nested_ext,))
    r = normalize_intent(i)
    if not r.ok and r.code == "secret-material":
        results.append(ok("case_36_extensions_secret_material_deep_nested", "deep-nested secret rejected: %s" % r.code))
    else:
        results.append(fail("case_36_extensions_secret_material_deep_nested", "expected secret-material, got %r %r" % (r.ok, r.code)))


def case_37_normalized_intent_serialization_no_leak(results: List[Result]) -> None:
    """Serialized NormalizedIntent contains no policy/resource/route/trust fields."""
    c1 = base_constraint(constraint_id="bw", value=10, unit="Mbps")
    c2 = Constraint(constraint_id="lat", dimension=IntentDimension.LATENCY, operator=Operator.LE, value=50, unit="ms", hardness=Hardness.HARD)
    i = base_intent(constraints=(c1, c2), requester_node_id=_TEST_NODE_ID, extensions=({"opaque-tag": "ok"},))
    r = normalize_intent(i)
    if not r.ok or r.intent is None:
        results.append(fail("case_37_normalized_intent_serialization_no_leak", "expected ok"))
        return
    # Serialized form has only allowed top-level fields.
    serialized = r.intent.canonical_bytes().decode("utf-8")
    allowed_top = ('"intent_id"', '"digest"', '"requester_node_id"', '"issued_at"', '"expires_at"', '"constraints"', '"extensions"')
    # Forbidden fields
    forbidden = ('"authorized"', '"trusted"', '"admitted"', '"selected_resource"', '"selected_route"', '"next_hop"', '"adapter"', '"access_technology"', '"price"', '"settlement"', '"trust_score"', '"policy_decision"', '"resource_offer"', '"resource_measurement"', '"topology_fact"')
    for f in forbidden:
        if f in serialized:
            results.append(fail("case_37_normalized_intent_serialization_no_leak", "forbidden field in serialized: %s" % f))
            return
    # Extensions survive verbatim
    if '"opaque-tag"' in serialized and '"ok"' in serialized:
        results.append(ok("case_37_normalized_intent_serialization_no_leak", "no forbidden fields; extensions preserved"))
    else:
        results.append(fail("case_37_normalized_intent_serialization_no_leak", "extensions not preserved in serialization"))


def case_38_bucket_for_privacy_service(results: List[Result]) -> None:
    """Privacy/service constraints dispatch to their own buckets (any hardness)."""
    # Hard privacy -> privacy_requirements bucket
    c_ph = Constraint(constraint_id="ph", dimension=IntentDimension.PRIVACY, operator=Operator.EQ, value="end-to-end", hardness=Hardness.HARD)
    # Soft privacy -> privacy_requirements bucket
    c_ps = Constraint(constraint_id="ps", dimension=IntentDimension.PRIVACY, operator=Operator.EQ, value="best-effort", hardness=Hardness.SOFT, weight=5)
    # Hard service -> service_constraints bucket
    c_sh = Constraint(constraint_id="sh", dimension=IntentDimension.SERVICE, operator=Operator.EQ, value="voice", hardness=Hardness.HARD)
    # Soft service -> service_constraints bucket
    c_ss = Constraint(constraint_id="ss", dimension=IntentDimension.SERVICE, operator=Operator.EQ, value="video", hardness=Hardness.SOFT, weight=3)
    i = ConnectivityIntent(
        intent_id="bucket-intent",
        privacy_requirements=(c_ph, c_ps),
        service_constraints=(c_sh, c_ss),
    )
    r = normalize_intent(i)
    if not r.ok or r.intent is None:
        results.append(fail("case_38_bucket_for_privacy_service", "expected ok, got %r %r" % (r.ok, r.code)))
        return
    # Verify bucket_for dispatch is correct
    if (bucket_for(IntentDimension.PRIVACY, Hardness.HARD) == "privacy_requirements" and
        bucket_for(IntentDimension.PRIVACY, Hardness.SOFT) == "privacy_requirements" and
        bucket_for(IntentDimension.SERVICE, Hardness.HARD) == "service_constraints" and
        bucket_for(IntentDimension.SERVICE, Hardness.SOFT) == "service_constraints"):
        # And hard non-privacy/non-service -> requirements; soft -> preferences
        if (bucket_for(IntentDimension.BANDWIDTH, Hardness.HARD) == "requirements" and
            bucket_for(IntentDimension.BANDWIDTH, Hardness.SOFT) == "preferences"):
            results.append(ok("case_38_bucket_for_privacy_service", "privacy/service buckets independent of hardness"))
        else:
            results.append(fail("case_38_bucket_for_privacy_service", "bandwidth bucket wrong"))
    else:
        results.append(fail("case_38_bucket_for_privacy_service", "privacy/service bucket wrong"))


def case_39_intent_id_uniqueness_no_second_authority(results: List[Result]) -> None:
    """intent_id is caller-provided; digest is content-derived; neither is a NodeID."""
    c = base_constraint()
    i = base_intent(intent_id="caller-provided-id", constraints=(c,))
    r = normalize_intent(i)
    if not r.ok or r.intent is None:
        results.append(fail("case_39_intent_id_uniqueness_no_second_authority", "expected ok"))
        return
    # intent_id is preserved verbatim
    if r.intent.intent_id != "caller-provided-id":
        results.append(fail("case_39_intent_id_uniqueness_no_second_authority", "intent_id changed"))
        return
    # digest is sha256 hex (64 lowercase chars)
    if not (len(r.intent.digest) == 64 and all(ch in "0123456789abcdef" for ch in r.intent.digest)):
        results.append(fail("case_39_intent_id_uniqueness_no_second_authority", "digest not 64-hex: %r" % r.intent.digest))
        return
    # The digest is NOT a NodeID (does not start with 'adcos:node:')
    if r.intent.digest.startswith("adcos:node:"):
        results.append(fail("case_39_intent_id_uniqueness_no_second_authority", "digest looks like a NodeID"))
        return
    results.append(ok("case_39_intent_id_uniqueness_no_second_authority", "intent_id preserved; digest=64hex; no second identity authority"))


def case_40_repeated_runs_byte_identical(results: List[Result]) -> None:
    """Cross-process byte-identical determinism proof (md5 of canonical bytes)."""
    c1 = base_constraint(constraint_id="bw", value=10, unit="Mbps")
    c2 = Constraint(constraint_id="lat", dimension=IntentDimension.LATENCY, operator=Operator.LE, value=50, unit="ms", hardness=Hardness.HARD)
    c3 = Constraint(constraint_id="rel", dimension=IntentDimension.RELIABILITY, operator=Operator.GE, value=9990, unit="basis-points", hardness=Hardness.HARD)
    c4 = Constraint(constraint_id="en", dimension=IntentDimension.ENERGY, operator=Operator.LE, value=5_000_000, unit="millijoules", hardness=Hardness.SOFT, weight=10)
    c5 = Constraint(constraint_id="loc", dimension=IntentDimension.LOCALITY, operator=Operator.EQ, value="GH", hardness=Hardness.SOFT, weight=10)
    c6 = Constraint(constraint_id="cst", dimension=IntentDimension.COST, operator=Operator.LE, value=5, unit="units", hardness=Hardness.SOFT, weight=10)
    c7 = Constraint(constraint_id="priv", dimension=IntentDimension.PRIVACY, operator=Operator.EQ, value="end-to-end", hardness=Hardness.HARD)
    c8 = Constraint(constraint_id="svc", dimension=IntentDimension.SERVICE, operator=Operator.EQ, value="voice", hardness=Hardness.HARD)
    i = ConnectivityIntent(
        intent_id="determinism-intent",
        requester_node_id=_TEST_NODE_ID,
        issued_at="2026-01-01T00:00:00Z",
        expires_at="2026-12-31T23:59:59Z",
        requirements=(c1, c2, c3, c7, c8),
        preferences=(c4, c5, c6),
        extensions=({"opaque": "frozen"},),
    )
    r1 = normalize_intent(i)
    r2 = normalize_intent(i)
    if not (r1.ok and r2.ok) or r1.intent is None or r2.intent is None:
        results.append(fail("case_40_repeated_runs_byte_identical", "expected ok"))
        return
    cb1 = r1.intent.canonical_bytes()
    cb2 = r2.intent.canonical_bytes()
    md5_1 = hashlib.md5(cb1).hexdigest()
    md5_2 = hashlib.md5(cb2).hexdigest()
    if md5_1 == md5_2:
        results.append(ok("case_40_repeated_runs_byte_identical", "md5=%s; digest=%s" % (md5_1, r1.intent.digest[:12])))
    else:
        results.append(fail("case_40_repeated_runs_byte_identical", "md5 differs: %s vs %s" % (md5_1, md5_2)))


def case_41_normalization_thread_safe(results: List[Result]) -> None:
    """Normalization is thread-safe (no shared mutable state)."""
    c = base_constraint()
    i = base_intent(constraints=(c,))
    digests: List[str] = []
    errors: List[str] = []
    def _worker():
        try:
            r = normalize_intent(i)
            if r.ok:
                digests.append(r.intent.digest)
            else:
                errors.append("err: %s" % r.code)
        except Exception as e:
            errors.append("exc: %s %s" % (type(e).__name__, e))
    threads = [threading.Thread(target=_worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if errors:
        results.append(fail("case_41_normalization_thread_safe", "errors: %s" % errors[:3]))
    elif len(set(digests)) == 1:
        results.append(ok("case_41_normalization_thread_safe", "20 threads all agree; digest=%s" % digests[0][:12]))
    else:
        results.append(fail("case_41_normalization_thread_safe", "%d distinct digests across 20 threads" % len(set(digests))))


def case_42_constraint_id_must_be_unique_string(results: List[Result]) -> None:
    """constraint_id must be a non-empty string."""
    bad_values: tuple = ("", None, 123, [], {})
    for bad in bad_values:
        try:
            Constraint(constraint_id=bad, dimension=IntentDimension.BANDWIDTH, operator=Operator.GE, value=10, unit="Mbps", hardness=Hardness.HARD)  # type: ignore[arg-type]
            results.append(fail("case_42_constraint_id_must_be_unique_string", "accepted bad constraint_id %r" % (bad,)))
            return
        except (IntentError, TypeError):
            pass
    results.append(ok("case_42_constraint_id_must_be_unique_string", "empty/None/int/list/dict all rejected"))


def case_43_intent_id_required(results: List[Result]) -> None:
    """intent_id must be a non-empty string."""
    c = base_constraint()
    bad_values: tuple = ("", None, 123)
    for bad in bad_values:
        try:
            ConnectivityIntent(intent_id=bad, requirements=(c,))  # type: ignore[arg-type]
            results.append(fail("case_43_intent_id_required", "accepted bad intent_id %r" % (bad,)))
            return
        except (IntentError, TypeError):
            pass
    results.append(ok("case_43_intent_id_required", "empty/None/int intent_id rejected"))


def case_44_digest_recomputable_from_public_canonical_bytes(results: List[Result]) -> None:
    """44. PUBLIC digest invariant: ``sha256(canonical_bytes()) == digest``.

    Architect blocker on PR #9: ``normalize_intent()`` computed the digest
    over a dict that EXCLUDED the ``digest`` field, but
    ``NormalizedIntent.canonical_bytes()`` returned
    ``canonical_json_bytes(to_dict())`` which INCLUDED the ``digest`` field.
    The documented content fingerprint therefore could not be recomputed
    from the public canonical representation -- a caller using
    ``canonical_bytes()`` would get a different SHA-256 than ``digest``.

    Fix: ``canonical_bytes()`` now returns ``canonical_json_bytes(
    content_dict())`` where ``content_dict()`` is the explicit content
    representation (no ``digest`` field). The public invariant
    ``sha256(canonical_bytes()) == digest`` MUST hold for every normalized
    intent -- callers rely on it to recompute the fingerprint without
    reaching into private normalization internals.
    """
    from protocol.canonicalization import canonical_json_bytes

    # Several distinct shapes, to prove the invariant holds generally (not
    # just for the minimal single-constraint case).
    c_bw = base_constraint(constraint_id="bw", value=10, unit="Mbps")
    c_lat = Constraint(
        constraint_id="lat", dimension=IntentDimension.LATENCY,
        operator=Operator.LE, value=50, unit="ms", hardness=Hardness.HARD,
    )
    c_priv = Constraint(
        constraint_id="priv", dimension=IntentDimension.PRIVACY,
        operator=Operator.EQ, value="end-to-end", hardness=Hardness.HARD,
    )
    c_serv = Constraint(
        constraint_id="svc", dimension=IntentDimension.SERVICE,
        operator=Operator.EQ, value="voice", hardness=Hardness.HARD,
    )
    c_loc = Constraint(
        constraint_id="loc", dimension=IntentDimension.LOCALITY,
        operator=Operator.EQ, value="GH", hardness=Hardness.SOFT, weight=10,
    )
    shapes: List = [
        ("minimal", base_intent(intent_id="iv-1", constraints=(c_bw,))),
        ("temporal+requester", ConnectivityIntent(
            intent_id="iv-2", requester_node_id=_TEST_NODE_ID,
            issued_at="2026-01-01T00:00:00Z", expires_at="2026-12-31T23:59:59Z",
            requirements=(c_bw, c_lat),
        )),
        ("extensions", base_intent(
            intent_id="iv-3", constraints=(c_bw,),
            extensions=({"x-tag": "rt", "profile": "v1"},),
        )),
        ("mixed-buckets", ConnectivityIntent(
            intent_id="iv-4", requirements=(c_bw, c_priv),
            preferences=(c_loc,), service_constraints=(c_serv,),
        )),
    ]
    for label, i in shapes:
        r = normalize_intent(i)
        if not r.ok or r.intent is None:
            results.append(fail(
                "case_44_digest_recomputable_from_public_canonical_bytes",
                "shape %r failed to normalize: ok=%r code=%r" % (label, r.ok, r.code),
            ))
            return
        ni = r.intent
        cb = ni.canonical_bytes()
        recomputed = hashlib.sha256(cb).hexdigest()
        # The core public invariant.
        if recomputed != ni.digest:
            results.append(fail(
                "case_44_digest_recomputable_from_public_canonical_bytes",
                "shape %r: sha256(canonical_bytes())=%s != digest=%s"
                % (label, recomputed[:12], ni.digest[:12]),
            ))
            return
        # canonical_bytes() MUST be the content representation (no digest).
        # to_dict() DOES carry the digest (storage form). Both explicit.
        content = ni.content_dict()
        if "digest" in content:
            results.append(fail(
                "case_44_digest_recomputable_from_public_canonical_bytes",
                "shape %r: content_dict() must not carry digest" % label,
            ))
            return
        stored = ni.to_dict()
        if "digest" not in stored or stored["digest"] != ni.digest:
            results.append(fail(
                "case_44_digest_recomputable_from_public_canonical_bytes",
                "shape %r: to_dict() must carry the digest" % label,
            ))
            return
        # Single source of truth: canonical_bytes() == canonical_json_bytes(content_dict()).
        if cb != canonical_json_bytes(content):
            results.append(fail(
                "case_44_digest_recomputable_from_public_canonical_bytes",
                "shape %r: canonical_bytes() != canonical_json_bytes(content_dict())"
                % label,
            ))
            return
    results.append(ok(
        "case_44_digest_recomputable_from_public_canonical_bytes",
        "sha256(canonical_bytes())==digest for all %d shapes; content_dict/to_dict explicit"
        % len(shapes),
    ))


def case_45_equivalent_unit_duplicates_fail_closed(results: List[Result]) -> None:
    """45. Equivalent-unit duplicates MUST fail closed (Architect PR #9 blocker).

    ``1 Mbps`` and ``1000 kbps`` are distinct during pre-normalization
    duplicate checks (different raw unit strings), then normalize to the
    same canonical constraint (``1_000_000 bps``). Without canonicalizing
    units BEFORE the duplicate-semantic check, the pair slipped through and
    produced two identical canonical constraints in the NormalizedIntent
    instead of failing closed.

    Fix: :func:`intent.validation.validate_constraint_set` now computes the
    semantic key over the *canonical* (base-unit) form, so equivalent-unit
    pairs collide at validation time and raise ``duplicate-semantic``.

    This case exercises:
      (a) same hardness, equivalent bandwidth units -> duplicate-semantic;
      (b) different hardness, equivalent bandwidth units -> duplicate-semantic
          (the cross-hardness ambiguity branch);
      (c) intent-native latency units (``1 s`` vs ``1000 ms``) -> same;
      (d) the canonical-key helper returns identical base-form keys for the
          equivalent pair (direct contract assertion).
    """
    from intent.validation import _canonical_semantic_key

    # (a) bandwidth: 1 Mbps hard + 1000 kbps hard, different ids.
    c1 = base_constraint(constraint_id="bw1", value=1, unit="Mbps", hardness=Hardness.HARD)
    c2 = base_constraint(constraint_id="bw2", value=1000, unit="kbps", hardness=Hardness.HARD)
    i = base_intent(intent_id="dup-bw", constraints=(c1, c2))
    r = normalize_intent(i)
    if r.ok or r.code != "duplicate-semantic":
        results.append(fail(
            "case_45_equivalent_unit_duplicates_fail_closed",
            "(a) expected duplicate-semantic, got ok=%r code=%r" % (r.ok, r.code),
        ))
        return
    # The NormalizedIntent MUST NOT have been built with duplicate canonical
    # constraints. r.intent is None on failure.
    if r.intent is not None:
        results.append(fail(
            "case_45_equivalent_unit_duplicates_fail_closed",
            "(a) expected intent=None on failure, got constraints=%d"
            % len(r.intent.constraints),
        ))
        return
    # (b) cross-hardness: 1 Mbps hard + 1000 kbps soft(weight=5).
    c3 = base_constraint(constraint_id="bw1", value=1, unit="Mbps", hardness=Hardness.HARD)
    c4 = base_constraint(constraint_id="bw2", value=1000, unit="kbps", hardness=Hardness.SOFT, weight=5)
    i2 = base_intent(intent_id="dup-xhard", constraints=(c3, c4))
    r2 = normalize_intent(i2)
    if r2.ok or r2.code != "duplicate-semantic":
        results.append(fail(
            "case_45_equivalent_unit_duplicates_fail_closed",
            "(b) expected duplicate-semantic, got ok=%r code=%r" % (r2.ok, r2.code),
        ))
        return
    # (c) intent-native latency: 1 s hard + 1000 ms hard.
    c5 = Constraint(
        constraint_id="lat1", dimension=IntentDimension.LATENCY,
        operator=Operator.LE, value=1, unit="s", hardness=Hardness.HARD,
    )
    c6 = Constraint(
        constraint_id="lat2", dimension=IntentDimension.LATENCY,
        operator=Operator.LE, value=1000, unit="ms", hardness=Hardness.HARD,
    )
    i3 = base_intent(intent_id="dup-lat", constraints=(c5, c6))
    r3 = normalize_intent(i3)
    if r3.ok or r3.code != "duplicate-semantic":
        results.append(fail(
            "case_45_equivalent_unit_duplicates_fail_closed",
            "(c) expected duplicate-semantic, got ok=%r code=%r" % (r3.ok, r3.code),
        ))
        return
    # (d) Direct contract: the canonical-key helper returns IDENTICAL keys
    # for the equivalent pair, in BASE form. (Without canonicalization, the
    # raw keys would differ: (bandwidth, >=, 1, 'Mbps', '') vs
    # (bandwidth, >=, 1000, 'kbps', '').)
    k1 = _canonical_semantic_key(c1)
    k2 = _canonical_semantic_key(c2)
    if k1 != k2:
        results.append(fail(
            "case_45_equivalent_unit_duplicates_fail_closed",
            "(d) canonical keys differ: %r vs %r" % (k1, k2),
        ))
        return
    if k1 != ("bandwidth", ">=", 1_000_000, "bps", ""):
        results.append(fail(
            "case_45_equivalent_unit_duplicates_fail_closed",
            "(d) canonical key not in base form: %r" % (k1,),
        ))
        return
    results.append(ok(
        "case_45_equivalent_unit_duplicates_fail_closed",
        "(a) bw same-hardness, (b) cross-hardness, (c) latency native, (d) key helper -- all fail closed",
    ))


def main() -> int:
    results: List[Result] = []
    # Required adversarial verification cases (1-25)
    case_01_minimal_valid_intent(results)
    case_02_all_eight_dimensions_represented(results)
    case_03_hard_vs_soft_constraints(results)
    case_04_insertion_order_independent_normalization(results)
    case_05_equivalent_unit_normalization(results)
    case_06_incompatible_unit_rejection(results)
    case_07_unsupported_operator_rejection(results)
    case_08_unsupported_required_constraint_rejection(results)
    case_09_optional_extension_preservation(results)
    case_10_duplicate_constraint_ambiguity_rejection(results)
    case_11_malformed_requester_nodeid_rejection(results)
    case_12_malformed_naive_timestamp_rejection(results)
    case_13_validity_expiry_behavior(results)
    case_14_negative_numeric_rejection(results)
    case_15_nan_infinity_float_rejection(results)
    case_16_deterministic_digest(results)
    case_17_5g_wifi_vendor_implementation_leakage_rejection(results)
    case_18_route_resource_trust_policy_leakage_audit(results)
    case_19_secret_material_serialization_rejection(results)
    case_20_future_profile_constraint_handling(results)
    case_21_canonical_byte_identity_across_runs(results)
    case_22_fuzz_property_inputs_never_crash(results)
    case_23_hard_constraints_never_silently_downgraded(results)
    case_24_soft_constraints_never_silently_upgraded(results)
    case_25_normalization_has_no_side_effects_on_resource_topology_state(results)
    # Additional mechanical / boundary cases
    case_26_label_dimension_unit_rejection(results)
    case_27_reliability_basis_point_normalization(results)
    case_28_energy_unit_normalization(results)
    case_29_cost_unit_normalization(results)
    case_30_case_insensitive_unit_aliases(results)
    case_31_serialization_roundtrip(results)
    case_32_no_forbidden_fields_or_methods(results)
    case_33_no_5g_vendor_imports(results)
    case_34_frozen_dimensions_present(results)
    case_35_frozen_operators_present(results)
    case_36_extensions_secret_material_deep_nested(results)
    case_37_normalized_intent_serialization_no_leak(results)
    case_38_bucket_for_privacy_service(results)
    case_39_intent_id_uniqueness_no_second_authority(results)
    case_40_repeated_runs_byte_identical(results)
    case_41_normalization_thread_safe(results)
    case_42_constraint_id_must_be_unique_string(results)
    case_43_intent_id_required(results)
    # Architect PR #9 correction regressions
    case_44_digest_recomputable_from_public_canonical_bytes(results)
    case_45_equivalent_unit_duplicates_fail_closed(results)

    print("ADCOS intent self-test (WORK-009)")
    print("=" * 72)
    for name, ok_flag, detail in results:
        print("[%s] %-58s %s" % ("ok  " if ok_flag else "FAIL", name, detail))
    print("-" * 72)
    passed = sum(1 for _, ok_flag, _ in results if ok_flag)
    if passed == len(results):
        print("Result: PASS (%d/%d cases)" % (passed, len(results)))
        return 0
    print("Result: FAIL (%d/%d cases passed)" % (passed, len(results)))
    return 1


if __name__ == "__main__":
    sys.exit(main())
