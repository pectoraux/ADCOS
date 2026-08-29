#!/usr/bin/env python3
"""ADCOS Open RAN/Core interoperability profile self-test (WORK-037).

The WORK-037 battery: the frozen vocabularies and value records, the
fail-closed profile validation (with the full negative matrix), the
class-B mixed-access scenario (one sacred WORK-012 ``session_id``
across the W019 core leg, the W020 radio leg, the W021 non-3GPP leg,
and back -- byte-identical round trips over REAL loopback conformance
peers, cross-family ref opacity, journaled access changes), the
class-C interoperability-lab gate (composition of the three accepted
real leg gates: GATE_DISABLED / LEG_DISABLED / FORBIDDEN /
UNREACHABLE / SESSION_DIVERGENCE / PASSED -- no new PASS path, no
in-repo fallback, no promotion of simulation to real-lab evidence),
and the three-class evidence model (A/B closed in-repo; C OPEN until
the real gate passes -- the W020 lesson enforced structurally).

Structural audits: no shadow authority, import discipline, ADCOS-core
purity (no interop / vendor adapter leakage into core), injected
clock only, secret hygiene, naming-token freedom, determinism across
fresh runs and hash seeds, replay verification, frozen surfaces (API,
spec/, PR-delta shape, CI wiring + ordering).
"""

from __future__ import annotations

import ast
import hashlib
import json as _json
import os
import py_compile
import re
import subprocess
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

# Make the repository root importable.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from interop import (  # noqa: E402
    DEFAULT_ORAN_INTEROP_SESSION_ID,
    DEFAULT_PROFILE_PAYLOAD,
    INTEROP_PREFIX,
    COMPONENT_FAMILY,
    COMPONENT_REFERENCE_POINTS,
    PROFILE_EVIDENCE_STATUS,
    PROFILE_LEG_SWITCHES,
    REAL_LAB_EVIDENCE_STATEMENT,
    REQUIRED_REFERENCE_POINTS,
    AccessLegKind,
    ComponentBinding,
    InteropError,
    InteropEventType,
    InteropReasonCode,
    LegGateStatus,
    ProfileComponentKind,
    ProfileDeclaration,
    ProfileLabConfig,
    ProfileLabOutcome,
    ReferencePointKind,
    ScenarioLegName,
    SessionFacts,
    aggregate_leg_outcomes,
    assert_no_real_lab_claim,
    canonical_profile,
    check_ref_opacity,
    check_session_coherence,
    classify_profile_evidence,
    oran_interop_gate_enabled,
    profile_lab_runbook,
    reference_points_for_component,
    run_profile_lab_gate,
    run_profile_scenario,
    validate_profile,
    verify_interop_replay,
)
from conformance.model import EvidenceClass  # noqa: E402

REPO_ROOT = _ROOT
Result = Tuple[str, bool, str]

_T0 = "2026-06-01T00:00:00Z"
_NOW = "2026-06-01T12:00:00Z"
_SESSION_ID = "sha256:" + "1" * 64


def ok(name: str, detail: str = "") -> Result:
    return (name, True, detail)


def fail(name: str, detail: str) -> Result:
    return (name, False, detail)


# ---------------------------------------------------------------------------
# The real WORK-012 session fixture (the scenario's session is INPUT,
# validated through a read-only lookup -- never minted by the profile).
# ---------------------------------------------------------------------------


def _established_session():
    from policy.model import PolicyDecision
    from resources import ResourceStore
    from routing import LinkMetrics, RoutingContext, RoutingEngine
    from sessions import SessionState, SessionStore
    from topology import (
        ClaimType,
        SourceClass,
        TopologyClaim,
        TopologyGraph,
        make_link_subject,
    )

    node_a = "adcos:node:test.interop.v1:" + "a" * 64
    node_b = "adcos:node:test.interop.v1:" + "b" * 64

    def policy_decision(instant: str = _NOW) -> PolicyDecision:
        ph = PolicyDecision(
            decision_id="0" * 64, effect="allow", code="allow",
            detail="fixture", matched_rule_ids=("r1",), policy_set_id="ps-1",
            policy_set_version=2, evaluation_instant=instant,
        )
        digest = hashlib.sha256(ph.canonical_bytes()).hexdigest()
        return PolicyDecision(
            decision_id=digest, effect="allow", code="allow",
            detail="fixture", matched_rule_ids=("r1",), policy_set_id="ps-1",
            policy_set_version=2, evaluation_instant=instant,
        )

    graph = TopologyGraph()
    graph.merge(TopologyClaim(
        subject=make_link_subject(node_a, node_b), reporter=node_a,
        claim_type=ClaimType.LINK_STATE, value="up",
        source_class=SourceClass.SELF_ADVERTISEMENT,
        issued_at=_T0, freshness_until="2026-12-31T23:59:59Z",
        sequence=1, provenance="",
    ))
    graph.merge(TopologyClaim(
        subject=node_b, reporter=node_a,
        claim_type=ClaimType.REACHABLE, value="true",
        source_class=SourceClass.DIRECT_OBSERVATION,
        issued_at=_T0, freshness_until="2026-12-31T23:59:59Z",
        sequence=1, provenance="",
    ))
    ctx = RoutingContext(
        source_node_id=node_a, destination_node_id=node_b,
        topology=graph, resources=ResourceStore(),
        evaluation_instant=_NOW, policy_decision=policy_decision(_NOW),
        link_metrics={
            make_link_subject(node_a, node_b): LinkMetrics(
                latency_ms=10, loss_basis_points=0, capacity_bps=1_000_000,
                energy_cost_millijoules=100, confidence_basis_points=10_000,
                observed_at=_T0, freshness_until="2026-12-31T23:59:59Z",
            ),
        },
    )
    res = RoutingEngine().evaluate(ctx)
    assert res.decision is not None and res.decision.selected is not None
    store = SessionStore()
    created = store.create(
        res.decision, policy_decision(_NOW), source_node_id=node_a,
        destination_node_id=node_b, creation_instant=_NOW,
    )
    assert created.ok and created.session is not None
    sid = created.session.session_id
    store.transition(sid, SessionState.AUTHORIZED, event_instant=_NOW)
    store.transition(sid, SessionState.ESTABLISHED, event_instant=_NOW)
    return store, sid


def _store_lookup(store) -> Callable[[str], Optional[SessionFacts]]:
    """The read-only session projection over a REAL WORK-012 store
    (the composition-root wiring the scenario validates through)."""

    def lookup(session_id: str) -> Optional[SessionFacts]:
        session = store.get(session_id)
        if session is None:
            return None
        return SessionFacts(
            secureable=session.state in ("ESTABLISHED", "DEGRADED"),
            initiator_node_id=session.binding.source_node_id,
            responder_node_id=session.binding.destination_node_id,
        )

    return lookup


def _run_scenario_with_real_session():
    store, sid = _established_session()
    result = run_profile_scenario(
        canonical_profile(),
        session_id=sid,
        session_lookup=_store_lookup(store),
    )
    return result


def _scenario_digest() -> str:
    """The full scenario digest (used by the hash-seed case)."""
    return _run_scenario_with_real_session().interop_digest()


# ---------------------------------------------------------------------------
# 01-06: frozen vocabularies, records, maps, disclosures
# ---------------------------------------------------------------------------


def case_01_frozen_vocabularies(results: List[Result]) -> None:
    name = "case_01_frozen_vocabularies"
    problems: List[str] = []
    if ProfileComponentKind.values() != (
        "five-g-core", "ran", "non-threegpp-access", "conformance",
        "reference-agent",
    ):
        problems.append("component kinds drifted")
    if ReferencePointKind.values() != (
        "core-control", "core-user-plane", "ran-control", "ran-user-plane",
        "non-threegpp-attach", "non-threegpp-tunnel", "mixed-access",
    ):
        problems.append("reference points drifted")
    if AccessLegKind.values() != ("three-gpp", "non-three-gpp"):
        problems.append("access legs drifted")
    if ScenarioLegName.values() != (
        "five-g-core-pdu", "ran-access-path", "non-threegpp-tunnel",
        "five-g-core-rebind",
    ):
        problems.append("scenario legs drifted")
    if InteropEventType.values() != (
        "profile-validated", "leg-started", "leg-bytes-verified",
        "leg-released", "access-changed", "session-coherence-verified",
        "ref-opacity-verified", "profile-verified", "evidence-recorded",
    ):
        problems.append("event kinds drifted")
    if len(InteropReasonCode.values()) != 16:
        problems.append("reason code count drifted")
    if not all(
        reason.startswith(INTEROP_PREFIX + ".")
        for reason in InteropReasonCode.values()
    ):
        problems.append("reason codes lost the interop. prefix")
    if ScenarioLegName.access_kind_for("non-threegpp-tunnel") != "non-three-gpp":
        problems.append("non-3GPP leg access mapping wrong")
    if ScenarioLegName.access_kind_for("ran-access-path") != "three-gpp":
        problems.append("RAN leg access mapping wrong")
    try:
        ScenarioLegName.access_kind_for("satellite")  # type: ignore[arg-type]
        problems.append("unknown leg accepted")
    except InteropError:
        pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "5 vocabularies + 16 reason codes frozen exact",
    ))


def case_02_ownership_maps_frozen(results: List[Result]) -> None:
    name = "case_02_ownership_maps_frozen"
    problems: List[str] = []
    if COMPONENT_FAMILY != {
        "five-g-core": "adapters.fivegc",
        "ran": "adapters.ran",
        "non-threegpp-access": "adapters.wifi",
        "conformance": "conformance",
        "reference-agent": "agent",
    }:
        problems.append("component-family map drifted")
    expected_points = {
        "five-g-core": ("core-control", "core-user-plane"),
        "ran": ("ran-control", "ran-user-plane"),
        "non-threegpp-access": ("non-threegpp-attach", "non-threegpp-tunnel"),
        "conformance": (),
        "reference-agent": ("mixed-access",),
    }
    if dict(COMPONENT_REFERENCE_POINTS) != expected_points:
        problems.append("reference-point ownership drifted")
    if REQUIRED_REFERENCE_POINTS != ReferencePointKind.values():
        problems.append("required points are not the full vocabulary")
    for kind in ProfileComponentKind.values():
        if reference_points_for_component(kind) != expected_points[kind]:
            problems.append("ownership accessor drifted for %r" % kind)
    try:
        reference_points_for_component("satellite")  # type: ignore[arg-type]
        problems.append("unknown component accepted")
    except InteropError:
        pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "component->family + component->reference-point maps frozen",
    ))


def case_03_profile_declaration_records(results: List[Result]) -> None:
    name = "case_03_profile_declaration_records"
    profile = canonical_profile()
    problems: List[str] = []
    if not re.fullmatch(r"[0-9a-f]{64}", profile.digest()):
        problems.append("digest is not 64-hex")
    if not profile.canonical_bytes().startswith(b"{"):
        problems.append("canonical bytes are not JSON")
    rebuilt = ProfileDeclaration(
        profile_id=profile.profile_id,
        version=profile.version,
        bindings=tuple(
            ComponentBinding(
                component_kind=b.component_kind,
                family=b.family,
                integration_id=b.integration_id,
                label=b.label,
            )
            for b in reversed(profile.bindings)  # construction order reversed
        ),
    )
    if rebuilt.canonical_bytes() != profile.canonical_bytes():
        problems.append("canonical bytes depend on construction order")
    if rebuilt.digest() != profile.digest():
        problems.append("digest depends on construction order")
    parsed = _json.loads(profile.canonical_bytes().decode("utf-8"))
    if parsed["profile_id"] != profile.profile_id:
        problems.append("round-trip profile_id mismatch")
    if len(parsed["bindings"]) != 5:
        problems.append("round-trip binding count mismatch")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "declaration records: canonical bytes + digests, "
              "order-independent",
    ))


def case_04_profile_validation_negatives(results: List[Result]) -> None:
    name = "case_04_profile_validation_negatives"
    problems: List[str] = []
    profile = canonical_profile()

    def mutate(**kwargs):
        base = dict(
            profile_id=profile.profile_id,
            version=profile.version,
            bindings=profile.bindings,
        )
        base.update(kwargs)
        return ProfileDeclaration(**base)

    # missing component (drop the conformance binding)
    try:
        mutate(bindings=tuple(
            b for b in profile.bindings
            if b.component_kind != ProfileComponentKind.CONFORMANCE
        ))
        problems.append("missing component accepted")
    except InteropError as exc:
        if exc.reason != InteropReasonCode.PROFILE_INVALID:
            problems.append("missing component reason %r" % exc.reason)
    # duplicate component
    try:
        mutate(bindings=profile.bindings + (profile.bindings[0],))
        problems.append("duplicate component accepted")
    except InteropError as exc:
        if exc.reason != InteropReasonCode.PROFILE_INVALID:
            problems.append("duplicate component reason %r" % exc.reason)
    # wrong family
    try:
        mutate(bindings=tuple(
            ComponentBinding(
                component_kind=b.component_kind,
                family="adapters.wifi" if b.component_kind == "five-g-core"
                else b.family,
                integration_id=b.integration_id,
                label=b.label,
            )
            for b in profile.bindings
        ))
        problems.append("wrong family accepted")
    except InteropError as exc:
        if exc.reason != InteropReasonCode.COMPONENT_MISMATCH:
            problems.append("wrong family reason %r" % exc.reason)
    # empty integration id
    try:
        ComponentBinding(
            component_kind="ran", family="adapters.ran",
            integration_id="", label="x",
        )
        problems.append("empty integration id accepted")
    except InteropError:
        pass
    # bad prefix
    try:
        mutate(profile_id="adcos:other:profile")
        problems.append("bad prefix accepted")
    except InteropError as exc:
        if exc.reason != InteropReasonCode.PROFILE_INVALID:
            problems.append("bad prefix reason %r" % exc.reason)
    # bad version
    try:
        mutate(version=0)
        problems.append("version 0 accepted")
    except InteropError:
        pass
    # incomplete reference-point set
    try:
        ProfileDeclaration(
            profile_id=profile.profile_id,
            version=profile.version,
            bindings=profile.bindings,
            required_reference_points=(
                "core-control", "core-user-plane", "ran-control",
                "ran-user-plane", "non-threegpp-attach",
                "non-threegpp-tunnel",
            ),  # MIXED_ACCESS missing
        )
        problems.append("six-point profile accepted")
    except InteropError as exc:
        if exc.reason != InteropReasonCode.REFERENCE_POINT_UNBOUND:
            problems.append("six-point reason %r" % exc.reason)
    # validate_profile rejects non-declarations
    try:
        validate_profile("not-a-profile")  # type: ignore[arg-type]
        problems.append("non-declaration accepted")
    except InteropError as exc:
        if exc.reason != InteropReasonCode.INVALID_INPUT:
            problems.append("non-declaration reason %r" % exc.reason)
    # the genuine profile validates
    digest = validate_profile(profile)
    if digest != profile.digest():
        problems.append("validate_profile digest mismatch")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "9 negative shapes rejected with typed reasons; genuine "
              "profile validates",
    ))


def case_05_evidence_class_map(results: List[Result]) -> None:
    name = "case_05_evidence_class_map"
    from interop import PROFILE_EVIDENCE_CLASS_MAP

    problems: List[str] = []
    if sorted(PROFILE_EVIDENCE_CLASS_MAP) != ["A", "B", "C"]:
        problems.append("map keys drifted")
    if PROFILE_EVIDENCE_CLASS_MAP["A"] is not EvidenceClass.ARCHITECTURE_CONFORMANCE:
        problems.append("A is not the W032 architecture-conformance class")
    if PROFILE_EVIDENCE_CLASS_MAP["B"] is not EvidenceClass.AUTOMATED_VERIFICATION:
        problems.append("B is not the W032 automated-verification class")
    if PROFILE_EVIDENCE_CLASS_MAP["C"] is not EvidenceClass.EXTERNAL_EVIDENCE:
        problems.append("C is not the W032 external-evidence class")
    # The W032 enum values are the frozen strings (no second vocabulary).
    if EvidenceClass.ARCHITECTURE_CONFORMANCE.value != "architecture-conformance":
        problems.append("W032 class A value drifted")
    if EvidenceClass.AUTOMATED_VERIFICATION.value != "automated-verification":
        problems.append("W032 class B value drifted")
    if EvidenceClass.EXTERNAL_EVIDENCE.value != "external-evidence":
        problems.append("W032 class C value drifted")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "A/B/C map reuses the W032 EvidenceClass vocabulary exactly",
    ))


def case_06_evidence_status_disclosure(results: List[Result]) -> None:
    name = "case_06_evidence_status_disclosure"
    problems: List[str] = []
    if PROFILE_EVIDENCE_STATUS != {
        "architecture_conformance": "supported-verified",
        "automated_verification": "supported-verified",
        "real_interop_lab": "open",
    }:
        problems.append("evidence status drifted")
    lowered = REAL_LAB_EVIDENCE_STATEMENT.lower()
    if "never be promoted" not in lowered:
        problems.append("statement lacks the never-promoted rule")
    if "rf simulation" not in lowered:
        problems.append("statement does not name RF simulation")
    if "rfsim" not in lowered.replace("-", " "):
        problems.append("statement does not name OAI RFsim")
    runbook = profile_lab_runbook()
    if runbook["evidence_status"] != PROFILE_EVIDENCE_STATUS:
        problems.append("runbook status drifted from the pinned status")
    if "FORBIDDEN" not in str(runbook["anti_faking"]):
        problems.append("runbook anti-faking lacks the FORBIDDEN rule")
    if profile_lab_runbook() != runbook:
        problems.append("runbook not deterministic")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "three-class disclosure pinned; class C open; runbook frozen",
    ))


# ---------------------------------------------------------------------------
# 07-16: the class-B scenario
# ---------------------------------------------------------------------------


def case_07_mixed_access_scenario(results: List[Result]) -> None:
    name = "case_07_mixed_access_scenario"
    result = _run_scenario_with_real_session()
    problems: List[str] = []
    if [leg.leg for leg in result.legs] != list(ScenarioLegName.values()):
        problems.append("leg order drifted")
    for leg in result.legs:
        if leg.session_id != result.session_id:
            problems.append("leg %r session diverged" % leg.leg)
        if leg.payload_sha256 != leg.echo_sha256:
            problems.append("leg %r bytes mismatched" % leg.leg)
        if leg.evidence_class != "B":
            problems.append("leg %r class %r" % (leg.leg, leg.evidence_class))
        if leg.payload_sha256 != hashlib.sha256(DEFAULT_PROFILE_PAYLOAD).hexdigest():
            problems.append("leg %r payload digest unexpected" % leg.leg)
    non3gpp = [leg for leg in result.legs if leg.access_kind == "non-three-gpp"]
    threegpp = [leg for leg in result.legs if leg.access_kind == "three-gpp"]
    if len(non3gpp) != 1 or len(threegpp) != 3:
        problems.append("access-kind mix wrong")
    kinds = [e.kind for e in result.events]
    for required in (
        "profile-validated", "leg-started", "leg-bytes-verified",
        "leg-released", "access-changed", "ref-opacity-verified",
        "session-coherence-verified", "profile-verified",
        "evidence-recorded",
    ):
        if required not in kinds:
            problems.append("journal lacks %r" % required)
    if kinds.count("access-changed") != 2:
        problems.append("expected exactly 2 journaled access changes")
    terminal = result.events[-1]
    if "class C" not in terminal.detail or "OPEN" not in terminal.detail:
        problems.append("terminal event does not disclose class C open")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "4 legs (3 three-gpp + 1 non-three-gpp) byte-identical over "
              "the W019/W020/W021 seams; %d journaled events; session_id "
              "sacred" % len(result.events),
    ))


def case_08_scenario_session_discipline(results: List[Result]) -> None:
    name = "case_08_scenario_session_discipline"
    store, sid = _established_session()
    lookup = _store_lookup(store)
    profile = canonical_profile()
    problems: List[str] = []

    try:
        run_profile_scenario(
            profile, session_id="sha256:" + "9" * 64, session_lookup=lookup,
        )
        problems.append("unknown session accepted")
    except InteropError as exc:
        if exc.reason != InteropReasonCode.SESSION_UNKNOWN:
            problems.append("unknown session reason %r" % exc.reason)

    # an unsecureable session: a fresh CREATED (not ESTABLISHED) session
    from sessions import SessionStore, SessionState

    def unsecureable_lookup(session_id: str) -> Optional[SessionFacts]:
        return SessionFacts(
            secureable=False,
            initiator_node_id="adcos:node:test.interop.v1:" + "a" * 64,
            responder_node_id="adcos:node:test.interop.v1:" + "b" * 64,
        )

    try:
        run_profile_scenario(
            profile, session_id=sid, session_lookup=unsecureable_lookup,
        )
        problems.append("unsecureable session accepted")
    except InteropError as exc:
        if exc.reason != InteropReasonCode.SESSION_UNSECUREABLE:
            problems.append("unsecureable reason %r" % exc.reason)

    def mistyped_lookup(session_id: str):
        return "not-session-facts"

    try:
        run_profile_scenario(
            profile, session_id=sid, session_lookup=mistyped_lookup,  # type: ignore[arg-type]
        )
        problems.append("mistyped lookup accepted")
    except InteropError as exc:
        if exc.reason != InteropReasonCode.INVALID_INPUT:
            problems.append("mistyped lookup reason %r" % exc.reason)

    try:
        run_profile_scenario(
            profile, session_id="", session_lookup=lookup,
        )
        problems.append("empty session id accepted")
    except InteropError as exc:
        if exc.reason != InteropReasonCode.INVALID_INPUT:
            problems.append("empty session id reason %r" % exc.reason)

    # SessionStore import used above is real (silence the unused warning
    # pattern used by the accepted batteries).
    _ = (SessionStore, SessionState)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "unknown/unsecureable/mistyped/empty session refusals typed",
    ))


def case_09_scenario_profile_gate(results: List[Result]) -> None:
    name = "case_09_scenario_profile_gate"
    profile = canonical_profile()
    problems: List[str] = []
    # The record constructor itself is fail-closed: a declaration with
    # a missing component cannot even be constructed.
    try:
        ProfileDeclaration(
            profile_id=profile.profile_id,
            version=profile.version,
            bindings=tuple(
                b for b in profile.bindings
                if b.component_kind != ProfileComponentKind.REFERENCE_AGENT
            ),
        )
        problems.append("missing-component declaration constructed")
    except InteropError as exc:
        if exc.reason != InteropReasonCode.PROFILE_INVALID:
            problems.append("construction reason %r" % exc.reason)
    # The scenario's own profile gate refuses non-declarations before
    # any peer is started.
    store, sid = _established_session()
    try:
        run_profile_scenario(
            "not-a-profile",  # type: ignore[arg-type]
            session_id=sid,
            session_lookup=_store_lookup(store),
        )
        problems.append("non-declaration accepted by the scenario")
    except InteropError as exc:
        if exc.reason != InteropReasonCode.INVALID_INPUT:
            problems.append("scenario gate reason %r" % exc.reason)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "fail-closed at BOTH gates: the record constructor and the "
              "scenario's validate_profile",
    ))


def case_10_ref_opacity_discrimination(results: List[Result]) -> None:
    name = "case_10_ref_opacity_discrimination"
    problems: List[str] = []
    # genuine-shaped refs (the accepted families' real prefixes)
    try:
        check_ref_opacity(
            fivegc_refs=("adcos:fivegc:pdu:" + "a" * 32,),
            ran_refs=("ran:gnb:" + "b" * 32,),
            wifi_refs=("wifi:tunnel:" + "c" * 32,),
        )
    except InteropError as exc:
        problems.append("genuine refs rejected: %s" % exc.detail)
    # leaky shapes: each family carrying ANOTHER family's fragment
    for kwargs in (
        {"fivegc_refs": ("adcos:fivegc:pdu:x-wifi:leak",)},
        {"fivegc_refs": ("adcos:fivegc:ref:ran:leak",)},
        {"ran_refs": ("ran:gnb:adcos:fivegc:leak",)},
        {"ran_refs": ("ran:gnb:wifi:tunnel:leak",)},
        {"wifi_refs": ("wifi:tunnel:ran:gnb:leak",)},
        {"wifi_refs": ("wifi:assoc:pdu:leak",)},
    ):
        try:
            check_ref_opacity(**kwargs)
            problems.append("leaky ref accepted: %r" % (kwargs,))
        except InteropError as exc:
            if exc.reason != InteropReasonCode.REF_OPACITY_VIOLATION:
                problems.append("leak reason %r" % exc.reason)
    # non-string refs
    try:
        check_ref_opacity(ran_refs=(42,))  # type: ignore[arg-type]
        problems.append("non-string ref accepted")
    except InteropError:
        pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "6 leaky shapes rejected; genuine cross-family refs pass",
    ))


def case_11_journal_events(results: List[Result]) -> None:
    name = "case_11_journal_events"
    result = _run_scenario_with_real_session()
    problems: List[str] = []
    instants: List[str] = []
    for index, event in enumerate(result.events):
        if event.sequence != index + 1:
            problems.append("sequence broken at %d" % index)
        recomputed = event.event_id()
        if not re.fullmatch(r"[0-9a-f]{64}", recomputed):
            problems.append("event id not 64-hex")
        instants.append(event.instant)
        if len(event.detail) > 200:
            problems.append("event %d detail unbounded" % event.sequence)
    if instants != sorted(instants):
        problems.append("instants not monotonic")
    if len(set(instants)) != len(instants):
        problems.append("instants not one-per-step")
    # the raw adapter refs never appear in any journaled detail
    journal_bytes = b"".join(e.canonical_bytes() for e in result.events)
    for fragment in ("adcos:fivegc:", "ran:gnb:", "wifi:"):
        if fragment.encode("utf-8") in journal_bytes:
            problems.append("raw ref fragment %r leaked into the journal" % fragment)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "content-derived ids, contiguous sequences, monotonic "
              "one-per-step instants, no raw refs in the journal",
    ))


def case_12_run_digest_and_round_trip(results: List[Result]) -> None:
    name = "case_12_run_digest_and_round_trip"
    result = _run_scenario_with_real_session()
    problems: List[str] = []
    digest = result.interop_digest()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        problems.append("run digest not 64-hex")
    payload = result.to_dict()
    if payload["interop_digest"] != digest:
        problems.append("to_dict digest mismatch")
    encoded = _json.dumps(payload, sort_keys=True).encode("utf-8")
    if _json.loads(encoded.decode("utf-8"))["session_id"] != result.session_id:
        problems.append("round-trip session mismatch")
    if len(payload["legs"]) != 4:
        problems.append("round-trip leg count mismatch")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "run digest 64-hex; to_dict round-trips; 4 legs carried",
    ))


def case_13_determinism_fresh_run(results: List[Result]) -> None:
    name = "case_13_determinism_fresh_run"
    first = _run_scenario_with_real_session()
    second = _run_scenario_with_real_session()
    if first.interop_digest() != second.interop_digest():
        results.append(fail(name, "fresh-run digests diverged"))
        return
    if first.canonical_bytes() != second.canonical_bytes():
        results.append(fail(name, "fresh-run canonical bytes diverged"))
        return
    results.append(ok(
        name, "two fresh runs byte-identical (digest + canonical bytes)",
    ))


def case_14_hashseed_invariance(results: List[Result]) -> None:
    name = "case_14_hashseed_invariance"
    script = (
        "import sys\n"
        "sys.path.insert(0, %r)\n"
        "from tools.oran_selftest import _scenario_digest\n"
        "print(_scenario_digest())\n"
    ) % (str(REPO_ROOT),)
    digests: List[str] = []
    problems: List[str] = []
    for seed in ("0", "1", "7919", None):
        env = dict(os.environ)
        # The gate cases scrub the interop environment; keep the seeds
        # the only variable.
        for key in (
            "ORAN_INTEROP", "OPEN5GS_INTEROP", "RAN_INTEROP",
            "WIFI_INTEROP", "RAN_PEER_KIND", "OPEN5GS_PEER_KIND",
            "WIFI_PEER_KIND",
        ):
            env.pop(key, None)
        env.pop("PYTHONHASHSEED", None)
        if seed is not None:
            env["PYTHONHASHSEED"] = seed
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, env=env, cwd=str(REPO_ROOT),
        )
        if proc.returncode != 0:
            problems.append("seed %s failed: %s" % (seed, proc.stderr[-200:]))
            break
        digests.append(proc.stdout.strip().splitlines()[-1])
    if not problems and len(set(digests)) != 1:
        problems.append("digests diverged across hash seeds")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "PYTHONHASHSEED 0/1/7919/None: identical digests"))


def case_15_replay_verification(results: List[Result]) -> None:
    name = "case_15_replay_verification"
    from interop import InteropEvent, InteropRunResult, LegEvidence

    store, sid = _established_session()
    lookup = _store_lookup(store)
    profile = canonical_profile()
    result = run_profile_scenario(
        profile, session_id=sid, session_lookup=lookup,
    )
    problems: List[str] = []

    def check(tampered) -> str:
        try:
            verify_interop_replay(
                tampered,
                profile=profile, session_id=sid, session_lookup=lookup,
            )
            return "accepted"
        except InteropError as exc:
            return exc.reason

    # the genuine result verifies (structural + full replay).
    if check(result) != "accepted":
        problems.append("genuine result rejected: %s" % check(result))

    # mutated event detail -> the replay digest diverges.
    fields: Dict[str, Any] = dict(
        sequence=result.events[0].sequence,
        instant=result.events[0].instant,
        kind=result.events[0].kind,
        subject=result.events[0].subject,
        detail=result.events[0].detail,
    )
    fields["detail"] = "tampered"

    def rebuilt(events, legs=None):
        return InteropRunResult(
            profile_digest=result.profile_digest,
            session_id=result.session_id,
            legs=legs if legs is not None else result.legs,
            events=events,
        )

    if check(rebuilt((InteropEvent(**fields),) + result.events[1:])) != InteropReasonCode.REPLAY_MISMATCH:
        problems.append("mutated detail accepted")
    # broken sequence -> the structural check fires.
    fields["detail"] = result.events[0].detail
    fields["sequence"] = 7
    if check(rebuilt((InteropEvent(**fields),) + result.events[1:])) != InteropReasonCode.REPLAY_MISMATCH:
        problems.append("broken sequence accepted")
    # dropped event -> sequence contiguity breaks.
    if check(rebuilt(result.events[1:])) != InteropReasonCode.REPLAY_MISMATCH:
        problems.append("dropped event accepted")
    # divergent leg session id -> the structural check fires.
    bad_leg = LegEvidence(
        leg=result.legs[0].leg,
        access_kind=result.legs[0].access_kind,
        session_id="sha256:" + "0" * 64,
        payload_sha256=result.legs[0].payload_sha256,
        echo_sha256=result.legs[0].echo_sha256,
        bytes_equal=True,
        adapter_ref_digest=result.legs[0].adapter_ref_digest,
    )
    if check(rebuilt(result.events, legs=(bad_leg,) + result.legs[1:])) != InteropReasonCode.REPLAY_MISMATCH:
        problems.append("divergent leg session accepted")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "replay verifies structural + full re-run; rejects 4 tamper "
              "shapes",
    ))


def case_16_session_coherence_pure(results: List[Result]) -> None:
    name = "case_16_session_coherence_pure"
    problems: List[str] = []
    if check_session_coherence({"a": "s1", "b": "s1", "c": "s1"}) != "s1":
        problems.append("coherent ids did not resolve")
    try:
        check_session_coherence({"a": "s1", "b": "s2"})
        problems.append("divergent ids accepted")
    except InteropError as exc:
        if exc.reason != InteropReasonCode.SESSION_DIVERGENCE:
            problems.append("divergence reason %r" % exc.reason)
    try:
        check_session_coherence({})
        problems.append("empty mapping accepted")
    except InteropError:
        pass
    try:
        check_session_coherence(["s1"])  # type: ignore[arg-type]
        problems.append("non-mapping accepted")
    except InteropError:
        pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "pure coherence check: coherent/divergent/empty/mistyped",
    ))


# ---------------------------------------------------------------------------
# 17-23: the class-C lab gate
# ---------------------------------------------------------------------------

_GATE_ENV_KEYS = (
    "ORAN_INTEROP", "OPEN5GS_INTEROP", "RAN_INTEROP", "WIFI_INTEROP",
    "RAN_PEER_KIND", "OPEN5GS_PEER_KIND", "WIFI_PEER_KIND",
    "ORAN_INTEROP_SESSION_ID", "RAN_CONTROL_URL", "OPEN5GS_SBI_URL",
    "WIFI_N3IWF_ENDPOINT",
)


class _EnvScrub:
    """Save/restore the interop-gate environment around a case."""

    def __enter__(self):
        self._saved = {k: os.environ.get(k) for k in _GATE_ENV_KEYS}
        for key in _GATE_ENV_KEYS:
            os.environ.pop(key, None)
        return self

    def __exit__(self, *exc):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        return False


def case_17_gate_disabled_default(results: List[Result]) -> None:
    name = "case_17_gate_disabled_default"
    with _EnvScrub():
        if oran_interop_gate_enabled():
            results.append(fail(name, "gate enabled on a clean environment"))
            return
        outcome = run_profile_lab_gate()
        if outcome.status != "GATE_DISABLED":
            results.append(fail(name, "status %r" % outcome.status))
            return
        lowered = outcome.detail.lower()
        if "class c" not in lowered or "open" not in lowered:
            results.append(fail(name, "disclosure lacks the class-C open rule"))
            return
        if "conformance" not in lowered:
            results.append(fail(name, "disclosure does not name the class-B scenario"))
            return
    results.append(ok(
        name, "clean environment: GATE_DISABLED with the honest "
              "disclosure (never a PASS)",
    ))


def case_18_gate_leg_disabled(results: List[Result]) -> None:
    name = "case_18_gate_leg_disabled"
    with _EnvScrub():
        os.environ["ORAN_INTEROP"] = "1"
        outcome = run_profile_lab_gate()
        if outcome.status != "LEG_DISABLED":
            results.append(fail(name, "status %r" % outcome.status))
            return
        for leg, switch in PROFILE_LEG_SWITCHES:
            if leg not in outcome.detail or switch not in outcome.detail:
                results.append(fail(name, "leg %s/%s not named" % (leg, switch)))
                return
        if "NOT a PASS" not in outcome.detail and "not a pass" not in outcome.detail.lower():
            results.append(fail(name, "LEG_DISABLED is not disclosed as a non-run"))
            return
    results.append(ok(
        name, "profile switch without leg switches: LEG_DISABLED names all "
              "three legs and their independent switches",
    ))


def case_19_gate_forbidden_propagation(results: List[Result]) -> None:
    name = "case_19_gate_forbidden_propagation"
    problems: List[str] = []
    with _EnvScrub():
        os.environ["ORAN_INTEROP"] = "1"
        os.environ["OPEN5GS_INTEROP"] = "1"
        os.environ["RAN_INTEROP"] = "1"
        os.environ["WIFI_INTEROP"] = "1"
        os.environ["RAN_PEER_KIND"] = "reference"
        outcome = run_profile_lab_gate()
        if outcome.status != "FORBIDDEN":
            problems.append("ran FORBIDDEN not propagated: %r" % outcome.status)
        elif "('ran', 'FORBIDDEN')" not in outcome.detail:
            problems.append("ran leg not named in the FORBIDDEN detail")
        os.environ["RAN_PEER_KIND"] = "real_oai"
        os.environ["WIFI_PEER_KIND"] = "simulator"
        outcome = run_profile_lab_gate()
        if outcome.status != "FORBIDDEN":
            problems.append("wifi FORBIDDEN not propagated: %r" % outcome.status)
        elif "('non-threegpp', 'FORBIDDEN')" not in outcome.detail:
            problems.append("wifi leg not named in the FORBIDDEN detail")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "per-leg anti-faking guards propagate (ran + wifi variants); "
              "the profile gate adds no new PASS path",
    ))


def case_20_gate_unreachable_aggregation(results: List[Result]) -> None:
    name = "case_20_gate_unreachable_aggregation"
    with _EnvScrub():
        os.environ["ORAN_INTEROP"] = "1"
        os.environ["OPEN5GS_INTEROP"] = "1"
        os.environ["RAN_INTEROP"] = "1"
        os.environ["WIFI_INTEROP"] = "1"
        os.environ["OPEN5GS_PEER_KIND"] = "real_open5gs"
        os.environ["RAN_PEER_KIND"] = "real_oai"
        os.environ["WIFI_PEER_KIND"] = "real_n3iwf"
        outcome = run_profile_lab_gate()
        if outcome.status != "UNREACHABLE":
            results.append(fail(name, "status %r" % outcome.status))
            return
        statuses = {leg.leg: leg.status for leg in outcome.legs}
        if set(statuses.values()) != {"UNREACHABLE"}:
            results.append(fail(name, "leg statuses %r" % statuses))
            return
        lowered = outcome.detail.lower()
        if "not a pass" not in lowered:
            results.append(fail(name, "UNREACHABLE not disclosed as a non-pass"))
            return
        if "open" not in lowered:
            results.append(fail(name, "class C openness not restated"))
            return
    results.append(ok(
        name, "no real lab: all three legs UNREACHABLE (verification-"
              "environment blocker; no in-repo fallback)",
    ))


def case_21_gate_aggregation_matrix(results: List[Result]) -> None:
    name = "case_21_gate_aggregation_matrix"
    problems: List[str] = []

    def legs(statuses):
        return tuple(
            LegGateStatus(
                leg=leg, family=family, switch=switch, status=status,
            )
            for (leg, switch), family, status in zip(
                PROFILE_LEG_SWITCHES,
                ("adapters.fivegc", "adapters.ran", "adapters.wifi"),
                statuses,
            )
        )

    sid = DEFAULT_ORAN_INTEROP_SESSION_ID
    if aggregate_leg_outcomes(legs(("PASSED", "PASSED", "PASSED")), session_id=sid).status != "PASSED":
        problems.append("all-PASSED did not aggregate to PASSED")
    if not aggregate_leg_outcomes(legs(("PASSED", "PASSED", "PASSED")), session_id=sid).session_coherent:
        problems.append("PASSED aggregation lost session coherence")
    if aggregate_leg_outcomes(legs(("PASSED", "SKIP", "PASSED")), session_id=sid).status != "LEG_DISABLED":
        problems.append("SKIP did not aggregate to LEG_DISABLED")
    if aggregate_leg_outcomes(legs(("FORBIDDEN", "UNREACHABLE", "PASSED")), session_id=sid).status != "FORBIDDEN":
        problems.append("FORBIDDEN does not outrank UNREACHABLE")
    if aggregate_leg_outcomes(legs(("UNREACHABLE", "BYTE_MISMATCH", "PASSED")), session_id=sid).status != "UNREACHABLE":
        problems.append("UNREACHABLE does not outrank LEG_FAILED")
    if aggregate_leg_outcomes(legs(("SBI_FAILED", "PASSED", "PASSED")), session_id=sid).status != "LEG_FAILED":
        problems.append("SBI_FAILED did not aggregate to LEG_FAILED")
    if aggregate_leg_outcomes(legs(("PASSED", "PEER_FAILED", "PASSED")), session_id=sid).status != "LEG_FAILED":
        problems.append("PEER_FAILED did not aggregate to LEG_FAILED")
    if aggregate_leg_outcomes(legs(("PASSED", "DATA_PEER_UNREACHABLE", "PASSED")), session_id=sid).status != "LEG_FAILED":
        problems.append("DATA_PEER_UNREACHABLE did not aggregate to LEG_FAILED")
    try:
        aggregate_leg_outcomes((), session_id=sid)
        problems.append("empty legs accepted")
    except InteropError:
        pass
    try:
        aggregate_leg_outcomes("not-legs", session_id=sid)  # type: ignore[arg-type]
        problems.append("non-tuple legs accepted")
    except InteropError:
        pass
    # PASSED requires EVERY leg
    outcome = aggregate_leg_outcomes(legs(("PASSED", "PASSED", "FAILED")), session_id=sid)
    if outcome.status != "LEG_FAILED" or outcome.session_coherent:
        problems.append("two-of-three PASSED must not close class C")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "aggregation matrix: precedence FORBIDDEN > UNREACHABLE > "
              "LEG_FAILED > LEG_DISABLED; PASSED only when every leg passes",
    ))


def case_22_gate_config_from_env(results: List[Result]) -> None:
    name = "case_22_gate_config_from_env"
    with _EnvScrub():
        config = ProfileLabConfig.from_env()
        if config.session_id != DEFAULT_ORAN_INTEROP_SESSION_ID:
            results.append(fail(name, "default session id drifted"))
            return
        if config.leg_switches != {
            "five-g-core": False, "ran": False, "non-threegpp": False,
        }:
            results.append(fail(name, "default switches drifted"))
            return
        os.environ["ORAN_INTEROP_SESSION_ID"] = "adcos:session:real-lab"
        os.environ["RAN_INTEROP"] = "1"
        config = ProfileLabConfig.from_env()
        if config.session_id != "adcos:session:real-lab":
            results.append(fail(name, "session override ignored"))
            return
        if config.leg_switches["ran"] is not True:
            results.append(fail(name, "ran switch ignored"))
            return
        if config.leg_switches["five-g-core"] is not False:
            results.append(fail(name, "fivegc switch leaked"))
            return
    results.append(ok(
        name, "config from env: shared session id + per-leg switches",
    ))


def case_23_runbook_data_frozen(results: List[Result]) -> None:
    name = "case_23_runbook_data_frozen"
    runbook = profile_lab_runbook()
    problems: List[str] = []
    for key in (
        "objective", "lab_requirements", "environment", "anti_faking",
        "evidence_status", "statement",
    ):
        if key not in runbook:
            problems.append("runbook lacks %r" % key)
    text = _json.dumps(runbook)
    for required in (
        "Open5GS", "SDR", "OpenAirInterface", "N3IWF", "IPsec",
        "ORAN_INTEROP=1", "OPEN5GS_INTEROP=1", "RAN_INTEROP=1",
        "WIFI_INTEROP=1", "ORAN_INTEROP_SESSION_ID", "rf_simulation",
    ):
        if required not in text:
            problems.append("runbook lacks %r" % required)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "runbook frozen: lab requirements, env surface, anti-faking "
              "rule, evidence status",
    ))


# ---------------------------------------------------------------------------
# 24-25: the evidence model
# ---------------------------------------------------------------------------


def case_24_evidence_classification(results: List[Result]) -> None:
    name = "case_24_evidence_classification"
    result = _run_scenario_with_real_session()
    report = classify_profile_evidence(
        profile_validated=True,
        legs_verified=len(result.legs),
        run_digest=result.interop_digest(),
    )
    problems: List[str] = []
    if report["A"]["evidence_class"] != "architecture-conformance":
        problems.append("class A label drifted")
    if not report["A"]["complete"]:
        problems.append("class A incomplete")
    if report["B"]["evidence_class"] != "automated-verification":
        problems.append("class B label drifted")
    if report["B"]["run_digest"] != result.interop_digest():
        problems.append("class B digest mismatch")
    if report["C"]["status"] != "open":
        problems.append("class C closed without a gate outcome")
    if report["C"]["statement"] != REAL_LAB_EVIDENCE_STATEMENT:
        problems.append("class C statement drifted")
    if report["status"] != PROFILE_EVIDENCE_STATUS:
        problems.append("report status drifted")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "A complete / B carries the run digest / C open with the "
              "pinned statement",
    ))


def case_25_evidence_anti_promotion(results: List[Result]) -> None:
    name = "case_25_evidence_anti_promotion"
    problems: List[str] = []
    assert_no_real_lab_claim(claimed_class="A")
    assert_no_real_lab_claim(claimed_class="B")
    try:
        assert_no_real_lab_claim(claimed_class="C")
        problems.append("class-C claim from A/B material accepted")
    except InteropError as exc:
        if exc.reason != InteropReasonCode.EVIDENCE_CLASS_VIOLATION:
            problems.append("anti-promotion reason %r" % exc.reason)
    try:
        assert_no_real_lab_claim(claimed_class="D")
        problems.append("unknown class accepted")
    except InteropError:
        pass
    # a non-PASSED gate outcome leaves class C open
    blocked = ProfileLabOutcome(status="UNREACHABLE", detail="blocked")
    report = classify_profile_evidence(
        profile_validated=True, legs_verified=4, run_digest="d",
        gate_outcome=blocked,
    )
    if report["C"]["status"] != "open":
        problems.append("UNREACHABLE gate closed class C")
    # a PASSED-but-incoherent gate outcome leaves class C open
    incoherent = ProfileLabOutcome(
        status="PASSED", detail="x", session_id="s", session_coherent=False,
    )
    report = classify_profile_evidence(
        profile_validated=True, legs_verified=4, run_digest="d",
        gate_outcome=incoherent,
    )
    if report["C"]["status"] != "open":
        problems.append("incoherent PASSED closed class C")
    # ONLY a PASSED + coherent gate outcome closes class C
    genuine = ProfileLabOutcome(
        status="PASSED", detail="real lab", session_id="s",
        session_coherent=True,
    )
    report = classify_profile_evidence(
        profile_validated=True, legs_verified=4, run_digest="d",
        gate_outcome=genuine,
    )
    if report["C"]["status"] != "closed":
        problems.append("genuine PASSED gate did not close class C")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "anti-promotion enforced; class C closes ONLY on a coherent "
              "PASSED gate outcome",
    ))


# ---------------------------------------------------------------------------
# 26-33: structural audits
# ---------------------------------------------------------------------------

_INTEROP_FILES = sorted(
    os.path.join(REPO_ROOT, "interop", name)
    for name in os.listdir(os.path.join(REPO_ROOT, "interop"))
    if name.endswith(".py")
)

#: The ADCOS core roots (the fivegc/ran batteries' frozen core list).
_CORE_DIRS = (
    "sessions", "identity", "protocol", "capabilities", "discovery",
    "transport", "topology", "routing", "multipath", "mobility",
    "federation", "policy", "intent", "resources",
)

#: Authority constructor tokens that must NEVER appear in interop/.
_AUTHORITY_TOKENS = (
    "SessionStore(", "RoutingEngine(", "PolicyEngine(", "IdentityStore(",
    "MultipathStore(", "MobilityStore(", "FederationStore(",
    "TransportManager(", "ServiceRegistry(", "DistributedCoreManager(",
    "EdgeGateway(", "AgentRuntime(",
)

_SANCTIONED_IMPORT_ROOTS = (
    "adapters.fivegc", "adapters.ran", "adapters.wifi",
    "conformance", "protocol.canonicalization",
)


def case_26_no_shadow_authority(results: List[Result]) -> None:
    name = "case_26_no_shadow_authority"
    problems: List[str] = []
    for path in _INTEROP_FILES:
        text = open(path, encoding="utf-8").read()
        for token in _AUTHORITY_TOKENS:
            if token in text:
                problems.append(
                    "%s constructs %r" % (os.path.basename(path), token)
                )
    if problems:
        results.append(fail(name, "; ".join(sorted(set(problems)))))
        return
    results.append(ok(
        name, "no authority constructor anywhere in interop/ (the profile "
              "validates and composes; it never mints)",
    ))


def case_27_import_discipline(results: List[Result]) -> None:
    name = "case_27_import_discipline"
    problems: List[str] = []
    for path in _INTEROP_FILES:
        tree = ast.parse(open(path, encoding="utf-8").read())
        for node in ast.walk(tree):
            targets: List[str] = []
            if isinstance(node, ast.Import):
                targets = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level and node.module:
                    targets = ["." * node.level + node.module]
                elif node.level:
                    targets = ["."]
                elif node.module:
                    targets = [node.module]
            for target in targets:
                if target.startswith("."):
                    continue  # intra-package
                root = target.split(".")[0]
                if root in ("adapters", "conformance", "protocol"):
                    if not target.startswith(_SANCTIONED_IMPORT_ROOTS):
                        problems.append(
                            "%s imports %r (outside the sanctioned roots)"
                            % (os.path.basename(path), target)
                        )
                elif root in (
                    "InteropError", "interop",
                ):
                    continue
                elif root not in (
                    "__future__", "hashlib", "dataclasses", "datetime",
                    "typing", "os", "re", "json", "ast", "sys", "random",
                    "subprocess", "py_compile",
                ):
                    problems.append(
                        "%s imports %r (unsanctioned root)"
                        % (os.path.basename(path), target)
                    )
    if problems:
        results.append(fail(name, "; ".join(sorted(set(problems)))))
        return
    results.append(ok(
        name, "interop/ imports only adapters.fivegc/ran/wifi + conformance "
              "+ protocol.canonicalization + stdlib",
    ))


def case_28_core_purity(results: List[Result]) -> None:
    name = "case_28_core_purity"
    problems: List[str] = []
    forbidden_roots = (
        "interop",
        "adapters.fivegc.open5gs", "adapters.fivegc.open5gs_interop",
        "adapters.ran.openran", "adapters.ran.openran_interop",
        "adapters.ran.rfsim", "adapters.wifi.n3iwf", "adapters.wifi.wifi_interop",
    )
    scanned = 0
    for core_dir in _CORE_DIRS:
        base = os.path.join(REPO_ROOT, core_dir)
        for dirpath, _dirnames, filenames in os.walk(base):
            for filename in filenames:
                if not filename.endswith(".py"):
                    continue
                scanned += 1
                tree = ast.parse(
                    open(os.path.join(dirpath, filename), encoding="utf-8").read()
                )
                for node in ast.walk(tree):
                    targets: List[str] = []
                    if isinstance(node, ast.Import):
                        targets = [alias.name for alias in node.names]
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        targets = [node.module]
                    for target in targets:
                        if target in forbidden_roots or target == "adapters":
                            problems.append(
                                "%s/%s imports %r"
                                % (core_dir, filename, target)
                            )
    if problems:
        results.append(fail(name, "; ".join(sorted(set(problems)))))
        return
    results.append(ok(
        name, "%d core modules import no interop/ and no adapter "
              "implementation modules (vendor/Open RAN types stay out of "
              "core)" % scanned,
    ))


def case_29_injected_clock_and_purity(results: List[Result]) -> None:
    name = "case_29_injected_clock_and_purity"
    problems: List[str] = []
    forbidden_tokens = (
        "time.time(", "time.monotonic(", "datetime.now(",
        "datetime.utcnow(", "random.", "urandom(", "uuid.uuid4(",
        "gethostbyname(", "socket.socket(",
    )
    for path in _INTEROP_FILES:
        text = open(path, encoding="utf-8").read()
        basename = os.path.basename(path)
        for token in forbidden_tokens:
            if token in text:
                problems.append("%s contains %r" % (basename, token))
        if "os.environ" in text and basename != "labgate.py":
            problems.append("%s reads the environment (labgate only)" % basename)
        if "import socket" in text:
            problems.append("%s imports socket" % basename)
        if "import datetime" in text and basename != "mixed.py":
            problems.append("%s imports datetime (mixed.py arithmetic only)" % basename)
    if problems:
        results.append(fail(name, "; ".join(sorted(set(problems)))))
        return
    results.append(ok(
        name, "no wall clock / randomness / socket in interop/; the "
              "environment is read only by the lab gate (operator switches)",
    ))


def case_30_secret_hygiene(results: List[Result]) -> None:
    name = "case_30_secret_hygiene"
    result = _run_scenario_with_real_session()
    problems: List[str] = []
    surface = _json.dumps(result.to_dict()).lower()
    for pattern in ("psk", "password", "secret=", "0xdeadbeef", "credential-material"):
        if pattern in surface:
            problems.append("result surface carries %r" % pattern)
    for event in result.events:
        if "psk" in event.detail.lower() or "secret=" in event.detail.lower():
            problems.append("event %d carries secret-looking text" % event.sequence)
    # credential material never appears as a source literal either
    for path in _INTEROP_FILES:
        text = open(path, encoding="utf-8").read()
        if re.search(r"(psk|password|secret_key)\s*=\s*[\"']", text):
            problems.append("%s assigns credential-looking material" % os.path.basename(path))
    if problems:
        results.append(fail(name, "; ".join(sorted(set(problems)))))
        return
    results.append(ok(
        name, "no credential material in any result surface or source "
              "literal (slot NAMES only, LOCK-023)",
    ))


def case_31_naming_token_freedom(results: List[Result]) -> None:
    name = "case_31_naming_token_freedom"
    problems: List[str] = []
    for path in _INTEROP_FILES:
        text = open(path, encoding="utf-8").read()
        for token in re.findall(r"\bW0(3[8-9]|4[0-9])\b", text):
            problems.append(
                "%s carries later-work token W%s"
                % (os.path.basename(path), token)
            )
    if problems:
        results.append(fail(name, "; ".join(sorted(set(problems)))))
        return
    results.append(ok(name, "no later-work naming tokens in interop/"))


def case_32_py_compile(results: List[Result]) -> None:
    name = "case_32_py_compile"
    problems: List[str] = []
    for path in _INTEROP_FILES:
        try:
            py_compile.compile(path, doraise=True)
        except py_compile.PyCompileError as exc:
            problems.append("%s: %s" % (os.path.basename(path), exc))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "all %d interop modules compile" % len(_INTEROP_FILES)))


_EXPECTED_API = [
    "INTEROP_PREFIX",
    "InteropError",
    "InteropReasonCode",
    "ProfileComponentKind",
    "ReferencePointKind",
    "AccessLegKind",
    "ScenarioLegName",
    "InteropEventType",
    "COMPONENT_FAMILY",
    "COMPONENT_REFERENCE_POINTS",
    "REQUIRED_REFERENCE_POINTS",
    "PROFILE_EVIDENCE_CLASS_MAP",
    "ComponentBinding",
    "ProfileDeclaration",
    "canonical_profile",
    "InteropEvent",
    "interop_events_canonical_bytes",
    "interop_event_list_digest",
    "LegEvidence",
    "InteropRunResult",
    "validate_profile",
    "reference_points_for_component",
    "profile_complete",
    "DEFAULT_PROFILE_PAYLOAD",
    "DEFAULT_START_INSTANT",
    "SessionFacts",
    "check_ref_opacity",
    "run_profile_scenario",
    "verify_interop_replay",
    "ORAN_INTEROP_ENV",
    "ORAN_INTEROP_SESSION_ID_ENV",
    "DEFAULT_ORAN_INTEROP_SESSION_ID",
    "PROFILE_LEG_SWITCHES",
    "ProfileLabConfig",
    "LegGateStatus",
    "ProfileLabOutcome",
    "oran_interop_gate_enabled",
    "check_session_coherence",
    "aggregate_leg_outcomes",
    "run_profile_lab_gate",
    "profile_lab_runbook",
    "PROFILE_EVIDENCE_STATUS",
    "REAL_LAB_EVIDENCE_STATEMENT",
    "assert_no_real_lab_claim",
    "classify_profile_evidence",
]


def case_33_frozen_api(results: List[Result]) -> None:
    name = "case_33_frozen_api"
    import interop

    actual = list(interop.__all__)
    missing = [item for item in _EXPECTED_API if item not in actual]
    extra = [
        entry for entry in actual
        if not entry.startswith("_") and entry not in _EXPECTED_API
    ]
    if missing or extra:
        results.append(fail(name, "missing=%r extra=%r" % (missing, extra)))
        return
    if len(_EXPECTED_API) != len(set(_EXPECTED_API)):
        results.append(fail(name, "expected API list has duplicates"))
        return
    results.append(ok(name, "frozen public API: %d exports exact" % len(_EXPECTED_API)))


# ---------------------------------------------------------------------------
# 34-36: frozen surfaces (spec, PR delta, CI wiring)
# ---------------------------------------------------------------------------


#: The Architect's own branch-anchored handoff prompt (commit 518c071
#: added it to THIS branch, not main -- main's publication was
#: reverted by the Architect before the branch was cut).  The spec
#: delta below admits EXACTLY this file, and case_35 additionally
#: asserts the implementation never modified it.
#: (W037 -> W038 amendment: the W038 handoff follows the identical
#: branch-anchor pattern -- commit 0be736e -- and is admitted the
#: same way.)
_ARCHITECT_HANDOFF = "spec/prompts/WORK-037.md"
_ARCHITECT_HANDOFF_COMMIT = "518c071"
_SUCCESSOR_HANDOFF = "spec/prompts/WORK-038.md"
_SUCCESSOR_HANDOFF_COMMIT = "0be736e"
_SECOND_SUCCESSOR_HANDOFF = "spec/prompts/WORK-039.md"
_SECOND_SUCCESSOR_HANDOFF_COMMIT = "7274384"


def _spec_delta_clean() -> List[str]:
    """The spec/ problems vs origin/main: the delta may contain EXACTLY
    the Architect's handoff prompt (added on this branch by the
    Architect); everything else must be byte-identical."""
    delta = subprocess.run(
        ["git", "diff", "--name-status", "origin/main", "HEAD", "--", "spec/"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    problems: List[str] = []
    for line in delta.stdout.splitlines():
        if not line.strip():
            continue
        status, _, path = line.partition("\t")
        if path == _ARCHITECT_HANDOFF and status == "A":
            continue  # the Architect's own anchor commit
        if path == _SUCCESSOR_HANDOFF and status == "A":
            continue  # the W038 successor's Architect anchor commit
        if path == _SECOND_SUCCESSOR_HANDOFF and status == "A":
            continue  # the W039 successor's Architect anchor commit
        problems.append("%s %s" % (status, path))
    # the handoff must be byte-untouched since the Architect's commit.
    untouched = subprocess.run(
        ["git", "diff", _ARCHITECT_HANDOFF_COMMIT, "HEAD", "--",
         _ARCHITECT_HANDOFF],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if untouched.stdout.strip():
        problems.append("the Architect's handoff was modified by the branch")
    # the W038 successor's handoff must equally be byte-untouched.
    successor_untouched = subprocess.run(
        ["git", "diff", _SUCCESSOR_HANDOFF_COMMIT, "HEAD", "--",
         _SUCCESSOR_HANDOFF],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if successor_untouched.stdout.strip():
        problems.append("the W038 successor handoff was modified by the branch")
    # the W039 successor's handoff must equally be byte-untouched.
    second_successor_untouched = subprocess.run(
        ["git", "diff", _SECOND_SUCCESSOR_HANDOFF_COMMIT, "HEAD", "--",
         _SECOND_SUCCESSOR_HANDOFF],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if second_successor_untouched.stdout.strip():
        problems.append("the W039 successor handoff was modified by the branch")
    return problems


def case_34_frozen_spec_intact(results: List[Result]) -> None:
    name = "case_34_frozen_spec_intact"
    status = subprocess.run(
        ["git", "status", "--porcelain", "--", "spec/"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if status.stdout.strip():
        results.append(fail(name, "uncommitted spec/ changes"))
        return
    ref_check = subprocess.run(
        ["git", "rev-parse", "--verify", "origin/main"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if ref_check.returncode != 0:
        results.append(ok(
            name, "spec/ clean (origin/main ref unavailable here)",
        ))
        return
    problems = _spec_delta_clean()
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "spec/ byte-identical to origin/main except the Architect's "
              "branch-anchored handoff (unmodified since 518c071)",
    ))


def case_35_pr_delta_shape(results: List[Result]) -> None:
    name = "case_35_pr_delta_shape"
    workflow_path = os.path.join(
        REPO_ROOT, ".github", "workflows", "spec-check.yml"
    )
    workflow = open(workflow_path, encoding="utf-8").read()
    status = subprocess.run(
        ["git", "status", "--porcelain", "--", "spec/"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if status.stdout.strip():
        results.append(fail(name, "uncommitted spec/ changes"))
        return
    ref_check = subprocess.run(
        ["git", "rev-parse", "--verify", "origin/main"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if ref_check.returncode != 0:
        if "python3 tools/oran_selftest.py" in workflow:
            results.append(ok(
                name, "spec/ clean; committed CI wiring present "
                      "(origin/main ref unavailable)",
            ))
        else:
            results.append(fail(name, "committed CI wiring missing"))
        return
    delta = subprocess.run(
        ["git", "diff", "--name-only", "origin/main", "HEAD"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    changed = {line for line in delta.stdout.splitlines() if line.strip()}
    if not changed:
        if "python3 tools/oran_selftest.py" in workflow:
            results.append(ok(name, "spec/ clean on main; wiring verified"))
        else:
            results.append(fail(name, "committed CI wiring missing on main"))
        return
    problems = _spec_delta_clean()
    if problems:
        results.append(fail(name, "spec/ delta beyond the Architect's handoff: %s" % problems))
        return
    allowed_exact = {
        "tools/oran_selftest.py",
        # DAG-sanctioned allowlist amendments:
        # W033 -> W037 (the interop profile battery extends the agent
        # battery's subject through the reference-agent component):
        "tools/agent_selftest.py",
        # W034 -> W037 (work-item order; the edge battery's PR-delta
        # shape admits the successor):
        "tools/edge_selftest.py",
        # W035 -> W037 (work-item order; same admission):
        "tools/mobile_selftest.py",
        # W036 -> W037 (work-item order; same admission):
        "tools/appliance_selftest.py",
        "docs/WORK-037-handoff.md",
        "docs/WORK-037-evidence.md",
        # W037 -> W038 (work-item order; the future-IMT profile
        # battery follows this one and its PR-delta shape admits the
        # successor's files):
        "tools/imt_selftest.py",
        "docs/WORK-038-handoff.md",
        "docs/WORK-038-evidence.md",
        # W038 -> W039 (work-item order; the federation-at-scale
        # battery follows this one and its PR-delta shape admits the
        # successor's files):
        "tools/scale_selftest.py",
        "docs/WORK-039-handoff.md",
        "docs/WORK-039-evidence.md",
        # DAG-sanctioned amendment (-> WORK-040): the pilot deployment
        # battery extends this one (work-item order in CI).
        "tools/pilot_selftest.py",
        "docs/WORK-040-handoff.md",
        "docs/WORK-040-evidence.md",
        # DAG-sanctioned allowlist amendment (W029 -> W038): the upgrade
        # battery's authority-boundary audit exempts the W038
        # future-IMT family as a DAG-sanctioned downstream consumer
        # (WORK-038 declares WORK-029 among its frozen dependencies;
        # imt/coexistence.py composes the real compatibility surfaces).
        "tools/upgrade_selftest.py",
        # the Architect's own branch anchors (validated by
        # _spec_delta_clean):
        _ARCHITECT_HANDOFF,
        _SUCCESSOR_HANDOFF,
        _SECOND_SUCCESSOR_HANDOFF,
    }
    unexpected = [
        c for c in changed
        if not c.startswith("interop/") and not c.startswith("imt/")
        and not c.startswith("scale/") and not c.startswith("pilot/")
        and c not in allowed_exact
        and not c.startswith(".github/")
    ]
    if unexpected:
        results.append(fail(name, "delta beyond the sanctioned shape: %s" % unexpected))
        return
    workflow_delta = subprocess.run(
        ["git", "diff", "origin/main", "--", ".github/"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    # The interop CI step was introduced by THIS family's PR; a
    # successor work item appending its own step further down the
    # workflow (W038 -> W039 amendment) pushes the interop step out of
    # the diff hunk context.  The discipline is therefore: the interop
    # step appears in the delta (this family's own PR) OR the committed
    # workflow still contains it AND the delta never weakens it (a
    # successor's PR) -- the W033 agent battery's case_40 pattern.
    removed_interop_step = any(
        line.startswith("-") and "oran_selftest.py" in line
        for line in workflow_delta.stdout.splitlines()
    )
    if "oran_selftest.py" not in workflow_delta.stdout:
        if removed_interop_step or "python3 tools/oran_selftest.py" not in workflow:
            results.append(fail(
                name, ".github delta weakens or drops the interop CI step",
            ))
            return
    results.append(ok(
        name, "PR delta exactly: interop/ + interop battery + agent/edge/"
              "mobile/appliance allowlist amendments + successor "
              "admissions + handoff/evidence docs + the Architect's branch "
              "anchors + CI step",
    ))


_EXPECTED_TOOLS = [
    "spec_check.py", "spec_check_selftest.py", "schema_check.py",
    "schema_selftest.py", "envelope_selftest.py", "identity_selftest.py",
    "capability_selftest.py", "discovery_selftest.py",
    "topology_selftest.py", "resource_selftest.py", "intent_selftest.py",
    "policy_selftest.py", "routing_selftest.py", "session_selftest.py",
    "multipath_selftest.py", "mobility_selftest.py",
    "federation_selftest.py", "adapter_selftest.py",
    "transport_selftest.py", "ipintegration_selftest.py",
    "fivegc_selftest.py", "ran_selftest.py", "wifi_selftest.py",
    "backhaul_selftest.py", "mesh_selftest.py", "distcore_selftest.py",
    "service_selftest.py", "telemetry_selftest.py", "energy_selftest.py",
    "security_selftest.py", "upgrade_selftest.py", "management_selftest.py",
    "simulator_selftest.py", "conformance_selftest.py",
    "agent_selftest.py", "edge_selftest.py", "mobile_selftest.py",
    "appliance_selftest.py", "oran_selftest.py", "imt_selftest.py",
]


def case_36_ci_wiring_all_tools(results: List[Result]) -> None:
    name = "case_36_ci_wiring_all_tools"
    workflow_path = os.path.join(
        REPO_ROOT, ".github", "workflows", "spec-check.yml"
    )
    workflow = open(workflow_path, encoding="utf-8").read()
    missing = [
        tool for tool in _EXPECTED_TOOLS
        if ("tools/%s" % tool) not in workflow
    ]
    if missing:
        results.append(fail(name, "batteries missing from CI: %s" % missing))
        return
    appliance_index = workflow.find("python3 tools/appliance_selftest.py")
    oran_index = workflow.find("python3 tools/oran_selftest.py")
    imt_index = workflow.find("python3 tools/imt_selftest.py")
    if not (appliance_index < oran_index < imt_index):
        results.append(fail(name, "imt step not ordered after oran"))
        return
    results.append(ok(
        name, "CI wired: interop battery + all %d prior tools; oran "
              "ordered after appliance and imt after oran (work-item order)"
        % (len(_EXPECTED_TOOLS) - 1),
    ))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> int:
    results: List[Result] = []
    for case in (
        case_01_frozen_vocabularies,
        case_02_ownership_maps_frozen,
        case_03_profile_declaration_records,
        case_04_profile_validation_negatives,
        case_05_evidence_class_map,
        case_06_evidence_status_disclosure,
        case_07_mixed_access_scenario,
        case_08_scenario_session_discipline,
        case_09_scenario_profile_gate,
        case_10_ref_opacity_discrimination,
        case_11_journal_events,
        case_12_run_digest_and_round_trip,
        case_13_determinism_fresh_run,
        case_14_hashseed_invariance,
        case_15_replay_verification,
        case_16_session_coherence_pure,
        case_17_gate_disabled_default,
        case_18_gate_leg_disabled,
        case_19_gate_forbidden_propagation,
        case_20_gate_unreachable_aggregation,
        case_21_gate_aggregation_matrix,
        case_22_gate_config_from_env,
        case_23_runbook_data_frozen,
        case_24_evidence_classification,
        case_25_evidence_anti_promotion,
        case_26_no_shadow_authority,
        case_27_import_discipline,
        case_28_core_purity,
        case_29_injected_clock_and_purity,
        case_30_secret_hygiene,
        case_31_naming_token_freedom,
        case_32_py_compile,
        case_33_frozen_api,
        case_34_frozen_spec_intact,
        case_35_pr_delta_shape,
        case_36_ci_wiring_all_tools,
    ):
        case(results)
    passed = sum(1 for _name, ok_flag, _detail in results if ok_flag)
    failed = len(results) - passed
    for name, ok_flag, detail in results:
        print("[%s] %s: %s" % ("PASS" if ok_flag else "FAIL", name, detail))
    print()
    print("oran selftest: %d passed, %d failed" % (passed, failed))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
