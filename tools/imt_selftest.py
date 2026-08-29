#!/usr/bin/env python3
"""ADCOS Future IMT / 6G adapter profile self-test (WORK-038).

The WORK-038 battery: the frozen vocabularies and value records, the
fail-closed profile validation (with the negative matrix), the class-B
synthetic conformance scenario (the future adapter registered as DATA
on a REAL runtime wired like the reference agent wires it, the full
nine-operation WORK-016 contract exercised over a REAL established
WORK-012 session, unknown-identifier preservation with no authority
gain, registry digest-pinning proving NO core schema change, and the
routing/session/resource/policy layers digest-proven byte-identical
for the same inputs), the W029/W005 coexistence discriminations (the
future capability never silently satisfies a requirement; mixed-
version coexistence unchanged), the sandbox's deterministic budget
model, and the three-class evidence model (A/B closed in-repo; C NOT
APPLICABLE -- the anti-fabrication rule enforced structurally, no
closure path at all).

Structural audits: authority discipline (the W032 conformance-world
pattern -- fixture composition in the scenario only, never a shadow
authority), import discipline, ADCOS-core purity (no imt/ leakage
into core), vendor/PHY token freedom, injected clock only, secret
hygiene, naming-token freedom, determinism across fresh runs and
hash seeds, TRUE replay verification, frozen surfaces (API, spec/,
PR-delta shape, CI wiring + ordering).
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
from typing import Any, Dict, List, Mapping, Optional, Tuple

# Make the repository root importable.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from imt import (  # noqa: E402
    CANONICAL_FUTURE_TECHNOLOGY_ID,
    CANONICAL_INSTANCE_LABEL,
    CORE_EQUIVALENCE_LAYERS,
    FUTURE_ADAPTER_LABEL,
    FUTURE_EVIDENCE_CLASS_MAP,
    FUTURE_EVIDENCE_STATUS,
    FUTURE_PREFIX,
    FUTURE_PROFILE_PROTOCOL_PROFILE,
    SCENARIO_START_INSTANT,
    STEP_CHARGES,
    SYNTHETIC_EVIDENCE_STATEMENT,
    UNKNOWN_FUTURE_TECHNOLOGY_ID,
    UNKNOWN_ID_INSTANCE_LABEL,
    CoreEquivalenceRecord,
    FutureError,
    FutureEvent,
    FutureEventType,
    FutureProfileDeclaration,
    FutureReasonCode,
    FutureRunResult,
    canonical_future_profile,
    classify_future_evidence,
    classify_technology_id,
    coexistence_with_future_profile,
    future_capability_negotiation,
    future_descriptor,
    future_envelope_disposition,
    registry_file_digest,
    registry_untouched,
    run_future_profile_conformance,
    scenario_summary,
    unknown_id_gained_no_authority,
    validate_future_profile,
    verify_future_replay,
)
from conformance.model import EvidenceClass  # noqa: E402

REPO_ROOT = _ROOT
Result = Tuple[str, bool, str]

_NOW = "2026-06-01T12:00:00Z"


def ok(name: str, detail: str = "") -> Result:
    return (name, True, detail)


def fail(name: str, detail: str) -> Result:
    return (name, False, detail)


# ---------------------------------------------------------------------------
# 01-06: frozen vocabularies, records, maps, disclosures
# ---------------------------------------------------------------------------


def case_01_frozen_vocabularies(results: List[Result]) -> None:
    name = "case_01_frozen_vocabularies"
    problems: List[str] = []
    if FutureEventType.values() != (
        "profile-validated", "technology-classified", "registry-pinned",
        "adapter-registered", "adapter-opened", "capabilities-exposed",
        "link-observed", "capacity-allocated", "capacity-released",
        "session-bound", "session-unbound", "health-reported",
        "adapter-closed", "unknown-id-preserved",
        "core-equivalence-verified", "profile-verified",
    ):
        problems.append("event-type vocabulary drifted")
    if CORE_EQUIVALENCE_LAYERS != ("routing", "sessions", "resources", "policy"):
        problems.append("core-equivalence layer list drifted")
    if FUTURE_PREFIX != "future.":
        problems.append("error prefix drifted")
    expected_map = {
        "A": EvidenceClass.ARCHITECTURE_CONFORMANCE,
        "B": EvidenceClass.AUTOMATED_VERIFICATION,
        "C": EvidenceClass.EXTERNAL_EVIDENCE,
    }
    if FUTURE_EVIDENCE_CLASS_MAP != expected_map:
        problems.append("evidence class map drifted (must reuse W032)")
    if FutureReasonCode.values() != (
        "future.invalid-input", "future.profile-invalid",
        "future.technology-id-invalid", "future.capability-invalid",
        "future.profile-version-invalid", "future.mapping-invalid",
        "future.not-open", "future.allocation-unknown",
        "future.binding-unknown", "future.evidence-class-violation",
        "future.replay-divergence",
    ):
        problems.append("reason vocabulary drifted")
    if STEP_CHARGES != {
        "open": 4, "capabilities": 1, "observe": 2, "allocate": 10,
        "release": 4, "bind_session": 6, "unbind_session": 3,
        "health": 1, "close": 4,
    }:
        problems.append("step charges drifted")
    if FUTURE_ADAPTER_LABEL != "future-imt2030-study":
        problems.append("adapter label drifted")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "vocabularies frozen: 16 event types, 4 core "
                            "layers, 11 reason codes, W032 evidence map reused"))


def case_02_profile_declaration_records(results: List[Result]) -> None:
    name = "case_02_profile_declaration_records"
    profile = canonical_future_profile()
    problems: List[str] = []
    if profile.technology_id != CANONICAL_FUTURE_TECHNOLOGY_ID:
        problems.append("canonical technology id drifted")
    if profile.technology_id != "access.3gpp.nr.imt2030":
        problems.append("canonical id must be the registry's reserved path")
    if profile.profile_versions != ("imt2030-study-1",):
        problems.append("canonical profile versions drifted")
    if profile.capability_references != (
        "capability.core.store-and-forward",
        "capability.profile.imt2030.data-transfer",
    ):
        problems.append("canonical capability set drifted")
    if profile.resource_kind != "bandwidth" or profile.resource_unit != "mbps":
        problems.append("canonical mapping must use WORK-008 kind/units")
    if profile.digest() != "sha256:" + hashlib.sha256(
        profile.canonical_bytes()
    ).hexdigest():
        problems.append("digest is not content-derived over canonical bytes")
    # canonical bytes are stable across constructions
    if canonical_future_profile().canonical_bytes() != profile.canonical_bytes():
        problems.append("canonical bytes not stable")
    # to_dict round trip shape
    d = profile.to_dict()
    if d["technology_id"] != profile.technology_id or \
            tuple(d["profile_versions"]) != profile.profile_versions:
        problems.append("to_dict drifted")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "canonical declaration frozen; digest "
                            "content-derived over canonical bytes"))


def case_03_event_records(results: List[Result]) -> None:
    name = "case_03_event_records"
    problems: List[str] = []
    event = FutureEvent(
        sequence=1, event_type=FutureEventType.PROFILE_VALIDATED,
        instant=SCENARIO_START_INSTANT, detail="d" * 500,
    )
    if len(event.detail) != 200 or not event.detail.endswith("..."):
        problems.append("detail not bounded to 200 chars")
    if not event.event_id().startswith("sha256:"):
        problems.append("event id not sha256-prefixed")
    same = FutureEvent(
        sequence=1, event_type=FutureEventType.PROFILE_VALIDATED,
        instant=SCENARIO_START_INSTANT, detail="d" * 500,
    )
    if same.event_id() != event.event_id():
        problems.append("content-derived id not stable for equal content")
    other = FutureEvent(
        sequence=2, event_type=FutureEventType.PROFILE_VALIDATED,
        instant=SCENARIO_START_INSTANT, detail="d" * 500,
    )
    if other.event_id() == event.event_id():
        problems.append("different content produced the same id")
    bad_events = (
        (0, FutureEventType.PROFILE_VALIDATED, SCENARIO_START_INSTANT),
        (True, FutureEventType.PROFILE_VALIDATED, SCENARIO_START_INSTANT),
        (1, "not-a-type", SCENARIO_START_INSTANT),
        (1, FutureEventType.PROFILE_VALIDATED, ""),
    )
    for bad_sequence, bad_type, bad_instant in bad_events:
        try:
            FutureEvent(
                sequence=bad_sequence, event_type=bad_type,
                instant=bad_instant, detail="x",
            )
            problems.append(
                "invalid event accepted: %r"
                % ((bad_sequence, bad_type, bad_instant),)
            )
        except FutureError:
            pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "events: content-derived ids, bounded detail, "
                            "fail-closed construction"))


def case_04_equivalence_record_shape(results: List[Result]) -> None:
    name = "case_04_equivalence_record_shape"
    good = ("sha256:" + "1" * 64, "sha256:" + "1" * 64)
    problems: List[str] = []
    record = CoreEquivalenceRecord(
        layers=tuple(
            (layer, good[0], good[1], True) for layer in CORE_EQUIVALENCE_LAYERS
        )
    )
    if not record.all_equal():
        problems.append("all_equal drifted")
    if record.to_dict()["all_equal"] is not True:
        problems.append("to_dict all_equal drifted")
    # a per-layer drift must be constructible but flagged false
    drifted = CoreEquivalenceRecord(
        layers=(
            ("routing", good[0], "sha256:" + "2" * 64, False),
            ("sessions", good[0], good[1], True),
            ("resources", good[0], good[1], True),
            ("policy", good[0], good[1], True),
        )
    )
    if drifted.all_equal():
        problems.append("drift not observable")
    # shape failures
    for bad_layers in (
        # duplicate layer
        (("routing", good[0], good[1], True),
         ("routing", good[0], good[1], True),
         ("sessions", good[0], good[1], True),
         ("resources", good[0], good[1], True),
         ("policy", good[0], good[1], True)),
        # missing layer
        (("routing", good[0], good[1], True),
         ("sessions", good[0], good[1], True),
         ("resources", good[0], good[1], True)),
        # wrong order
        (("sessions", good[0], good[1], True),
         ("routing", good[0], good[1], True),
         ("resources", good[0], good[1], True),
         ("policy", good[0], good[1], True)),
        # equal flag disagrees with digests
        (("routing", good[0], "sha256:" + "2" * 64, True),
         ("sessions", good[0], good[1], True),
         ("resources", good[0], good[1], True),
         ("policy", good[0], good[1], True)),
        # non-sha digest
        (("routing", "not-a-digest", "not-a-digest", True),
         ("sessions", good[0], good[1], True),
         ("resources", good[0], good[1], True),
         ("policy", good[0], good[1], True)),
    ):
        try:
            CoreEquivalenceRecord(layers=bad_layers)
            problems.append("misshapen record accepted")
            break
        except FutureError:
            continue
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "equivalence record: 4 frozen layers in order, "
                            "fail-closed shape, drift observable"))


def case_05_evidence_disclosures(results: List[Result]) -> None:
    name = "case_05_evidence_disclosures"
    problems: List[str] = []
    if FUTURE_EVIDENCE_STATUS != {
        "architecture_conformance": "supported-verified",
        "automated_verification": "supported-verified",
        "future_network_interop": "not-applicable",
    }:
        problems.append("evidence status drifted")
    required_in_statement = (
        "No real-world", "entirely synthetic", "no radio",
        "NEW work item", "never be promoted",
    )
    for token in required_in_statement:
        if token not in SYNTHETIC_EVIDENCE_STATEMENT:
            problems.append("synthetic statement lacks %r" % token)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "A/B supported-verified; C not-applicable with "
                            "the pinned anti-fabrication statement"))


def case_06_run_result_shape(results: List[Result]) -> None:
    name = "case_06_run_result_shape"
    result = run_future_profile_conformance()
    problems: List[str] = []
    if not result.future_digest().startswith("sha256:"):
        problems.append("run digest not sha256-prefixed")
    if result.technology_classification != "known":
        problems.append("canonical classification must be 'known'")
    if result.registry_digest_before != result.registry_digest_after:
        problems.append("registry digest changed")
    if result.registry_digest_before != registry_file_digest():
        problems.append("registry digest is not the live file digest")
    if result.unknown_id != UNKNOWN_FUTURE_TECHNOLOGY_ID:
        problems.append("unknown id drifted")
    if result.unknown_id_classification != "unknown_but_well_formed":
        problems.append("unknown id classification drifted")
    if not result.unknown_id_still_unknown:
        problems.append("unknown id gained authority")
    if len(result.adapter_ids) != 2:
        problems.append("the run registers exactly two adapters")
    for keyword in ("registry_unchanged", "journal_digest", "core_equivalence"):
        if keyword not in result.to_dict():
            problems.append("to_dict lacks %r" % keyword)
    # negative: misshapen run results refused
    base = result.to_dict()
    try:
        FutureRunResult(
            profile_digest="not-a-digest",
            technology_classification="known",
            registry_digest_before=result.registry_digest_before,
            registry_digest_after=result.registry_digest_after,
            adapter_ids=result.adapter_ids,
            unknown_id=result.unknown_id,
            unknown_id_classification=result.unknown_id_classification,
            unknown_id_still_unknown=True,
            core_equivalence=result.core_equivalence,
            events=result.events,
        )
        problems.append("misshapen run result accepted")
    except FutureError:
        pass
    if base.get("technology_classification") != "known":
        problems.append("to_dict classification drifted")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "run result: digest-pinned registry, two "
                            "adapters, unknown-id facts, fail-closed shape"))


# ---------------------------------------------------------------------------
# 07-16: the synthetic conformance scenario (class B)
# ---------------------------------------------------------------------------


def case_07_scenario_journal(results: List[Result]) -> None:
    name = "case_07_scenario_journal"
    result = run_future_profile_conformance()
    expected_order = (
        "profile-validated", "technology-classified", "adapter-registered",
        "adapter-opened", "capabilities-exposed", "link-observed",
        "capacity-allocated", "capacity-released", "session-bound",
        "session-unbound", "health-reported", "adapter-closed",
        "unknown-id-preserved", "registry-pinned",
        "core-equivalence-verified", "profile-verified",
    )
    problems: List[str] = []
    actual_order = tuple(event.event_type for event in result.events)
    if actual_order != expected_order:
        problems.append("journal order drifted: %s" % (actual_order,))
    if [event.sequence for event in result.events] != list(
        range(1, len(result.events) + 1)
    ):
        problems.append("journal sequence not 1-based contiguous")
    if any(event.instant != SCENARIO_START_INSTANT for event in result.events):
        problems.append("journal instants not the injected start instant")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "16 journaled decisions in frozen order, "
                            "1-based sequences, injected instants only"))


def case_08_no_core_schema_change(results: List[Result]) -> None:
    name = "case_08_no_core_schema_change"
    result = run_future_profile_conformance()
    problems: List[str] = []
    # the registry bytes are digest-stable across the run
    if not registry_untouched(
        digest_before=result.registry_digest_before,
        digest_after=result.registry_digest_after,
    ):
        problems.append("registry changed during the run")
    # the live registry file still carries the reserved entry, RESERVED
    registry_path = os.path.join(
        REPO_ROOT, "spec", "schemas", "registries",
        "access-profile-registry.json",
    )
    data = _json.loads(open(registry_path, encoding="utf-8").read())
    entry = data["entries"].get(CANONICAL_FUTURE_TECHNOLOGY_ID)
    if entry is None:
        problems.append("reserved entry missing")
    else:
        if entry.get("status") != "reserved":
            problems.append("reserved entry was ACTIVATED (status %r)"
                            % entry.get("status"))
        description = entry.get("description", "")
        if "specifies and freezes no 6G semantics" not in description:
            problems.append("reservation description drifted")
    if len(data["entries"]) != 11:
        problems.append("registry entry count drifted: %d" % len(data["entries"]))
    # git must show no spec/ modification
    status = subprocess.run(
        ["git", "status", "--porcelain", "--", "spec/"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if status.stdout.strip():
        problems.append("uncommitted spec/ changes: %s" % status.stdout.strip())
    # the classification of the reserved id is the registry's own verdict
    if classify_technology_id(CANONICAL_FUTURE_TECHNOLOGY_ID) != "known":
        problems.append("reserved id must classify known (registry membership)")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "registry digest-pinned across the run; entry "
                            "still reserved (never activated); spec/ clean"))


def case_09_additive_registration(results: List[Result]) -> None:
    name = "case_09_additive_registration"
    profile = canonical_future_profile()
    problems: List[str] = []
    descriptor = future_descriptor(profile, CANONICAL_INSTANCE_LABEL)
    if descriptor.access_technology_id != CANONICAL_FUTURE_TECHNOLOGY_ID:
        problems.append("descriptor technology drifted")
    if descriptor.adapter_id != (
        "adcos:adapter:access.3gpp.nr.imt2030:7916f1900a1612e2"
    ):
        problems.append("adapter id drifted: %s" % descriptor.adapter_id)
    if descriptor.supported_profile_versions != profile.profile_versions:
        problems.append("descriptor versions drifted")
    if tuple(descriptor.capabilities) != profile.capability_references:
        problems.append("descriptor capabilities drifted")
    if descriptor.extensions.get("work-item") != "WORK-038":
        problems.append("descriptor extensions lack the WORK-038 marker")
    if descriptor.extensions.get("profile-digest") != profile.digest():
        problems.append("descriptor extensions lack the profile digest")
    if descriptor.security_state.profile != "baseline" or \
            descriptor.security_state.credential_slots != (
                "technology-credential",):
        problems.append("security state structure drifted")
    # duplicate registration fails closed on a REAL runtime
    from adapters import AdapterRuntime

    runtime = AdapterRuntime()
    runtime.register(
        descriptor, __import__("imt").FutureTechnologyAdapter(
            profile.capability_references
        ), now=SCENARIO_START_INSTANT,
    )
    try:
        runtime.register(
            descriptor, __import__("imt").FutureTechnologyAdapter(
                profile.capability_references
            ), now=SCENARIO_START_INSTANT,
        )
        problems.append("duplicate registration accepted")
    except Exception as exc:
        if "already registered" not in str(exc):
            problems.append("unexpected duplicate error: %s" % exc)
    # misshapen descriptor factory input refused
    try:
        future_descriptor("not-a-profile", CANONICAL_INSTANCE_LABEL)  # type: ignore[arg-type]
        problems.append("misshapen profile accepted by the factory")
    except FutureError:
        pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "descriptor derived over the reserved id with "
                            "WORK-038 marker; duplicates fail closed"))


def case_10_contract_exercise(results: List[Result]) -> None:
    name = "case_10_contract_exercise"
    from adapters import AdapterRuntime

    profile = canonical_future_profile()
    descriptor = future_descriptor(profile, CANONICAL_INSTANCE_LABEL)
    runtime = AdapterRuntime()
    runtime.register(
        descriptor, __import__("imt").FutureTechnologyAdapter(
            profile.capability_references
        ), now=SCENARIO_START_INSTANT,
    )
    problems: List[str] = []
    opened = runtime.open_adapter(descriptor.adapter_id, now=_NOW)
    if not opened.ok:
        problems.append("open failed")
    caps = runtime.capabilities(descriptor.adapter_id, now=_NOW)
    if tuple(caps) != profile.capability_references:
        problems.append("capabilities drifted from the declaration")
    observed = runtime.observe(descriptor.adapter_id, now=_NOW)
    if not observed.ok:
        problems.append("observe failed")
    else:
        metrics = {sample.metric for sample in observed.value}
        for key in ("link-up", "rx-bytes-total", "tx-bytes-total"):
            if key not in metrics:
                problems.append("generic metric %r missing" % key)
    allocation = runtime.allocate(
        descriptor.adapter_id, kind="bandwidth", quantity=10, unit="mbps",
        purpose="battery", now=_NOW,
    )
    if not allocation.ok:
        problems.append("allocate failed")
    else:
        released = runtime.release(allocation.value.allocation_id, now=_NOW)
        if not released.ok:
            problems.append("release failed")
    # the OPAQUE technology references: the implementation's own
    # return values driven through the real least-authority context
    from adapters import AdapterContext

    context = AdapterContext(
        descriptor.adapter_id, descriptor.access_technology_id,
        _NOW, 10_000,
    )
    implementation = __import__("imt").FutureTechnologyAdapter(
        profile.capability_references
    )
    implementation.open(context)
    ref = implementation.allocate(
        context, kind="bandwidth", quantity_base=1, purpose="direct",
    )
    bearer = implementation.bind_session(
        context, session_id="sha256:" + "0" * 64, requirements=None,
    )
    if not ref.startswith("imt2030:allocation:"):
        problems.append("opaque allocation ref drifted: %s" % ref)
    if not bearer.startswith("imt2030:bearer:"):
        problems.append("opaque bearer ref drifted: %s" % bearer)
    health = runtime.health(descriptor.adapter_id, now=_NOW)
    if health.state not in ("HEALTHY", "DEGRADED", "FAILED"):
        problems.append("health state drifted: %s" % health.state)
    closed = runtime.close_adapter(descriptor.adapter_id, now=_NOW)
    if not closed.ok:
        problems.append("close failed")
    # capabilities() when closed returns empty (contract-shaped)
    caps_closed = runtime.capabilities(descriptor.adapter_id, now=_NOW)
    if tuple(caps_closed) != ():
        problems.append("closed adapter still exposes capabilities")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "nine operations exercised through the real "
                            "runtime; opaque imt2030: refs only"))


def case_11_unknown_id_preservation(results: List[Result]) -> None:
    name = "case_11_unknown_id_preservation"
    result = run_future_profile_conformance()
    problems: List[str] = []
    if result.unknown_id != "access.3gpp.future.unknown":
        problems.append("unknown id drifted")
    if result.unknown_id_classification != "unknown_but_well_formed":
        problems.append("unknown id not classified unknown-but-well-formed")
    if not result.unknown_id_still_unknown:
        problems.append("unknown id gained registry authority")
    # the delegated verdict recomputes clean
    if not unknown_id_gained_no_authority(
        technology_id=result.unknown_id,
        classification=result.unknown_id_classification,
    ):
        problems.append("recomputed verdict disagrees")
    # a recorded disagreement fails closed
    try:
        unknown_id_gained_no_authority(
            technology_id=result.unknown_id,
            classification=result.unknown_id_classification,
            still_unknown=False,
        )
        problems.append("disagreeing authority verdict accepted")
    except FutureError:
        pass
    # the unknown adapter id is derived over the unknown technology id
    unknown_adapter = result.adapter_ids[1]
    if "access.3gpp.future.unknown" not in unknown_adapter:
        problems.append("unknown adapter id not derived over the unknown id")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "unknown-but-well-formed id registered as DATA, "
                            "preserved verbatim, provably no authority"))


def case_12_core_equivalence(results: List[Result]) -> None:
    name = "case_12_core_equivalence"
    result = run_future_profile_conformance()
    problems: List[str] = []
    record = result.core_equivalence
    if not record.all_equal():
        problems.append("core layers not equivalent")
    for entry in record.to_dict()["layers"]:
        if not entry["equal"] or entry["before"] != entry["after"]:
            problems.append("layer %s drifted" % entry["layer"])
    # the equivalence record is covered by the run digest (structural):
    # any tampering with it changes the digest
    tampered = CoreEquivalenceRecord(
        layers=tuple(
            (layer, before, after, True)
            for layer, before, after, _eq in [
                ("routing", "sha256:" + "9" * 64,
                 "sha256:" + "9" * 64, True),
                ("sessions", "sha256:" + "9" * 64,
                 "sha256:" + "9" * 64, True),
                ("resources", "sha256:" + "9" * 64,
                 "sha256:" + "9" * 64, True),
                ("policy", "sha256:" + "9" * 64,
                 "sha256:" + "9" * 64, True),
            ]
        )
    )
    tampered_result = FutureRunResult(
        profile_digest=result.profile_digest,
        technology_classification=result.technology_classification,
        registry_digest_before=result.registry_digest_before,
        registry_digest_after=result.registry_digest_after,
        adapter_ids=result.adapter_ids,
        unknown_id=result.unknown_id,
        unknown_id_classification=result.unknown_id_classification,
        unknown_id_still_unknown=result.unknown_id_still_unknown,
        core_equivalence=tampered,
        events=result.events,
    )
    if tampered_result.future_digest() == result.future_digest():
        problems.append("equivalence record not covered by the run digest")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "routing/sessions/resources/policy byte-identical "
                            "before/after; record covered by the run digest"))


def case_13_determinism_fresh_run(results: List[Result]) -> None:
    name = "case_13_determinism_fresh_run"
    first = run_future_profile_conformance()
    second = run_future_profile_conformance()
    if first.future_digest() != second.future_digest():
        results.append(fail(
            name, "fresh-run digests diverged: %s vs %s"
            % (first.future_digest(), second.future_digest()),
        ))
        return
    if scenario_summary(first) != scenario_summary(second):
        results.append(fail(name, "summaries diverged"))
        return
    results.append(ok(name, "fresh-run digest stable: %s"
                      % first.future_digest()[:26]))


def case_14_hashseed_invariance(results: List[Result]) -> None:
    name = "case_14_hashseed_invariance"
    base = run_future_profile_conformance().future_digest()
    problems: List[str] = []
    for seed in ("1", "99", "31337"):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        proc = subprocess.run(
            [sys.executable, "-c",
             "import sys; sys.path.insert(0, %r); "
             "from imt import run_future_profile_conformance; "
             "print(run_future_profile_conformance().future_digest())"
             % REPO_ROOT],
            capture_output=True, text=True, env=env, cwd=str(REPO_ROOT),
        )
        if proc.returncode != 0:
            problems.append("seed %s run failed: %s" % (seed, proc.stderr[-200:]))
        elif proc.stdout.strip() != base:
            problems.append("seed %s digest diverged" % seed)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "digest invariant across PYTHONHASHSEED 1/99/31337"))


def case_15_replay_verification(results: List[Result]) -> None:
    name = "case_15_replay_verification"
    result = run_future_profile_conformance()
    problems: List[str] = []
    if not verify_future_replay(result):
        problems.append("true replay failed")
    # tamper: a mutated journal must NOT verify against the original
    tampered = FutureRunResult(
        profile_digest=result.profile_digest,
        technology_classification=result.technology_classification,
        registry_digest_before=result.registry_digest_before,
        registry_digest_after=result.registry_digest_after,
        adapter_ids=result.adapter_ids,
        unknown_id=result.unknown_id,
        unknown_id_classification=result.unknown_id_classification,
        unknown_id_still_unknown=result.unknown_id_still_unknown,
        core_equivalence=result.core_equivalence,
        events=result.events[:-1],
    )
    try:
        verify_future_replay(tampered)
        problems.append("tampered run verified")
    except FutureError as exc:
        if exc.reason != FutureReasonCode.REPLAY_DIVERGENCE:
            problems.append("unexpected replay reason: %s" % exc.reason)
    try:
        verify_future_replay("not-a-result")  # type: ignore[arg-type]
        problems.append("misshapen replay input accepted")
    except FutureError:
        pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "TRUE replay (re-run + digest compare); tamper "
                            "diverges with the typed reason"))


def case_16_coexistence_matrix(results: List[Result]) -> None:
    name = "case_16_coexistence_matrix"
    profile = canonical_future_profile()
    problems: List[str] = []
    # envelope seam: the future profile adds nothing at the version line
    if future_envelope_disposition() != "known_compatible":
        problems.append("envelope disposition drifted")
    # mixed-version coexistence: the W029 verdict is unchanged
    from upgrade.model import ProtocolProfile

    negotiation = coexistence_with_future_profile(
        FUTURE_PROFILE_PROTOCOL_PROFILE, ProtocolProfile(major=1, max_minor=0),
    )
    if not negotiation.succeeded or negotiation.selected is None:
        problems.append("same-major coexistence broken")
    mismatch = coexistence_with_future_profile(
        FUTURE_PROFILE_PROTOCOL_PROFILE, ProtocolProfile(major=2, max_minor=0),
    )
    if mismatch.succeeded or mismatch.reason != "major-mismatch":
        problems.append("major mismatch did not fail closed")
    # the capability matrix (the W005 authority's own verdicts)
    optional_offered = future_capability_negotiation(
        profile, peer_offers_future=True, required=False,
        evaluation_instant=_NOW,
    )
    optional_absent = future_capability_negotiation(
        profile, peer_offers_future=False, required=False,
        evaluation_instant=_NOW,
    )
    required_offered = future_capability_negotiation(
        profile, peer_offers_future=True, required=True,
        evaluation_instant=_NOW,
    )
    required_absent = future_capability_negotiation(
        profile, peer_offers_future=False, required=True,
        evaluation_instant=_NOW,
    )
    # optional unknown capability: safely ignored both ways (no reason)
    for outcome, label in (
        (optional_offered, "optional/offered"),
        (optional_absent, "optional/absent"),
    ):
        if outcome.succeeded or outcome.reason is not None:
            problems.append(
                "optional future capability not safely ignored (%s)" % label
            )
    # required unknown capability: explicit fail-closed reason BOTH ways
    # (the data's presence on both sides grants no authority)
    for outcome, label in (
        (required_offered, "required/offered"),
        (required_absent, "required/absent"),
    ):
        if outcome.succeeded or outcome.reason != "unknown-required-capability":
            problems.append(
                "required future capability not refused (%s: %r)"
                % (label, outcome.reason)
            )
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "envelope/coexistence verdicts unchanged; the "
                            "future capability never silently satisfies"))


# ---------------------------------------------------------------------------
# 17-22: negative and divergence discriminations
# ---------------------------------------------------------------------------


def case_17_profile_validation_negatives(results: List[Result]) -> None:
    name = "case_17_profile_validation_negatives"
    good = canonical_future_profile()
    problems: List[str] = []
    # The declaration delegates shape validation to the ACCEPTED
    # authorities (W016 version/mapping validators, W002 id
    # classification, W005 capability classification): their OWN
    # typed errors surface (the SDK-bridge precedent), together with
    # the profile's own FutureError checks.
    from adapters.errors import AdapterError
    from capabilities.model import CapabilityError

    sanctioned = (FutureError, AdapterError, CapabilityError)

    def variant(**overrides: Any) -> FutureProfileDeclaration:
        values = dict(
            technology_id=good.technology_id,
            profile_versions=good.profile_versions,
            capability_references=good.capability_references,
            technology_resource=good.technology_resource,
            resource_kind=good.resource_kind,
            resource_unit=good.resource_unit,
            resource_quantity=good.resource_quantity,
            security_profile=good.security_profile,
            credential_slots=good.credential_slots,
            extensions=good.extensions,
        )
        values.update(overrides)
        return FutureProfileDeclaration(**values)  # type: ignore[arg-type]

    # INVALID technology ids fail at construction (malformed grammar)
    for bad_id in ("not-access-id", "access..double", "Access.Upper",
                   "access._leading-underscore"):
        try:
            variant(technology_id=bad_id)
            problems.append("malformed id accepted: %r" % bad_id)
        except sanctioned:
            pass
        except Exception as exc:
            problems.append("non-typed error for %r: %s" % (bad_id, type(exc)))
    # empty versions / no capabilities fail
    for overrides, label in (
        ({"profile_versions": ()}, "empty versions"),
        ({"capability_references": ()}, "no capabilities"),
        ({"resource_quantity": 0}, "zero quantity"),
        ({"resource_quantity": True}, "boolean quantity"),
        ({"security_profile": ""}, "empty security profile"),
        ({"technology_resource": ""}, "empty resource name"),
        ({"extensions": "not-a-mapping"}, "extensions not a mapping"),
        ({"capability_references": ("capability-bogus!",)}, "invalid capability"),
        ({"credential_slots": ("",)}, "empty slot name"),
    ):
        try:
            variant(**overrides)
            problems.append("invalid declaration accepted: %s" % label)
        except sanctioned:
            pass
        except Exception as exc:
            problems.append("non-typed error for %s: %s" % (label, type(exc)))
    # validate_future_profile also refuses non-declarations
    try:
        validate_future_profile("not-a-declaration")
        problems.append("non-declaration accepted")
    except FutureError:
        pass
    # classify_technology_id refuses malformed ids with the typed reason
    try:
        classify_technology_id("bad id")
        problems.append("malformed classification accepted")
    except FutureError as exc:
        if exc.reason != FutureReasonCode.TECHNOLOGY_ID_INVALID:
            problems.append("classification reason drifted: %s" % exc.reason)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "negative matrix: malformed ids, empty "
                            "declarations, misshapen inputs all refused"))


def case_18_adapter_discipline_negatives(results: List[Result]) -> None:
    name = "case_18_adapter_discipline_negatives"
    from adapters import AdapterContext
    from imt import FutureTechnologyAdapter

    problems: List[str] = []
    adapter = FutureTechnologyAdapter(
        canonical_future_profile().capability_references
    )
    # the REAL least-authority context (typed, immutable, budgeted)
    ctx = AdapterContext(
        "adcos:adapter:access.3gpp.nr.imt2030:" + "0" * 16,
        CANONICAL_FUTURE_TECHNOLOGY_ID, _NOW, 10_000,
    )
    for operation, call in (
        ("observe", lambda: adapter.observe(ctx)),
        ("allocate", lambda: adapter.allocate(
            ctx, kind="bandwidth", quantity_base=1, purpose="x")),
        ("release", lambda: adapter.release(ctx, "imt2030:allocation:000001")),
        ("unbind", lambda: adapter.unbind_session(ctx, "imt2030:bearer:000001")),
    ):
        try:
            call()
            problems.append("pre-open %s accepted" % operation)
        except FutureError as exc:
            if exc.reason != FutureReasonCode.NOT_OPEN:
                problems.append("%s reason drifted: %s" % (operation, exc.reason))
    adapter.open(ctx)
    # unknown refs fail closed
    try:
        adapter.release(ctx, "imt2030:allocation:999999")
        problems.append("unknown ref released")
    except FutureError as exc:
        if exc.reason != FutureReasonCode.ALLOCATION_UNKNOWN:
            problems.append("release reason drifted")
    try:
        adapter.unbind_session(ctx, "imt2030:bearer:999999")
        problems.append("unknown bearer unbound")
    except FutureError as exc:
        if exc.reason != FutureReasonCode.BINDING_UNKNOWN:
            problems.append("unbind reason drifted")
    # empty session id refused
    try:
        adapter.bind_session(ctx, session_id="", requirements=None)
        problems.append("empty session id bound")
    except FutureError:
        pass
    # non-positive quantities refused
    for bad_quantity in (0, -5, True):
        try:
            adapter.allocate(
                ctx, kind="bandwidth", quantity_base=bad_quantity, purpose="x"
            )
            problems.append("bad quantity accepted: %r" % (bad_quantity,))
        except FutureError:
            pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "adapter discipline: not-open, unknown refs, "
                            "empty session, bad quantities all refused"))


def case_19_session_binding_discipline(results: List[Result]) -> None:
    name = "case_19_session_binding_discipline"
    # A REAL runtime + REAL store: binding a non-bindable session
    # fails closed (the runtime's own read-only verification).
    from adapters import AdapterRuntime
    from policy.model import PolicyDecision
    from resources import ResourceStore
    from routing import LinkMetrics, RoutingContext, RoutingEngine
    from sessions import SessionStore
    from topology import (
        ClaimType,
        SourceClass,
        TopologyClaim,
        TopologyGraph,
        make_link_subject,
    )

    node_a = "adcos:node:test.future.v1:" + "a" * 64
    node_b = "adcos:node:test.future.v1:" + "b" * 64
    t0 = "2026-06-01T00:00:00Z"
    fresh = "2026-12-31T23:59:59Z"
    placeholder = PolicyDecision(
        decision_id="0" * 64, effect="allow", code="allow", detail="fixture",
        matched_rule_ids=("r1",), policy_set_id="ps-1", policy_set_version=2,
        evaluation_instant=_NOW,
    )
    decision = PolicyDecision(
        decision_id=hashlib.sha256(
            placeholder.canonical_bytes()
        ).hexdigest(),
        effect="allow", code="allow", detail="fixture",
        matched_rule_ids=("r1",), policy_set_id="ps-1", policy_set_version=2,
        evaluation_instant=_NOW,
    )
    graph = TopologyGraph()
    graph.merge(TopologyClaim(
        subject=make_link_subject(node_a, node_b), reporter=node_a,
        claim_type=ClaimType.LINK_STATE, value="up",
        source_class=SourceClass.SELF_ADVERTISEMENT,
        issued_at=t0, freshness_until=fresh, sequence=1, provenance="",
    ))
    graph.merge(TopologyClaim(
        subject=node_b, reporter=node_a,
        claim_type=ClaimType.REACHABLE, value="true",
        source_class=SourceClass.DIRECT_OBSERVATION,
        issued_at=t0, freshness_until=fresh, sequence=1, provenance="",
    ))
    context = RoutingContext(
        source_node_id=node_a, destination_node_id=node_b,
        topology=graph, resources=ResourceStore(), evaluation_instant=_NOW,
        policy_decision=decision,
        link_metrics={
            make_link_subject(node_a, node_b): LinkMetrics(
                latency_ms=10, loss_basis_points=0, capacity_bps=1_000_000,
                energy_cost_millijoules=100, confidence_basis_points=10_000,
                observed_at=t0, freshness_until=fresh,
            ),
        },
    )
    route = RoutingEngine().evaluate(context)
    store = SessionStore()
    created = store.create(
        route.decision, decision,
        source_node_id=node_a, destination_node_id=node_b,
        creation_instant=_NOW,
    )
    if not created.ok or created.session is None:
        results.append(fail(name, "fixture session creation failed"))
        return
    session_id = created.session.session_id  # state: REQUESTED (not bindable)
    runtime = AdapterRuntime(session_store=store)
    profile = canonical_future_profile()
    descriptor = future_descriptor(profile, "future-radio-b19")
    runtime.register(
        descriptor, __import__("imt").FutureTechnologyAdapter(
            profile.capability_references
        ), now=_NOW,
    )
    runtime.open_adapter(descriptor.adapter_id, now=_NOW)
    binding = runtime.bind_session(
        descriptor.adapter_id, session_id=session_id, now=_NOW,
    )
    if binding.ok:
        results.append(fail(name, "non-bindable session bound"))
        return
    if binding.failure is None or \
            binding.failure.reason != "session-not-bindable":
        results.append(fail(
            name, "unexpected bind failure reason: %r"
            % (binding.failure.reason if binding.failure else None),
        ))
        return
    results.append(ok(name, "REQUESTED (non-bindable) session refused by the "
                            "runtime's read-only verification"))


def case_20_registry_and_authority_facts(results: List[Result]) -> None:
    name = "case_20_registry_and_authority_facts"
    problems: List[str] = []
    if registry_untouched(digest_before="a", digest_after="a") is not True:
        problems.append("registry_untouched true case drifted")
    if registry_untouched(digest_before="a", digest_after="b") is not False:
        problems.append("registry_untouched false case drifted")
    try:
        registry_untouched(digest_before=1, digest_after=1)  # type: ignore[arg-type]
        problems.append("non-string digests accepted")
    except FutureError:
        pass
    # the known set does NOT contain the unknown id (no authority)
    from adapters.validation import known_access_technology_ids

    if UNKNOWN_FUTURE_TECHNOLOGY_ID in known_access_technology_ids():
        problems.append("unknown id entered the known set")
    if CANONICAL_FUTURE_TECHNOLOGY_ID not in known_access_technology_ids():
        problems.append("reserved id missing from the known set")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "registry facts: unchanged/changed verdicts, "
                            "known-set membership exactly as registered"))


def case_21_evidence_anti_fabrication(results: List[Result]) -> None:
    name = "case_21_evidence_anti_fabrication"
    result = run_future_profile_conformance()
    report = classify_future_evidence(
        profile_validated=True, contract_exercised=True,
        run_digest=result.future_digest(),
    )
    problems: List[str] = []
    if report["A"]["evidence_class"] != "architecture-conformance":
        problems.append("class A label drifted")
    if not report["A"]["complete"]:
        problems.append("class A incomplete")
    if report["B"]["evidence_class"] != "automated-verification":
        problems.append("class B label drifted")
    if report["B"]["run_digest"] != result.future_digest():
        problems.append("class B digest mismatch")
    if report["C"]["status"] != "not-applicable":
        problems.append("class C status drifted")
    if report["C"]["statement"] != SYNTHETIC_EVIDENCE_STATEMENT:
        problems.append("class C statement drifted")
    if report["status"] != FUTURE_EVIDENCE_STATUS:
        problems.append("report status drifted")
    # incompletion propagates
    incomplete = classify_future_evidence(
        profile_validated=True, contract_exercised=False, run_digest=None,
    )
    if incomplete["A"]["complete"]:
        problems.append("incomplete run marked complete")
    # the anti-fabrication guard
    from imt import assert_no_real_world_claim

    assert_no_real_world_claim(claimed_class="A")
    assert_no_real_world_claim(claimed_class="B")
    for bad in ("C", "D", ""):
        try:
            assert_no_real_world_claim(claimed_class=bad)
            problems.append("claim %r accepted" % bad)
        except FutureError as exc:
            if bad == "C" and exc.reason != FutureReasonCode.EVIDENCE_CLASS_VIOLATION:
                problems.append("class-C claim reason drifted: %s" % exc.reason)
    # ANY operator-side gate outcome is refused (no closure path at all)
    try:
        classify_future_evidence(
            profile_validated=True, contract_exercised=True,
            run_digest=result.future_digest(), gate_outcome=object(),
        )
        problems.append("gate outcome accepted for the N/A class")
    except FutureError as exc:
        if exc.reason != FutureReasonCode.EVIDENCE_CLASS_VIOLATION:
            problems.append("gate refusal reason drifted: %s" % exc.reason)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "A/B closed in-repo; C not-applicable with NO "
                            "closure path (anti-fabrication in code)"))


def case_22_registry_additivity_temp_tree(results: List[Result]) -> None:
    name = "case_22_registry_additivity_temp_tree"
    # The additive future path demonstrated in a TEMP tree (never
    # committed): a hypothetical future registration grows the
    # registry as pure data, keeping every invariant the registry
    # itself declares.
    import tempfile

    registry_path = os.path.join(
        REPO_ROOT, "spec", "schemas", "registries",
        "access-profile-registry.json",
    )
    original = _json.loads(open(registry_path, encoding="utf-8").read())
    hypothetical = _json.loads(_json.dumps(original))
    hypothetical["entries"]["access.3gpp.future.hypothetical"] = {
        "description": "Hypothetical future registration (temp-tree "
                       "demonstration only; never committed).",
        "status": "active",
    }
    problems: List[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        temp_path = os.path.join(tmp, "access-profile-registry.json")
        with open(temp_path, "w", encoding="utf-8") as handle:
            _json.dump(hypothetical, handle, indent=2, sort_keys=True)
        reloaded = _json.loads(open(temp_path, encoding="utf-8").read())
        if len(reloaded["entries"]) != len(original["entries"]) + 1:
            problems.append("temp-tree registration not additive")
        if not set(original["entries"]) <= set(reloaded["entries"]):
            problems.append("temp tree dropped existing entries")
        # the new entry matches the declared id grammar
        grammar = re.compile(original["id_grammar"])
        if grammar.fullmatch("access.3gpp.future.hypothetical") is None:
            problems.append("hypothetical id violates the grammar")
        # every registry member survives unchanged
        for member in ("architecture_version", "id_grammar", "registry",
                       "schema_version", "unknown_id_policy",
                       "profile_scoped_rule" if "profile_scoped_rule"
                       in original else "description"):
            if member in original and original[member] != reloaded.get(member):
                problems.append("member %r drifted in the temp tree" % member)
    # the committed registry is untouched (no temp leakage)
    if registry_file_digest() != "sha256:" + hashlib.sha256(
        open(registry_path, "rb").read()
    ).hexdigest():
        problems.append("live registry digest drifted")
    status = subprocess.run(
        ["git", "status", "--porcelain", "--", "spec/"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if status.stdout.strip():
        problems.append("spec/ modified")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "hypothetical registration is additive data in a "
                            "temp tree; committed registry untouched"))


# ---------------------------------------------------------------------------
# 23-34: structural audits
# ---------------------------------------------------------------------------

_IMT_FILES = sorted(
    os.path.join(REPO_ROOT, "imt", name)
    for name in os.listdir(os.path.join(REPO_ROOT, "imt"))
    if name.endswith(".py")
)

#: The ADCOS core roots (the frozen core list, W037 precedent).
_CORE_DIRS = (
    "sessions", "identity", "protocol", "capabilities", "discovery",
    "transport", "topology", "routing", "multipath", "mobility",
    "federation", "policy", "intent", "resources",
)

#: Authority constructors that must NEVER appear in imt/.  The
#: scenario's fixture world (the W032 conformance-world pattern) is
#: allowed to construct exactly the three authorities the
#: core-equivalence probe composes through their public contracts
#: (SessionStore / RoutingEngine / ResourceStore, in scenario.py
#: only); every other authority constructor is forbidden everywhere.
_AUTHORITY_TOKENS_FORBIDDEN_EVERYWHERE = (
    "PolicyEngine(", "IdentityStore(", "MultipathStore(",
    "MobilityStore(", "FederationStore(", "TransportManager(",
    "ServiceRegistry(", "DistributedCoreManager(", "EdgeGateway(",
    "AgentRuntime(",
)
_AUTHORITY_TOKENS_SCENARIO_ONLY = (
    "SessionStore(", "RoutingEngine(", "ResourceStore(",
)

#: The sanctioned import roots for imt/: the W016 adapter SDK, the
#: W002 classification surface, the W032 evidence vocabulary, the
#: WORK-003 canonicalization, the W029 compatibility contracts, the
#: W005 capability authority (delegated verdicts), and the fixture
#: world's authority contracts (W008/W010/W012/W013/W014 -- the
#: conformance-world composition pattern).
_SANCTIONED_IMPORT_ROOTS = (
    "adapters", "adapters.validation",
    "conformance",
    "protocol.canonicalization",
    "upgrade.compatibility", "upgrade.model",
    "capabilities.negotiation", "capabilities.model",
    "policy.model", "resources", "routing", "sessions", "topology",
)

_STDLIB_ROOTS = (
    "__future__", "hashlib", "dataclasses", "datetime", "typing",
    "re", "json",
)

#: Vendor and radio/PHY implementation tokens that must NEVER appear
#: in imt/ (the adapter is contract-shaped, never radio-modeled;
#: LOCK-016/LOCK-017 and the handoff's vendor-leakage prohibition).
_VENDOR_PHY_TOKENS = (
    "ericsson", "nokia", "huawei", "qualcomm", "samsung", "zte",
    "ofdm", "orthogonal-frequency", "beamform", "waveform",
    "terahertz", "mmwave", "numerology", "rf-chain", "antenna-array",
)


def case_23_authority_discipline(results: List[Result]) -> None:
    name = "case_23_authority_discipline"
    problems: List[str] = []
    for path in _IMT_FILES:
        text = open(path, encoding="utf-8").read()
        basename = os.path.basename(path)
        for token in _AUTHORITY_TOKENS_FORBIDDEN_EVERYWHERE:
            if token in text:
                problems.append("%s constructs %r" % (basename, token))
        for token in _AUTHORITY_TOKENS_SCENARIO_ONLY:
            if token in text and basename != "scenario.py":
                problems.append(
                    "%s constructs %r (scenario.py fixture world only)"
                    % (basename, token)
                )
    if problems:
        results.append(fail(name, "; ".join(sorted(set(problems)))))
        return
    results.append(ok(name, "no shadow authority: fixture composition of "
                            "SessionStore/RoutingEngine/ResourceStore in "
                            "scenario.py only; no other authority anywhere"))


def case_24_import_discipline(results: List[Result]) -> None:
    name = "case_24_import_discipline"
    problems: List[str] = []
    for path in _IMT_FILES:
        tree = ast.parse(open(path, encoding="utf-8").read())
        basename = os.path.basename(path)
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
                if target in _SANCTIONED_IMPORT_ROOTS or any(
                    target.startswith(root + ".")
                    for root in _SANCTIONED_IMPORT_ROOTS
                ):
                    continue
                if target in _STDLIB_ROOTS:
                    continue
                problems.append(
                    "%s imports %r (outside the sanctioned roots)"
                    % (basename, target)
                )
    if problems:
        results.append(fail(name, "; ".join(sorted(set(problems)))))
        return
    results.append(ok(name, "imt/ imports only the sanctioned roots: W016 "
                            "SDK + W002 classification + W032 evidence + "
                            "W003 canonicalization + W029/W005 delegations "
                            "+ fixture-world authority contracts + stdlib"))


def case_25_core_purity(results: List[Result]) -> None:
    name = "case_25_core_purity"
    problems: List[str] = []
    forbidden_roots = (
        "imt",
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
        name, "%d core modules import no imt/ and no adapter "
              "implementation modules (the future profile stays out of "
              "core)" % scanned,
    ))


def case_26_injected_clock_and_purity(results: List[Result]) -> None:
    name = "case_26_injected_clock_and_purity"
    problems: List[str] = []
    forbidden_tokens = (
        "time.time(", "time.monotonic(", "datetime.now(",
        "datetime.utcnow(", "random.", "urandom(", "uuid.uuid4(",
        "gethostbyname(", "socket.socket(", "os.environ",
    )
    for path in _IMT_FILES:
        text = open(path, encoding="utf-8").read()
        basename = os.path.basename(path)
        for token in forbidden_tokens:
            if token in text:
                problems.append("%s contains %r" % (basename, token))
        if "import socket" in text:
            problems.append("%s imports socket" % basename)
        # datetime is allowed only in coexistence.py (the delegated
        # WORK-005 negotiation spec's injected instant)
        if "import datetime" in text and basename != "coexistence.py":
            problems.append("%s imports datetime (coexistence only)" % basename)
    if problems:
        results.append(fail(name, "; ".join(sorted(set(problems)))))
        return
    results.append(ok(name, "no wall clock / randomness / socket / "
                            "environment anywhere in imt/ (everything is "
                            "in-repo; no lab gate exists)"))


def case_27_secret_hygiene(results: List[Result]) -> None:
    name = "case_27_secret_hygiene"
    result = run_future_profile_conformance()
    problems: List[str] = []
    surface = _json.dumps(result.to_dict()).lower()
    for pattern in ("psk", "password", "secret=", "0xdeadbeef",
                    "credential-material"):
        if pattern in surface:
            problems.append("result surface carries %r" % pattern)
    for event in result.events:
        if "psk" in event.detail.lower() or "secret=" in event.detail.lower():
            problems.append("event %d carries secret-looking text" % event.sequence)
    for path in _IMT_FILES:
        text = open(path, encoding="utf-8").read()
        if re.search(r"(psk|password|secret_key)\s*=\s*[\"']", text):
            problems.append(
                "%s assigns credential-looking material" % os.path.basename(path)
            )
    if problems:
        results.append(fail(name, "; ".join(sorted(set(problems)))))
        return
    results.append(ok(name, "no credential material in any result surface or "
                            "source literal (slot NAMES only, LOCK-023)"))


def case_28_naming_and_vendor_token_freedom(results: List[Result]) -> None:
    name = "case_28_naming_and_vendor_token_freedom"
    problems: List[str] = []
    for path in _IMT_FILES:
        text = open(path, encoding="utf-8").read().lower()
        basename = os.path.basename(path)
        for token in re.findall(r"\bw0(3[9]|4[0-9])\b", text):
            problems.append("%s carries later-work token W0%s" % (basename, token))
        for token in _VENDOR_PHY_TOKENS:
            if token in text:
                problems.append("%s carries vendor/PHY token %r" % (basename, token))
    if problems:
        results.append(fail(name, "; ".join(sorted(set(problems)))))
        return
    results.append(ok(name, "no later-work tokens and no vendor/radio-PHY "
                            "implementation tokens in imt/"))


def case_29_budget_model_enforced(results: List[Result]) -> None:
    name = "case_29_budget_model_enforced"
    # The deterministic hang model: a tiny step budget converts an
    # overrunning future-technology operation into an isolated
    # BUDGET_EXHAUSTED failure value (mediated by the real sandbox).
    from adapters import (
        AdapterDescriptor,
        AdapterRuntime,
        AdapterSecurityState,
        ResourceMappingEntry,
    )
    from adapters.sandbox import SandboxedAdapter

    profile = canonical_future_profile()
    descriptor = future_descriptor(profile, "future-radio-b29")
    runtime = AdapterRuntime()
    runtime.register(
        descriptor, __import__("imt").FutureTechnologyAdapter(
            profile.capability_references
        ), now=_NOW,
    )
    problems: List[str] = []
    # 1. the runtime path: normal budget works (already proven in
    #    case_10); here we drive the sandbox directly with a tiny
    #    budget.
    tiny = SandboxedAdapter(
        descriptor,
        __import__("imt").FutureTechnologyAdapter(
            profile.capability_references
        ),
        step_budget=STEP_CHARGES["open"] - 1,
    )
    outcome = tiny.open(_NOW)
    if outcome.ok:
        problems.append("under-budget open succeeded (hang model broken)")
    elif outcome.failure is None or \
            outcome.failure.reason != "budget-exhausted":
        problems.append(
            "unexpected failure reason: %r"
            % (outcome.failure.reason if outcome.failure else None)
        )
    # 2. ample budget succeeds
    ample = SandboxedAdapter(
        descriptor,
        __import__("imt").FutureTechnologyAdapter(
            profile.capability_references
        ),
        step_budget=10_000,
    )
    outcome = ample.open(_NOW)
    if not outcome.ok:
        problems.append("ample-budget open failed")
    # 3. exceptions from the implementation surface as isolated
    #    failure values, never as exceptions crossing the boundary
    from adapters import AdapterContract, AdapterContext

    class _Exploding(AdapterContract):
        label = "exploding"

        def open(self, context: AdapterContext) -> None:
            raise RuntimeError("vendor SDK exploded")

        def capabilities(self) -> Tuple[str, ...]:
            return ()

        def observe(self, context: AdapterContext) -> Dict[str, int]:
            return {}

        def allocate(
            self, context: AdapterContext, *, kind: str,
            quantity_base: int, purpose: str,
        ) -> str:
            return "ref"

        def release(self, context: AdapterContext, technology_ref: str) -> None:
            return None

        def bind_session(
            self, context: AdapterContext, *, session_id: str,
            requirements: Optional[Mapping[str, Any]],
        ) -> str:
            return "bearer"

        def unbind_session(
            self, context: AdapterContext, bearer_ref: str,
        ) -> None:
            return None

        def health(self) -> str:
            return "HEALTHY"

        def close(self, context: AdapterContext) -> None:
            return None

    exploding_descriptor = AdapterDescriptor(
        adapter_id="adcos:adapter:access.3gpp.nr.imt2030:" + "e" * 16,
        access_technology_id=CANONICAL_FUTURE_TECHNOLOGY_ID,
        supported_profile_versions=profile.profile_versions,
        capabilities=profile.capability_references,
        resource_mapping=(
            ResourceMappingEntry(
                technology_resource="imt2030:study-bandwidth",
                kind="bandwidth", unit="mbps", quantity=100,
                availability="continuous",
            ),
        ),
        security_state=AdapterSecurityState(
            profile="baseline", credential_slots=("technology-credential",),
            attested=False,
        ),
    )
    sandbox = SandboxedAdapter(exploding_descriptor, _Exploding())
    outcome = sandbox.open(_NOW)
    if outcome.ok or outcome.failure is None:
        problems.append("exploding implementation not isolated")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "hang model + exception isolation: budget "
                            "exhaustion and vendor explosions become typed "
                            "failure values"))


def case_30_py_compile(results: List[Result]) -> None:
    name = "case_30_py_compile"
    problems: List[str] = []
    for path in _IMT_FILES:
        try:
            py_compile.compile(path, doraise=True)
        except py_compile.PyCompileError as exc:
            problems.append("%s: %s" % (os.path.basename(path), exc))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "all %d imt modules compile" % len(_IMT_FILES)))


_EXPECTED_API = [
    "FUTURE_PREFIX",
    "FutureError",
    "FutureReasonCode",
    "FutureEventType",
    "FUTURE_EVIDENCE_CLASS_MAP",
    "CORE_EQUIVALENCE_LAYERS",
    "FutureProfileDeclaration",
    "CANONICAL_FUTURE_TECHNOLOGY_ID",
    "canonical_future_profile",
    "UNKNOWN_FUTURE_TECHNOLOGY_ID",
    "FutureEvent",
    "future_events_canonical_bytes",
    "future_event_list_digest",
    "CoreEquivalenceRecord",
    "FutureRunResult",
    "validate_future_profile",
    "classify_technology_id",
    "profile_complete",
    "registry_untouched",
    "unknown_id_gained_no_authority",
    "FUTURE_ADAPTER_LABEL",
    "STEP_CHARGES",
    "FutureTechnologyAdapter",
    "future_descriptor",
    "SCENARIO_START_INSTANT",
    "CANONICAL_INSTANCE_LABEL",
    "UNKNOWN_ID_INSTANCE_LABEL",
    "run_future_profile_conformance",
    "verify_future_replay",
    "registry_file_digest",
    "scenario_summary",
    "FUTURE_PROTOCOL_MAJOR",
    "FUTURE_PROFILE_PROTOCOL_PROFILE",
    "FutureCapabilityNegotiation",
    "coexistence_with_future_profile",
    "future_capability_negotiation",
    "future_envelope_disposition",
    "FUTURE_EVIDENCE_STATUS",
    "SYNTHETIC_EVIDENCE_STATEMENT",
    "assert_no_real_world_claim",
    "classify_future_evidence",
]


def case_31_frozen_api(results: List[Result]) -> None:
    name = "case_31_frozen_api"
    import imt

    actual = list(imt.__all__)
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
    results.append(ok(name, "frozen public API: %d exports exact"
                      % len(_EXPECTED_API)))


# ---------------------------------------------------------------------------
# 32-34: frozen surfaces (spec, PR delta, CI wiring)
# ---------------------------------------------------------------------------


#: The Architect's own branch-anchored handoff prompt (commit 0be736e
#: added it to THIS branch).  The spec delta below admits EXACTLY
#: this file, and case_33 additionally asserts the implementation
#: never modified it.
_ARCHITECT_HANDOFF = "spec/prompts/WORK-038.md"
_ARCHITECT_HANDOFF_COMMIT = "0be736e"
_SUCCESSOR_HANDOFF = "spec/prompts/WORK-039.md"
_SUCCESSOR_HANDOFF_COMMIT = "7274384"


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
    # the W039 successor's handoff must equally be byte-untouched
    # (the W038 -> W039 successor admission; the same pattern the
    # oran battery applied for W037 -> W038).
    successor_untouched = subprocess.run(
        ["git", "diff", _SUCCESSOR_HANDOFF_COMMIT, "HEAD", "--",
         _SUCCESSOR_HANDOFF],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if successor_untouched.stdout.strip():
        problems.append("the W039 successor handoff was modified by the branch")
    return problems


def case_32_frozen_spec_intact(results: List[Result]) -> None:
    name = "case_32_frozen_spec_intact"
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
              "branch-anchored handoff (unmodified since 0be736e)",
    ))


def case_33_pr_delta_shape(results: List[Result]) -> None:
    name = "case_33_pr_delta_shape"
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
        if "python3 tools/imt_selftest.py" in workflow:
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
        if "python3 tools/imt_selftest.py" in workflow:
            results.append(ok(name, "spec/ clean on main; wiring verified"))
        else:
            results.append(fail(name, "committed CI wiring missing on main"))
        return
    problems = _spec_delta_clean()
    if problems:
        results.append(fail(name, "spec/ delta beyond the Architect's handoff: %s" % problems))
        return
    allowed_exact = {
        "tools/imt_selftest.py",
        # DAG-sanctioned allowlist amendment (W029 -> W038): the
        # upgrade battery's authority-boundary audit exempts the W038
        # family as a DAG-sanctioned downstream consumer (WORK-038
        # declares WORK-029 among its frozen dependencies;
        # imt/coexistence.py composes the real compatibility surfaces).
        "tools/upgrade_selftest.py",
        # DAG-sanctioned allowlist amendments (work-item order):
        # W033 -> W038 (the future profile composes the agent's
        # AdapterRuntime wiring seam):
        "tools/agent_selftest.py",
        # W034 -> W038:
        "tools/edge_selftest.py",
        # W035 -> W038:
        "tools/mobile_selftest.py",
        # W036 -> W038:
        "tools/appliance_selftest.py",
        # W037 -> W038 (the immediately preceding work item):
        "tools/oran_selftest.py",
        "docs/WORK-038-handoff.md",
        "docs/WORK-038-evidence.md",
        # DAG-sanctioned allowlist amendment (W038 -> W039; work-item
        # order; the federation-at-scale battery follows this one and
        # its PR-delta shape admits the successor's files):
        "tools/scale_selftest.py",
        "docs/WORK-039-handoff.md",
        "docs/WORK-039-evidence.md",
        # DAG-sanctioned amendment (-> WORK-040): the pilot deployment
        # battery extends this one (work-item order in CI).
        "tools/pilot_selftest.py",
        "docs/WORK-040-handoff.md",
        "docs/WORK-040-evidence.md",
        # the Architect's own branch anchors (validated by _spec_delta_clean):
        _ARCHITECT_HANDOFF,
        _SUCCESSOR_HANDOFF,
    }
    unexpected = [
        c for c in changed
        if not c.startswith("imt/") and not c.startswith("scale/")
        and not c.startswith("pilot/")
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
    if "imt_selftest.py" not in workflow_delta.stdout:
        results.append(fail(name, ".github delta does not include the future-profile CI step"))
        return
    results.append(ok(
        name, "PR delta exactly: imt/ + imt battery + agent/edge/mobile/"
              "appliance/oran allowlist amendments + handoff/evidence "
              "docs + the Architect's branch anchor + CI step",
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


def case_34_ci_wiring_all_tools(results: List[Result]) -> None:
    name = "case_34_ci_wiring_all_tools"
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
    oran_index = workflow.find("python3 tools/oran_selftest.py")
    imt_index = workflow.find("python3 tools/imt_selftest.py")
    if not (oran_index < imt_index):
        results.append(fail(name, "imt step not ordered after oran"))
        return
    results.append(ok(
        name, "CI wired: future-profile battery + all %d prior tools; imt "
              "ordered after oran (work-item order)"
        % (len(_EXPECTED_TOOLS) - 1),
    ))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> int:
    results: List[Result] = []
    for case in (
        case_01_frozen_vocabularies,
        case_02_profile_declaration_records,
        case_03_event_records,
        case_04_equivalence_record_shape,
        case_05_evidence_disclosures,
        case_06_run_result_shape,
        case_07_scenario_journal,
        case_08_no_core_schema_change,
        case_09_additive_registration,
        case_10_contract_exercise,
        case_11_unknown_id_preservation,
        case_12_core_equivalence,
        case_13_determinism_fresh_run,
        case_14_hashseed_invariance,
        case_15_replay_verification,
        case_16_coexistence_matrix,
        case_17_profile_validation_negatives,
        case_18_adapter_discipline_negatives,
        case_19_session_binding_discipline,
        case_20_registry_and_authority_facts,
        case_21_evidence_anti_fabrication,
        case_22_registry_additivity_temp_tree,
        case_23_authority_discipline,
        case_24_import_discipline,
        case_25_core_purity,
        case_26_injected_clock_and_purity,
        case_27_secret_hygiene,
        case_28_naming_and_vendor_token_freedom,
        case_29_budget_model_enforced,
        case_30_py_compile,
        case_31_frozen_api,
        case_32_frozen_spec_intact,
        case_33_pr_delta_shape,
        case_34_ci_wiring_all_tools,
    ):
        case(results)
    passed = sum(1 for _name, ok_flag, _detail in results if ok_flag)
    failed = len(results) - passed
    for name, ok_flag, detail in results:
        print("[%s] %s: %s" % ("PASS" if ok_flag else "FAIL", name, detail))
    print()
    print("imt selftest: %d passed, %d failed" % (passed, failed))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
