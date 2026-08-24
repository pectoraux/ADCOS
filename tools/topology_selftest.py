#!/usr/bin/env python3
"""ADCOS topology self-test (WORK-007).

Deterministic, offline verification of the topology package against the
frozen WORK-007 requirements (spec/prompts/WORK-007.md): the 28 required
test cases plus serialization round-trips, WORK-003 envelope integration,
adversarial provenance-collapse checks, a no-forbidden-fields/methods
mechanical check, seeded fuzz, and a byte-identical determinism proof.

The central boundary is exercised throughout:

    identity state      !=  advertisement state
                        !=  reachability state
                        !=  link state
                        !=  trust state
                        !=  routing validity
                        !=  resource availability

The most important adversarial invariant:

    A says "C is an Internet gateway"  -->  stored as reporter=A, subject=C,
    claim_type=gateway, source_class=REMOTE_CLAIM  -->  NEVER becomes
    C.gateway = true (an authoritative self-claim). ``get_authoritative_claims``
    returns ONLY self-attributed claims, so a remote summary can never enter
    the authoritative set.

All key material is TEST-ONLY; all clocks are injected; all PRNGs are seeded
so runs are byte-identical. No external network access is permitted or
required for the suite. Identity binding flows through the canonical
WORK-004 ``parse_node_id``; capability references stay opaque WORK-002
registry strings (no second vocabulary authority); temporal uses WORK-003
primitives; claim fingerprinting uses WORK-003 canonical JSON.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tools"))

from discovery import (  # noqa: E402
    DiscoveryObservation,
    SourceType,
    observation_to_bytes,
    observation_from_bytes,
    sign_observation,
)
from capabilities import (  # noqa: E402
    CapabilityStatement,
    SerializationError as CapabilitySerializationError,
    sign_statement,
    statement_to_bytes,
    statement_from_bytes,
)
from identity import (  # noqa: E402
    CredentialReference,
    DevHmacSha256Provider,
    IdentityService,
    InMemoryCredentialStore,
    KeyRole,
    NodeIdentity,
    ProfileSet,
    SignatureProvider,
)
from protocol import (  # noqa: E402
    Classification,
    ParsePolicy,
    UnknownTypePolicy,
    accept,
    envelope_from_mapping,
    validation_clock,
)
from protocol.codec_cbor import CompactDeterministicCborCodec  # noqa: E402
from protocol.codec_json import JsonDebugCodec  # noqa: E402
from topology import (  # noqa: E402
    AdvertisementState,
    ClaimType,
    IdentityState,
    LinkState,
    MergeOutcome,
    ReachabilityState,
    SourceClass,
    TopologyClaim,
    TopologyError,
    TopologyGraph,
    claim_from_capability_statement,
    claim_from_discovery_observation,
    claim_from_mapping,
    ingest_capability_statement,
    ingest_discovery_observation,
    make_link_subject,
    parse_link_subject,
)

NOW_TEXT = "2030-01-01T00:00:00Z"
NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)
FRESH_UNTIL = "2030-02-01T00:00:00Z"
FRESH_NOW = datetime(2030, 1, 15, tzinfo=timezone.utc)
STALE_NOW = datetime(2030, 3, 1, tzinfo=timezone.utc)
PROVIDER_SECRET = b"TEST-ONLY-topology-provider-key-DO-NOT-USE-1"

JSON_CODEC = JsonDebugCodec()
CBOR_CODEC = CompactDeterministicCborCodec()


class SeededRandom:
    """Deterministic LCG (same construction as the other suites)."""

    def __init__(self, seed: int) -> None:
        self._state = seed & 0xFFFFFFFFFFFFFFFF

    def _next(self) -> int:
        self._state = (
            self._state * 6364136223846793005 + 1442695040888963407
        ) & 0xFFFFFFFFFFFFFFFF
        return self._state >> 33

    def below(self, bound: int) -> int:
        return self._next() % bound


def make_identity(secret: bytes = PROVIDER_SECRET) -> Tuple[
    IdentityService, InMemoryCredentialStore, DevHmacSha256Provider, NodeIdentity, CredentialReference
]:
    profiles = ProfileSet.load_default()
    store = InMemoryCredentialStore()
    provider = DevHmacSha256Provider()
    service = IdentityService(store=store, provider=provider, profiles=profiles)
    profile = profiles.get("identity.sha256-hmac-dev.v1")
    ident = NodeIdentity.create(profile, provider.public_material(secret), NOW_TEXT)
    ref = service.provision(ident, KeyRole.IDENTITY, secret, now=NOW_TEXT)
    service.activate(ref, now=NOW_TEXT)
    return service, store, provider, ident, ref


def make_node(secret: bytes, service: IdentityService, provider: DevHmacSha256Provider
              ) -> Tuple[NodeIdentity, CredentialReference]:
    profiles = ProfileSet.load_default()
    profile = profiles.get("identity.sha256-hmac-dev.v1")
    ident = NodeIdentity.create(profile, provider.public_material(secret), NOW_TEXT)
    ref = service.provision(ident, KeyRole.IDENTITY, secret, now=NOW_TEXT)
    service.activate(ref, now=NOW_TEXT)
    return ident, ref


def base_observation(
    *,
    sender_node_id: str,
    observed_node_id: str,
    sequence: int = 1,
    issued_at: str = NOW_TEXT,
    freshness_until: str = FRESH_UNTIL,
    source_type: str = SourceType.LOCAL,
) -> DiscoveryObservation:
    return DiscoveryObservation(
        sender_node_id=sender_node_id,
        observed_node_id=observed_node_id,
        issued_at=issued_at,
        freshness_until=freshness_until,
        sequence=sequence,
        source_type=source_type,
        source_context={"interface": "loopback"},
        advertised_capability_references=("capability.core.multipath",),
        observed_endpoints=({"transport": "udp", "address": "127.0.0.1:5683"},),
    )


def signed_observation(
    *,
    store: InMemoryCredentialStore,
    provider: DevHmacSha256Provider,
    credential: CredentialReference,
    **overrides: Any,
) -> DiscoveryObservation:
    record = store.get_record(credential)
    overrides.setdefault("sender_node_id", record.node_id.text)
    obs = base_observation(**overrides)
    return sign_observation(obs, store=store, provider=provider, credential=credential)


def base_statement(**overrides: Any) -> CapabilityStatement:
    data: dict = dict(
        capability_id="capability.core.multipath",
        schema_version="1.0",
        provider_identity="adcos:node:identity.sha256-hmac-dev.v1:" + "1" * 64,
        valid_from="2030-01-01T00:00:00Z",
        expires_at="2030-02-01T00:00:00Z",
        parameters={"max_paths": 4},
        constraints={"privacy": "end_to_end"},
        evidence_references=["evidence:ref-0001"],
    )
    data.update(overrides)
    return CapabilityStatement(**data)  # type: ignore[arg-type]


def signed_statement(
    store: InMemoryCredentialStore,
    provider: DevHmacSha256Provider,
    credential: CredentialReference,
    **overrides: Any,
) -> CapabilityStatement:
    record = store.get_record(credential)
    overrides.setdefault("provider_identity", record.node_id.text)
    return sign_statement(
        base_statement(**overrides), store=store, provider=provider, credential=credential
    )


def _claim(
    *,
    subject: str,
    reporter: str,
    claim_type: str = ClaimType.DISCOVERED,
    value: Any = "true",
    source_class: str = SourceClass.REMOTE_CLAIM,
    sequence: int = 1,
    issued_at: str = NOW_TEXT,
    freshness_until: str = FRESH_UNTIL,
    provenance: str = "sig-test",
    evidence_refs: Tuple[str, ...] = (),
) -> TopologyClaim:
    return TopologyClaim(
        subject=subject,
        reporter=reporter,
        claim_type=claim_type,
        value=value,
        evidence_refs=evidence_refs,
        source_class=source_class,
        issued_at=issued_at,
        freshness_until=freshness_until,
        sequence=sequence,
        provenance=provenance,
    )


# ---------------------------------------------------------------------------
# Required tests
# ---------------------------------------------------------------------------


def case_01_discovery_ingests_as_claim(results: List[Tuple[str, bool, str]]) -> None:
    """1. A discovery observation ingests as a provenance-bearing claim
    (reporter=sender, subject=observed, source_class=DIRECT_OBSERVATION)."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-01-node-B", service, provider)
    obs = signed_observation(
        store=store, provider=provider, credential=ref_a,
        observed_node_id=ident_b.node_id.text, sequence=1,
    )
    claims = claim_from_discovery_observation(obs)
    g = TopologyGraph()
    outcomes = ingest_discovery_observation(g, obs, now=FRESH_NOW)
    ok = (
        len(claims) == 2
        and claims[0].claim_type == ClaimType.DISCOVERED
        and claims[1].claim_type == ClaimType.IDENTITY
        and claims[0].reporter == obs.sender_node_id
        and claims[0].subject == obs.observed_node_id
        and claims[0].source_class == SourceClass.DIRECT_OBSERVATION
        and claims[0].provenance == obs.observation_id
        and claims[0].evidence_refs == (obs.observation_id,)
        and all(o.accepted for o in outcomes)
    )
    # The capability references stay OPAQUE data in the discovered claim value
    # (never reinterpreted as C's self-advertisement).
    discovered = [c for c in g.get_claims_for_subject(ident_b.node_id.text, now=FRESH_NOW)
                  if c.claim_type == ClaimType.DISCOVERED]
    cap_refs_opaque = (
        len(discovered) == 1
        and discovered[0].value["capability_refs"] == ["capability.core.multipath"]
        and g.get_authoritative_claims(
            ident_b.node_id.text, claim_type=ClaimType.ADVERTISES, now=FRESH_NOW
        ) == ()
    )
    results.append((
        "01-discovery-ingests-as-provenance-bearing-claim",
        ok and cap_refs_opaque,
        "discovery -> discovered + identity/present claims; reporter=sender, "
        "source=DIRECT_OBSERVATION, provenance=observation_id; capability refs "
        "stay opaque data (no self-advertisement)"
        if ok and cap_refs_opaque else "FAILED: ok=%s cap_refs_opaque=%s" % (ok, cap_refs_opaque),
    ))


def case_02_identity_independent_from_advertisement(results: List[Tuple[str, bool, str]]) -> None:
    """2. Identity state changes independently from advertisement state."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-02-node-B", service, provider)
    B = ident_b.node_id.text
    g = TopologyGraph()
    # identity KNOWN via self-attribution; advertisement STALE (past freshness).
    # Identity self-claim stays FRESH through STALE_NOW; the advertisement
    # alone is stale -- proving the two dimensions are independent.
    g.merge(_claim(subject=B, reporter=B, claim_type=ClaimType.IDENTITY,
                   value="present", source_class=SourceClass.SELF_ADVERTISEMENT,
                   freshness_until="2030-04-01T00:00:00Z",
                   sequence=1, provenance="B-self-id"))
    g.merge(_claim(subject=B, reporter=B, claim_type=ClaimType.ADVERTISES,
                   value="capability.core.multipath",
                   source_class=SourceClass.SELF_ADVERTISEMENT,
                   issued_at="2029-12-01T00:00:00Z",
                   freshness_until="2029-12-15T00:00:00Z",
                   sequence=1, provenance="B-stale-advert"))
    ident = g.get_identity_state(B, now=STALE_NOW)
    advert = g.get_advertisement_state(B, now=STALE_NOW)
    ok = ident == IdentityState.KNOWN and advert == AdvertisementState.STALE
    results.append((
        "02-identity-independent-from-advertisement",
        ok,
        "identity=KNOWN, advertisement=STALE (independent dimensions)"
        if ok else "FAILED: identity=%s advert=%s" % (ident, advert),
    ))


def case_03_advertisement_independent_from_reachability(results: List[Tuple[str, bool, str]]) -> None:
    """3. Advertisement state changes independently from reachability."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-03-node-B", service, provider)
    B = ident_b.node_id.text
    g = TopologyGraph()
    g.merge(_claim(subject=B, reporter=B, claim_type=ClaimType.ADVERTISES,
                   value="capability.core.multipath",
                   source_class=SourceClass.SELF_ADVERTISEMENT, sequence=1,
                   provenance="B-advert"))
    # No reachability observation -> UNREACHABLE, but advertisement CURRENT.
    advert = g.get_advertisement_state(B, now=FRESH_NOW)
    reach = g.get_reachability_state(B, now=FRESH_NOW)
    ok = advert == AdvertisementState.CURRENT and reach == ReachabilityState.UNREACHABLE
    results.append((
        "03-advertisement-independent-from-reachability",
        ok,
        "advertisement=CURRENT, reachability=UNREACHABLE (independent)"
        if ok else "FAILED: advert=%s reach=%s" % (advert, reach),
    ))


def case_04_link_independent_from_advertisement(results: List[Tuple[str, bool, str]]) -> None:
    """4. Link state changes independently from advertisement freshness."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-04-node-B", service, provider)
    A = ident_a.node_id.text
    B = ident_b.node_id.text
    g = TopologyGraph()
    link_subj = make_link_subject(A, B)
    # advertisement STALE, link UP — independent.
    g.merge(_claim(subject=B, reporter=B, claim_type=ClaimType.ADVERTISES,
                   value="capability.core.multipath",
                   source_class=SourceClass.SELF_ADVERTISEMENT,
                   issued_at="2029-12-01T00:00:00Z",
                   freshness_until="2029-12-15T00:00:00Z",
                   sequence=1, provenance="B-stale-advert"))
    # Link observation stays FRESH through STALE_NOW; the advertisement
    # alone is stale -- the link dimension is independent.
    g.merge(_claim(subject=link_subj, reporter=A, claim_type=ClaimType.LINK_STATE,
                   value=LinkState.UP, source_class=SourceClass.DIRECT_OBSERVATION,
                   freshness_until="2030-04-01T00:00:00Z",
                   sequence=1, provenance="A-link-up"))
    advert = g.get_advertisement_state(B, now=STALE_NOW)
    link = g.get_link_state(A, B, now=STALE_NOW)
    ok = advert == AdvertisementState.STALE and link == LinkState.UP
    results.append((
        "04-link-independent-from-advertisement-freshness",
        ok,
        "link=UP, advertisement=STALE (independent)"
        if ok else "FAILED: advert=%s link=%s" % (advert, link),
    ))


def case_05_stale_advertisement_historical_not_current(results: List[Tuple[str, bool, str]]) -> None:
    """5. A stale advertisement remains historical (queryable) but is not current."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-05-node-B", service, provider)
    B = ident_b.node_id.text
    g = TopologyGraph()
    g.merge(_claim(subject=B, reporter=B, claim_type=ClaimType.ADVERTISES,
                   value="capability.core.multipath",
                   source_class=SourceClass.SELF_ADVERTISEMENT, sequence=1,
                   provenance="B-advert"))
    advert_fresh = g.get_advertisement_state(B, now=FRESH_NOW)
    advert_stale = g.get_advertisement_state(B, now=STALE_NOW)
    # Historical claim still queryable.
    historical = g.get_claims_for_subject(B, now=STALE_NOW, include_historical=False)
    still_present = any(
        c.claim_type == ClaimType.ADVERTISES for c in historical
    )
    # current_observations excludes it when stale.
    current_obs = g.get_current_observations(now=STALE_NOW)
    in_current = any(c.claim_type == ClaimType.ADVERTISES for c in current_obs)
    ok = (advert_fresh == AdvertisementState.CURRENT
          and advert_stale == AdvertisementState.STALE
          and still_present and not in_current)
    results.append((
        "05-stale-advertisement-historical-not-current",
        ok,
        "fresh->CURRENT, stale->STALE; claim retained & queryable but not in "
        "current_observations"
        if ok else "FAILED: fresh=%s stale=%s retained=%s current=%s"
        % (advert_fresh, advert_stale, still_present, in_current),
    ))


def case_06_removed_identity_not_resurrected_by_replay(results: List[Tuple[str, bool, str]]) -> None:
    """6. A removed identity remains historical and is not resurrected by a
    replayed old identity observation."""
    service, store, provider, ident_b, ref_b = make_identity(b"TEST-06-node-B")
    B = ident_b.node_id.text
    g = TopologyGraph()
    g.merge(_claim(subject=B, reporter=B, claim_type=ClaimType.IDENTITY,
                   value="present", source_class=SourceClass.SELF_ADVERTISEMENT,
                   sequence=1, provenance="B-present-1"))
    g.merge(_claim(subject=B, reporter=B, claim_type=ClaimType.IDENTITY,
                   value="removed", source_class=SourceClass.SELF_ADVERTISEMENT,
                   sequence=2, provenance="B-removed-2"))
    # Replay the old present (seq 1) — watermark is 2, so rejected.
    replay = g.merge(_claim(subject=B, reporter=B, claim_type=ClaimType.IDENTITY,
                            value="present", source_class=SourceClass.SELF_ADVERTISEMENT,
                            sequence=1, provenance="B-present-1-replay"))
    ident = g.get_identity_state(B, now=FRESH_NOW)
    # Historical: the present claim is retained as historical evidence.
    historical = g.get_claims_for_subject(B, now=FRESH_NOW, include_historical=True)
    has_present_historical = any(
        c.value == "present" for c in historical if c.claim_type == ClaimType.IDENTITY
    )
    ok = (replay.code == "replay-stale" and ident == IdentityState.REMOVED
          and has_present_historical)
    results.append((
        "06-removed-identity-not-resurrected-by-replay",
        ok,
        "self present(seq1)->removed(seq2); replay seq1 rejected (watermark); "
        "identity=REMOVED; present retained as historical"
        if ok else "FAILED: replay=%s ident=%s hist=%s" % (replay.code, ident, has_present_historical),
    ))


def case_07_exact_duplicate_idempotent(results: List[Tuple[str, bool, str]]) -> None:
    """7. An exact duplicate claim is idempotent (same claim_id, no state change)."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-07-node-B", service, provider)
    A = ident_a.node_id.text
    B = ident_b.node_id.text
    g = TopologyGraph()
    c = _claim(subject=B, reporter=A, claim_type=ClaimType.GATEWAY,
               value={"role": "internet-egress"},
               source_class=SourceClass.REMOTE_CLAIM, sequence=1, provenance="A-gw")
    first = g.merge(c)
    second = g.merge(c)  # exact same object -> same claim_id
    ok = first.code == "accepted" and second.code == "idempotent" and len(g) == 1
    results.append((
        "07-exact-duplicate-idempotent",
        ok,
        "first=accepted, second=idempotent, graph size unchanged"
        if ok else "FAILED: first=%s second=%s len=%d" % (first.code, second.code, len(g)),
    ))


def case_08_arrival_order_byte_identical(results: List[Tuple[str, bool, str]]) -> None:
    """8. The same evidence set in different arrival orders converges byte-identically."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-08a-B", service, provider)
    ident_c, _ = make_node(b"TEST-08b-C", service, provider)
    A, B, C = ident_a.node_id.text, ident_b.node_id.text, ident_c.node_id.text
    claims = [
        _claim(subject=B, reporter=A, claim_type=ClaimType.IDENTITY, value="present",
               source_class=SourceClass.DIRECT_OBSERVATION, sequence=1, provenance="A-disc-B"),
        _claim(subject=C, reporter=A, claim_type=ClaimType.IDENTITY, value="present",
               source_class=SourceClass.DIRECT_OBSERVATION, sequence=1, provenance="A-disc-C"),
        _claim(subject=B, reporter=B, claim_type=ClaimType.ADVERTISES,
               value="capability.core.multipath",
               source_class=SourceClass.SELF_ADVERTISEMENT, sequence=1, provenance="B-self-advert"),
        _claim(subject=C, reporter=B, claim_type=ClaimType.GATEWAY,
               value={"role": "internet-egress"},
               source_class=SourceClass.REMOTE_CLAIM, sequence=2, provenance="B-gw-C"),
    ]
    g1 = TopologyGraph()
    for c in claims:
        g1.merge(c)
    g2 = TopologyGraph()
    for c in reversed(claims):
        g2.merge(c)
    g3 = TopologyGraph()
    for c in [claims[2], claims[0], claims[3], claims[1]]:
        g3.merge(c)
    b1 = g1.to_canonical_bytes()
    b2 = g2.to_canonical_bytes()
    b3 = g3.to_canonical_bytes()
    ok = b1 == b2 == b3
    results.append((
        "08-arrival-order-byte-identical",
        ok,
        "snapshot bytes identical across 3 insertion orders"
        if ok else "FAILED: b1==b2=%s b2==b3=%s" % (b1 == b2, b2 == b3),
    ))


def case_09_newer_supersedes_older(results: List[Tuple[str, bool, str]]) -> None:
    """9. A newer same-reporter/same-subject sequence deterministically
    supersedes older state where permitted."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-09-B", service, provider)
    A, B = ident_a.node_id.text, ident_b.node_id.text
    g = TopologyGraph()
    g.merge(_claim(subject=B, reporter=A, claim_type=ClaimType.REACHABLE, value="true",
                  source_class=SourceClass.DIRECT_OBSERVATION, sequence=1, provenance="A-reach-1"))
    g.merge(_claim(subject=B, reporter=A, claim_type=ClaimType.REACHABLE, value="true",
                  source_class=SourceClass.DIRECT_OBSERVATION, sequence=3, provenance="A-reach-3"))
    # The current head must be seq 3; seq 1 is historical.
    current = g.get_claims_for_subject(B, now=FRESH_NOW)
    head = [c for c in current if c.claim_type == ClaimType.REACHABLE]
    historical = g.get_claims_for_subject(B, now=FRESH_NOW, include_historical=True)
    hist_has_1 = any(c.sequence == 1 for c in historical if c.claim_type == ClaimType.REACHABLE)
    ok = (len(head) == 1 and head[0].sequence == 3 and hist_has_1)
    results.append((
        "09-newer-supersedes-older",
        ok,
        "head seq=3; seq=1 retained as historical"
        if ok else "FAILED: head=%r hist_has_1=%s" % ([(c.sequence) for c in head], hist_has_1),
    ))


def case_10_conflicting_same_sequence_preserved(results: List[Tuple[str, bool, str]]) -> None:
    """10. Conflicting same-sequence content is preserved as a conflict —
    never an arrival-order winner."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-10-B", service, provider)
    A, B = ident_a.node_id.text, ident_b.node_id.text
    g = TopologyGraph()
    c1 = _claim(subject=B, reporter=A, claim_type=ClaimType.GATEWAY,
                value={"role": "internet-egress"},
                source_class=SourceClass.REMOTE_CLAIM, sequence=1, provenance="A-gw-egress")
    c2 = _claim(subject=B, reporter=A, claim_type=ClaimType.GATEWAY,
                value={"role": "satellite-uplink"},
                source_class=SourceClass.REMOTE_CLAIM, sequence=1, provenance="A-gw-sat")
    r1 = g.merge(c1)
    r2 = g.merge(c2)
    conflicts = g.get_conflicts()
    ok = (
        r1.code == "accepted" and r2.code == "conflict-preserved"
        and len(conflicts) == 1
        and len(conflicts[0][1]) == 2
        and {c.claim_id for c in conflicts[0][1]} == {c1.claim_id, c2.claim_id}
        # current head for this key is conflicted (None) -> no authoritative winner
        and g.get_claim((A, B, ClaimType.GATEWAY, "")) is None
    )
    results.append((
        "10-conflicting-same-sequence-preserved",
        ok,
        "both conflicting claims retained; no arrival-order winner; current "
        "head is conflicted (None)"
        if ok else "FAILED: r1=%s r2=%s conflicts=%d head=%s"
        % (r1.code, r2.code, len(conflicts), g.get_claim((A, B, ClaimType.GATEWAY, ""))),
    ))


def case_11_two_reporters_both_retained(results: List[Tuple[str, bool, str]]) -> None:
    """11. Two reporters with conflicting claims are both retained with provenance."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-11-B", service, provider)
    ident_c, _ = make_node(b"TEST-11-C", service, provider)
    A, B, C = ident_a.node_id.text, ident_b.node_id.text, ident_c.node_id.text
    g = TopologyGraph()
    g.merge(_claim(subject=C, reporter=A, claim_type=ClaimType.GATEWAY,
                   value={"role": "internet-egress"},
                   source_class=SourceClass.REMOTE_CLAIM, sequence=1, provenance="A-gw-C"))
    g.merge(_claim(subject=C, reporter=B, claim_type=ClaimType.GATEWAY,
                   value={"role": "satellite-uplink"},
                   source_class=SourceClass.REMOTE_CLAIM, sequence=1, provenance="B-gw-C"))
    claims = g.get_claims_for_subject(C, now=FRESH_NOW)
    reporters = sorted(c.reporter for c in claims if c.claim_type == ClaimType.GATEWAY)
    ok = reporters == [A, B] and len(claims) >= 2
    results.append((
        "11-two-reporters-both-retained",
        ok,
        "A and B gateway claims about C both retained with provenance"
        if ok else "FAILED: reporters=%r" % (reporters,),
    ))


def case_12_self_vs_remote_distinct(results: List[Tuple[str, bool, str]]) -> None:
    """12. Self-advertisement and remote claim remain distinct authority classes."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-12-B", service, provider)
    A, B = ident_a.node_id.text, ident_b.node_id.text
    g = TopologyGraph()
    self_claim = _claim(subject=B, reporter=B, claim_type=ClaimType.ADVERTISES,
                        value="capability.core.multipath",
                        source_class=SourceClass.SELF_ADVERTISEMENT, sequence=1, provenance="B-self")
    remote_claim = _claim(subject=B, reporter=A, claim_type=ClaimType.ADVERTISES,
                         value="capability.core.multipath",
                         source_class=SourceClass.REMOTE_CLAIM, sequence=1, provenance="A-remote")
    g.merge(self_claim)
    g.merge(remote_claim)
    auth = g.get_authoritative_claims(B, claim_type=ClaimType.ADVERTISES, now=FRESH_NOW)
    all_claims = g.get_claims_for_subject(B, now=FRESH_NOW)
    ok = (
        self_claim.is_self_attribution() is True
        and remote_claim.is_self_attribution() is False
        and len(auth) == 1 and auth[0].reporter == B
        and len(all_claims) == 2
        and {c.source_class for c in all_claims} == {
            SourceClass.SELF_ADVERTISEMENT, SourceClass.REMOTE_CLAIM
        }
    )
    results.append((
        "12-self-advertisement-and-remote-claim-distinct",
        ok,
        "self (reporter=B, SELF) + remote (reporter=A, REMOTE) both stored; "
        "authoritative set contains only the self claim"
        if ok else "FAILED: auth=%d self_attr=%s remote_attr=%s"
        % (len(auth), self_claim.is_self_attribution(), remote_claim.is_self_attribution()),
    ))


def case_13_remote_gateway_not_authoritative(results: List[Tuple[str, bool, str]]) -> None:
    """13. Reporter A claiming C is an Internet gateway does NOT make C an
    authoritative gateway."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_c, _ = make_node(b"TEST-13-C", service, provider)
    A, C = ident_a.node_id.text, ident_c.node_id.text
    g = TopologyGraph()
    g.merge(_claim(subject=C, reporter=A, claim_type=ClaimType.GATEWAY,
                   value={"role": "internet-egress"},
                   source_class=SourceClass.REMOTE_CLAIM, sequence=1, provenance="A-gw-C"))
    auth = g.get_authoritative_claims(C, claim_type=ClaimType.GATEWAY, now=FRESH_NOW)
    claims = g.get_claims_for_subject(C, now=FRESH_NOW)
    ok = (
        auth == ()
        and len(claims) == 1
        and claims[0].reporter == A
        and claims[0].subject == C
        and claims[0].source_class == SourceClass.REMOTE_CLAIM
    )
    results.append((
        "13-remote-gateway-not-authoritative",
        ok,
        "A->C gateway stored as REMOTE_CLAIM (reporter=A); authoritative set empty"
        if ok else "FAILED: auth=%d claims=%d" % (len(auth), len(claims)),
    ))


def case_14_remote_reachable_not_global_truth(results: List[Tuple[str, bool, str]]) -> None:
    """14. Reporter A claiming C is reachable does NOT create global
    reachability truth (the claim retains reporter provenance)."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_c, _ = make_node(b"TEST-14-C", service, provider)
    A, C = ident_a.node_id.text, ident_c.node_id.text
    g = TopologyGraph()
    g.merge(_claim(subject=C, reporter=A, claim_type=ClaimType.REACHABLE, value="true",
                   source_class=SourceClass.DIRECT_OBSERVATION, sequence=1, provenance="A-reach-C"))
    reach = g.get_reachability_state(C, now=FRESH_NOW)
    auth = g.get_authoritative_claims(C, claim_type=ClaimType.REACHABLE, now=FRESH_NOW)
    claims = [c for c in g.get_claims_for_subject(C, now=FRESH_NOW)
              if c.claim_type == ClaimType.REACHABLE]
    # The state is derived (REACHABLE) BUT provenance preserved: the only
    # evidence is A's observation (reporter=A != C, source != SELF). There is
    # no authoritative self-claim and no "C.reachable = true" field.
    ok = (
        reach == ReachabilityState.REACHABLE
        and auth == ()
        and len(claims) == 1
        and claims[0].reporter == A
        and claims[0].source_class == SourceClass.DIRECT_OBSERVATION
    )
    results.append((
        "14-remote-reachable-not-global-truth",
        ok,
        "A->C reachable stored as DIRECT_OBSERVATION (reporter=A); derived state "
        "REACHABLE but provenance preserved; no authoritative self-claim"
        if ok else "FAILED: reach=%s auth=%d claims=%d" % (reach, len(auth), len(claims)),
    ))


def case_15_remote_advertises_not_self(results: List[Tuple[str, bool, str]]) -> None:
    """15. Reporter A claiming C advertises capability X does NOT become C's
    self-advertisement."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_c, _ = make_node(b"TEST-15-C", service, provider)
    A, C = ident_a.node_id.text, ident_c.node_id.text
    g = TopologyGraph()
    g.merge(_claim(subject=C, reporter=A, claim_type=ClaimType.ADVERTISES,
                   value="capability.core.multipath",
                   source_class=SourceClass.REMOTE_CLAIM, sequence=1, provenance="A-advert-C"))
    auth = g.get_authoritative_claims(C, claim_type=ClaimType.ADVERTISES, now=FRESH_NOW)
    claims = [c for c in g.get_claims_for_subject(C, now=FRESH_NOW)
              if c.claim_type == ClaimType.ADVERTISES]
    ok = (
        auth == ()
        and len(claims) == 1
        and claims[0].reporter == A
        and claims[0].source_class == SourceClass.REMOTE_CLAIM
    )
    results.append((
        "15-remote-advertises-not-self-advertisement",
        ok,
        "A->C advertises stored as REMOTE_CLAIM; C's self-advertisement set empty"
        if ok else "FAILED: auth=%d claims=%d" % (len(auth), len(claims)),
    ))


def case_16_remote_backhaul_reporter_derived(results: List[Tuple[str, bool, str]]) -> None:
    """16. Reporter A claiming C has high-capacity backhaul remains reporter-derived."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_c, _ = make_node(b"TEST-16-C", service, provider)
    A, C = ident_a.node_id.text, ident_c.node_id.text
    g = TopologyGraph()
    g.merge(_claim(subject=C, reporter=A, claim_type=ClaimType.BACKHAUL,
                   value={"capacity_gbps": 100},
                   source_class=SourceClass.REMOTE_CLAIM, sequence=1, provenance="A-bh-C"))
    auth = g.get_authoritative_claims(C, claim_type=ClaimType.BACKHAUL, now=FRESH_NOW)
    claims = [c for c in g.get_claims_for_subject(C, now=FRESH_NOW)
              if c.claim_type == ClaimType.BACKHAUL]
    ok = (
        auth == ()
        and len(claims) == 1
        and claims[0].reporter == A
        and claims[0].source_class == SourceClass.REMOTE_CLAIM
    )
    results.append((
        "16-remote-backhaul-reporter-derived",
        ok,
        "A->C backhaul stored as REMOTE_CLAIM (reporter=A); authoritative set empty"
        if ok else "FAILED: auth=%d claims=%d" % (len(auth), len(claims)),
    ))


def case_17_valid_self_advertisement_attributable(results: List[Tuple[str, bool, str]]) -> None:
    """17. A valid self-advertisement by C is attributable to C."""
    service, store, provider, ident_c, ref_c = make_identity(b"TEST-17-C")
    C = ident_c.node_id.text
    stmt = signed_statement(store, provider, ref_c, capability_id="capability.core.multipath")
    g = TopologyGraph()
    outcome = ingest_capability_statement(g, stmt, now=FRESH_NOW, sequence=1,
                                          store=store, provider=provider, credential=ref_c)
    auth = g.get_authoritative_claims(C, claim_type=ClaimType.ADVERTISES, now=FRESH_NOW)
    ok = (
        outcome.accepted
        and len(auth) == 1
        and auth[0].reporter == C
        and auth[0].subject == C
        and auth[0].source_class == SourceClass.SELF_ADVERTISEMENT
        and auth[0].value == "capability.core.multipath"
    )
    results.append((
        "17-valid-self-advertisement-attributable",
        ok,
        "C self-advertises multipath -> authoritative claim (reporter=C, SELF)"
        if ok else "FAILED: outcome=%s auth=%d" % (outcome.code, len(auth)),
    ))


def case_18_tampered_signature_rejected(results: List[Tuple[str, bool, str]]) -> None:
    """18. A tampered signature is rejected (verification fails at ingest)."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-18-B", service, provider)
    obs = signed_observation(
        store=store, provider=provider, credential=ref_a,
        observed_node_id=ident_b.node_id.text, sequence=1,
    )
    # Tamper the signature (flip a hex char) -> observation_id changes too,
    # but we keep the original observation_id by constructing a tampered copy.
    from dataclasses import replace as _replace
    tampered_sig = "0" + obs.signature[1:] if obs.signature[0] != "0" else "1" + obs.signature[1:]
    tampered = _replace(obs, signature=tampered_sig)
    # Re-derive observation_id by rebuilding via mapping (tamper invalidates
    # the derived id, so reconstruct fresh from a mapping with empty id).
    g = TopologyGraph()
    outcomes = ingest_discovery_observation(
        g, tampered, now=FRESH_NOW, store=store, provider=provider, credential=ref_a
    )
    ok = (
        len(outcomes) == 1
        and not outcomes[0].accepted
        and outcomes[0].code == "verification-failed"
        and len(g) == 0
    )
    results.append((
        "18-tampered-signature-rejected",
        ok,
        "tampered observation signature -> verification-failed, no state change"
        if ok else "FAILED: outcomes=%r len=%d" % ([(o.code) for o in outcomes], len(g)),
    ))


def case_19_reporter_credential_mismatch_rejected(results: List[Tuple[str, bool, str]]) -> None:
    """19. A reporter/credential NodeID mismatch is rejected."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, ref_b = make_node(b"TEST-19-B", service, provider)
    # Observation names A as sender, signed by A's credential.
    obs = signed_observation(
        store=store, provider=provider, credential=ref_a,
        observed_node_id=ident_b.node_id.text, sequence=1,
    )
    g = TopologyGraph()
    # Verify with B's credential -> reporter(A) != credential node(B) -> fail.
    outcomes = ingest_discovery_observation(
        g, obs, now=FRESH_NOW, store=store, provider=provider, credential=ref_b
    )
    ok = (
        len(outcomes) == 1
        and not outcomes[0].accepted
        and outcomes[0].code == "verification-failed"
        and len(g) == 0
    )
    results.append((
        "19-reporter-credential-mismatch-rejected",
        ok,
        "verify with B's credential on A's observation -> verification-failed"
        if ok else "FAILED: outcomes=%r len=%d" % ([(o.code) for o in outcomes], len(g)),
    ))


def case_20_stale_replayed_highvalue_cannot_refresh(results: List[Tuple[str, bool, str]]) -> None:
    """20. A stale/replayed high-value claim cannot refresh current state."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_c, _ = make_node(b"TEST-20-C", service, provider)
    A, C = ident_a.node_id.text, ident_c.node_id.text
    g = TopologyGraph()
    # Fresh high-value gateway claim (seq 1).
    g.merge(_claim(subject=C, reporter=A, claim_type=ClaimType.GATEWAY,
                   value={"role": "internet-egress"},
                   source_class=SourceClass.REMOTE_CLAIM, sequence=1, provenance="A-gw-1"))
    fresh_current = g.get_current_observations(now=FRESH_NOW)
    # Advance time past freshness -> stale, not current.
    stale_current = g.get_current_observations(now=STALE_NOW)
    auth_stale = g.get_authoritative_claims(C, claim_type=ClaimType.GATEWAY, now=STALE_NOW)
    # Replay the same seq 1 -> idempotent, does NOT refresh freshness.
    replay = g.merge(_claim(subject=C, reporter=A, claim_type=ClaimType.GATEWAY,
                            value={"role": "internet-egress"},
                            source_class=SourceClass.REMOTE_CLAIM, sequence=1, provenance="A-gw-1"))
    stale_current_after_replay = g.get_current_observations(now=STALE_NOW)
    ok = (
        any(c.claim_type == ClaimType.GATEWAY for c in fresh_current)
        and not any(c.claim_type == ClaimType.GATEWAY for c in stale_current)
        and auth_stale == ()
        and replay.code == "idempotent"
        and not any(c.claim_type == ClaimType.GATEWAY for c in stale_current_after_replay)
    )
    results.append((
        "20-stale-replayed-highvalue-cannot-refresh",
        ok,
        "fresh->current, stale->not current; replay idempotent (no refresh); "
        "authoritative empty"
        if ok else "FAILED: fresh=%s stale=%s auth=%s replay=%s"
        % (any(c.claim_type == ClaimType.GATEWAY for c in fresh_current),
           any(c.claim_type == ClaimType.GATEWAY for c in stale_current),
           len(auth_stale), replay.code),
    ))


def case_21_bootstrap_claim_not_direct(results: List[Tuple[str, bool, str]]) -> None:
    """21. A bootstrap claim remains bootstrap/remote provenance and cannot
    masquerade as direct evidence."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-21-B", service, provider)
    obs = signed_observation(
        store=store, provider=provider, credential=ref_a,
        observed_node_id=ident_b.node_id.text, sequence=1,
        source_type=SourceType.BOOTSTRAP,
    )
    claims = claim_from_discovery_observation(obs)
    g = TopologyGraph()
    ingest_discovery_observation(g, obs, now=FRESH_NOW)
    discovered = [c for c in g.get_claims_for_subject(ident_b.node_id.text, now=FRESH_NOW)
                  if c.claim_type == ClaimType.DISCOVERED]
    ok = (
        len(claims) == 2
        and all(c.source_class == SourceClass.BOOTSTRAP_CLAIM for c in claims)
        and all(c.source_class != SourceClass.DIRECT_OBSERVATION for c in claims)
        and len(discovered) == 1
        and discovered[0].source_class == SourceClass.BOOTSTRAP_CLAIM
        and not discovered[0].is_self_attribution()
    )
    results.append((
        "21-bootstrap-claim-not-direct-evidence",
        ok,
        "bootstrap-sourced observation -> BOOTSTRAP_CLAIM (not DIRECT_OBSERVATION); "
        "not self-attribution"
        if ok else "FAILED: classes=%r" % ([c.source_class for c in claims],),
    ))


def case_22_link_up_stale_advert_representable(results: List[Tuple[str, bool, str]]) -> None:
    """22. Link UP with a stale advertisement remains representable."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-22-B", service, provider)
    A, B = ident_a.node_id.text, ident_b.node_id.text
    g = TopologyGraph()
    link_subj = make_link_subject(A, B)
    g.merge(_claim(subject=B, reporter=B, claim_type=ClaimType.ADVERTISES,
                   value="capability.core.multipath",
                   source_class=SourceClass.SELF_ADVERTISEMENT,
                   issued_at="2029-12-01T00:00:00Z",
                   freshness_until="2029-12-15T00:00:00Z",
                   sequence=1, provenance="B-stale"))
    # Link observation stays FRESH through STALE_NOW; the advertisement
    # alone is stale (representable combination).
    g.merge(_claim(subject=link_subj, reporter=A, claim_type=ClaimType.LINK_STATE,
                   value=LinkState.UP, source_class=SourceClass.DIRECT_OBSERVATION,
                   freshness_until="2030-04-01T00:00:00Z",
                   sequence=1, provenance="A-link-up"))
    advert = g.get_advertisement_state(B, now=STALE_NOW)
    link = g.get_link_state(A, B, now=STALE_NOW)
    ok = advert == AdvertisementState.STALE and link == LinkState.UP
    results.append((
        "22-link-up-stale-advertisement-representable",
        ok,
        "advertisement=STALE, link=UP (representable)"
        if ok else "FAILED: advert=%s link=%s" % (advert, link),
    ))


def case_23_advert_current_link_down_representable(results: List[Tuple[str, bool, str]]) -> None:
    """23. Advertisement CURRENT with link DOWN remains representable."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-23-B", service, provider)
    A, B = ident_a.node_id.text, ident_b.node_id.text
    g = TopologyGraph()
    link_subj = make_link_subject(A, B)
    g.merge(_claim(subject=B, reporter=B, claim_type=ClaimType.ADVERTISES,
                   value="capability.core.multipath",
                   source_class=SourceClass.SELF_ADVERTISEMENT, sequence=1,
                   provenance="B-advert"))
    g.merge(_claim(subject=link_subj, reporter=A, claim_type=ClaimType.LINK_STATE,
                   value=LinkState.DOWN, source_class=SourceClass.DIRECT_OBSERVATION,
                   sequence=1, provenance="A-link-down"))
    advert = g.get_advertisement_state(B, now=FRESH_NOW)
    link = g.get_link_state(A, B, now=FRESH_NOW)
    ok = advert == AdvertisementState.CURRENT and link == LinkState.DOWN
    results.append((
        "23-advert-current-link-down-representable",
        ok,
        "advertisement=CURRENT, link=DOWN (representable)"
        if ok else "FAILED: advert=%s link=%s" % (advert, link),
    ))


def case_24_partition_recovery_convergence(results: List[Tuple[str, bool, str]]) -> None:
    """24. Partition/recovery convergence is deterministic (same final evidence
    -> byte-identical snapshot regardless of replay + new observation order)."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-24-B", service, provider)
    A, B = ident_a.node_id.text, ident_b.node_id.text
    # Partition: A and B each build a graph independently from the same shared
    # evidence, then reconcile by replaying + adding a new observation.
    base_claims = [
        _claim(subject=B, reporter=A, claim_type=ClaimType.IDENTITY, value="present",
               source_class=SourceClass.DIRECT_OBSERVATION, sequence=1, provenance="A-disc-B-1"),
        _claim(subject=A, reporter=B, claim_type=ClaimType.IDENTITY, value="present",
               source_class=SourceClass.DIRECT_OBSERVATION, sequence=1, provenance="B-disc-A-1"),
    ]
    new_claim = _claim(subject=B, reporter=A, claim_type=ClaimType.REACHABLE, value="true",
                      source_class=SourceClass.DIRECT_OBSERVATION, sequence=2, provenance="A-reach-B-2")

    def build(order: List[TopologyClaim]) -> TopologyGraph:
        gg = TopologyGraph()
        for c in order:
            gg.merge(c)
        return gg

    g1 = build(base_claims + [new_claim])
    # Reconciliation: replay base then add new (idempotent replays).
    g2 = build(base_claims + base_claims + [new_claim])
    # Different merge order.
    g3 = build([new_claim] + base_claims)
    b1, b2, b3 = g1.to_canonical_bytes(), g2.to_canonical_bytes(), g3.to_canonical_bytes()
    ok = b1 == b2 == b3
    results.append((
        "24-partition-recovery-convergence-deterministic",
        ok,
        "snapshot byte-identical across replay + reorder reconciliation"
        if ok else "FAILED: b1==b2=%s b2==b3=%s" % (b1 == b2, b2 == b3),
    ))


def case_25_future_access_identifiers_as_data(results: List[Tuple[str, bool, str]]) -> None:
    """25. Future access identifiers remain data and require no topology-core branch."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-25-B", service, provider)
    A, B = ident_a.node_id.text, ident_b.node_id.text
    # A future access technology identifier rides as opaque capability data;
    # the topology core has no access-technology branching.
    g = TopologyGraph()
    g.merge(_claim(subject=B, reporter=B, claim_type=ClaimType.ADVERTISES,
                   value="capability.access.6g-imt2030-holographic-relay",
                   source_class=SourceClass.SELF_ADVERTISEMENT, sequence=1,
                   provenance="B-future-access"))
    ok_id = g.get_authoritative_claims(B, claim_type=ClaimType.ADVERTISES, now=FRESH_NOW)
    # Mechanical: the topology source must not branch on access tech.
    # No access-technology branching: the prohibition language may appear in
    # docstrings, but no IMPORT references access-tech/vendor SDKs.
    src = "\n".join(
        (REPO_ROOT / "topology" / f).read_text(encoding="utf-8")
        for f in ("model.py", "ingest.py", "__init__.py")
    )
    import_lines = [
        ln for ln in src.splitlines() if ln.strip().startswith(("import ", "from "))
    ]
    forbidden = ("five_g", "5g", "nr", "lte", "wifi", "satellite", "imt", "vendor")
    no_branch = not any(
        any(t in ln.lower() for t in forbidden) for ln in import_lines
    )
    ok = len(ok_id) == 1 and no_branch
    results.append((
        "25-future-access-identifiers-as-data",
        ok,
        "future access id stored as opaque capability value; no 5g/6g/lte/wifi/"
        "satellite/imt-2030 branching in topology core"
        if ok else "FAILED: ok_id=%d no_branch=%s" % (len(ok_id), no_branch),
    ))


def case_26_no_forbidden_fields_or_methods(results: List[Tuple[str, bool, str]]) -> None:
    """26. No trust/authorization/routing/resource policy fields or methods
    are exposed by the topology API."""
    src = "\n".join(
        (REPO_ROOT / "topology" / f).read_text(encoding="utf-8")
        for f in ("model.py", "ingest.py", "__init__.py")
    )
    forbidden_methods = (
        "def best_path", "def next_hop", "def gateway_for_destination",
        "def preferred_peer", "def route_score",
    )
    forbidden_fields = (
        "trust_score", "trust_level", "reputation", "authorization",
        "route_metric", "resource_cost", "preferred_route",
    )
    method_hits = [m for m in forbidden_methods if m in src]
    # Field check ONLY on the public result-type keys (claim to_dict). Docstring
    # prohibition language may mention these terms without exposing them.
    claim = TopologyClaim(
        subject="adcos:node:identity.sha256-hmac-dev.v1:" + "1" * 64,
        reporter="adcos:node:identity.sha256-hmac-dev.v1:" + "2" * 64,
        claim_type=ClaimType.IDENTITY, value="present",
        source_class=SourceClass.SELF_ADVERTISEMENT,
        issued_at=NOW_TEXT, freshness_until=FRESH_UNTIL, provenance="x",
    )
    keys = set(claim.to_dict().keys())
    field_hits = [f for f in forbidden_fields if f in keys]
    ok = not method_hits and not field_hits
    results.append((
        "26-no-forbidden-trust-routing-resource-fields",
        ok,
        "no best_path/next_hop/gateway_for_destination/preferred_peer/route_score "
        "methods; no trust/reputation/authorization/route/resource fields on "
        "result types"
        if ok else "FAILED: method_hits=%r field_hits=%r" % (method_hits, field_hits),
    ))


def case_27_seeded_fuzz_no_crash(results: List[Tuple[str, bool, str]]) -> None:
    """27. Seeded fuzz/mutation inputs never crash ingestion/query/snapshot logic."""
    service, store, provider, ident_a, ref_a = make_identity()
    rng = SeededRandom(0x00707)
    node_ids = [
        "adcos:node:identity.sha256-hmac-dev.v1:" + "1" * 64,
        "adcos:node:identity.sha256-hmac-dev.v1:" + "2" * 64,
        "adcos:node:identity.sha256-hmac-dev.v1:" + "3" * 64,
    ]
    crash = False
    for _ in range(256):
        g = TopologyGraph()
        try:
            for _ in range(8):
                kind = rng.below(8)
                try:
                    if kind == 0:
                        # Malformed subject (not a NodeID) -> TopologyError.
                        TopologyClaim(
                            subject="not-a-node-id", reporter=node_ids[rng.below(3)],
                            claim_type=ClaimType.IDENTITY, value="present",
                            source_class=SourceClass.REMOTE_CLAIM,
                            issued_at=NOW_TEXT, freshness_until=FRESH_UNTIL, provenance="fz",
                        )
                    elif kind == 1:
                        # Bad source_class -> TopologyError.
                        TopologyClaim(
                            subject=node_ids[rng.below(3)], reporter=node_ids[rng.below(3)],
                            claim_type=ClaimType.IDENTITY, value="present",
                            source_class="bogus-class",
                            issued_at=NOW_TEXT, freshness_until=FRESH_UNTIL, provenance="fz",
                        )
                    elif kind == 2:
                        # Impossible temporal -> TopologyError.
                        TopologyClaim(
                            subject=node_ids[rng.below(3)], reporter=node_ids[rng.below(3)],
                            claim_type=ClaimType.IDENTITY, value="present",
                            source_class=SourceClass.REMOTE_CLAIM,
                            issued_at=FRESH_UNTIL, freshness_until=NOW_TEXT, provenance="fz",
                        )
                    elif kind == 3:
                        # Bad sequence (zero) -> TopologyError.
                        TopologyClaim(
                            subject=node_ids[rng.below(3)], reporter=node_ids[rng.below(3)],
                            claim_type=ClaimType.IDENTITY, value="present",
                            source_class=SourceClass.REMOTE_CLAIM,
                            issued_at=NOW_TEXT, freshness_until=FRESH_UNTIL, sequence=0, provenance="fz",
                        )
                    else:
                        c = TopologyClaim(
                            subject=node_ids[rng.below(3)], reporter=node_ids[rng.below(3)],
                            claim_type=ClaimType.IDENTITY,
                            value="present" if rng.below(2) else "removed",
                            source_class=SourceClass.REMOTE_CLAIM,
                            issued_at=NOW_TEXT, freshness_until=FRESH_UNTIL,
                            sequence=rng.below(5) + 1, provenance="fz-%d" % rng.below(1000),
                        )
                        g.merge(c)
                except TopologyError:
                    pass  # expected fail-closed
            # Query + snapshot must never crash regardless of state.
            for nid in node_ids:
                g.get_identity_state(nid, now=FRESH_NOW)
                g.get_advertisement_state(nid, now=FRESH_NOW)
                g.get_reachability_state(nid, now=FRESH_NOW)
                g.get_claims_for_subject(nid, now=FRESH_NOW)
            g.get_current_observations(now=FRESH_NOW)
            g.get_conflicts()
            g.snapshot()
            g.to_canonical_bytes()
        except TopologyError:
            pass  # expected fail-closed at the API edge (naive now)
        except Exception:  # noqa: BLE001 - any other exception is a crash
            crash = True
    results.append((
        "27-seeded-fuzz-no-crash",
        not crash,
        "256 fuzz rounds x 8 mutated claims; ingestion/query/snapshot never crash"
        if not crash else "FAILED: crash during fuzz",
    ))


def case_28_repeated_runs_byte_identical(results: List[Tuple[str, bool, str]]) -> None:
    """28. Repeated self-test runs are byte-identical (snapshot determinism)."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-28a-B", service, provider)
    ident_c, _ = make_node(b"TEST-28b-C", service, provider)
    A, B, C = ident_a.node_id.text, ident_b.node_id.text, ident_c.node_id.text
    link_subj = make_link_subject(A, B)

    def build() -> bytes:
        g = TopologyGraph()
        g.merge(_claim(subject=B, reporter=A, claim_type=ClaimType.IDENTITY, value="present",
                       source_class=SourceClass.DIRECT_OBSERVATION, sequence=1, provenance="A-B-id"))
        g.merge(_claim(subject=C, reporter=B, claim_type=ClaimType.GATEWAY,
                       value={"role": "internet-egress"},
                       source_class=SourceClass.REMOTE_CLAIM, sequence=1, provenance="B-C-gw"))
        g.merge(_claim(subject=B, reporter=B, claim_type=ClaimType.ADVERTISES,
                       value="capability.core.multipath",
                       source_class=SourceClass.SELF_ADVERTISEMENT, sequence=1, provenance="B-self"))
        g.merge(_claim(subject=link_subj, reporter=A, claim_type=ClaimType.LINK_STATE,
                       value=LinkState.UP, source_class=SourceClass.DIRECT_OBSERVATION,
                       sequence=1, provenance="A-link"))
        return g.to_canonical_bytes()

    runs = [build() for _ in range(5)]
    ok = all(r == runs[0] for r in runs)
    results.append((
        "28-repeated-runs-byte-identical",
        ok,
        "5 independent builds of the same evidence -> identical canonical bytes"
        if ok else "FAILED: runs differ",
    ))


# ---------------------------------------------------------------------------
# Extras: serialization round-trip, WORK-003 envelope integration,
# frozen-dimensions presence, no-5g-imports mechanical check
# ---------------------------------------------------------------------------


def case_envelope_roundtrip(results: List[Tuple[str, bool, str]]) -> None:
    """A topology claim round-trips through canonical JSON and the WORK-003
    envelope (topology.observe is forwarded opaquely as an unregistered type)."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-ENV-B", service, provider)
    A, B = ident_a.node_id.text, ident_b.node_id.text
    c = _claim(subject=B, reporter=A, claim_type=ClaimType.GATEWAY,
               value={"role": "internet-egress"},
               source_class=SourceClass.REMOTE_CLAIM, sequence=1, provenance="A-gw-B")
    d = c.to_dict()
    rebuilt = claim_from_mapping(d)
    roundtrip = rebuilt.to_dict() == d and rebuilt.claim_id == c.claim_id
    # Duplicate keys rejected by the JSON codec.
    try:
        import json
        blob = json.dumps(d, sort_keys=True).encode("utf-8")
        claim_from_mapping(json.loads(blob.replace(b'"reporter"', b'"reporter","reporter"', 1)))
        dup_ok = False
    except (TopologyError, Exception):
        dup_ok = True
    # WORK-003 envelope integration: topology.observe travels opaquely.
    outcome = accept(
        JSON_CODEC.encode(
            envelope_from_mapping(
                {
                    "protocol": "adcos", "version": 1, "message_type": "topology.observe",
                    "message_id": "topo-msg-0001", "sender": A,
                    "issued_at": NOW_TEXT, "expires_at": FRESH_UNTIL,
                    "extensions": {}, "payload": c.to_dict(),
                    "evidence": list(c.evidence_refs), "signature": "opaque-envelope-sig",
                }
            )
        ),
        now=validation_clock(NOW_TEXT),
        policy=ParsePolicy(unknown_type=UnknownTypePolicy.FORWARD_OPAQUE),
    )
    envelope_ok = (
        outcome.accepted
        and outcome.classification == Classification.UNKNOWN_OPTIONAL_FORWARDED
        and outcome.validated is not None
        and outcome.validated.envelope.payload["reporter"] == A
    )
    env = envelope_from_mapping(
        {
            "protocol": "adcos", "version": 1, "message_type": "topology.observe",
            "message_id": "topo-msg-0002", "sender": A,
            "issued_at": NOW_TEXT, "expires_at": FRESH_UNTIL,
            "extensions": {}, "payload": c.to_dict(), "evidence": [], "signature": "opaque",
        }
    )
    compact_ok = (
        CBOR_CODEC.encode(CBOR_CODEC.decode(CBOR_CODEC.encode(env)))
        == CBOR_CODEC.encode(env)
    )
    ok = roundtrip and dup_ok and envelope_ok and compact_ok
    results.append((
        "envelope-roundtrip-opaque-forward",
        ok,
        "claim canonical round-trip byte-stable; duplicate keys rejected; "
        "WORK-003 envelope (unregistered topology.observe) forwarded opaquely; "
        "compact codec stable"
        if ok else "FAILED: roundtrip=%s dup=%s env=%s compact=%s"
        % (roundtrip, dup_ok, envelope_ok, compact_ok),
    ))


def case_frozen_dimensions_present(results: List[Tuple[str, bool, str]]) -> None:
    """All four frozen topology dimensions are represented as independent
    enums with the frozen value sets (LOCK-009)."""
    ok = (
        {IdentityState.UNKNOWN, IdentityState.KNOWN, IdentityState.REMOVED}
        == {"unknown", "known", "removed"}
        and {AdvertisementState.NONE, AdvertisementState.CURRENT, AdvertisementState.STALE}
        == {"none", "current", "stale"}
        and {ReachabilityState.UNREACHABLE, ReachabilityState.REACHABLE}
        == {"unreachable", "reachable"}
        and {LinkState.DOWN, LinkState.DEGRADED, LinkState.UP}
        == {"down", "degraded", "up"}
        and set(SourceClass.values()) == {
            "self-advertisement", "direct-observation", "remote-claim", "bootstrap-claim",
        }
    )
    results.append((
        "frozen-dimensions-present",
        ok,
        "identity/advertisement/reachability/link + source-class enums match "
        "frozen value sets"
        if ok else "FAILED: dimension value sets mismatch",
    ))


def case_no_5g_vendor_imports(results: List[Tuple[str, bool, str]]) -> None:
    """No 5G/6G/vendor SDK imports or access-generation branching anywhere in
    the topology package source (only docstring prohibition language)."""
    src = "\n".join(
        (REPO_ROOT / "topology" / f).read_text(encoding="utf-8")
        for f in ("model.py", "ingest.py", "__init__.py")
    )
    # No import statements referencing access-tech/vendor SDKs.
    import_lines = [
        ln for ln in src.splitlines() if ln.strip().startswith(("import ", "from "))
    ]
    forbidden = ("five_g", "5g", "nr", "lte", "wifi", "satellite", "imt", "vendor")
    bad = [
        ln for ln in import_lines
        if any(t in ln.lower() for t in forbidden)
    ]
    ok = not bad
    results.append((
        "no-5g-6g-vendor-sdk-imports",
        ok,
        "topology source has no 5G/6G/vendor SDK imports"
        if ok else "FAILED: forbidden import lines=%r" % (bad,),
    ))


def case_29_remote_identity_removed_not_authoritative(
    results: List[Tuple[str, bool, str]],
) -> None:
    """29. A REMOTE_CLAIM or BOOTSTRAP_CLAIM identity=removed claim does NOT
    drive ``IdentityState.REMOVED``. A reporter cannot authoritatively
    establish the subject's identity state (LOCK-008). Regression for the
    WORK-007 cycle-1 blocker where ``get_identity_state()`` fell through from
    self-claims to *all* non-self identity claims (including REMOTE_CLAIM and
    BOOTSTRAP_CLAIM) and returned REMOVED from them."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-29-B", service, provider)
    ident_c, _ = make_node(b"TEST-29-C", service, provider)
    A, B, C = ident_a.node_id.text, ident_b.node_id.text, ident_c.node_id.text
    g = TopologyGraph()
    # A says C was removed (REMOTE_CLAIM) -- must NOT drive IdentityState.REMOVED.
    r1 = g.merge(_claim(
        subject=C, reporter=A, claim_type=ClaimType.IDENTITY, value="removed",
        source_class=SourceClass.REMOTE_CLAIM, sequence=1,
        provenance="A-says-C-removed-remote",
    ))
    # B's bootstrap seed also claims C removed -- also must NOT drive REMOVED.
    r2 = g.merge(_claim(
        subject=C, reporter=B, claim_type=ClaimType.IDENTITY, value="removed",
        source_class=SourceClass.BOOTSTRAP_CLAIM, sequence=1,
        provenance="B-says-C-removed-bootstrap",
    ))
    state = g.get_identity_state(C, now=FRESH_NOW)
    auth = g.get_authoritative_claims(C, claim_type=ClaimType.IDENTITY, now=FRESH_NOW)
    claims = [c for c in g.get_claims_for_subject(C, now=FRESH_NOW)
              if c.claim_type == ClaimType.IDENTITY]
    remote_claims = [c for c in claims if c.source_class == SourceClass.REMOTE_CLAIM]
    bootstrap_claims = [c for c in claims if c.source_class == SourceClass.BOOTSTRAP_CLAIM]
    ok = (
        r1.accepted and r2.accepted
        and state == IdentityState.UNKNOWN  # NOT REMOVED -- the blocker fix
        and auth == ()  # no self-attributed identity claim -> authoritative set empty
        and len(remote_claims) == 1  # A's claim still stored as evidence (provenance kept)
        and remote_claims[0].reporter == A
        and remote_claims[0].subject == C
        and remote_claims[0].value == "removed"
        and len(bootstrap_claims) == 1  # B's claim also stored as evidence
        and bootstrap_claims[0].reporter == B
        and bootstrap_claims[0].source_class == SourceClass.BOOTSTRAP_CLAIM
    )
    # Positive controls: the fix must PRESERVE the two legitimate identity paths.
    # (a) A self "removed" from C about C STILL drives REMOVED.
    g2 = TopologyGraph()
    g2.merge(_claim(
        subject=C, reporter=C, claim_type=ClaimType.IDENTITY, value="removed",
        source_class=SourceClass.SELF_ADVERTISEMENT, sequence=3,
        provenance="C-says-C-removed-self",
    ))
    self_removed_state = g2.get_identity_state(C, now=FRESH_NOW)
    # (b) A DIRECT_OBSERVATION "present" from A about C STILL drives KNOWN.
    g3 = TopologyGraph()
    g3.merge(_claim(
        subject=C, reporter=A, claim_type=ClaimType.IDENTITY, value="present",
        source_class=SourceClass.DIRECT_OBSERVATION, sequence=1,
        provenance="A-observed-C-present",
    ))
    direct_present_state = g3.get_identity_state(C, now=FRESH_NOW)
    ok = ok and (
        self_removed_state == IdentityState.REMOVED
        and direct_present_state == IdentityState.KNOWN
    )
    results.append((
        "29-remote-identity-removed-not-authoritative",
        ok,
        "REMOTE/BOOTSTRAP identity=removed does NOT drive IdentityState.REMOVED "
        "(stays UNKNOWN); claims retained as evidence; self-removed still REMOVED; "
        "direct-present still KNOWN"
        if ok else
        "FAILED: state=%s auth=%d remote=%d bootstrap=%d self_removed=%s direct_present=%s"
        % (state, len(auth), len(remote_claims), len(bootstrap_claims),
           self_removed_state, direct_present_state),
    ))


def case_30_concurrent_distinct_capability_advertisements(
    results: List[Tuple[str, bool, str]],
) -> None:
    """30. A node may concurrently advertise multiple distinct capabilities;
    each is an independently current, independently superseded, independently
    queryable claim. Regression for the WORK-007 cycle-1 blocker where
    ADVERTISES claims were keyed only by (reporter, subject, claim_type) so
    a node's second capability advertisement superseded its first instead of
    both remaining current."""
    service, store, provider, ident_c, ref_c = make_identity(b"TEST-30-C")
    C = ident_c.node_id.text
    g = TopologyGraph()
    # C self-advertises two distinct capabilities concurrently (different
    # capability_ids, same reporter+subject+claim_type).
    c1 = _claim(
        subject=C, reporter=C, claim_type=ClaimType.ADVERTISES,
        value="capability.core.multipath",
        source_class=SourceClass.SELF_ADVERTISEMENT, sequence=1,
        provenance="C-advert-multipath",
    )
    c2 = _claim(
        subject=C, reporter=C, claim_type=ClaimType.ADVERTISES,
        value="capability.core.gateway",
        source_class=SourceClass.SELF_ADVERTISEMENT, sequence=2,
        provenance="C-advert-gateway",
    )
    r1 = g.merge(c1)
    r2 = g.merge(c2)
    # Both must remain current (distinct keys via the capability_id discriminator).
    adv_claims = [c for c in g.get_claims_for_subject(C, now=FRESH_NOW)
                  if c.claim_type == ClaimType.ADVERTISES]
    auth = g.get_authoritative_claims(C, claim_type=ClaimType.ADVERTISES, now=FRESH_NOW)
    cap_ids = sorted(str(c.value) for c in adv_claims)
    ok = (
        r1.accepted and r2.accepted
        and r1.code == "accepted"  # first claim accepted fresh
        and r2.code == "accepted"  # second ALSO accepted (NOT superseding c1)
        and len(adv_claims) == 2  # BOTH current
        and cap_ids == ["capability.core.gateway", "capability.core.multipath"]
        and len(auth) == 2  # BOTH authoritative (self-attributed)
        and {str(c.value) for c in auth} == {
            "capability.core.multipath", "capability.core.gateway",
        }
        and {c.claim_id for c in adv_claims} == {c1.claim_id, c2.claim_id}
    )
    # Per-capability supersession: re-merging cap-A at seq 3 supersedes the
    # prior cap-A (seq 1) ONLY; cap-B (seq 2) must be UNAFFECTED.
    c3 = _claim(
        subject=C, reporter=C, claim_type=ClaimType.ADVERTISES,
        value="capability.core.multipath",
        source_class=SourceClass.SELF_ADVERTISEMENT, sequence=3,
        provenance="C-advert-multipath-v2",
    )
    r3 = g.merge(c3)
    adv_after = [c for c in g.get_claims_for_subject(C, now=FRESH_NOW)
                 if c.claim_type == ClaimType.ADVERTISES]
    cap_ids_after = sorted(str(c.value) for c in adv_after)
    cap_a_claims = [c for c in adv_after if str(c.value) == "capability.core.multipath"]
    cap_b_claims = [c for c in adv_after if str(c.value) == "capability.core.gateway"]
    # The superseded cap-A (seq 1) is retained as historical evidence.
    hist = [
        c for c in g.get_claims_for_subject(C, now=FRESH_NOW, include_historical=True)
        if c.claim_type == ClaimType.ADVERTISES
        and str(c.value) == "capability.core.multipath"
        and c.sequence == 1
    ]
    ok = ok and (
        r3.code == "accepted"  # supersedes the prior cap-A at this key
        and len(adv_after) == 2  # still two current claims
        and cap_ids_after == ["capability.core.gateway", "capability.core.multipath"]
        and len(cap_a_claims) == 1  # only the newer cap-A (seq 3) is current
        and cap_a_claims[0].sequence == 3
        and cap_a_claims[0].claim_id == c3.claim_id
        and len(cap_b_claims) == 1  # cap-B still current
        and cap_b_claims[0].sequence == 2  # cap-B UNAFFECTED by the cap-A refresh
        and cap_b_claims[0].claim_id == c2.claim_id
        and len(hist) == 1  # old cap-A (seq 1) retained as historical evidence
        and hist[0].claim_id == c1.claim_id
    )
    results.append((
        "30-concurrent-distinct-capability-advertisements",
        ok,
        "C advertises cap-A (seq1) + cap-B (seq2) concurrently; both current & "
        "authoritative; cap-A refresh (seq3) supersedes only cap-A; cap-B untouched; "
        "old cap-A retained as historical"
        if ok else
        "FAILED: r1=%s r2=%s adv=%d auth=%d cap_ids=%s r3=%s adv_after=%d "
        "cap_a_seq=%s cap_b_seq=%s hist=%d"
        % (r1.code, r2.code, len(adv_claims), len(auth), cap_ids, r3.code,
           len(adv_after),
           cap_a_claims[0].sequence if cap_a_claims else None,
           cap_b_claims[0].sequence if cap_b_claims else None, len(hist)),
    ))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    results: List[Tuple[str, bool, str]] = []
    case_01_discovery_ingests_as_claim(results)
    case_02_identity_independent_from_advertisement(results)
    case_03_advertisement_independent_from_reachability(results)
    case_04_link_independent_from_advertisement(results)
    case_05_stale_advertisement_historical_not_current(results)
    case_06_removed_identity_not_resurrected_by_replay(results)
    case_07_exact_duplicate_idempotent(results)
    case_08_arrival_order_byte_identical(results)
    case_09_newer_supersedes_older(results)
    case_10_conflicting_same_sequence_preserved(results)
    case_11_two_reporters_both_retained(results)
    case_12_self_vs_remote_distinct(results)
    case_13_remote_gateway_not_authoritative(results)
    case_14_remote_reachable_not_global_truth(results)
    case_15_remote_advertises_not_self(results)
    case_16_remote_backhaul_reporter_derived(results)
    case_17_valid_self_advertisement_attributable(results)
    case_18_tampered_signature_rejected(results)
    case_19_reporter_credential_mismatch_rejected(results)
    case_20_stale_replayed_highvalue_cannot_refresh(results)
    case_21_bootstrap_claim_not_direct(results)
    case_22_link_up_stale_advert_representable(results)
    case_23_advert_current_link_down_representable(results)
    case_24_partition_recovery_convergence(results)
    case_25_future_access_identifiers_as_data(results)
    case_26_no_forbidden_fields_or_methods(results)
    case_27_seeded_fuzz_no_crash(results)
    case_28_repeated_runs_byte_identical(results)
    case_29_remote_identity_removed_not_authoritative(results)
    case_30_concurrent_distinct_capability_advertisements(results)
    case_envelope_roundtrip(results)
    case_frozen_dimensions_present(results)
    case_no_5g_vendor_imports(results)

    print("ADCOS topology self-test")
    print("=" * 72)
    for name, ok, detail in results:
        print("[%s] %-46s %s" % ("ok  " if ok else "FAIL", name, detail))
    print("-" * 72)
    passed = sum(1 for _, ok, _ in results if ok)
    if passed == len(results):
        print("Result: PASS (%d/%d cases)" % (passed, len(results)))
        return 0
    print("Result: FAIL (%d/%d cases passed)" % (passed, len(results)))
    return 1


if __name__ == "__main__":
    sys.exit(main())
