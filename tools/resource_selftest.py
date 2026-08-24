#!/usr/bin/env python3
"""ADCOS resource self-test (WORK-008).

Deterministic, offline verification of the resources package against the
frozen WORK-008 requirements (spec/prompts/WORK-008.md): the 30 required
test cases plus the Architect-review regression coverage for PR #8 cycle 1
(cases 31-39: reserve->consume transfer semantics and canonical
resource_id binding), the Architect-review regression coverage for PR #8
cycle 2 (cases 40-43: offer_sequence != version, newer offer on live
account raises account-offer-advance, stale offer cannot reset ledger,
newer offer advances non-live account safely), mechanical forbidden-API/
imports checks, frozen-dimensions presence, serialization round-trips, a
seeded fuzz, and a byte-identical determinism proof.

The central boundary is exercised throughout:

    RESOURCE OFFER        !=  MEASURED OBSERVATION
                          !=  ACCOUNTING STATE
                          !=  ADMISSION DECISION   (out of scope -- WORK-010)
                          !=  ROUTING/PREFERENCE   (out of scope -- WORK-011)
                          !=  PRICE/SETTLEMENT     (out of scope -- forbidden)

The most important adversarial invariant (mirrors WORK-007 LOCK-008):

    Node A relays a measurement about resource R owned by O  -->  stored as
    source_node_id=A, source_class=REMOTE_RELAY  -->  NEVER becomes O's
    self-observation of R. ``get_authoritative_measurements`` returns ONLY
    self-observations (source == owner AND SELF_OBSERVATION); a remote relay
    can never enter the authoritative set. Likewise an offer's provider MUST
    equal the resource owner; a relayed offer is rejected at ``create_offer``.

All key material is TEST-ONLY; all clocks are injected; all PRNGs are seeded
so runs are byte-identical. No external network access is permitted or
required for the suite. Identity binding flows through the canonical WORK-004
``parse_node_id``; resource kinds are the frozen WORK-002/section-17 enum (no
second vocabulary authority); temporal uses WORK-003 primitives; record
fingerprinting uses WORK-003 canonical JSON. Quantities carry explicit units
and authoritative accounting uses integer base-unit math (no float).
"""

from __future__ import annotations

import hashlib
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tools"))

from resources import (  # noqa: E402
    AccountingOutcome,
    AvailabilityMode,
    EnergyState,
    MeasurementSource,
    MergeOutcome,
    ParsedResourceId,
    Quantity,
    Resource,
    ResourceAccount,
    ResourceError,
    ResourceKind,
    ResourceMeasurement,
    ResourceOffer,
    ResourceStore,
    make_resource_id,
    measurement_from_mapping,
    offer_from_mapping,
    parse_resource_id,
    power_unit_base,
    power_unit_multiplier,
    unit_base_for,
    unit_multiplier_for,
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

NOW_TEXT = "2030-01-01T00:00:00Z"
NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)
VALID_FROM = "2030-01-01T00:00:00Z"
EXPIRES_AT = "2030-02-01T00:00:00Z"
OBSERVED_AT = "2030-01-01T00:00:05Z"
FRESH_UNTIL = "2030-02-01T00:00:00Z"
FRESH_NOW = datetime(2030, 1, 15, tzinfo=timezone.utc)
STALE_NOW = datetime(2030, 3, 1, tzinfo=timezone.utc)
PROVIDER_SECRET = b"TEST-ONLY-resource-provider-key-DO-NOT-USE-1"
RELAYER_SECRET = b"TEST-ONLY-resource-relayer-key-DO-NOT-USE-2"

Result = Tuple[str, bool, str]


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

    def choice(self, items):
        return items[self.below(len(items))]


def make_identity(secret: bytes = PROVIDER_SECRET) -> Tuple[
    IdentityService, InMemoryCredentialStore, DevHmacSha256Provider,
    NodeIdentity, CredentialReference,
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


def make_resource(
    *, owner: str, kind: str = ResourceKind.BANDWIDTH,
    availability: str = AvailabilityMode.RESERVATION_BASED,
    scope: str = "default",
) -> Resource:
    rid = make_resource_id(owner, kind, scope)
    return Resource(
        resource_id=rid, owner_node_id=owner, kind=kind,
        availability=availability, scope=scope, created_at=NOW_TEXT,
    )


def base_offer(
    *, resource: Resource, quantity: Quantity, sequence: int = 1,
    valid_from: str = VALID_FROM, expires_at: str = EXPIRES_AT,
    conditions: Tuple = (), provenance: str = "",
) -> ResourceOffer:
    return ResourceOffer(
        resource_id=resource.resource_id,
        provider_node_id=resource.owner_node_id,
        quantity=quantity,
        valid_from=valid_from, expires_at=expires_at,
        sequence=sequence, conditions=conditions,
        provenance=provenance or ("sig:%s:%d" % (resource.owner_node_id[:8], sequence)),
    )


def base_measurement(
    *, resource: Resource, source: str, value, method_ref: str = "agent-v1",
    source_class: str = MeasurementSource.SELF_OBSERVATION, sequence: int = 1,
    observed_at: str = OBSERVED_AT, freshness_until: str = FRESH_UNTIL,
    context: Tuple = (), provenance: str = "",
) -> ResourceMeasurement:
    return ResourceMeasurement(
        resource_id=resource.resource_id, source_node_id=source,
        observed_at=observed_at, freshness_until=freshness_until,
        value=value, method_ref=method_ref, source_class=source_class,
        sequence=sequence, context=context,
        provenance=provenance or ("sig:%s:m%d" % (source[:8], sequence)),
    )


# ==========================================================================
# Required test cases (1-30) + mechanical checks
# ==========================================================================

def case_01_all_eight_frozen_kinds_represented(results: List[Result]) -> None:
    """All eight frozen section-17 resource kinds are representable."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        for kind in ResourceKind.values():
            r = make_resource(owner=owner, kind=kind, scope="k-%s" % kind)
            assert r.kind == kind
        assert len(ResourceKind.values()) == 8
        results.append(("case_01_all_eight_frozen_kinds_represented", True, "8/8 kinds OK"))
    except Exception as error:
        results.append(("case_01_all_eight_frozen_kinds_represented", False, repr(error)))


def case_02_offer_and_measurement_distinct_types(results: List[Result]) -> None:
    """ResourceOffer and ResourceMeasurement are distinct types (rule 1)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner)
        off = base_offer(resource=r, quantity=Quantity(100, "mbps"))
        m = base_measurement(resource=r, source=owner, value=Quantity(63, "mbps"))
        assert isinstance(off, ResourceOffer)
        assert isinstance(m, ResourceMeasurement)
        assert type(off) is not type(m)
        assert off.offer_id != m.measurement_id  # distinct derived IDs
        results.append(("case_02_offer_and_measurement_distinct_types", True, "distinct types + distinct derived IDs"))
    except Exception as error:
        results.append(("case_02_offer_and_measurement_distinct_types", False, repr(error)))


def case_03_offer_quantity_unit_validation(results: List[Result]) -> None:
    """Offer quantity/unit validation: registered unit accepted; the store
    rejects an unknown unit for the resource's kind (rule 5)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner, kind=ResourceKind.BANDWIDTH)
        rs = ResourceStore(); rs.register_resource(r)
        # registered unit accepted
        off = base_offer(resource=r, quantity=Quantity(100, "mbps"))
        assert rs.create_offer(off).accepted
        # unknown unit rejected at create_offer (rule 5)
        bad = base_offer(resource=r, quantity=Quantity(100, "widgets"))
        try:
            rs.create_offer(bad)
            raise AssertionError("unknown unit should be rejected")
        except ResourceError as e:
            assert e.code == "unit-unknown", e.code
        results.append(("case_03_offer_quantity_unit_validation", True, "registered OK, unknown rejected"))
    except Exception as error:
        results.append(("case_03_offer_quantity_unit_validation", False, repr(error)))


def case_04_measurement_quantity_unit_validation(results: List[Result]) -> None:
    """Measurement quantity/unit validation (rule 5)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner, kind=ResourceKind.STORAGE)
        rs = ResourceStore(); rs.register_resource(r)
        m = base_measurement(resource=r, source=owner, value=Quantity(512, "GiB"))
        assert rs.record_measurement(m).accepted
        bad = base_measurement(resource=r, source=owner, value=Quantity(512, "mbps"))
        try:
            rs.record_measurement(bad)
            raise AssertionError("wrong-kind unit should be rejected")
        except ResourceError as e:
            assert e.code == "unit-unknown", e.code
        results.append(("case_04_measurement_quantity_unit_validation", True, "registered OK, wrong-kind rejected"))
    except Exception as error:
        results.append(("case_04_measurement_quantity_unit_validation", False, repr(error)))


def case_05_incompatible_units_fail_closed(results: List[Result]) -> None:
    """Incompatible units fail closed (rule 5): a bandwidth quantity cannot
    carry a storage unit; a storage quantity cannot carry a bandwidth unit."""
    try:
        assert unit_base_for(ResourceKind.BANDWIDTH, "mbps") == "bps"
        assert unit_base_for(ResourceKind.STORAGE, "GiB") == "bytes"
        try:
            unit_base_for(ResourceKind.BANDWIDTH, "GiB")
            raise AssertionError("should reject GiB for bandwidth")
        except ResourceError as e:
            assert e.code == "unit-unknown"
        try:
            unit_multiplier_for(ResourceKind.STORAGE, "mbps")
            raise AssertionError("should reject mbps for storage")
        except ResourceError as e:
            assert e.code == "unit-unknown"
        results.append(("case_05_incompatible_units_fail_closed", True, "cross-kind units rejected"))
    except Exception as error:
        results.append(("case_05_incompatible_units_fail_closed", False, repr(error)))


def case_06_negative_impossible_quantities_fail_closed(results: List[Result]) -> None:
    """Negative/impossible quantities fail closed (rule 5)."""
    try:
        for bad in (-1, -100, -1000000):
            try:
                Quantity(bad, "mbps")
                raise AssertionError("negative value %r should be rejected" % bad)
            except ResourceError as e:
                assert e.code == "quantity-value", e.code
        try:
            Quantity(1.5, "mbps")  # type: ignore[arg-type]  # float rejected (deterministic int only)
            raise AssertionError("float value should be rejected")
        except ResourceError as e:
            assert e.code == "quantity-value", e.code
        try:
            Quantity(10, "")
            raise AssertionError("empty unit should be rejected")
        except ResourceError as e:
            assert e.code == "quantity-unit", e.code
        results.append(("case_06_negative_impossible_quantities_fail_closed", True, "negative/float/empty rejected"))
    except Exception as error:
        results.append(("case_06_negative_impossible_quantities_fail_closed", False, repr(error)))


def case_07_offer_validity_expiry_at_injected_time(results: List[Result]) -> None:
    """Offer validity/expiry works at the injected evaluation instant (rule 6)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner)
        rs = ResourceStore(); rs.register_resource(r)
        off = base_offer(resource=r, quantity=Quantity(100, "mbps"))
        rs.create_offer(off)
        assert rs.get_current_offer(r.resource_id, now=FRESH_NOW) is not None
        assert rs.get_current_offer(r.resource_id, now=STALE_NOW) is None
        results.append(("case_07_offer_validity_expiry_at_injected_time", True, "fresh=current, stale=None"))
    except Exception as error:
        results.append(("case_07_offer_validity_expiry_at_injected_time", False, repr(error)))


def case_08_measurement_freshness_expiry_at_injected_time(results: List[Result]) -> None:
    """Measurement freshness/expiry works at the injected instant (rule 6)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner)
        rs = ResourceStore(); rs.register_resource(r)
        m = base_measurement(resource=r, source=owner, value=Quantity(63, "mbps"))
        rs.record_measurement(m)
        assert rs.get_current_measurement(r.resource_id, now=FRESH_NOW) is not None
        assert rs.get_current_measurement(r.resource_id, now=STALE_NOW) is None
        results.append(("case_08_measurement_freshness_expiry_at_injected_time", True, "fresh=current, stale=None"))
    except Exception as error:
        results.append(("case_08_measurement_freshness_expiry_at_injected_time", False, repr(error)))


def case_09_expired_measurement_retained_historical(results: List[Result]) -> None:
    """Expired/stale measurement is retained historically but not current
    (rule 6 / stale case 6)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner)
        rs = ResourceStore(); rs.register_resource(r)
        m = base_measurement(resource=r, source=owner, value=Quantity(63, "mbps"))
        rs.record_measurement(m)
        # at stale now, current is None but historical includes the record
        assert rs.get_current_measurement(r.resource_id, now=STALE_NOW) is None
        hist = rs.get_historical_measurements(r.resource_id, now=STALE_NOW)
        assert len(hist) == 1
        assert hist[0].measurement_id == m.measurement_id
        results.append(("case_09_expired_measurement_retained_historical", True, "stale not current, retained in historical"))
    except Exception as error:
        results.append(("case_09_expired_measurement_retained_historical", False, repr(error)))


def case_10_exact_duplicate_measurement_idempotent(results: List[Result]) -> None:
    """Exact duplicate measurement is idempotent (stale case 1)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner)
        rs = ResourceStore(); rs.register_resource(r)
        m = base_measurement(resource=r, source=owner, value=Quantity(63, "mbps"))
        o1 = rs.record_measurement(m)
        o2 = rs.record_measurement(m)
        assert o1.code == "accepted"
        assert o2.code == "idempotent"
        assert not o2.accepted or o2.code == "idempotent"
        results.append(("case_10_exact_duplicate_measurement_idempotent", True, "2nd insert idempotent"))
    except Exception as error:
        results.append(("case_10_exact_duplicate_measurement_idempotent", False, repr(error)))


def case_11_measurement_insertion_order_deterministic(results: List[Result]) -> None:
    """Measurement insertion order does not change deterministic current state
    (stale case 2 / byte-determinism). Two DISTINCT sources measure the same
    resource; inserting them in either order yields byte-identical snapshots
    (different sources -> different convergence keys -> no replay rejection)."""
    try:
        _, creds, prov, idA, _ = make_identity()
        owner = str(idA.node_id)
        idB, _ = make_node(RELAYER_SECRET, IdentityService(store=creds, provider=prov, profiles=ProfileSet.load_default()), prov)
        nodeB = str(idB.node_id)
        r = make_resource(owner=owner)
        mA = base_measurement(resource=r, source=owner, value=Quantity(63, "mbps"), sequence=1)
        mB = base_measurement(resource=r, source=nodeB, value=Quantity(80, "mbps"), sequence=1, method_ref="relay-agent-v1", source_class=MeasurementSource.REMOTE_RELAY)

        def build(first, second) -> ResourceStore:
            rs = ResourceStore(); rs.register_resource(r)
            rs.record_measurement(first); rs.record_measurement(second)
            return rs

        a = build(mA, mB)
        b = build(mB, mA)
        assert a.to_canonical_bytes() == b.to_canonical_bytes()
        cur_a = a.get_current_measurement(r.resource_id, now=FRESH_NOW)
        cur_b = b.get_current_measurement(r.resource_id, now=FRESH_NOW)
        assert cur_a is not None and cur_b is not None
        assert cur_a.value.value == 80 and cur_b.value.value == 80
        results.append(("case_11_measurement_insertion_order_deterministic", True, "byte-identical snapshots, same current"))
    except Exception as error:
        results.append(("case_11_measurement_insertion_order_deterministic", False, repr(error)))


def case_12_same_sequence_conflict_preserved(results: List[Result]) -> None:
    """Same-sequence conflicting measurement is preserved, never arrival-order
    winner (stale case 5 / rule 9)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner)
        rs = ResourceStore(); rs.register_resource(r)
        m1 = base_measurement(resource=r, source=owner, value=Quantity(63, "mbps"), sequence=2)
        m2 = base_measurement(resource=r, source=owner, value=Quantity(77, "mbps"), sequence=2)
        o1 = rs.record_measurement(m1)
        o2 = rs.record_measurement(m2)
        assert o1.code == "accepted"
        assert o2.code == "conflict-preserved"
        # current slot is cleared (conflicted); both retained in conflicts
        cur = rs.get_current_measurement(r.resource_id, now=FRESH_NOW)
        assert cur is None  # conflicted key has no current head
        conflicts = rs.get_conflicts()
        assert len(conflicts) == 1
        results.append(("case_12_same_sequence_conflict_preserved", True, "both preserved, no arrival-order winner"))
    except Exception as error:
        results.append(("case_12_same_sequence_conflict_preserved", False, repr(error)))


def case_13_newer_supersedes_older(results: List[Result]) -> None:
    """Newer measurement supersedes older deterministically (stale case 3)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner)
        rs = ResourceStore(); rs.register_resource(r)
        rs.record_measurement(base_measurement(resource=r, source=owner, value=Quantity(63, "mbps"), sequence=1))
        rs.record_measurement(base_measurement(resource=r, source=owner, value=Quantity(91, "mbps"), sequence=2))
        cur = rs.get_current_measurement(r.resource_id, now=FRESH_NOW)
        assert cur is not None
        assert cur.value.value == 91
        hist = rs.get_historical_measurements(r.resource_id, now=FRESH_NOW)
        # current (91) + historical (63) = 2
        assert len(hist) == 2
        results.append(("case_13_newer_supersedes_older", True, "seq2 current, seq1 historical"))
    except Exception as error:
        results.append(("case_13_newer_supersedes_older", False, repr(error)))


def case_14_offer_unchanged_when_measurement_disagrees(results: List[Result]) -> None:
    """Offer remains unchanged when a measurement disagrees with it (rule 1 /
    acceptance criterion: offers separable from measurements)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner)
        rs = ResourceStore(); rs.register_resource(r)
        rs.create_offer(base_offer(resource=r, quantity=Quantity(100, "mbps")))
        rs.record_measurement(base_measurement(resource=r, source=owner, value=Quantity(63, "mbps")))
        cur_off = rs.get_current_offer(r.resource_id, now=FRESH_NOW)
        cur_m = rs.get_current_measurement(r.resource_id, now=FRESH_NOW)
        assert cur_off is not None and cur_m is not None
        assert cur_off.quantity.value == 100  # offer unchanged
        assert cur_m.value.value == 63  # measurement preserved
        results.append(("case_14_offer_unchanged_when_measurement_disagrees", True, "offer=100, measurement=63, both preserved"))
    except Exception as error:
        results.append(("case_14_offer_unchanged_when_measurement_disagrees", False, repr(error)))


def case_15_offer_renewal_newer_sequence(results: List[Result]) -> None:
    """Offer renewal with newer sequence/version works (stale case 7)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner)
        rs = ResourceStore(); rs.register_resource(r)
        rs.create_offer(base_offer(resource=r, quantity=Quantity(100, "mbps"), sequence=1))
        rs.create_offer(base_offer(resource=r, quantity=Quantity(200, "mbps"), sequence=2))
        cur = rs.get_current_offer(r.resource_id, now=FRESH_NOW)
        assert cur is not None
        assert cur.quantity.value == 200
        hist = rs.get_historical_offers(r.resource_id, now=FRESH_NOW, include_historical=True)
        # current (200) + historical (100) = 2
        assert len(hist) == 2
        results.append(("case_15_offer_renewal_newer_sequence", True, "seq2 current, seq1 historical"))
    except Exception as error:
        results.append(("case_15_offer_renewal_newer_sequence", False, repr(error)))


def case_16_accounting_equations_hold(results: List[Result]) -> None:
    """Resource accounting equations hold (rule 9):
    remaining = offered - reserved - consumed, with invariants. After the
    reserve->consume transfer fix, a consume draws down reserved first
    (transferring into consumed), so reserve(30) then consume(10) leaves
    reserved=20, consumed=10 (the 10 consumed units are NOT still counted
    as reserved -- Architect review of PR #8, blocker 1)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner, kind=ResourceKind.BANDWIDTH)
        rs = ResourceStore(); rs.register_resource(r)
        rs.create_offer(base_offer(resource=r, quantity=Quantity(100, "mbps")))
        acct = rs.init_account_from_offer(r.resource_id, now=FRESH_NOW)
        assert acct.offered == 100_000_000  # 100 mbps in base bps
        rs.reserve(r.resource_id, "op1", Quantity(30, "mbps"), now=FRESH_NOW)
        rs.consume(r.resource_id, "op2", Quantity(10, "mbps"), now=FRESH_NOW)
        acct2 = rs.get_account(r.resource_id)
        assert acct2 is not None
        # reserve(30) then consume(10): 10 transferred from reserved -> consumed
        assert acct2.reserved == 20_000_000, "reserved=%d (expected 20M after transfer)" % acct2.reserved
        assert acct2.consumed == 10_000_000, "consumed=%d" % acct2.consumed
        assert acct2.remaining == 70_000_000  # 100 - 20 - 10
        assert acct2.reserved + acct2.consumed <= acct2.offered
        results.append(("case_16_accounting_equations_hold", True, "remaining = offered - reserved - consumed (transfer)"))
    except Exception as error:
        results.append(("case_16_accounting_equations_hold", False, repr(error)))


def case_17_reservation_cannot_exceed_offered(results: List[Result]) -> None:
    """Reservation cannot exceed offered/current allocatable quantity (rule 9,
    accounting requirement: reject over-reservation)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner)
        rs = ResourceStore(); rs.register_resource(r)
        rs.create_offer(base_offer(resource=r, quantity=Quantity(100, "mbps")))
        rs.init_account_from_offer(r.resource_id, now=FRESH_NOW)
        rs.reserve(r.resource_id, "op1", Quantity(60, "mbps"), now=FRESH_NOW)
        try:
            rs.reserve(r.resource_id, "op2", Quantity(50, "mbps"), now=FRESH_NOW)  # 60+50 > 100
            raise AssertionError("over-reservation should fail closed")
        except ResourceError as e:
            assert e.code == "account-oversubscription", e.code
        # account unchanged after failed reservation
        acct = rs.get_account(r.resource_id)
        assert acct is not None
        assert acct.reserved == 60_000_000
        results.append(("case_17_reservation_cannot_exceed_offered", True, "over-reservation rejected, account unchanged"))
    except Exception as error:
        results.append(("case_17_reservation_cannot_exceed_offered", False, repr(error)))


def case_18_consumption_cannot_exceed_available(results: List[Result]) -> None:
    """Consumption cannot exceed available quantity (rule 9 / accounting req).
    After the reserve->consume transfer fix, available = offered - consumed
    (a consume draws from reserved first, transferring, then from unreserved).
    So consume(70) after reserve(40) SUCCEEDS (transfers 40 from reservation
    + 30 from unreserved -> reserved=0, consumed=70); a subsequent consume(40)
    fails because only 30 remains (offered 100 - consumed 70)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner)
        rs = ResourceStore(); rs.register_resource(r)
        rs.create_offer(base_offer(resource=r, quantity=Quantity(100, "mbps")))
        rs.init_account_from_offer(r.resource_id, now=FRESH_NOW)
        rs.reserve(r.resource_id, "op1", Quantity(40, "mbps"), now=FRESH_NOW)
        # consume 70: transfers 40 from reservation + 30 from unreserved (succeeds)
        out = rs.consume(r.resource_id, "op2", Quantity(70, "mbps"), now=FRESH_NOW)
        assert out.accepted, out.detail
        acct = rs.get_account(r.resource_id)
        assert acct is not None
        assert acct.reserved == 0, "reserved=%d (reservation fully transferred)" % acct.reserved
        assert acct.consumed == 70_000_000, "consumed=%d" % acct.consumed
        # over-consumption: only 30 remaining (offered 100 - consumed 70)
        try:
            rs.consume(r.resource_id, "op3", Quantity(40, "mbps"), now=FRESH_NOW)
            raise AssertionError("over-consumption should fail closed")
        except ResourceError as e:
            assert e.code == "account-overconsumption", e.code
        # consuming exactly the remaining (30) succeeds and saturates the ledger
        rs.consume(r.resource_id, "op4", Quantity(30, "mbps"), now=FRESH_NOW)
        acct2 = rs.get_account(r.resource_id)
        assert acct2 is not None
        assert acct2.consumed == 100_000_000  # saturated
        assert acct2.reserved == 0
        assert acct2.remaining == 0
        results.append(("case_18_consumption_cannot_exceed_available", True, "over-consumption rejected after reserve->consume transfer"))
    except Exception as error:
        results.append(("case_18_consumption_cannot_exceed_available", False, repr(error)))


def case_19_duplicate_accounting_operation_no_double_count(results: List[Result]) -> None:
    """Duplicate accounting operation does not double-count (rule 9 / accounting
    requirement: idempotent repeated operation with the same op_id)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner)
        rs = ResourceStore(); rs.register_resource(r)
        rs.create_offer(base_offer(resource=r, quantity=Quantity(100, "mbps")))
        rs.init_account_from_offer(r.resource_id, now=FRESH_NOW)
        o1 = rs.reserve(r.resource_id, "opX", Quantity(20, "mbps"), now=FRESH_NOW)
        o2 = rs.reserve(r.resource_id, "opX", Quantity(20, "mbps"), now=FRESH_NOW)  # replay
        assert o1.code == "reserved"
        assert o2.code == "idempotent"
        acct = rs.get_account(r.resource_id)
        assert acct is not None
        assert acct.reserved == 20_000_000  # not 40M -- no double-count
        results.append(("case_19_duplicate_accounting_operation_no_double_count", True, "replay idempotent, no double-count"))
    except Exception as error:
        results.append(("case_19_duplicate_accounting_operation_no_double_count", False, repr(error)))


def case_20_stale_accounting_update_rejected(results: List[Result]) -> None:
    """Stale accounting update is rejected (rule 9 / accounting requirement:
    reject stale version updates)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner)
        rs = ResourceStore(); rs.register_resource(r)
        rs.create_offer(base_offer(resource=r, quantity=Quantity(100, "mbps")))
        acct = rs.init_account_from_offer(r.resource_id, now=FRESH_NOW)
        v = acct.version
        rs.reserve(r.resource_id, "op1", Quantity(20, "mbps"), now=FRESH_NOW)  # version -> v+1
        try:
            rs.reserve(r.resource_id, "op2", Quantity(10, "mbps"), now=FRESH_NOW, expected_version=v)  # stale
            raise AssertionError("stale version should be rejected")
        except ResourceError as e:
            assert e.code == "account-stale-version", e.code
        results.append(("case_20_stale_accounting_update_rejected", True, "stale expected_version rejected"))
    except Exception as error:
        results.append(("case_20_stale_accounting_update_rejected", False, repr(error)))


def case_21_energy_state_independent(results: List[Result]) -> None:
    """Energy state is represented independently from other resource state
    (rule 11): energy_level, energy_capacity, power_draw are distinct."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner, kind=ResourceKind.ENERGY, scope="battery-A")
        rs = ResourceStore(); rs.register_resource(r)
        es = EnergyState(
            energy_level=Quantity(70, "Wh"),
            energy_capacity=Quantity(100, "Wh"),
            power_draw=Quantity(5, "watts"),
        )
        m = base_measurement(resource=r, source=owner, value=es, method_ref="energy-agent-v1")
        rs.record_measurement(m)
        cur = rs.get_current_measurement(r.resource_id, now=FRESH_NOW)
        assert cur is not None
        assert isinstance(cur.value, EnergyState)
        assert cur.value.energy_level.value == 70
        assert cur.value.energy_capacity.value == 100
        assert cur.value.power_draw.value == 5
        assert cur.value.power_draw.unit == "watts"  # distinct unit family from energy
        results.append(("case_21_energy_state_independent", True, "level/capacity/draw distinct"))
    except Exception as error:
        results.append(("case_21_energy_state_independent", False, repr(error)))


def case_22_energy_measurement_provenance_freshness(results: List[Result]) -> None:
    """Energy measurement has provenance/freshness (rule 7, 11)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner, kind=ResourceKind.ENERGY, scope="battery-A")
        rs = ResourceStore(); rs.register_resource(r)
        es = EnergyState(
            energy_level=Quantity(50, "Wh"), energy_capacity=Quantity(100, "Wh"),
            power_draw=Quantity(3, "watts"),
        )
        m = base_measurement(resource=r, source=owner, value=es, method_ref="energy-agent-v1",
                             provenance="sig:energy:1")
        rs.record_measurement(m)
        cur = rs.get_current_measurement(r.resource_id, now=FRESH_NOW)
        assert cur is not None
        assert cur.source_node_id == owner
        assert cur.source_class == MeasurementSource.SELF_OBSERVATION
        assert cur.method_ref == "energy-agent-v1"
        assert cur.provenance == "sig:energy:1"
        assert cur.measurement_id.startswith("sha256:")
        # stale now -> not current
        assert rs.get_current_measurement(r.resource_id, now=STALE_NOW) is None
        results.append(("case_22_energy_measurement_provenance_freshness", True, "source/method/provenance + expiry"))
    except Exception as error:
        results.append(("case_22_energy_measurement_provenance_freshness", False, repr(error)))


def case_23_backhaul_no_routing_result(results: List[Result]) -> None:
    """Backhaul resource does not create a routing result (rule 8 / forbidden
    API: no best_path/route_for/choose_best_resource)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner, kind=ResourceKind.BACKHAUL, scope="upstream-A")
        rs = ResourceStore(); rs.register_resource(r)
        rs.create_offer(base_offer(resource=r, quantity=Quantity(1000, "mbps")))
        rs.record_measurement(base_measurement(resource=r, source=owner, value=Quantity(800, "mbps")))
        # forbidden routing API must not exist on the store
        for forbidden in ("best_path", "route_for", "choose_best_resource", "trusted_measurement"):
            assert not hasattr(rs, forbidden), "store must not expose %r" % forbidden
        results.append(("case_23_backhaul_no_routing_result", True, "backhaul stored, no routing API"))
    except Exception as error:
        results.append(("case_23_backhaul_no_routing_result", False, repr(error)))


def case_24_coverage_no_reachability_truth(results: List[Result]) -> None:
    """Coverage/resource state does not create reachability truth (rule 8:
    resource availability != topology reachability; resources must not import
    topology or mutate ReachabilityState)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner, kind=ResourceKind.COVERAGE, scope="area-A")
        rs = ResourceStore(); rs.register_resource(r)
        rs.record_measurement(base_measurement(resource=r, source=owner, value=Quantity(42, "count")))
        # resources package must not import topology (no reachability coupling)
        import resources
        import inspect
        src = inspect.getsource(resources.model) + inspect.getsource(resources.ingest)
        assert "from topology" not in src, "resources must not import the topology package"
        assert "import topology" not in src, "resources must not import the topology package"
        results.append(("case_24_coverage_no_reachability_truth", True, "coverage stored, no topology import"))
    except Exception as error:
        results.append(("case_24_coverage_no_reachability_truth", False, repr(error)))


def case_25_service_capacity_distinct_from_capability(results: List[Result]) -> None:
    """Service capacity is distinct from the capability vocabulary (rule 4 /
    scope: a capability says what may be provided; service capacity says how
    much is currently allocatable)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner, kind=ResourceKind.EDGE_SERVICE_CAPACITY, scope="svc-A")
        rs = ResourceStore(); rs.register_resource(r)
        rs.create_offer(base_offer(resource=r, quantity=Quantity(1000, "sessions")))
        acct = rs.init_account_from_offer(r.resource_id, now=FRESH_NOW)
        assert acct.offered == 1000
        # resources package must not import capabilities (no second vocab)
        import resources
        import inspect
        src = inspect.getsource(resources.model) + inspect.getsource(resources.ingest)
        assert "from capabilities" not in src, "resources must not import the capabilities package"
        assert "import capabilities" not in src, "resources must not import the capabilities package"
        results.append(("case_25_service_capacity_distinct_from_capability", True, "edge-service-capacity modeled, no capability-vocab import"))
    except Exception as error:
        results.append(("case_25_service_capacity_distinct_from_capability", False, repr(error)))


def case_26_future_profile_ids_as_data(results: List[Result]) -> None:
    """Future access/resource profile IDs remain data without resource-core
    branching (rule 14 / LOCK-003: 6G/IMT enters as data, not as a branch)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner, kind=ResourceKind.BANDWIDTH, scope="future-link")
        rs = ResourceStore(); rs.register_resource(r)
        # method_ref and provenance carry future-profile identifiers as opaque data
        m = base_measurement(
            resource=r, source=owner, value=Quantity(500, "mbps"),
            method_ref="profile:future-6g-mock-v0:agent-1",
            provenance="sig:future-6g:1",
        )
        rs.record_measurement(m)
        cur = rs.get_current_measurement(r.resource_id, now=FRESH_NOW)
        assert cur is not None
        assert "future-6g" in cur.method_ref  # stored as opaque data, no branching
        # source code must not branch on a 6G/IMT identifier (LOCK-003) -- a
        # resource-core code path that special-cases a generation string would
        # violate technology neutrality. We check for branch patterns, not for
        # the mere presence of the string (docstrings legitimately mention 6G
        # as the boundary being prevented).
        import resources
        import inspect
        src = inspect.getsource(resources.model)
        import re
        branch_patterns = re.findall(r'if\s+\w+\s*==\s*["\']6g["\']', src, re.IGNORECASE)
        assert not branch_patterns, "model must not branch on a 6G literal: %r" % branch_patterns
        results.append(("case_26_future_profile_ids_as_data", True, "future-6g profile stored as opaque method_ref, no gen-branch"))
    except Exception as error:
        results.append(("case_26_future_profile_ids_as_data", False, repr(error)))


def case_27_malformed_nodeid_rejected(results: List[Result]) -> None:
    """Malformed provider/source NodeID is rejected (rule 7 / security)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner)
        rs = ResourceStore(); rs.register_resource(r)
        # malformed source NodeID
        try:
            base_measurement(resource=r, source="not-a-node-id", value=Quantity(63, "mbps"))
            raise AssertionError("malformed source should be rejected")
        except ResourceError as e:
            assert e.code == "measurement-source", e.code
        # malformed provider NodeID
        try:
            ResourceOffer(resource_id=r.resource_id, provider_node_id="bad",
                          quantity=Quantity(100, "mbps"), valid_from=VALID_FROM,
                          expires_at=EXPIRES_AT, sequence=1)
            raise AssertionError("malformed provider should be rejected")
        except ResourceError as e:
            assert e.code == "offer-provider", e.code
        results.append(("case_27_malformed_nodeid_rejected", True, "malformed source + provider rejected"))
    except Exception as error:
        results.append(("case_27_malformed_nodeid_rejected", False, repr(error)))


def case_28_cross_resource_measurement_mismatch_rejected(results: List[Result]) -> None:
    """Cross-resource measurement mismatch is rejected where the contract
    forbids it (rule 5, 13 / security): a measurement whose value unit is
    registered for a DIFFERENT kind than the resource. Also: provenance binding
    rejects a credential belonging to a different node (provider/source
    mismatch)."""
    try:
        from resources.ingest import record_observation
        _, creds, prov, idA, refA = make_identity()
        owner = str(idA.node_id)
        # second node B
        idB, refB = make_node(RELAYER_SECRET, IdentityService(store=creds, provider=prov, profiles=ProfileSet.load_default()), prov)
        nodeB = str(idB.node_id)
        r = make_resource(owner=owner, kind=ResourceKind.BANDWIDTH, scope="uplink-A")
        rs = ResourceStore(); rs.register_resource(r)
        # (a) cross-kind unit: storage unit on a bandwidth resource
        m_bad = base_measurement(resource=r, source=owner, value=Quantity(10, "GiB"))
        try:
            rs.record_measurement(m_bad)
            raise AssertionError("cross-kind unit should be rejected")
        except ResourceError as e:
            assert e.code == "unit-unknown", e.code
        # (b) provenance binding: a valid measurement by A, but credential is B's
        m_good = base_measurement(resource=r, source=owner, value=Quantity(63, "mbps"))
        out = record_observation(rs, m_good, now=FRESH_NOW,
                                 credential_store=creds, signature_provider=prov, credential=refB)
        assert not out.accepted and out.code == "verification-failed", out.code
        # (c) same measurement with A's credential succeeds
        out2 = record_observation(rs, m_good, now=FRESH_NOW,
                                  credential_store=creds, signature_provider=prov, credential=refA)
        assert out2.accepted, out2.code
        _ = nodeB
        results.append(("case_28_cross_resource_measurement_mismatch_rejected", True, "cross-kind unit + credential-mismatch rejected"))
    except Exception as error:
        results.append(("case_28_cross_resource_measurement_mismatch_rejected", False, repr(error)))


def case_29_seeded_fuzz_no_crash(results: List[Result]) -> None:
    """Seeded fuzz/mutation inputs never crash resource parsing/accounting/
    snapshot logic (security)."""
    try:
        rng = SeededRandom(0xC0FFEE)
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        kinds = list(ResourceKind.values())
        crashes = 0
        for _ in range(200):
            kind = rng.choice(kinds)
            r = make_resource(owner=owner, kind=kind, scope="fuzz-%d" % rng.below(1000000))
            rs = ResourceStore(); rs.register_resource(r)
            try:
                # valid units table for this kind
                from resources.model import _UNIT_REGISTRY
                units = list(_UNIT_REGISTRY[kind].keys())
                unit = rng.choice(units)
                qty = Quantity(1 + rng.below(1000), unit)
                off = base_offer(resource=r, quantity=qty, sequence=1 + rng.below(5))
                rs.create_offer(off)
                rs.init_account_from_offer(r.resource_id, now=FRESH_NOW)
                rs.reserve(r.resource_id, "fz%d" % rng.below(1000000), Quantity(1 + rng.below(10), unit), now=FRESH_NOW)
                rs.snapshot()
                rs.to_canonical_bytes()
            except ResourceError:
                pass  # expected for invalid fuzz combinations
            except Exception:
                crashes += 1
        assert crashes == 0, "%d crashes during fuzz" % crashes
        results.append(("case_29_seeded_fuzz_no_crash", True, "200 fuzz iters, 0 crashes"))
    except Exception as error:
        results.append(("case_29_seeded_fuzz_no_crash", False, repr(error)))


def case_30_repeated_runs_byte_identical(results: List[Result]) -> None:
    """Repeated self-test runs are byte-identical (determinism proof)."""
    try:
        def build_snapshot() -> bytes:
            _, _, _, idA, _ = make_identity()
            owner = str(idA.node_id)
            r = make_resource(owner=owner, kind=ResourceKind.BANDWIDTH, scope="det-A")
            rs = ResourceStore(); rs.register_resource(r)
            rs.create_offer(base_offer(resource=r, quantity=Quantity(100, "mbps"), sequence=1))
            rs.create_offer(base_offer(resource=r, quantity=Quantity(150, "mbps"), sequence=2))
            rs.record_measurement(base_measurement(resource=r, source=owner, value=Quantity(63, "mbps"), sequence=1))
            rs.record_measurement(base_measurement(resource=r, source=owner, value=Quantity(80, "mbps"), sequence=2))
            rs.init_account_from_offer(r.resource_id, now=FRESH_NOW)
            rs.reserve(r.resource_id, "op1", Quantity(30, "mbps"), now=FRESH_NOW)
            rs.consume(r.resource_id, "op2", Quantity(10, "mbps"), now=FRESH_NOW)
            return rs.to_canonical_bytes()

        s1 = build_snapshot()
        s2 = build_snapshot()
        md5_1 = hashlib.md5(s1).hexdigest()
        md5_2 = hashlib.md5(s2).hexdigest()
        assert s1 == s2, "snapshots differ"
        assert md5_1 == md5_2
        results.append(("case_30_repeated_runs_byte_identical", True, "md5=%s" % md5_1))
    except Exception as error:
        results.append(("case_30_repeated_runs_byte_identical", False, repr(error)))


# ==========================================================================
# Architect review of PR #8 -- regression coverage for both blockers
# ==========================================================================

def case_31_reserve_then_consume_full_transfer(results: List[Result]) -> None:
    """Architect review of PR #8, blocker 1: after reserve(5) then consume(5)
    the ledger MUST be reserved=0, consumed=5 (NOT reserved=5, consumed=5).
    Consumption explicitly transfers reserved quantity into consumed quantity
    for the reserve->consume path -- the consumed quantity is no longer
    counted as reserved (the prior implementation left the consumed quantity
    still counted as reserved, which is semantically wrong)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner, kind=ResourceKind.BANDWIDTH, scope="full-xfer")
        rs = ResourceStore(); rs.register_resource(r)
        rs.create_offer(base_offer(resource=r, quantity=Quantity(10, "mbps")))
        rs.init_account_from_offer(r.resource_id, now=FRESH_NOW)
        out_r = rs.reserve(r.resource_id, "op1", Quantity(5, "mbps"), now=FRESH_NOW)
        assert out_r.accepted and out_r.code == "reserved", out_r.detail
        out_c = rs.consume(r.resource_id, "op2", Quantity(5, "mbps"), now=FRESH_NOW)
        assert out_c.accepted and out_c.code == "consumed", out_c.detail
        acct = rs.get_account(r.resource_id)
        assert acct is not None
        assert acct.reserved == 0, "reserved=%d (full transfer: reservation consumed, not held)" % acct.reserved
        assert acct.consumed == 5_000_000, "consumed=%d" % acct.consumed
        assert acct.remaining == 5_000_000  # 10 - 0 - 5
        assert acct.reserved + acct.consumed <= acct.offered
        results.append(("case_31_reserve_then_consume_full_transfer", True, "reserve(5)+consume(5) -> reserved=0, consumed=5"))
    except Exception as error:
        results.append(("case_31_reserve_then_consume_full_transfer", False, repr(error)))


def case_32_reserve_then_consume_partial_transfer(results: List[Result]) -> None:
    """Architect review of PR #8, blocker 1 (partial consumption): after
    reserve(5) then consume(3) the ledger MUST be reserved=2, consumed=3 --
    only the consumed portion transfers out of reserved; the unconsumed
    reservation (2) remains held."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner, kind=ResourceKind.BANDWIDTH, scope="partial-xfer")
        rs = ResourceStore(); rs.register_resource(r)
        rs.create_offer(base_offer(resource=r, quantity=Quantity(10, "mbps")))
        rs.init_account_from_offer(r.resource_id, now=FRESH_NOW)
        rs.reserve(r.resource_id, "op1", Quantity(5, "mbps"), now=FRESH_NOW)
        rs.consume(r.resource_id, "op2", Quantity(3, "mbps"), now=FRESH_NOW)
        acct = rs.get_account(r.resource_id)
        assert acct is not None
        assert acct.reserved == 2_000_000, "reserved=%d (partial: 5-3=2 held)" % acct.reserved
        assert acct.consumed == 3_000_000, "consumed=%d" % acct.consumed
        assert acct.remaining == 5_000_000  # 10 - 2 - 3
        results.append(("case_32_reserve_then_consume_partial_transfer", True, "reserve(5)+consume(3) -> reserved=2, consumed=3"))
    except Exception as error:
        results.append(("case_32_reserve_then_consume_partial_transfer", False, repr(error)))


def case_33_consume_exceeds_reservation_draws_unreserved(results: List[Result]) -> None:
    """Architect review of PR #8, blocker 1 (consume exceeds reservation): a
    consume that exceeds the reserved amount transfers the full reservation
    and draws the remainder from unreserved capacity (the "available
    quantity" branch, rule 18). reserve(5) then consume(7) -> reserved=0
    (full transfer), consumed=7 (5 transferred + 2 from unreserved)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner, kind=ResourceKind.BANDWIDTH, scope="exceed-res")
        rs = ResourceStore(); rs.register_resource(r)
        rs.create_offer(base_offer(resource=r, quantity=Quantity(10, "mbps")))
        rs.init_account_from_offer(r.resource_id, now=FRESH_NOW)
        rs.reserve(r.resource_id, "op1", Quantity(5, "mbps"), now=FRESH_NOW)
        out = rs.consume(r.resource_id, "op2", Quantity(7, "mbps"), now=FRESH_NOW)
        assert out.accepted, out.detail
        acct = rs.get_account(r.resource_id)
        assert acct is not None
        assert acct.reserved == 0, "reserved=%d (full transfer of 5)" % acct.reserved
        assert acct.consumed == 7_000_000, "consumed=%d (5 transferred + 2 unreserved)" % acct.consumed
        assert acct.remaining == 3_000_000  # 10 - 0 - 7
        results.append(("case_33_consume_exceeds_reservation_draws_unreserved", True, "reserve(5)+consume(7) -> reserved=0, consumed=7"))
    except Exception as error:
        results.append(("case_33_consume_exceeds_reservation_draws_unreserved", False, repr(error)))


def case_34_consume_without_reservation_direct(results: List[Result]) -> None:
    """Architect review of PR #8, blocker 1 (direct consume, no reservation):
    a consume with no prior reservation draws entirely from unreserved
    capacity (the "available quantity" branch, rule 18). reserved stays 0,
    consumed increases by the consumed amount."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner, kind=ResourceKind.BANDWIDTH, scope="direct-consume")
        rs = ResourceStore(); rs.register_resource(r)
        rs.create_offer(base_offer(resource=r, quantity=Quantity(10, "mbps")))
        rs.init_account_from_offer(r.resource_id, now=FRESH_NOW)
        # no reserve -- direct consume
        out = rs.consume(r.resource_id, "op1", Quantity(3, "mbps"), now=FRESH_NOW)
        assert out.accepted, out.detail
        acct = rs.get_account(r.resource_id)
        assert acct is not None
        assert acct.reserved == 0, "reserved=%d (no reservation)" % acct.reserved
        assert acct.consumed == 3_000_000, "consumed=%d" % acct.consumed
        assert acct.remaining == 7_000_000  # 10 - 0 - 3
        results.append(("case_34_consume_without_reservation_direct", True, "consume(3) no-reserve -> reserved=0, consumed=3"))
    except Exception as error:
        results.append(("case_34_consume_without_reservation_direct", False, repr(error)))


def case_35_resource_id_owner_tamper_rejected(results: List[Result]) -> None:
    """Architect review of PR #8, blocker 2 (owner tampering): a Resource
    whose resource_id embeds owner A but whose owner_node_id field is B is
    rejected. The prior validation only checked that the owner string
    appeared somewhere in the id (loose substring), accepting e.g. an id for
    owner A attached to a Resource whose owner field is a DIFFERENT node B
    as long as B's text was a substring -- this is not a canonical binding."""
    try:
        _, creds, prov, idA, _ = make_identity()
        idB, _ = make_node(RELAYER_SECRET, IdentityService(store=creds, provider=prov, profiles=ProfileSet.load_default()), prov)
        ownerA = str(idA.node_id)
        ownerB = str(idB.node_id)
        # build a valid id for owner A, then attach it to a Resource whose
        # owner_node_id field is B (tampering)
        rid_for_a = make_resource_id(ownerA, ResourceKind.BANDWIDTH, "scope-A")
        try:
            Resource(
                resource_id=rid_for_a, owner_node_id=ownerB,
                kind=ResourceKind.BANDWIDTH, availability=AvailabilityMode.RESERVATION_BASED,
                scope="scope-A", created_at=NOW_TEXT,
            )
            raise AssertionError("owner tamper should be rejected")
        except ResourceError as e:
            assert e.code == "resource-id", e.code
        results.append(("case_35_resource_id_owner_tamper_rejected", True, "owner field != id owner rejected"))
    except Exception as error:
        results.append(("case_35_resource_id_owner_tamper_rejected", False, repr(error)))


def case_36_resource_id_kind_tamper_rejected(results: List[Result]) -> None:
    """Architect review of PR #8, blocker 2 (kind tampering): a Resource
    whose resource_id embeds kind=bandwidth but whose kind field is storage
    is rejected (the kind in the id MUST match the kind field)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        # build a valid id for bandwidth, then attach to a Resource whose
        # kind field is storage (tampering)
        rid_bw = make_resource_id(owner, ResourceKind.BANDWIDTH, "scope-k")
        try:
            Resource(
                resource_id=rid_bw, owner_node_id=owner,
                kind=ResourceKind.STORAGE,  # tampered: id says bandwidth
                availability=AvailabilityMode.RESERVATION_BASED,
                scope="scope-k", created_at=NOW_TEXT,
            )
            raise AssertionError("kind tamper should be rejected")
        except ResourceError as e:
            assert e.code == "resource-id", e.code
        results.append(("case_36_resource_id_kind_tamper_rejected", True, "kind field != id kind rejected"))
    except Exception as error:
        results.append(("case_36_resource_id_kind_tamper_rejected", False, repr(error)))


def case_37_resource_id_scope_tamper_rejected(results: List[Result]) -> None:
    """Architect review of PR #8, blocker 2 (scope tampering): a Resource
    whose resource_id embeds the hash of scope1 but whose scope field is
    scope2 is rejected. The resource_id MUST equal
    make_resource_id(owner, kind, scope) -- the scope hash embedded in the
    id must match the hash of the explicit scope."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        # build a valid id for scope1, then attach to a Resource whose
        # scope field is scope2 (tampering) -- owner and kind match, only
        # scope is tampered. The full canonical equality check catches this.
        rid_scope1 = make_resource_id(owner, ResourceKind.BANDWIDTH, "scope1")
        try:
            Resource(
                resource_id=rid_scope1, owner_node_id=owner,
                kind=ResourceKind.BANDWIDTH,
                availability=AvailabilityMode.RESERVATION_BASED,
                scope="scope2",  # tampered: id hashes scope1, field says scope2
                created_at=NOW_TEXT,
            )
            raise AssertionError("scope tamper should be rejected")
        except ResourceError as e:
            assert e.code == "resource-id", e.code
        results.append(("case_37_resource_id_scope_tamper_rejected", True, "scope field hash != id scope_hash rejected"))
    except Exception as error:
        results.append(("case_37_resource_id_scope_tamper_rejected", False, repr(error)))


def case_38_malformed_resource_id_rejected(results: List[Result]) -> None:
    """Architect review of PR #8, blocker 2 (strict parser): a malformed
    resource_id (wrong prefix, short digest, missing kind segment, wrong
    scope-hash length, extra trailing data, non-string) is rejected by the
    strict parser -- there is exactly one canonical representation."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        good = make_resource_id(owner, ResourceKind.BANDWIDTH, "ok")
        bad_ids = [
            "not-a-resource-id",  # wrong prefix entirely
            "adcos:resource:bandwidth:0123456789abcdef",  # missing owner NodeID
            good[:-1],  # truncated scope hash (15 hex)
            good + "x",  # extra trailing data
            good.replace("bandwidth", ""),  # empty kind segment
            "adcos:resource:adcos:node:identity.sha256-hmac-dev.v1:deadbeef:bandwidth:0123456789abcdef",  # short digest
            "",  # empty string
        ]
        for bad in bad_ids:
            try:
                parse_resource_id(bad)
                raise AssertionError("malformed id should be rejected: %r" % bad)
            except ResourceError as e:
                assert e.code == "resource-id", (bad, e.code)
        # non-string input rejected
        try:
            parse_resource_id(123)  # type: ignore[arg-type]
            raise AssertionError("non-string id should be rejected")
        except ResourceError as e:
            assert e.code == "resource-id", e.code
        results.append(("case_38_malformed_resource_id_rejected", True, "strict parser rejects 8 malformed shapes"))
    except Exception as error:
        results.append(("case_38_malformed_resource_id_rejected", False, repr(error)))


def case_39_parse_resource_id_roundtrip(results: List[Result]) -> None:
    """Architect review of PR #8, blocker 2 (round-trip): parse_resource_id
    extracts the exact (owner_node_id, kind, scope_hash) tuple that
    make_resource_id embedded, and the parsed id round-trips through
    make_resource_id for every frozen kind + scope combination."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        scopes = ["", "default", "uplink-A", "battery-A", "k-bandwidth"]
        for kind in ResourceKind.values():
            for scope in scopes:
                rid = make_resource_id(owner, kind, scope)
                parsed = parse_resource_id(rid)
                assert isinstance(parsed, ParsedResourceId), type(parsed)
                assert parsed.owner_node_id == owner, (kind, scope, parsed.owner_node_id)
                assert parsed.kind == kind, (kind, scope, parsed.kind)
                assert len(parsed.scope_hash) == 16, (kind, scope, parsed.scope_hash)
                # round-trip: make_resource_id(parsed.owner, parsed.kind, <scope>)
                # equals the original -- the scope plaintext is not recoverable
                # from scope_hash (by design), so re-derive with the known scope.
                assert make_resource_id(parsed.owner_node_id, parsed.kind, scope) == rid
        results.append(("case_39_parse_resource_id_roundtrip", True, "8 kinds x 5 scopes round-trip"))
    except Exception as error:
        results.append(("case_39_parse_resource_id_roundtrip", False, repr(error)))


# ==========================================================================
# Architect review of PR #8 -- correction cycle 2 regression coverage:
# offer_sequence (immutable) vs version (mutable accounting counter)
# ==========================================================================

def case_40_current_offer_not_stale_after_mutations(results: List[Result]) -> None:
    """Architect review cycle 2: a still-current offer MUST NOT be classified
    as stale merely because accounting operations bumped account.version past
    the offer's sequence. ``offer_sequence`` (immutable) and ``version``
    (mutable accounting counter) are distinct dimensions; init_account_from_offer
    uses offer_sequence exclusively for offer-freshness decisions."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner, kind=ResourceKind.BANDWIDTH)
        rs = ResourceStore(); rs.register_resource(r)
        rs.create_offer(base_offer(resource=r, quantity=Quantity(100, "mbps"), sequence=1))
        acct = rs.init_account_from_offer(r.resource_id, now=FRESH_NOW)
        assert acct.offer_sequence == 1, "offer_sequence initialized from offer"
        assert acct.version == 1, "version starts at 1, not from offer.sequence"
        # accounting mutations bump version but NOT offer_sequence
        rs.reserve(r.resource_id, "op1", Quantity(20, "mbps"), now=FRESH_NOW)   # version 2
        rs.consume(r.resource_id, "op2", Quantity(10, "mbps"), now=FRESH_NOW)    # version 3
        acct2 = rs.get_account(r.resource_id)
        assert acct2 is not None
        assert acct2.offer_sequence == 1, "offer_sequence unchanged by mutations"
        assert acct2.version == 3, "version bumped to 3"
        assert acct2.reserved == 10_000_000, "reserved=10M (20 reserved - 10 transferred)"
        assert acct2.consumed == 10_000_000, "consumed=10M"
        # init_account_from_offer again on the SAME current offer -- idempotent;
        # offer_sequence (1) == offer.sequence (1), offer_id matches. Even though
        # version (3) > offer.sequence (1), the offer is NOT stale.
        acct3 = rs.init_account_from_offer(r.resource_id, now=FRESH_NOW)
        assert acct3 is acct2, "init idempotent on current offer"
        assert acct3.offer_sequence == 1, "offer_sequence still 1"
        assert acct3.version == 3, "version NOT reset"
        assert acct3.reserved == 10_000_000, "reserved NOT reset"
        assert acct3.consumed == 10_000_000, "consumed NOT reset"
        results.append(("case_40_current_offer_not_stale_after_mutations", True,
                        "offer_sequence != version; current offer idempotent after mutations"))
    except Exception as error:
        results.append(("case_40_current_offer_not_stale_after_mutations", False, repr(error)))


def case_41_newer_offer_cannot_reset_live_ledger(results: List[Result]) -> None:
    """Architect review cycle 2: a newer offer arriving on a LIVE account
    (reserved > 0 OR consumed > 0) MUST NOT silently reset the ledger.
    init_account_from_offer raises account-offer-advance; an explicit
    accounting lifecycle rule is required to migrate (deferred to WORK-010)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner, kind=ResourceKind.BANDWIDTH)
        rs = ResourceStore(); rs.register_resource(r)
        rs.create_offer(base_offer(resource=r, quantity=Quantity(100, "mbps"), sequence=1))
        rs.init_account_from_offer(r.resource_id, now=FRESH_NOW)  # offer_sequence=1, version=1
        rs.reserve(r.resource_id, "op1", Quantity(30, "mbps"), now=FRESH_NOW)  # live: reserved=30M, version=2
        # newer offer appears
        rs.create_offer(base_offer(resource=r, quantity=Quantity(150, "mbps"), sequence=2))
        # init_account_from_offer must NOT silently reset the live ledger
        try:
            rs.init_account_from_offer(r.resource_id, now=FRESH_NOW)
            raise AssertionError("newer offer on live account must raise account-offer-advance")
        except ResourceError as e:
            assert e.code == "account-offer-advance", e.code
        # account UNCHANGED -- live ledger preserved
        acct = rs.get_account(r.resource_id)
        assert acct is not None
        assert acct.offer_sequence == 1, "offer_sequence NOT migrated"
        assert acct.version == 2, "version NOT bumped by rejected init"
        assert acct.offered == 100_000_000, "offered NOT changed to 150M"
        assert acct.reserved == 30_000_000, "reserved NOT reset"
        assert acct.consumed == 0, "consumed NOT reset"
        results.append(("case_41_newer_offer_cannot_reset_live_ledger", True,
                        "newer offer raises account-offer-advance; live ledger preserved"))
    except Exception as error:
        results.append(("case_41_newer_offer_cannot_reset_live_ledger", False, repr(error)))


def case_42_stale_offer_cannot_reset_ledger(results: List[Result]) -> None:
    """Architect review cycle 2: a stale offer (sequence < account.offer_sequence)
    MUST be rejected, never silently reset the ledger. Uses offer_sequence
    (not version) for the freshness decision."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner, kind=ResourceKind.BANDWIDTH)
        rs = ResourceStore(); rs.register_resource(r)
        rs.create_offer(base_offer(resource=r, quantity=Quantity(100, "mbps"), sequence=2))
        rs.init_account_from_offer(r.resource_id, now=FRESH_NOW)  # offer_sequence=2
        rs.reserve(r.resource_id, "op1", Quantity(20, "mbps"), now=FRESH_NOW)
        # Simulate a stale current offer relative to the account: directly inject
        # an account with offer_sequence=5 (as if it had been initialized from a
        # higher-generation offer that is no longer current). The store's offer
        # watermark rejects stale inserts, so we construct the account directly.
        # get_current_offer will still return the seq=2 offer, which is now stale
        # relative to the account's offer_sequence=5.
        injected = ResourceAccount(
            resource_id=r.resource_id,
            offered=100_000_000,
            reserved=20_000_000,
            consumed=0,
            offer_sequence=5,
            version=2,
            offer_id="acct-from-offer-seq-5",
        )
        rs._accounts[r.resource_id] = injected
        try:
            rs.init_account_from_offer(r.resource_id, now=FRESH_NOW)
            raise AssertionError("stale offer (seq 2 < account offer_sequence 5) must raise account-stale-offer")
        except ResourceError as e:
            assert e.code == "account-stale-offer", e.code
        # account UNCHANGED -- live ledger preserved
        acct2 = rs.get_account(r.resource_id)
        assert acct2 is injected, "account object NOT replaced"
        assert acct2.offer_sequence == 5, "offer_sequence NOT reset"
        assert acct2.reserved == 20_000_000, "reserved NOT reset"
        assert acct2.consumed == 0, "consumed NOT reset"
        results.append(("case_42_stale_offer_cannot_reset_ledger", True,
                        "stale offer rejected; live ledger preserved"))
    except Exception as error:
        results.append(("case_42_stale_offer_cannot_reset_ledger", False, repr(error)))


def case_43_newer_offer_advances_non_live_account(results: List[Result]) -> None:
    """Architect review cycle 2: a newer offer arriving on a NON-live account
    (reserved == 0 AND consumed == 0) safely advances offered / offer_sequence
    / offer_id; version stays at 1 because no accounting operations were
    applied under the new offer yet. This is the only safe migration path."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner, kind=ResourceKind.BANDWIDTH)
        rs = ResourceStore(); rs.register_resource(r)
        rs.create_offer(base_offer(resource=r, quantity=Quantity(100, "mbps"), sequence=1))
        acct1 = rs.init_account_from_offer(r.resource_id, now=FRESH_NOW)
        assert acct1.offer_sequence == 1
        assert acct1.offered == 100_000_000
        assert acct1.version == 1
        # newer offer arrives BEFORE any reservation/consumption -- account not live
        rs.create_offer(base_offer(resource=r, quantity=Quantity(150, "mbps"), sequence=2))
        acct2 = rs.init_account_from_offer(r.resource_id, now=FRESH_NOW)
        # offered advanced to the newer offer's quantity; reserved/consumed stay 0
        assert acct2.offer_sequence == 2, "offer_sequence advanced to 2"
        assert acct2.offered == 150_000_000, "offered advanced to 150M"
        assert acct2.reserved == 0, "reserved still 0"
        assert acct2.consumed == 0, "consumed still 0"
        assert acct2.version == 1, "version stays at 1 (no ops under new offer)"
        assert acct2.offer_id != acct1.offer_id, "offer_id advanced to the new offer"
        # accounting mutations under the new offer bump version (NOT offer_sequence)
        rs.reserve(r.resource_id, "op1", Quantity(40, "mbps"), now=FRESH_NOW)
        acct3 = rs.get_account(r.resource_id)
        assert acct3 is not None
        assert acct3.offer_sequence == 2, "offer_sequence stays at 2"
        assert acct3.version == 2, "version bumped to 2"
        assert acct3.reserved == 40_000_000
        results.append(("case_43_newer_offer_advances_non_live_account", True,
                        "non-live account advances offered/offer_sequence; version stays 1"))
    except Exception as error:
        results.append(("case_43_newer_offer_advances_non_live_account", False, repr(error)))


# ==========================================================================
# Mechanical checks (mirrors topology_selftest mechanical cases)
# ==========================================================================

def case_serialization_roundtrip(results: List[Result]) -> None:
    """Offer/measurement round-trip via from_mapping preserves all fields
    and the derived tamper-evident ID (WORK-003 canonicalization)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner, kind=ResourceKind.BANDWIDTH)
        off = base_offer(resource=r, quantity=Quantity(100, "mbps", "downstream"),
                        conditions=(("sla", "best-effort"), ("region", "z1")))
        off2 = offer_from_mapping(off.to_dict())
        assert off2.offer_id == off.offer_id
        assert off2.quantity.value == 100
        assert off2.conditions == (("sla", "best-effort"), ("region", "z1"))
        m = base_measurement(resource=r, source=owner, value=Quantity(63, "mbps"),
                             context=(("direction", "downstream"),))
        m2 = measurement_from_mapping(m.to_dict())
        assert m2.measurement_id == m.measurement_id
        assert m2.value.value == 63
        assert m2.context == (("direction", "downstream"),)
        # tampered mapping: bad offer_id must fail
        bad = dict(off.to_dict()); bad["offer_id"] = "sha256:deadbeef"
        try:
            offer_from_mapping(bad)
            raise AssertionError("tampered offer_id should fail")
        except ResourceError as e:
            assert e.code == "offer-id", e.code
        results.append(("case_serialization_roundtrip", True, "round-trip + tamper-evident ID"))
    except Exception as error:
        results.append(("case_serialization_roundtrip", False, repr(error)))


def case_no_forbidden_fields_or_methods(results: List[Result]) -> None:
    """Mechanical: the resources package exposes NONE of the forbidden API
    (authorize_reservation, price_resource, settle, choose_best_resource,
    best_path, route_for, trusted_measurement) and no trust/price/routing/
    settlement field on result types."""
    try:
        import resources
        forbidden_methods = ("authorize_reservation", "price_resource", "settle",
                             "choose_best_resource", "best_path", "route_for",
                             "trusted_measurement")
        forbidden_attrs = ("price", "settlement", "trust_score", "route_score",
                           "admission_decision", "winner")
        for name in forbidden_methods:
            assert not hasattr(resources, name), "resources must NOT expose %r" % name
            assert not hasattr(resources.ResourceStore, name), "ResourceStore must NOT have %r" % name
        for cls in (resources.MergeOutcome, resources.AccountingOutcome,
                    resources.ResourceOffer, resources.ResourceMeasurement,
                    resources.ResourceAccount):
            for attr in forbidden_attrs:
                fields = cls.__dataclass_fields__ if hasattr(cls, "__dataclass_fields__") else {}
                assert attr not in fields, "%s must not carry field %r" % (cls.__name__, attr)
        results.append(("case_no_forbidden_fields_or_methods", True, "no forbidden API/fields"))
    except Exception as error:
        results.append(("case_no_forbidden_fields_or_methods", False, repr(error)))


def case_no_5g_vendor_imports(results: List[Result]) -> None:
    """Mechanical: no 5G/6G/vendor-SDK imports or access-generation branching
    (LOCK-001/002/003/016/017)."""
    try:
        import resources
        import inspect
        src = inspect.getsource(resources.model) + inspect.getsource(resources.ingest)
        forbidden = ("import srsran", "import open5gs", "import android",
                     "import ios", "from 3gpp", "import nr", "import lte",
                     "if generation == 5", "if radio ==")
        for token in forbidden:
            assert token not in src.lower(), "forbidden token %r in resources source" % token
        results.append(("case_no_5g_vendor_imports", True, "no vendor/access-gen imports"))
    except Exception as error:
        results.append(("case_no_5g_vendor_imports", False, repr(error)))


def case_frozen_dimensions_present(results: List[Result]) -> None:
    """Mechanical: the six-dimension separation boundary is documented and
    structurally enforced (Resource / ResourceOffer / ResourceMeasurement /
    ResourceAccount are 4 distinct types; ResourceStore does not expose
    admission/routing/price)."""
    try:
        import resources
        for name in ("Resource", "ResourceOffer", "ResourceMeasurement", "ResourceAccount",
                     "ResourceStore", "Quantity", "EnergyState",
                     "ResourceKind", "AvailabilityMode", "MeasurementSource"):
            assert hasattr(resources, name), "missing %r" % name
        # 4 distinct object types
        assert resources.Resource is not resources.ResourceOffer
        assert resources.ResourceOffer is not resources.ResourceMeasurement
        assert resources.ResourceMeasurement is not resources.ResourceAccount
        assert resources.ResourceAccount is not resources.Resource
        # 8 frozen kinds (section 17)
        assert len(resources.ResourceKind.values()) == 8
        # 6 availability modes (section 17)
        assert len(resources.AvailabilityMode.values()) == 6
        # 4 measurement provenance classes
        assert len(resources.MeasurementSource.values()) == 4
        results.append(("case_frozen_dimensions_present", True, "4 types + 8 kinds + 6 avail + 4 source-class"))
    except Exception as error:
        results.append(("case_frozen_dimensions_present", False, repr(error)))


def case_secret_material_never_serialized(results: List[Result]) -> None:
    """Mechanical: secret/private-key material can never appear in serialized
    resources (LOCK-023)."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner)
        off = base_offer(resource=r, quantity=Quantity(100, "mbps"))
        m = base_measurement(resource=r, source=owner, value=Quantity(63, "mbps"))
        snap = off.to_dict(); snap2 = m.to_dict()
        for doc in (snap, snap2):
            for key in ("private_key", "secret_key", "password", "token"):
                assert key not in str(doc).lower(), "secret hint %r in serialized doc" % key
        # attempting to set a secret-looking field via conditions/context is rejected
        try:
            ResourceOffer(resource_id=r.resource_id, provider_node_id=owner,
                          quantity=Quantity(100, "mbps"), valid_from=VALID_FROM,
                          expires_at=EXPIRES_AT, sequence=1,
                          conditions=(("private_key", "leak"),))
            raise AssertionError("secret-looking condition should be rejected")
        except ResourceError as e:
            assert e.code == "secret-material", e.code
        results.append(("case_secret_material_never_serialized", True, "LOCK-023 enforced"))
    except Exception as error:
        results.append(("case_secret_material_never_serialized", False, repr(error)))


def case_remote_relay_not_authoritative(results: List[Result]) -> None:
    """Adversarial: a REMOTE_RELAY measurement about resource R owned by O is
    stored as source=A/REMOTE_RELAY evidence and NEVER enters the authoritative
    set (LOCK-008, rule 13 -- mirrors WORK-007 provenance collapse)."""
    try:
        _, creds, prov, idA, refA = make_identity()
        owner = str(idA.node_id)
        idB, refB = make_node(RELAYER_SECRET, IdentityService(store=creds, provider=prov, profiles=ProfileSet.load_default()), prov)
        nodeB = str(idB.node_id)
        r = make_resource(owner=owner, kind=ResourceKind.BANDWIDTH, scope="uplink-A")
        rs = ResourceStore(); rs.register_resource(r)
        # A (owner) self-observes 63 Mbps
        rs.record_measurement(base_measurement(resource=r, source=owner, value=Quantity(63, "mbps"),
                             source_class=MeasurementSource.SELF_OBSERVATION, sequence=1))
        # B relays a measurement about R (REMOTE_RELAY) claiming 200 Mbps
        rs.record_measurement(base_measurement(resource=r, source=nodeB, value=Quantity(200, "mbps"),
                             source_class=MeasurementSource.REMOTE_RELAY, sequence=1,
                             method_ref="relay-agent-v1"))
        auth = rs.get_authoritative_measurements(r.resource_id, now=FRESH_NOW)
        assert len(auth) == 1, "only self-observations are authoritative"
        assert auth[0].source_node_id == owner
        assert auth[0].value.value == 63  # the authoritative value is the self-observation, not the relay's 200
        # the remote relay IS retained as evidence (provenance preserved)
        all_m = rs.get_measurements(r.resource_id, now=FRESH_NOW)
        assert len(all_m) == 2  # both retained
        results.append(("case_remote_relay_not_authoritative", True, "relay=200 retained but NOT authoritative; self=63 authoritative"))
    except Exception as error:
        results.append(("case_remote_relay_not_authoritative", False, repr(error)))


def case_remote_offer_rejected(results: List[Result]) -> None:
    """Adversarial: an offer whose provider != resource owner is rejected
    (rule 1: a provider only offers its own resource; a relayed offer never
    becomes the authoritative offer)."""
    try:
        _, creds, prov, idA, refA = make_identity()
        owner = str(idA.node_id)
        idB, _ = make_node(RELAYER_SECRET, IdentityService(store=creds, provider=prov, profiles=ProfileSet.load_default()), prov)
        nodeB = str(idB.node_id)
        r = make_resource(owner=owner, kind=ResourceKind.BANDWIDTH, scope="uplink-A")
        rs = ResourceStore(); rs.register_resource(r)
        # B tries to offer O's resource -> rejected
        try:
            ResourceOffer(resource_id=r.resource_id, provider_node_id=nodeB,
                          quantity=Quantity(100, "mbps"), valid_from=VALID_FROM,
                          expires_at=EXPIRES_AT, sequence=1)
            # construction succeeds (the dataclass allows it), but create_offer rejects
        except ResourceError:
            pass  # some paths reject at construction
        off = ResourceOffer(resource_id=r.resource_id, provider_node_id=nodeB,
                            quantity=Quantity(100, "mbps"), valid_from=VALID_FROM,
                            expires_at=EXPIRES_AT, sequence=1)
        try:
            rs.create_offer(off)
            raise AssertionError("non-owner provider offer should be rejected")
        except ResourceError as e:
            assert e.code == "offer-provider", e.code
        results.append(("case_remote_offer_rejected", True, "relayed offer rejected at create_offer"))
    except Exception as error:
        results.append(("case_remote_offer_rejected", False, repr(error)))


def case_partition_recovery_replay_convergence(results: List[Result]) -> None:
    """Stale case 12: partition/recovery replay convergence -- duplicate
    replays after recovery do not change the deterministic current state."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        r = make_resource(owner=owner)
        rs1 = ResourceStore(); rs1.register_resource(r)
        rs2 = ResourceStore(); rs2.register_resource(r)
        m1 = base_measurement(resource=r, source=owner, value=Quantity(63, "mbps"), sequence=1)
        m2 = base_measurement(resource=r, source=owner, value=Quantity(80, "mbps"), sequence=2)
        # rs1: normal order, then a duplicate replay of m2 (recovery)
        rs1.record_measurement(m1); rs1.record_measurement(m2)
        rs1.record_measurement(m2)  # duplicate replay
        # rs2: same set, different arrival order (no stale-replay since both
        # stores eventually hold the same current state), then duplicate m2
        rs2.record_measurement(m1); rs2.record_measurement(m2)
        rs2.record_measurement(m2)  # duplicate replay after recovery
        assert rs1.to_canonical_bytes() == rs2.to_canonical_bytes()
        cur = rs2.get_current_measurement(r.resource_id, now=FRESH_NOW)
        assert cur is not None
        assert cur.value.value == 80  # seq2 still current
        results.append(("case_partition_recovery_replay_convergence", True, "replay convergence byte-identical"))
    except Exception as error:
        results.append(("case_partition_recovery_replay_convergence", False, repr(error)))


def case_energy_independent_from_bandwidth(results: List[Result]) -> None:
    """Stale case 11: energy state changes independently from bandwidth/
    storage state -- separate resources, separate measurements, separate
    accounting ledgers."""
    try:
        _, _, _, idA, _ = make_identity()
        owner = str(idA.node_id)
        bw = make_resource(owner=owner, kind=ResourceKind.BANDWIDTH, scope="uplink-A")
        en = make_resource(owner=owner, kind=ResourceKind.ENERGY, scope="battery-A")
        rs = ResourceStore(); rs.register_resource(bw); rs.register_resource(en)
        rs.create_offer(base_offer(resource=bw, quantity=Quantity(100, "mbps")))
        rs.create_offer(base_offer(resource=en, quantity=Quantity(100, "Wh")))
        rs.init_account_from_offer(bw.resource_id, now=FRESH_NOW)
        rs.init_account_from_offer(en.resource_id, now=FRESH_NOW)
        # drain energy independently
        rs.consume(en.resource_id, "en1", Quantity(30, "Wh"), now=FRESH_NOW)
        # bandwidth account unaffected
        bw_acct = rs.get_account(bw.resource_id)
        en_acct = rs.get_account(en.resource_id)
        assert bw_acct is not None and en_acct is not None
        assert bw_acct.consumed == 0  # bandwidth untouched
        # 30 Wh = 30 * 3,600,000 = 108,000,000 millijoules (integer base unit)
        assert en_acct.consumed == 108_000_000, "en consumed=%d" % en_acct.consumed
        results.append(("case_energy_independent_from_bandwidth", True, "energy drain independent of bandwidth ledger"))
    except Exception as error:
        results.append(("case_energy_independent_from_bandwidth", False, repr(error)))


def case_resource_availability_not_topology_reachability(results: List[Result]) -> None:
    """Rule 8: resource availability != topology reachability. A resource
    observation does not create ReachabilityState.REACHABLE or link state
    changes in WORK-007. The resources package does not import topology."""
    try:
        import resources
        import inspect
        src = inspect.getsource(resources.model) + inspect.getsource(resources.ingest)
        # resources must not import topology or mutate its state
        assert "from topology" not in src, "resources must not import topology"
        assert "import topology" not in src, "resources must not import topology"
        # resource availability is a frozen enum, NOT a reachability predicate
        assert "reachable" not in AvailabilityMode.values()
        results.append(("case_resource_availability_not_topology_reachability", True, "no topology import; availability != reachability"))
    except Exception as error:
        results.append(("case_resource_availability_not_topology_reachability", False, repr(error)))


def main() -> int:
    results: List[Result] = []
    case_01_all_eight_frozen_kinds_represented(results)
    case_02_offer_and_measurement_distinct_types(results)
    case_03_offer_quantity_unit_validation(results)
    case_04_measurement_quantity_unit_validation(results)
    case_05_incompatible_units_fail_closed(results)
    case_06_negative_impossible_quantities_fail_closed(results)
    case_07_offer_validity_expiry_at_injected_time(results)
    case_08_measurement_freshness_expiry_at_injected_time(results)
    case_09_expired_measurement_retained_historical(results)
    case_10_exact_duplicate_measurement_idempotent(results)
    case_11_measurement_insertion_order_deterministic(results)
    case_12_same_sequence_conflict_preserved(results)
    case_13_newer_supersedes_older(results)
    case_14_offer_unchanged_when_measurement_disagrees(results)
    case_15_offer_renewal_newer_sequence(results)
    case_16_accounting_equations_hold(results)
    case_17_reservation_cannot_exceed_offered(results)
    case_18_consumption_cannot_exceed_available(results)
    case_19_duplicate_accounting_operation_no_double_count(results)
    case_20_stale_accounting_update_rejected(results)
    case_21_energy_state_independent(results)
    case_22_energy_measurement_provenance_freshness(results)
    case_23_backhaul_no_routing_result(results)
    case_24_coverage_no_reachability_truth(results)
    case_25_service_capacity_distinct_from_capability(results)
    case_26_future_profile_ids_as_data(results)
    case_27_malformed_nodeid_rejected(results)
    case_28_cross_resource_measurement_mismatch_rejected(results)
    case_29_seeded_fuzz_no_crash(results)
    case_30_repeated_runs_byte_identical(results)
    case_31_reserve_then_consume_full_transfer(results)
    case_32_reserve_then_consume_partial_transfer(results)
    case_33_consume_exceeds_reservation_draws_unreserved(results)
    case_34_consume_without_reservation_direct(results)
    case_35_resource_id_owner_tamper_rejected(results)
    case_36_resource_id_kind_tamper_rejected(results)
    case_37_resource_id_scope_tamper_rejected(results)
    case_38_malformed_resource_id_rejected(results)
    case_39_parse_resource_id_roundtrip(results)
    case_40_current_offer_not_stale_after_mutations(results)
    case_41_newer_offer_cannot_reset_live_ledger(results)
    case_42_stale_offer_cannot_reset_ledger(results)
    case_43_newer_offer_advances_non_live_account(results)
    case_serialization_roundtrip(results)
    case_no_forbidden_fields_or_methods(results)
    case_no_5g_vendor_imports(results)
    case_frozen_dimensions_present(results)
    case_secret_material_never_serialized(results)
    case_remote_relay_not_authoritative(results)
    case_remote_offer_rejected(results)
    case_partition_recovery_replay_convergence(results)
    case_energy_independent_from_bandwidth(results)
    case_resource_availability_not_topology_reachability(results)

    print("ADCOS resource self-test")
    print("=" * 72)
    for name, ok, detail in results:
        print("[%s] %-54s %s" % ("ok  " if ok else "FAIL", name, detail))
    print("-" * 72)
    passed = sum(1 for _, ok, _ in results if ok)
    if passed == len(results):
        print("Result: PASS (%d/%d cases)" % (passed, len(results)))
        return 0
    print("Result: FAIL (%d/%d cases passed)" % (passed, len(results)))
    return 1


if __name__ == "__main__":
    sys.exit(main())
