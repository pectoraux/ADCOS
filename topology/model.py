"""ADCOS topology graph domain model (WORK-007).

Evidence-aware topology graph with independent identity / advertisement /
reachability / link dimensions, explicit claim provenance, and deterministic
stale/removed/reachable convergence, per spec/architecture.md section 11 and
the frozen WORK-007 handoff.

The central boundary (enforced throughout):

    identity state      !=  advertisement state
                        !=  reachability state
                        !=  link state
                        !=  trust
                        !=  routing validity
                        !=  resource availability

A topology claim is an attributable OBSERVATION/record that a reporter made a
statement about a subject at a particular time/context. It carries enough
provenance and freshness metadata for downstream layers (WORK-008/011) to
consume it WITHOUT silently promoting a remote summary into authoritative
truth.

The most important adversarial invariant:

    A says "C is an Internet gateway"
              |
              v
    stored as:
        reporter      = A
        subject       = C
        claim_type    = gateway
        source_class  = REMOTE_CLAIM
              |
              v
    NEVER becomes:
        C.gateway = true   (authoritative self-claim)

``get_authoritative_claims(subject)`` returns ONLY claims where
``reporter == subject`` AND ``source_class == SELF_ADVERTISEMENT`` -- a remote
summary can never enter that set. This is the mechanical provenance-collapse
prevention (LOCK-008, WORK-007 rule 3/4).

Topology logic never branches on 5G, Wi-Fi, LTE, 6G, satellite, or vendor
names. Access generation is data behind capability/profile identifiers -- a
hypothetical future access technology is representable without topology-core
code changes. Identity binding uses the canonical WORK-004 ``parse_node_id``
(no duplicated identity grammar). Temporal uses WORK-003 primitives; claim
fingerprinting uses WORK-003 canonical JSON. No trust, authorization,
routing, resource, or federation policy is decided here.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Tuple

from identity.node_id import NodeIdError, parse_node_id
from protocol.canonicalization import CanonicalizationError, canonical_json_bytes
from protocol.temporal import TemporalError, parse_instant


class TopologyError(ValueError):
    """Raised when a topology claim violates its contract (fail closed).
    ``code`` is a stable machine-readable reason."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------
# Independent topology dimensions (frozen architecture section 11 / LOCK-009)
# --------------------------------------------------------------------------

class IdentityState:
    """A subject's identity lifecycle state. Independent from advertisement,
    reachability, and link state."""

    UNKNOWN = "unknown"  # no identity evidence observed
    KNOWN = "known"  # identity evidence present (self or observed)
    REMOVED = "removed"  # authoritative removal evidence (self-withdrawal)


class AdvertisementState:
    """A subject's advertisement freshness state. Independent from identity,
    reachability, and link state."""

    NONE = "none"  # NONE/UNKNOWN -- no advertisement evidence observed
    CURRENT = "current"  # a current-fresh advertisement claim exists
    STALE = "stale"  # advertisement evidence exists but is past freshness


class ReachabilityState:
    """A subject's observation-scoped reachability state. Independent from
    identity, advertisement, and link state.

    REACHABLE here means "a current-fresh reachability observation exists for
    this subject" -- it is NOT global Internet reachability or gateway
    authority (WORK-007 rule 10). The underlying claims retain reporter
    provenance so downstream code can tell who observed it.
    """

    UNREACHABLE = "unreachable"
    REACHABLE = "reachable"


class LinkState:
    """A link's observed state. Independent from advertisement freshness and
    node identity state (WORK-007 rule 11)."""

    DOWN = "down"
    DEGRADED = "degraded"
    UP = "up"


class SourceClass:
    """Authority class of a topology claim's evidence (WORK-007 rule 3).

    A ``REMOTE_CLAIM`` about a subject MUST NOT be converted into a
    ``SELF_ADVERTISEMENT`` for that subject. The class is immutable on the
    claim and stored as-is -- no upgrade path exists in WORK-007.
    """

    SELF_ADVERTISEMENT = "self-advertisement"  # reporter == subject (self)
    DIRECT_OBSERVATION = "direct-observation"  # reporter directly observed subject
    REMOTE_CLAIM = "remote-claim"  # reporter relays a claim about subject
    BOOTSTRAP_CLAIM = "bootstrap-claim"  # bootstrap-sourced (non-authoritative)

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.SELF_ADVERTISEMENT,
            cls.DIRECT_OBSERVATION,
            cls.REMOTE_CLAIM,
            cls.BOOTSTRAP_CLAIM,
        )


class ClaimType:
    """Topology claim/observation types. ``value`` semantics depend on type."""

    IDENTITY = "identity"  # value: "present" | "removed"
    ADVERTISES = "advertises"  # value: capability_id (opaque WORK-002 ref)
    REACHABLE = "reachable"  # value: context ("true" or a context object)
    UNREACHABLE = "unreachable"  # value: context
    GATEWAY = "gateway"  # value: context (HIGH-VALUE -- needs subject provenance)
    BACKHAUL = "backhaul"  # value: capacity context (HIGH-VALUE)
    LINK_STATE = "link-state"  # value: LinkState; subject = link id
    DISCOVERED = "discovered"  # value: observation context (endpoints/caps)

    #: Claim types where a remote summary could materially alter future
    #: routing/resource decisions if it were silently upgraded to a self-claim.
    #: The provenance-collapse prevention is UNIFORM across all claim types
    #: (a REMOTE_CLAIM never becomes SELF_ADVERTISEMENT); this set is called out
    #: for test emphasis, not for special-cased logic.
    HIGH_VALUE = frozenset({GATEWAY, BACKHAUL, REACHABLE, UNREACHABLE, ADVERTISES})

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.IDENTITY,
            cls.ADVERTISES,
            cls.REACHABLE,
            cls.UNREACHABLE,
            cls.GATEWAY,
            cls.BACKHAUL,
            cls.LINK_STATE,
            cls.DISCOVERED,
        )


#: Claim types whose ``subject`` is a canonical ADCOS NodeID (WORK-004 grammar).
_NODE_SUBJECT_TYPES = frozenset(
    {
        ClaimType.IDENTITY,
        ClaimType.ADVERTISES,
        ClaimType.REACHABLE,
        ClaimType.UNREACHABLE,
        ClaimType.GATEWAY,
        ClaimType.BACKHAUL,
        ClaimType.DISCOVERED,
    }
)

_LINK_SUBJECT_PREFIX = "link:"


# --------------------------------------------------------------------------
# Topology claim (provenance-bearing, tamper-evident)
# --------------------------------------------------------------------------


def make_link_subject(endpoint_a: str, endpoint_b: str) -> str:
    """Canonical link subject identifier: ``link:<a>:<b>`` with endpoints
    sorted so (a,b) and (b,a) produce identical subjects (independent of
    caller order -- deterministic). Both endpoints must be canonical NodeIDs.
    """
    try:
        na = parse_node_id(endpoint_a)
        nb = parse_node_id(endpoint_b)
    except NodeIdError as error:
        raise TopologyError(
            "link-endpoint", "link endpoints must be canonical NodeIDs: %s" % error
        ) from error
    ordered = sorted([na.text, nb.text])
    if ordered[0] == ordered[1]:
        raise TopologyError("link-endpoint", "link endpoints must be distinct")
    return "link:%s:%s" % (ordered[0], ordered[1])


def parse_link_subject(subject: str) -> Tuple[str, str]:
    """Return the (sorted) endpoint NodeIDs of a link subject."""
    if not isinstance(subject, str) or not subject.startswith(_LINK_SUBJECT_PREFIX):
        raise TopologyError("link-subject", "subject %r is not a link identifier" % subject)
    tail = subject[len(_LINK_SUBJECT_PREFIX):]
    # The tail is "<node-a>:<node-b>" where each node text is
    # "adcos:node:<profile_id>:<64 hex>". Split on the canonical node prefix.
    prefix = "adcos:node:"
    if not tail.startswith(prefix):
        raise TopologyError("link-subject", "malformed link subject %r" % subject)
    rest = tail[len(prefix):]
    sep = ":" + prefix
    idx = rest.find(sep)
    if idx < 0:
        raise TopologyError("link-subject", "malformed link subject %r" % subject)
    first = prefix + rest[:idx]
    second = prefix + rest[idx + len(sep):]
    try:
        a = parse_node_id(first).text
        b = parse_node_id(second).text
    except NodeIdError as error:
        raise TopologyError(
            "link-subject", "link endpoints must be NodeIDs: %s" % error
        ) from error
    return (a, b)


def _claim_signature_input(claim: "TopologyClaim") -> bytes:
    """Canonical signature-input bytes (WORK-003 canonicalization; covers every
    semantic member except ``claim_id`` -- the derived fingerprint)."""
    try:
        return canonical_json_bytes(_signed_view(claim))
    except CanonicalizationError as error:
        raise TopologyError(
            "canonicalization", "claim is not canonically representable: %s" % error
        ) from error


def _signed_view(claim: "TopologyClaim") -> dict:
    document = claim.to_dict()
    document.pop("claim_id", None)
    return document


def _derive_claim_id(claim: "TopologyClaim") -> str:
    return "sha256:" + hashlib.sha256(_claim_signature_input(claim)).hexdigest()


@dataclass(frozen=True)
class TopologyClaim:
    """An attributable, provenance-bearing topology claim.

    A signature/provenance reference authenticates the REPORTER, never the
    subject. ``claim_id`` is auto-derived from the canonical signed content;
    a non-empty supplied value MUST equal the derived value (fail closed on
    mismatch -- prevents claim_id spoofing, mirroring WORK-006).
    """

    subject: str
    reporter: str
    claim_type: str
    value: Any
    evidence_refs: Tuple[str, ...] = ()
    source_class: str = SourceClass.REMOTE_CLAIM
    issued_at: str = ""
    freshness_until: str = ""
    sequence: int = 1
    provenance: str = ""
    claim_id: str = ""

    def __post_init__(self) -> None:
        if self.claim_type not in ClaimType.values():
            raise TopologyError(
                "claim-type",
                "claim_type %r must be one of %s" % (self.claim_type, ClaimType.values()),
            )
        # Subject validation: node-oriented types require a canonical NodeID;
        # link-state requires a canonical link subject.
        if self.claim_type == ClaimType.LINK_STATE:
            try:
                parse_link_subject(self.subject)
            except TopologyError as error:
                raise TopologyError(
                    "subject", "link-state subject must be a canonical link id: %s" % error
                ) from error
        elif self.claim_type in _NODE_SUBJECT_TYPES:
            try:
                parse_node_id(self.subject)
            except NodeIdError as error:
                raise TopologyError(
                    "subject",
                    "subject must be a canonical ADCOS NodeID: %s" % error,
                ) from error
        # Reporter must ALWAYS be a canonical NodeID (who made the claim).
        try:
            parse_node_id(self.reporter)
        except NodeIdError as error:
            raise TopologyError(
                "reporter", "reporter must be a canonical ADCOS NodeID: %s" % error
            ) from error
        # source_class must be a known authority class.
        if self.source_class not in SourceClass.values():
            raise TopologyError(
                "source-class",
                "source_class %r must be one of %s" % (self.source_class, SourceClass.values()),
            )
        # Temporal: RFC 3339 UTC; freshness_until >= issued_at.
        try:
            issued = parse_instant(self.issued_at)
            fresh = parse_instant(self.freshness_until)
        except TemporalError as error:
            raise TopologyError("temporal", str(error)) from error
        if fresh < issued:
            raise TopologyError(
                "temporal",
                "freshness_until %s is before issued_at %s"
                % (self.freshness_until, self.issued_at),
            )
        # Sequence: per-(reporter, subject, claim_type) monotonic integer.
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int):
            raise TopologyError("sequence", "sequence must be an integer")
        if self.sequence < 1:
            raise TopologyError("sequence", "sequence must be >= 1")
        # Evidence refs: opaque non-empty strings (references, never truth).
        for ref in self.evidence_refs:
            if not isinstance(ref, str) or not ref:
                raise TopologyError("evidence", "evidence refs must be non-empty strings")
        # Provenance reference: opaque string (signature/observation_id ref).
        if not isinstance(self.provenance, str):
            raise TopologyError("provenance", "provenance must be an opaque string")
        # Value must be canonical-JSON-representable (deterministic snapshots).
        try:
            canonical_json_bytes(self.value)
        except CanonicalizationError as error:
            raise TopologyError(
                "value", "value is not canonically representable: %s" % error
            ) from error
        # claim_id: derived fingerprint -- tamper-evident identifier.
        derived = _derive_claim_id(self)
        if not self.claim_id:
            object.__setattr__(self, "claim_id", derived)
        elif self.claim_id != derived:
            raise TopologyError(
                "claim-id",
                "claim_id %r does not match the derived fingerprint %r"
                % (self.claim_id, derived),
            )

    @property
    def derived_claim_id(self) -> str:
        return _derive_claim_id(self)

    def is_self_attribution(self) -> bool:
        """True iff reporter == subject AND source_class is SELF_ADVERTISEMENT.
        This is the authoritative-provenance predicate used by
        ``get_authoritative_claims`` -- a remote summary never satisfies it."""
        if self.source_class != SourceClass.SELF_ADVERTISEMENT:
            return False
        if self.claim_type == ClaimType.LINK_STATE:
            return False  # a link claim is never a self-attribution
        return self.reporter == self.subject

    def to_dict(self) -> dict:
        """Canonical field shape (WORK-003 canonicalization-ready). The value
        is serialized as-is; the field SET is frozen."""
        return {
            "claim_id": self.claim_id,
            "subject": self.subject,
            "reporter": self.reporter,
            "claim_type": self.claim_type,
            "value": self.value,
            "evidence_refs": list(self.evidence_refs),
            "source_class": self.source_class,
            "issued_at": self.issued_at,
            "freshness_until": self.freshness_until,
            "sequence": self.sequence,
            "provenance": self.provenance,
        }

    def __repr__(self) -> str:
        subj = self.subject[:24] + ("..." if len(self.subject) > 24 else "")
        rep = self.reporter[:24] + ("..." if len(self.reporter) > 24 else "")
        return (
            "TopologyClaim(subject=%s, reporter=%s, type=%s, seq=%d, source=%s)"
            % (subj, rep, self.claim_type, self.sequence, self.source_class)
        )


def claim_from_mapping(data: object) -> TopologyClaim:
    """Build a claim from a mapping, failing closed on every contract
    violation (missing members, wrong types, malformed NodeIDs, impossible
    temporal, bad sequence, bad source class)."""
    if not isinstance(data, Mapping):
        raise TopologyError("claim", "topology claim must be a JSON object")
    required = (
        "subject",
        "reporter",
        "claim_type",
        "value",
        "evidence_refs",
        "source_class",
        "issued_at",
        "freshness_until",
        "sequence",
        "provenance",
    )
    for member in required:
        if member not in data:
            raise TopologyError("missing", "required member %r is absent" % member)
    if not isinstance(data["evidence_refs"], list):
        raise TopologyError("evidence", "evidence_refs must be an array")
    claim_id = data.get("claim_id", "")
    if claim_id is None:
        claim_id = ""
    if not isinstance(claim_id, str):
        raise TopologyError("claim-id", "claim_id must be a string when present")
    return TopologyClaim(
        subject=data["subject"],
        reporter=data["reporter"],
        claim_type=data["claim_type"],
        value=data["value"],
        evidence_refs=tuple(data["evidence_refs"]),
        source_class=data["source_class"],
        issued_at=data["issued_at"],
        freshness_until=data["freshness_until"],
        sequence=data["sequence"],
        provenance=data["provenance"],
        claim_id=claim_id,
    )


# --------------------------------------------------------------------------
# Merge outcome + convergence graph
# --------------------------------------------------------------------------


class MergeRejectedError(ValueError):
    """Raised when a claim merge is rejected (fail closed). ``code`` is a
    stable machine-readable reason."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class MergeOutcome:
    """The outcome of a merge attempt. Carries ONLY selection/rejection data
    -- no trust/authorization/routing/resource surface."""

    accepted: bool
    code: str  # "accepted" | "idempotent" | "conflict-preserved" | "<rejection>"
    detail: str
    claim: Optional[TopologyClaim] = None


ClaimKey = Tuple[str, str, str, str]
# (reporter, subject, claim_type, discriminator). The discriminator is the
# claim's value-derived identity discriminator: for ADVERTISES claims it is the
# capability_id (so a node may concurrently advertise multiple distinct
# capabilities, each independently current / superseded / conflict-preserved
# -- WORK-005/WORK-007 rule: capabilities are individually attributable
# statements, not a single "latest advertisement wins" slot). For all other
# claim types the discriminator is the empty string -- value is a STATE of the
# (reporter, subject, claim_type) assertion (e.g. identity "present"/
# "removed", reachability context, link state) and the latest sequence
# supersedes the prior, so value must NOT be part of the key.


def _claim_key(claim: TopologyClaim) -> ClaimKey:
    if claim.claim_type == ClaimType.ADVERTISES:
        discriminator = claim.value if isinstance(claim.value, str) else str(claim.value)
    else:
        discriminator = ""
    return (claim.reporter, claim.subject, claim.claim_type, discriminator)


class TopologyGraph:
    """Evidence-aware topology graph with deterministic convergence and
    provenance-collapse prevention.

    Holds at most one *current* claim per ``(reporter, subject, claim_type,
    discriminator)`` key -- the highest-sequence claim seen. For ADVERTISES
    claims the discriminator is the capability_id (so a node may concurrently
    advertise multiple distinct capabilities, each independently current,
    independently superseded, independently conflict-preserved). For all other
    claim types the discriminator is the empty string (value is a state, latest
    sequence supersedes the prior). Per-key sequence watermarks reject replays
    (an old sequence cannot refresh freshness). Same-sequence
    different-content claims are preserved as conflicts rather than resolved
    by arrival order (WORK-007 convergence rule 10). Different reporters
    making conflicting claims are naturally both retained (different keys).

    The graph exposes query methods that DERIVE per-node/per-link state from
    claims at an injected evaluation instant. Every returned claim retains
    its reporter/subject/source_class provenance -- no query silently discards
    provenance. ``get_authoritative_claims`` returns ONLY self-attributed
    claims, so a remote summary can never become authoritative truth.
    """

    def __init__(self) -> None:
        self._current: Dict[ClaimKey, TopologyClaim] = {}
        self._watermarks: Dict[ClaimKey, int] = {}
        self._historical: Dict[ClaimKey, List[TopologyClaim]] = {}
        self._conflicts: Dict[ClaimKey, List[TopologyClaim]] = {}
        self._by_id: Dict[str, TopologyClaim] = {}

    # -- merge -------------------------------------------------------------

    def merge(self, claim: TopologyClaim) -> MergeOutcome:
        """Merge a claim deterministically (see class docstring).

        Merge rules (mirroring WORK-006 convergence, extended with conflict
        preservation):

        1. ``sequence < watermark``  -> reject (replay-stale; cannot refresh).
        2. ``sequence == watermark``:
           * existing current claim has the SAME claim_id -> idempotent.
           * otherwise -> CONFLICT: preserve both claims (no arrival-order
             winner); the key's current head becomes conflicted (cleared).
        3. ``sequence > watermark``  -> newer; supersede (existing moves to
           historical; any prior conflict at this key also moves to
           historical and is cleared).
        """
        key = _claim_key(claim)
        watermark = self._watermarks.get(key, 0)
        if claim.sequence < watermark:
            return MergeOutcome(
                False, "replay-stale",
                "sequence %d < watermark %d -- replay cannot refresh freshness"
                % (claim.sequence, watermark),
            )
        if claim.sequence == watermark:
            existing = self._current.get(key)
            if existing is not None and existing.claim_id == claim.claim_id:
                return MergeOutcome(
                    True, "idempotent",
                    "exact duplicate claim (sequence %d) -- no state change" % claim.sequence,
                    claim,
                )
            bucket = self._conflicts.setdefault(key, [])
            if existing is not None and existing.claim_id not in {c.claim_id for c in bucket}:
                bucket.append(existing)
                self._current.pop(key, None)  # conflicted current slot cleared
            if claim.claim_id not in {c.claim_id for c in bucket}:
                bucket.append(claim)
            self._by_id[claim.claim_id] = claim
            return MergeOutcome(
                True, "conflict-preserved",
                "sequence %d already seen with different content -- both claims "
                "preserved with provenance (no arrival-order winner)" % claim.sequence,
                claim,
            )
        # sequence > watermark: newer claim supersedes.
        existing = self._current.get(key)
        hist = self._historical.setdefault(key, [])
        if existing is not None:
            hist.append(existing)
        prior_conflicts = self._conflicts.pop(key, None)
        if prior_conflicts:
            hist.extend(prior_conflicts)
        self._current[key] = claim
        self._watermarks[key] = claim.sequence
        self._by_id[claim.claim_id] = claim
        return MergeOutcome(
            True, "accepted",
            "newer claim (sequence %d > watermark %d) -- superseded" % (claim.sequence, watermark),
            claim,
        )

    # -- queries (deterministic, provenance-preserving) -------------------

    def get_claim(self, key: ClaimKey) -> Optional[TopologyClaim]:
        return self._current.get(key)

    def watermark(self, key: ClaimKey) -> int:
        return self._watermarks.get(key, 0)

    def get_claims_for_subject(
        self, subject: str, *, now: datetime, include_historical: bool = False
    ) -> Tuple[TopologyClaim, ...]:
        """All claims about ``subject``, deterministically sorted by
        (reporter, claim_type, sequence, claim_id). Historical claims are
        included only when requested (audit). Every claim retains provenance."""
        out: List[TopologyClaim] = []
        for key, claim in self._current.items():
            if key[1] == subject:
                out.append(claim)
        for key, claims in self._conflicts.items():
            if key[1] == subject:
                out.extend(claims)
        if include_historical:
            for key, claims in self._historical.items():
                if key[1] == subject:
                    out.extend(claims)
        return tuple(sorted(out, key=_claim_sort_key))

    def get_claims_by_reporter(
        self, reporter: str, *, now: datetime, include_historical: bool = False
    ) -> Tuple[TopologyClaim, ...]:
        out: List[TopologyClaim] = []
        for key, claim in self._current.items():
            if key[0] == reporter:
                out.append(claim)
        for key, claims in self._conflicts.items():
            if key[0] == reporter:
                out.extend(claims)
        if include_historical:
            for key, claims in self._historical.items():
                if key[0] == reporter:
                    out.extend(claims)
        return tuple(sorted(out, key=_claim_sort_key))

    def get_authoritative_claims(
        self, subject: str, *, claim_type: Optional[str] = None, now: datetime
    ) -> Tuple[TopologyClaim, ...]:
        """ONLY self-attributed claims (reporter == subject AND
        SELF_ADVERTISEMENT). A remote summary can never enter this set --
        this is the mechanical provenance-collapse prevention."""
        out: List[TopologyClaim] = []
        for key, claim in self._current.items():
            if key[1] != subject:
                continue
            if claim_type is not None and key[2] != claim_type:
                continue
            if claim.is_self_attribution() and _is_fresh(claim, now):
                out.append(claim)
        return tuple(sorted(out, key=_claim_sort_key))

    def get_current_observations(self, *, now: datetime) -> Tuple[TopologyClaim, ...]:
        """All current-fresh claims across all keys, deterministically
        sorted. Conflicts are included (each retains provenance)."""
        out: List[TopologyClaim] = []
        for key in sorted(self._current.keys()):
            claim = self._current[key]
            if _is_fresh(claim, now):
                out.append(claim)
        for key in sorted(self._conflicts.keys()):
            for claim in sorted(self._conflicts[key], key=lambda c: c.claim_id):
                if _is_fresh(claim, now):
                    out.append(claim)
        return tuple(out)

    def get_conflicts(self) -> Tuple[Tuple[ClaimKey, Tuple[TopologyClaim, ...]], ...]:
        """All unresolved same-sequence conflicts, deterministically sorted.
        Each entry is ((reporter, subject, claim_type, discriminator),
        (claims...)). The discriminator is the capability_id for ADVERTISES
        (so concurrent distinct-capability advertisements never conflict)
        and the empty string for all other claim types."""
        out: List[Tuple[ClaimKey, Tuple[TopologyClaim, ...]]] = []
        for key in sorted(self._conflicts.keys()):
            claims = tuple(sorted(self._conflicts[key], key=lambda c: c.claim_id))
            out.append((key, claims))
        return tuple(out)

    def get_link_claims(
        self, endpoint_a: str, endpoint_b: str, *, now: datetime
    ) -> Tuple[TopologyClaim, ...]:
        """All current-fresh link-state claims for the (a,b) link, with
        provenance. Independent from advertisement freshness."""
        subject = make_link_subject(endpoint_a, endpoint_b)
        out: List[TopologyClaim] = []
        for key in sorted(self._current.keys()):
            if key[1] == subject and key[2] == ClaimType.LINK_STATE:
                claim = self._current[key]
                if _is_fresh(claim, now):
                    out.append(claim)
        return tuple(out)

    # -- derived dimension state ------------------------------------------

    def get_identity_state(self, subject: str, *, now: datetime) -> str:
        """Derive identity state at ``now``.

        A subject's OWN signed identity statement (self-attribution,
        ``source_class == SELF_ADVERTISEMENT`` and ``reporter == subject``)
        is the authoritative evidence for its identity lifecycle: a self
        "present" claim establishes ``KNOWN``; a self "removed" claim
        establishes ``REMOVED``. This is provenance, not trust policy.

        If no current-fresh self identity claim exists, the ONLY non-self
        evidence class that can drive state is ``DIRECT_OBSERVATION``: a
        directly-observed "present" claim establishes ``KNOWN`` (the local
        node exchanged packets with the subject -- the strongest non-self
        evidence class). ``REMOTE_CLAIM`` and ``BOOTSTRAP_CLAIM`` identity
        claims are stored as evidence (queryable via
        ``get_claims_for_subject`` with full reporter/subject/source_class
        provenance) but CANNOT drive ``IdentityState`` -- a remote "removed"
        claim must NOT produce authoritative ``IdentityState.REMOVED``, and
        a bootstrap seed must NOT authoritatively establish existence. This
        is the frozen WORK-007 rule: a reporter cannot authoritatively
        establish the subject's identity state (LOCK-008).

        Replay of an old sequence is rejected by the per-(reporter, subject,
        "identity") watermark before this derivation.
        """
        for key in sorted(self._current.keys()):
            rep, subj, ct, _disc = key
            if subj != subject or ct != ClaimType.IDENTITY or rep != subject:
                continue
            claim = self._current[key]
            if not _is_fresh(claim, now):
                continue
            if claim.source_class != SourceClass.SELF_ADVERTISEMENT:
                continue
            value = _as_identity_value(claim.value)
            if value == "present":
                return IdentityState.KNOWN
            if value == "removed":
                return IdentityState.REMOVED
        # Second pass: only DIRECT_OBSERVATION identity "present" claims by
        # other reporters can establish KNOWN (the local node directly
        # observed the subject present -- the strongest non-self evidence
        # class). REMOTE_CLAIM and BOOTSTRAP_CLAIM identity claims are stored
        # as evidence (queryable via get_claims_for_subject, retaining
        # reporter/subject/source_class provenance) but CANNOT drive
        # IdentityState -- a remote "removed" claim must not produce
        # authoritative IdentityState.REMOVED, and a bootstrap seed must not
        # authoritatively establish existence. (LOCK-008 provenance; WORK-007
        # rule: identity lifecycle is self-authored or directly observed,
        # never remotely asserted or bootstrap-seeded.)
        saw_present_via_direct_observation = False
        saw_remote_removed = False  # retained only for the assertion below
        for key in sorted(self._current.keys()):
            rep, subj, ct, _disc = key
            if subj != subject or ct != ClaimType.IDENTITY or rep == subject:
                continue
            claim = self._current[key]
            if not _is_fresh(claim, now):
                continue
            value = _as_identity_value(claim.value)
            if claim.source_class == SourceClass.DIRECT_OBSERVATION:
                if value == "present":
                    saw_present_via_direct_observation = True
            elif value == "removed":
                # A non-self "removed" claim (REMOTE_CLAIM or
                # BOOTSTRAP_CLAIM) is recorded as evidence but explicitly
                # NOT promoted to IdentityState.REMOVED. We track it only so
                # downstream audit (get_claims_for_subject) can still surface
                # the reporter's claim with full provenance.
                saw_remote_removed = True
        if saw_present_via_direct_observation:
            return IdentityState.KNOWN
        # saw_remote_removed is intentionally NOT returned as REMOVED here.
        # The remote "removed" claim remains queryable via get_claims_for_subject
        # (provenance preserved), but cannot drive authoritative state.
        _ = saw_remote_removed  # provenance-evidence marker, not state driver
        return IdentityState.UNKNOWN

    def get_advertisement_state(self, subject: str, *, now: datetime) -> str:
        """Derive advertisement freshness state at ``now``. Independent from
        identity, reachability, and link state. A stale advertisement remains
        queryable (historical evidence) but is not CURRENT."""
        has_any = False
        has_fresh = False
        for key in sorted(self._current.keys()):
            rep, subj, ct, _disc = key
            if subj != subject or ct != ClaimType.ADVERTISES:
                continue
            claim = self._current[key]
            has_any = True
            if _is_fresh(claim, now):
                has_fresh = True
        if has_fresh:
            return AdvertisementState.CURRENT
        if has_any:
            return AdvertisementState.STALE
        return AdvertisementState.NONE

    def get_reachability_state(self, subject: str, *, now: datetime) -> str:
        """Derive observation-scoped reachability state at ``now``. This is
        NOT global Internet reachability or gateway authority -- the
        underlying claims retain reporter provenance so downstream code can
        tell who observed it (WORK-007 rule 10)."""
        has_fresh_reachable = False
        for key in sorted(self._current.keys()):
            rep, subj, ct, _disc = key
            if subj != subject:
                continue
            if ct not in (ClaimType.REACHABLE, ClaimType.UNREACHABLE):
                continue
            claim = self._current[key]
            if not _is_fresh(claim, now):
                continue
            if ct == ClaimType.REACHABLE:
                has_fresh_reachable = True
        return ReachabilityState.REACHABLE if has_fresh_reachable else ReachabilityState.UNREACHABLE

    def get_link_state(self, endpoint_a: str, endpoint_b: str, *, now: datetime) -> str:
        """Derive link state at ``now`` from current-fresh link-state claims.
        Independent from advertisement freshness and node identity state.
        When multiple reporters observe conflicting states, the conservative
        (worst) observed state is derived (UP > DEGRADED > DOWN -- fail-safe);
        all claims remain queryable via ``get_link_claims`` so no provenance
        is lost (WORK-007 convergence rule: do not invent a winner silently).
        """
        claims = self.get_link_claims(endpoint_a, endpoint_b, now=now)
        if not claims:
            return LinkState.DOWN
        worst = LinkState.UP
        rank = {LinkState.UP: 2, LinkState.DEGRADED: 1, LinkState.DOWN: 0}
        for claim in claims:
            state = claim.value if isinstance(claim.value, str) else str(claim.value)
            if state not in rank:
                continue
            if rank[state] < rank[worst]:
                worst = state
        return worst

    # -- snapshot (deterministic) ----------------------------------------

    def snapshot(self) -> dict:
        """Deterministic graph snapshot, byte-identical regardless of
        insertion order. Claims are sorted by (reporter, subject,
        claim_type, sequence, claim_id); watermarks by key."""
        current: List[dict] = []
        for key in sorted(self._current.keys()):
            current.append(self._current[key].to_dict())
        conflicts: List[dict] = []
        for key in sorted(self._conflicts.keys()):
            for claim in sorted(self._conflicts[key], key=lambda c: c.claim_id):
                conflicts.append(claim.to_dict())
        historical: List[dict] = []
        for key in sorted(self._historical.keys()):
            for claim in sorted(self._historical[key], key=lambda c: c.claim_id):
                historical.append(claim.to_dict())
        watermarks: List[dict] = []
        for key in sorted(self._watermarks.keys()):
            watermarks.append(
                {"reporter": key[0], "subject": key[1], "claim_type": key[2],
                 "discriminator": key[3],
                 "watermark": self._watermarks[key]}
            )
        return {
            "claims": current,
            "conflicts": conflicts,
            "historical": historical,
            "watermarks": watermarks,
        }

    def to_canonical_bytes(self) -> bytes:
        """Canonical JSON bytes of the snapshot (WORK-003 canonicalization;
        byte-identical across runs regardless of insertion order)."""
        return canonical_json_bytes(self.snapshot())

    def __len__(self) -> int:
        return len(self._current) + sum(len(v) for v in self._conflicts.values())


# --------------------------------------------------------------------------
# Freshness + sort helpers
# --------------------------------------------------------------------------


def _is_fresh(claim: TopologyClaim, now: datetime) -> bool:
    """True iff the claim is within its freshness window at ``now``
    (issued_at <= now <= freshness_until). Stale claims remain stored but are
    not current. Mirrors WORK-006 ``evaluate_status`` FRESH semantics without
    the FUTURE branch (FUTURE is rejected at merge via temporal parse)."""
    if now.tzinfo is None:
        raise TopologyError("now", "evaluation instant must be timezone-aware")
    try:
        issued = parse_instant(claim.issued_at)
        fresh = parse_instant(claim.freshness_until)
    except TemporalError:
        return False
    return issued <= now <= fresh


def _as_identity_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    return ""


def _claim_sort_key(claim: TopologyClaim) -> Tuple[str, str, str, int, str]:
    return (
        claim.reporter,
        claim.subject,
        claim.claim_type,
        claim.sequence,
        claim.claim_id,
    )
