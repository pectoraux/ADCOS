"""WORK-047 NetworkPath handoff and reservation/lease coordination.

The two composition seams of the marketplace -- both DRIVE
canonical authorities through their accepted PUBLIC interfaces and
own none of their state:

**NetworkPath handoff** (:func:`handoff_to_networkpath`): the
selected proposal's candidates are handed to the WORK-041
machinery one at a time in the deterministic fallback order.  For
each candidate the handoff ONLY drives the public manager chain

    discover -> validate -> bind -> probe -> activate

and fails closed on the first unobserved/unvalidated interface.  A
candidate is "connected" IFF the NetworkPath machinery itself
reports ``ACTIVE`` -- and even then the recorded fact is a CITATION
of the machinery's state, never a marketplace-owned connectivity
claim.  The marketplace never constructs paths, never touches
routing/session/transport state, and never calls any private
machinery.  A successful handoff also advances the proposal's
lifecycle immutably: the returned outcome carries the advanced
proposal record (status ``handed-off``), and the ORIGINAL proposal
record stays untouched (no mutation, no second journal).

**Reservation/lease coordination** (:func:`coordinate_reservation`,
:func:`record_path_activation`): the canonical WORK-051
CommercialCore chain

    submit_intent -> select_offer -> hold_reservation
    authorize_session -> activate_path

is driven with deterministic, content-derived command ids
(replaying the same coordination against the same journal is an
idempotent no-op -- the core's own dedup).  The marketplace keeps
NO journal of its own (no second commercial authority), and a
successful reservation NEVER implies physical connectivity: the
coordination record cites commercial state only.

**PATH_ACTIVE requires a PROVEN W041 ACTIVE state**
(:func:`record_path_activation`): the commercial path-activation
record is only made against a genuine :class:`HandoffOutcome`
whose cited machinery state is ``ACTIVE`` AND whose exact
``network_path_id`` the W041 machinery's own PUBLIC reads prove is
CURRENTLY ``ACTIVE`` for the exact logical session
(``manager.path(...).state`` and ``manager.active_path_id(...)``).
A reference that merely exists in the W051 ``ReferenceIndex`` is
NOT sufficient: W041 owns connectivity truth, and commercial
``PATH_ACTIVE`` is only a citation of W041's ``ACTIVE`` state.
Every unproven case fails closed with the typed
``PATH_ACTIVE_UNPROVEN`` reason and records NOTHING on the
canonical journal.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from protocol.canonicalization import canonical_json_bytes

from commercial.errors import CommercialError
from commercial.lifecycle import CommercialCore
from networkpath.errors import NetworkPathError
from networkpath.lifecycle import NetworkPathManager, NetworkPathState

from .errors import MarketplaceError, MarketplaceReasonCode
from .index import MarketplaceIndex
from .selection import SelectionProposal

#: The frozen handoff attempt outcomes.
ATTEMPT_OUTCOME_VALUES: Tuple[str, ...] = (
    "accepted",
    "rejected",
)

#: How long a held reservation is coordinated to live (seconds)
#: when the caller does not override it.
DEFAULT_RESERVATION_TTL_SECONDS = 900

#: The frozen coordination actor/source provenance recorded on
#: canonical commercial commands issued by the marketplace seam.
COORDINATION_SOURCE = "marketplace-coordination"


def derive_coordination_command_id(proposal_id: str, step: str) -> str:
    """The deterministic commercial command id of one coordination
    step (content-derived: replay of the same coordination against
    the same journal dedups instead of duplicating)."""
    return "mpk-" + hashlib.sha256(
        canonical_json_bytes([proposal_id, step])
    ).hexdigest()[:24]


# ---------------------------------------------------------------------------
# Pure-integer RFC 3339 UTC instant arithmetic (no datetime import:
# the family's import discipline; deterministic on every platform)
# ---------------------------------------------------------------------------


def _epoch_seconds(instant: str) -> int:
    """RFC 3339 UTC ``YYYY-MM-DDTHH:MM:SSZ`` -> epoch seconds
    (Howard Hinnant's days-from-civil algorithm, pure integers)."""
    try:
        year = int(instant[0:4])
        month = int(instant[5:7])
        day = int(instant[8:10])
        hour = int(instant[11:13])
        minute = int(instant[14:16])
        second = int(instant[17:19])
        if instant[4] != "-" or instant[7] != "-" or instant[10] != "T":
            raise ValueError("separator")
        if instant[13] != ":" or instant[16] != ":" or instant[19] != "Z":
            raise ValueError("separator")
    except (ValueError, IndexError) as error:
        raise MarketplaceError(
            MarketplaceReasonCode.INVALID_INPUT,
            "instant %r must be RFC 3339 UTC (YYYY-MM-DDTHH:MM:SSZ): %s"
            % (instant, error),
        ) from error
    y = year - (1 if month <= 2 else 0)
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    days = era * 146097 + doe - 719468
    return days * 86400 + hour * 3600 + minute * 60 + second


def _instant_from_epoch(seconds: int) -> str:
    """Epoch seconds -> RFC 3339 UTC (civil-from-days, pure
    integers; the inverse of :func:`_epoch_seconds`)."""
    days = seconds // 86400
    rem = seconds - days * 86400
    hour = rem // 3600
    minute = (rem - hour * 3600) // 60
    second = rem % 60
    z = days + 719468
    era = (z if z >= 0 else z - 146096) // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    day = doy - (153 * mp + 2) // 5 + 1
    month = mp + (3 if mp < 10 else -9)
    year = y + (1 if month <= 2 else 0)
    return "%04d-%02d-%02dT%02d:%02d:%02dZ" % (
        year, month, day, hour, minute, second,
    )


def instant_plus_seconds(instant: str, seconds: int) -> str:
    """A deadline instant (deterministic pure-integer arithmetic)."""
    if not isinstance(seconds, int) or isinstance(seconds, bool) or seconds < 0:
        raise MarketplaceError(
            MarketplaceReasonCode.INVALID_INPUT,
            "seconds must be a non-negative integer",
        )
    return _instant_from_epoch(_epoch_seconds(instant) + seconds)


# ---------------------------------------------------------------------------
# NetworkPath handoff (composition with WORK-041 machinery)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HandoffAttempt:
    """One fallback attempt: which candidate, what outcome, and
    the deterministic rejection reason when the machinery
    rejected it (the W041 reason text verbatim -- never a
    marketplace-invented connectivity verdict)."""

    offer_key: Tuple[str, str]
    outcome: str
    reason: str = ""

    def __post_init__(self) -> None:
        if self.outcome not in ATTEMPT_OUTCOME_VALUES:
            raise MarketplaceError(
                MarketplaceReasonCode.INVALID_INPUT,
                "handoff attempt outcome %r is not one of %s"
                % (self.outcome, list(ATTEMPT_OUTCOME_VALUES)),
            )

    def content(self) -> Dict[str, Any]:
        return {
            "provider_id": self.offer_key[0],
            "offer_id": self.offer_key[1],
            "outcome": self.outcome,
            "reason": self.reason,
        }

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.content())


@dataclass(frozen=True)
class HandoffOutcome:
    """The result of the NetworkPath handoff composition.

    ``network_path_state`` is the machinery's OWN state, cited as
    evidence (the marketplace never derives it).  The outcome
    carries the full attempt chain for audit, AND the ADVANCED
    proposal record (``advanced_proposal``: the immutable
    ``handed-off`` transition of the proposal this outcome hands
    off -- the handoff composition is the only status-advancing
    seam, and it advances by RETURNING a new record, never by
    mutating the original).  When every fallback was rejected,
    :func:`handoff_to_networkpath` raises the typed
    ``HANDOFF_REJECTED`` error (fail closed -- a rejected handoff
    is never a silent success); the caller then composes the frozen
    ``rejected`` transition through the same immutable
    ``with_status`` seam if it needs the record.
    """

    proposal_id: str
    session_id: str
    accepted_offer_key: Tuple[str, str]
    network_path_id: str
    network_path_state: str
    attempts: Tuple[HandoffAttempt, ...]
    advanced_proposal: SelectionProposal

    def __post_init__(self) -> None:
        if not isinstance(self.advanced_proposal, SelectionProposal):
            raise MarketplaceError(
                MarketplaceReasonCode.INVALID_INPUT,
                "the handoff outcome must carry the advanced "
                "SelectionProposal record",
            )
        if self.advanced_proposal.status != "handed-off":
            raise MarketplaceError(
                MarketplaceReasonCode.INVALID_INPUT,
                "the outcome's advanced proposal must carry status "
                "'handed-off' (the accepted-handoff transition)",
            )
        if self.advanced_proposal.proposal_id != self.proposal_id:
            raise MarketplaceError(
                MarketplaceReasonCode.INVALID_INPUT,
                "the advanced proposal identity %r does not match the "
                "outcome's proposal %r"
                % (
                    self.advanced_proposal.proposal_id,
                    self.proposal_id,
                ),
            )

    def content(self) -> Dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "session_id": self.session_id,
            "provider_id": self.accepted_offer_key[0],
            "offer_id": self.accepted_offer_key[1],
            "network_path_id": self.network_path_id,
            "network_path_state": self.network_path_state,
            "attempts": [attempt.to_dict() for attempt in self.attempts],
            "proposal_status": self.advanced_proposal.status,
        }

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.content())


def _path_id_for_interface(
    manager: NetworkPathManager, interface_name: str, link_kind: str
) -> str:
    """Resolve the machinery's candidate path for one interface.

    Uses ONLY the public ``paths()``/``path()`` reads.  The link
    kind must match the listing's declared substrate: a mismatched
    kind is a fail-closed rejection (the marketplace never
    re-binds an offer to a different substrate)."""
    for path_id in manager.paths():
        path = manager.path(path_id)
        if path.interface_name == interface_name:
            if path.link_kind == link_kind:
                return path_id
            raise MarketplaceError(
                MarketplaceReasonCode.HANDOFF_REJECTED,
                "interface %r exists with link kind %r but the offer "
                "declares %r"
                % (interface_name, path.link_kind, link_kind),
            )
    raise MarketplaceError(
        MarketplaceReasonCode.HANDOFF_REJECTED,
        "interface %r is not observed by the NetworkPath machinery"
        % interface_name,
    )


def handoff_to_networkpath(
    *,
    proposal: SelectionProposal,
    index: MarketplaceIndex,
    manager: NetworkPathManager,
    session_id: str,
) -> HandoffOutcome:
    """Hand the proposal's candidates to the NetworkPath machinery.

    The chain per candidate (the machinery's own public lifecycle):

    1. ``manager.discover()`` -- one observation cycle (the
       machinery's idempotent public read of the platform);
    2. resolve the interface's candidate path id (public reads);
    3. ``manager.validate(path_id)`` -- the machinery's validation
       authority (a rejection advances to the next fallback);
    4. ``manager.bind(path_id, session_id)`` then
       ``manager.probe(path_id)`` then ``manager.activate(path_id)``
       -- the machinery's binding/probe/activation authority.

    The FIRST candidate that survives the whole chain is the
    accepted candidate; the outcome records the machinery's state
    verbatim.  Rejections are recorded per attempt with the W041
    reason; exhausting the chain raises (fail closed).

    The outcome also RETURNS the advanced immutable proposal
    record (status ``handed-off``): the handoff composition is the
    proposal lifecycle's only status-advancing seam, and it
    advances by returning a NEW record -- the caller's original
    proposal object is never mutated.
    """
    if not isinstance(manager, NetworkPathManager):
        raise MarketplaceError(
            MarketplaceReasonCode.INVALID_INPUT,
            "handoff requires a NetworkPathManager (the accepted W041 "
            "machinery)",
        )
    if not isinstance(session_id, str) or not session_id:
        raise MarketplaceError(
            MarketplaceReasonCode.INVALID_INPUT,
            "handoff requires a real logical session id (the session "
            "authority's own identity, cited here as DATA)",
        )
    manager.discover()  # the machinery's public observation cycle
    attempts: Tuple[HandoffAttempt, ...] = ()
    for offer_key in proposal.chain:
        offer = index.offer(offer_key[0], offer_key[1])
        try:
            path_id = _path_id_for_interface(
                manager, offer.interface_name, offer.link_kind
            )
            manager.validate(path_id)
            manager.bind(path_id, session_id)
            manager.probe(path_id)
            manager.activate(path_id)
        except MarketplaceError as error:
            attempts = attempts + (
                HandoffAttempt(
                    offer_key=offer_key,
                    outcome="rejected",
                    reason="%s: %s" % (error.reason, error.message),
                ),
            )
            continue
        except NetworkPathError as error:
            attempts = attempts + (
                HandoffAttempt(
                    offer_key=offer_key,
                    outcome="rejected",
                    reason="%s: %s" % (error.reason, error.detail),
                ),
            )
            continue
        path = manager.path(path_id)
        attempts = attempts + (
            HandoffAttempt(offer_key=offer_key, outcome="accepted"),
        )
        return HandoffOutcome(
            proposal_id=proposal.proposal_id,
            session_id=session_id,
            accepted_offer_key=offer_key,
            network_path_id=path_id,
            network_path_state=path.state,
            attempts=attempts,
            advanced_proposal=proposal.with_status("handed-off"),
        )
    raise MarketplaceError(
        MarketplaceReasonCode.HANDOFF_REJECTED,
        "every fallback candidate was rejected by the NetworkPath "
        "machinery (%d attempt(s))" % len(attempts),
    )


# ---------------------------------------------------------------------------
# Reservation/lease coordination (composition with WORK-051 core)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReservationCoordination:
    """The record of one canonical commercial coordination.

    Members are CITATIONS of the CommercialCore's own state and
    commands (the marketplace holds no commercial journal):

    - ``transaction_id``: the core's content-derived transaction;
    - ``commands``: the deterministic command ids issued;
    - ``commercial_state``: the core's projected state, read back
      through its public ``transaction()`` surface;
    - ``expires_at``: the reservation deadline recorded by the
      core.

    The record deliberately has NO connectivity member: commercial
    reservation success is commercial state, nothing more (the
    connectivity truth of the selected candidate is the NetworkPath
    machinery's alone)."""

    proposal_id: str
    transaction_id: str
    commands: Tuple[str, ...]
    commercial_state: str
    expires_at: str

    def content(self) -> Dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "transaction_id": self.transaction_id,
            "commands": list(self.commands),
            "commercial_state": self.commercial_state,
            "expires_at": self.expires_at,
        }

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.content())


def _commercial_intent(
    proposal: SelectionProposal,
    buyer_id: str,
    jurisdiction: str,
    offer_key: Tuple[str, str],
) -> Dict[str, Any]:
    """The canonical ConnectivityIntent payload (deterministic
    from the proposal + query basis; the transaction identity is
    content-derived by the core, so identical coordination inputs
    yield the identical transaction id)."""
    return {
        "buyer": buyer_id,
        "want": "connectivity",
        "region": jurisdiction,
        "provider": offer_key[0],
        "offer": offer_key[1],
        "proposal": proposal.proposal_id,
        "chain": [
            {"provider_id": provider_id, "offer_id": offer_id}
            for provider_id, offer_id in proposal.selected
        ],
    }


def _transaction_of_command(
    core: CommercialCore, command_id: str
) -> str:
    """Recover the transaction id of an ALREADY-ADMITTED command
    (the idempotent-replay path: the core's DUPLICATE outcome for
    ``submit_intent`` carries an empty transaction_id by the W051
    contract, so the coordination re-derives it from the core's
    public journal reads -- never from any private state)."""
    for record in core.journal_records():
        if record.command.command_id == command_id:
            return record.event.transaction_id
    raise MarketplaceError(
        MarketplaceReasonCode.RESERVATION_REJECTED,
        "command %r is not admitted on the canonical journal (the "
        "core's dedup state diverged)" % command_id,
    )


def coordinate_reservation(
    *,
    proposal: SelectionProposal,
    index: MarketplaceIndex,
    core: CommercialCore,
    buyer_id: str,
    jurisdiction: str,
    ttl_seconds: int = DEFAULT_RESERVATION_TTL_SECONDS,
    payment_refs: Tuple[str, ...] = (),
) -> ReservationCoordination:
    """Drive the canonical reservation chain on the CommercialCore.

    ``submit_intent`` -> ``select_offer`` -> ``hold_reservation``,
    each with a deterministic content-derived command id, the
    listing's commercial terms as the offer payload, and the
    reservation deadline anchored DETERMINISTICALLY on the
    proposal's own evidence instant (``proposal.instant`` + TTL)
    -- NOT on a fresh clock read -- so replaying the same
    coordination against the same journal produces byte-identical
    commands and the core's own dedup makes it an idempotent
    no-op (replay determinism).  Commercial errors are re-wrapped
    typed (fail closed; W051 remains the authority)."""
    if not isinstance(core, CommercialCore):
        raise MarketplaceError(
            MarketplaceReasonCode.INVALID_INPUT,
            "coordination requires a CommercialCore (the accepted W051 "
            "authority)",
        )
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
        raise MarketplaceError(
            MarketplaceReasonCode.INVALID_INPUT,
            "ttl_seconds must be a positive integer",
        )
    primary = proposal.primary
    offer = index.offer(primary[0], primary[1])
    actor = buyer_id
    source = COORDINATION_SOURCE
    step_intent = derive_coordination_command_id(proposal.proposal_id, "submit-intent")
    step_select = derive_coordination_command_id(proposal.proposal_id, "select-offer")
    step_hold = derive_coordination_command_id(proposal.proposal_id, "hold-reservation")
    if not proposal.instant:
        raise MarketplaceError(
            MarketplaceReasonCode.INVALID_INPUT,
            "coordination requires a proposal carrying its discovery "
            "instant (the deterministic reservation-deadline anchor)",
        )
    expires_at = instant_plus_seconds(proposal.instant, ttl_seconds)
    try:
        outcome_intent = core.submit_intent(
            command_id=step_intent,
            actor=actor,
            source=source,
            intent=_commercial_intent(proposal, buyer_id, jurisdiction, primary),
        )
        transaction_id = outcome_intent.transaction_id
        if not transaction_id:
            # idempotent replay: the DUPLICATE outcome carries no
            # transaction id (the W051 contract); recover it from
            # the core's public journal reads
            transaction_id = _transaction_of_command(core, step_intent)
        core.select_offer(
            command_id=step_select,
            transaction_id=transaction_id,
            actor=actor,
            source=source,
            offer={
                "provider_id": offer.provider_id,
                "offer_id": offer.offer_id,
                "currency": offer.currency,
                "price_minor": offer.price_minor,
                "price_exponent": offer.price_exponent,
                "billing_mode": offer.billing_mode,
                "jurisdiction": offer.jurisdiction,
            },
        )
        core.hold_reservation(
            command_id=step_hold,
            transaction_id=transaction_id,
            actor=actor,
            source=source,
            expires_at=expires_at,
            payment_refs=tuple(payment_refs),
        )
    except CommercialError as error:
        raise MarketplaceError(
            MarketplaceReasonCode.RESERVATION_REJECTED,
            "the canonical commercial authority rejected the "
            "coordination (%s: %s)" % (error.reason, error.detail),
        ) from error
    transaction = core.transaction(transaction_id)
    return ReservationCoordination(
        proposal_id=proposal.proposal_id,
        transaction_id=transaction_id,
        commands=(step_intent, step_select, step_hold),
        commercial_state=transaction.state,
        expires_at=expires_at,
    )


def record_path_activation(
    *,
    coordination: ReservationCoordination,
    core: CommercialCore,
    manager: NetworkPathManager,
    outcome: HandoffOutcome,
    session_id: str,
    actor: str,
) -> ReservationCoordination:
    """Record the commercial session authorization and path
    activation against a PROVEN W041 ACTIVE state.

    The seam consumes a genuine :class:`HandoffOutcome` (the result
    of :func:`handoff_to_networkpath`) and the W041 machinery
    itself, and PROVES -- before any commercial command is issued --
    that the exact referenced path is currently ``ACTIVE`` for the
    exact logical session, through the machinery's own PUBLIC
    reads only:

    - the outcome's cited ``network_path_state`` is ``ACTIVE``;
    - ``manager.path(network_path_id).state`` is CURRENTLY
      ``ACTIVE`` (a stale or hand-crafted outcome cannot survive
      this read);
    - ``manager.active_path_id(session_id)`` is exactly the
      outcome's path (the session's active path, per the
      machinery);
    - the outcome's session and proposal identities match the
      session being recorded and the coordination's proposal.

    A W051 ``ReferenceIndex`` entry alone proves only that a
    network-path-family reference EXISTS -- it can never prove the
    current state -- so it is deliberately NOT the proof here.
    Every unproven case fails closed with the typed
    ``PATH_ACTIVE_UNPROVEN`` reason and records NOTHING on the
    canonical journal.  Only after the proof does the seam drive
    ``authorize_session`` (citing the REAL logical session id) and
    ``activate_path`` (citing the REAL NetworkPath id the handoff
    accepted) on the canonical core, with deterministic command
    ids.  The core's ReferenceIndex must still resolve both
    citations (the CALLER builds that index from the session
    authority's and the NetworkPath machinery's public reads --
    exactly the W051 injection contract).  The returned record
    cites the core's resulting commercial state; it is still NOT a
    connectivity claim (the machinery's state is the connectivity
    truth, and the commercial record is its canonical commercial
    reflection).
    """
    if not isinstance(core, CommercialCore):
        raise MarketplaceError(
            MarketplaceReasonCode.INVALID_INPUT,
            "coordination requires a CommercialCore (the accepted W051 "
            "authority)",
        )
    if not isinstance(manager, NetworkPathManager):
        raise MarketplaceError(
            MarketplaceReasonCode.INVALID_INPUT,
            "the path-activation record requires a NetworkPathManager "
            "(the accepted W041 machinery whose ACTIVE state is proven)",
        )
    if not isinstance(outcome, HandoffOutcome):
        raise MarketplaceError(
            MarketplaceReasonCode.INVALID_INPUT,
            "the path-activation record requires a genuine HandoffOutcome "
            "(the NetworkPath handoff result being recorded)",
        )
    if not isinstance(session_id, str) or not session_id:
        raise MarketplaceError(
            MarketplaceReasonCode.INVALID_INPUT,
            "the path-activation record requires the real logical session "
            "id (the session authority's own identity, cited as DATA)",
        )
    # ------------------------------------------------------------------
    # The W041 ACTIVE proof (fail closed; W041 owns connectivity
    # truth, commercial PATH_ACTIVE only cites a PROVEN ACTIVE state)
    # ------------------------------------------------------------------
    if outcome.session_id != session_id:
        raise MarketplaceError(
            MarketplaceReasonCode.PATH_ACTIVE_UNPROVEN,
            "the outcome's session %r is not the session being recorded "
            "%r (the W041 ACTIVE proof must be for the EXACT session)"
            % (outcome.session_id, session_id),
        )
    if outcome.proposal_id != coordination.proposal_id:
        raise MarketplaceError(
            MarketplaceReasonCode.PATH_ACTIVE_UNPROVEN,
            "the outcome belongs to proposal %r, not this coordination's "
            "proposal %r"
            % (outcome.proposal_id, coordination.proposal_id),
        )
    if outcome.network_path_state != NetworkPathState.ACTIVE:
        raise MarketplaceError(
            MarketplaceReasonCode.PATH_ACTIVE_UNPROVEN,
            "the outcome cites machinery state %r; commercial PATH_ACTIVE "
            "may only cite the machinery's ACTIVE state"
            % outcome.network_path_state,
        )
    try:
        path = manager.path(outcome.network_path_id)
    except NetworkPathError as error:
        raise MarketplaceError(
            MarketplaceReasonCode.PATH_ACTIVE_UNPROVEN,
            "the machinery does not observe path %r (%s: %s)"
            % (
                outcome.network_path_id[:23],
                error.reason,
                error.detail,
            ),
        ) from error
    if path.state != NetworkPathState.ACTIVE:
        raise MarketplaceError(
            MarketplaceReasonCode.PATH_ACTIVE_UNPROVEN,
            "the machinery's CURRENT public state for the path is %r, "
            "not ACTIVE (a reference that exists is not a proof)"
            % path.state,
        )
    active_path = manager.active_path_id(session_id)
    if active_path != outcome.network_path_id:
        raise MarketplaceError(
            MarketplaceReasonCode.PATH_ACTIVE_UNPROVEN,
            "the machinery's active path for session %r is %r, not the "
            "outcome's path %r"
            % (session_id, active_path, outcome.network_path_id[:23]),
        )
    # ------------------------------------------------------------------
    # The canonical W051 chain (the proof held; cite the REAL ids)
    # ------------------------------------------------------------------
    step_authorize = derive_coordination_command_id(
        coordination.proposal_id, "authorize-session"
    )
    step_activate = derive_coordination_command_id(
        coordination.proposal_id, "activate-path"
    )
    try:
        core.authorize_session(
            command_id=step_authorize,
            transaction_id=coordination.transaction_id,
            actor=actor,
            source=COORDINATION_SOURCE,
            session_ref=session_id,
        )
        core.activate_path(
            command_id=step_activate,
            transaction_id=coordination.transaction_id,
            actor=actor,
            source=COORDINATION_SOURCE,
            path_ref=outcome.network_path_id,
        )
    except CommercialError as error:
        raise MarketplaceError(
            MarketplaceReasonCode.RESERVATION_REJECTED,
            "the canonical commercial authority rejected the path "
            "activation record (%s: %s)" % (error.reason, error.detail),
        ) from error
    transaction = core.transaction(coordination.transaction_id)
    return ReservationCoordination(
        proposal_id=coordination.proposal_id,
        transaction_id=coordination.transaction_id,
        commands=coordination.commands + (step_authorize, step_activate),
        commercial_state=transaction.state,
        expires_at=coordination.expires_at,
    )


__all__ = [
    "HandoffAttempt",
    "HandoffOutcome",
    "ReservationCoordination",
    "ATTEMPT_OUTCOME_VALUES",
    "DEFAULT_RESERVATION_TTL_SECONDS",
    "COORDINATION_SOURCE",
    "derive_coordination_command_id",
    "instant_plus_seconds",
    "handoff_to_networkpath",
    "coordinate_reservation",
    "record_path_activation",
]
