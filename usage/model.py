"""WORK-052 UsageLedger value model.

The frozen value records of the delivered-usage ledger
(authorization WORK-052-CORE-001 / DEC-0059):

- **UsageState / UsageAction / ACCOUNT_TRANSITIONS** -- the
  canonical usage-account lifecycle the W052 contract requires.
  One usage account meters ONE WORK-051 commercial transaction:

      OBSERVED -> RECONCILED -> BILLABLE_FINAL -> {REFUNDED,
      REVERSED, DISPUTED}

  ``OBSERVED`` is created by the first usage observation and is
  state-preserving under further observations (delayed or
  out-of-order arrivals are legal and deterministic).  A late
  observation arriving after a reconciliation honestly returns
  the account ``RECONCILED -> OBSERVED`` (the reconciliation was
  a snapshot; a NEW reconciliation must supersede it as an
  appended record -- the historical record stays immutable).
  ``BILLABLE_FINAL`` is explicit and immutable: no observation,
  reconciliation, or second finality may follow it, and the only
  outgoing edges are the three compensating families.  Every
  compensating state is terminal: refunds, reversals, and
  disputes are append-only compensating records, never rewrites.

- **UsageCommand** -- one caller-issued command with an external
  ``command_id`` (journal-level idempotency key) and a
  content-derived digest; repeated delivery of the identical
  command is an idempotent no-op, a conflicting redelivery fails
  closed.  Observations carry a SECOND identity -- the
  metering-plane ``observation_id`` -- whose durable
  observation-level idempotency (duplicate observations never
  double-charge; conflicting reuse of an observation identity
  fails closed) lives in :mod:`usage.journal` and
  :mod:`usage.lifecycle`.

- **UsageEvent** -- one append-only journaled usage fact with
  its deterministic, content-derived ``event_id``.  Every event
  identifies the previous account state, the new account state,
  the action, the causal command, the resolved causal evidence
  references, and the authoritative actor/source
  (attribution).

- **UsageAccount** -- the fold projection of one commercial
  transaction's journaled usage history (its current account
  state, the deterministically ordered observation summary, the
  latest reconciliation snapshot, the frozen billable finality,
  and the compensation records).  It is a frozen value record:
  "mutation" is always replacement by a new projected record
  derived from an appended journal record, never an in-place
  edit, and an account in a compensating terminal state can
  never be re-projected (the transition table has no outgoing
  terminal edges).

Identity discipline (the W041/W042/W051 precedent):
``event_id`` and the observation digest are CONTENT-DERIVED
fingerprints -- ``"sha256:" + sha256(canonical_json_bytes(
content))`` (WORK-003 canonical JSON).  They are fingerprints
ONLY: not NodeIDs, not trust, never an authorization, and never
a session, path, or delivery identity.  The account key is the
WORK-051 commercial transaction id (an external
authority-owned identity the ledger cites, never derives).  The
constructors mechanically verify content bindings, so a
tampered or deserialized record can never carry an
attacker-chosen id.

Temporal discipline: every instant is an injected RFC 3339 UTC
string (the WORK-033 ``AgentClock`` seam read by the ledger
manager -- one clock read per executed command; duplicates
consume no read).  No wall-clock reads, no UUIDs, no
randomness, no environment-dependent identity anywhere in this
family.  Quantity and money are INTEGERS only (canonical-JSON
DATA; floating-point values fail closed at command admission --
usage quantities and billable amounts are never floats).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import UsageLedgerError, UsageReasonCode
from .evidence import EvidenceReference


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise UsageLedgerError(
            UsageReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


def _require_instant(value: object, label: str) -> str:
    """A required RFC 3339 UTC instant string (shape-validated)."""
    from agent.clock import parse_utc

    if not isinstance(value, str) or not value:
        raise UsageLedgerError(
            UsageReasonCode.INSTANT_INVALID,
            "%s must be an RFC 3339 UTC instant string" % label,
        )
    try:
        parse_utc(value)
    except Exception as error:  # noqa: BLE001 - re-wrapped typed
        raise UsageLedgerError(
            UsageReasonCode.INSTANT_INVALID,
            "%s %r is not RFC 3339 UTC: %s" % (label, value, error),
        ) from error
    return value


def _require_mapping(value: object, label: str) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise UsageLedgerError(
            UsageReasonCode.INVALID_INPUT,
            "%s must be a mapping" % label,
        )
    return dict(value)


def _require_non_negative_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise UsageLedgerError(
            UsageReasonCode.INVALID_INPUT,
            "%s must be an integer (quantities and amounts are integer "
            "DATA; floats are rejected)" % label,
        )
    if value < 0:
        raise UsageLedgerError(
            UsageReasonCode.INVALID_INPUT,
            "%s must be non-negative" % label,
        )
    return value


# ---------------------------------------------------------------------------
# The frozen usage-account lifecycle vocabulary (W052 contract)
# ---------------------------------------------------------------------------


class UsageState:
    """The frozen canonical usage-account lifecycle states.

    ``OBSERVED`` (usage observations accumulating), ``RECONCILED``
    (an explicit reconciliation snapshot), ``BILLABLE_FINAL``
    (explicit, immutable billable finality), and the three
    compensating terminals ``REFUNDED`` / ``REVERSED`` /
    ``DISPUTED`` (append-only compensating records; terminal --
    historical usage facts are immutable and corrections are
    compensating records, never rewrites).
    """

    OBSERVED = "OBSERVED"
    RECONCILED = "RECONCILED"
    BILLABLE_FINAL = "BILLABLE_FINAL"
    REFUNDED = "REFUNDED"
    REVERSED = "REVERSED"
    DISPUTED = "DISPUTED"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.OBSERVED,
            cls.RECONCILED,
            cls.BILLABLE_FINAL,
            cls.REFUNDED,
            cls.REVERSED,
            cls.DISPUTED,
        )

    @classmethod
    def canonical_values(cls) -> Tuple[str, ...]:
        return (cls.OBSERVED, cls.RECONCILED, cls.BILLABLE_FINAL)

    @classmethod
    def compensating_values(cls) -> Tuple[str, ...]:
        return (cls.REFUNDED, cls.REVERSED, cls.DISPUTED)

    @classmethod
    def terminal_values(cls) -> Tuple[str, ...]:
        return (cls.REFUNDED, cls.REVERSED, cls.DISPUTED)


#: The frozen account-transition table.  ``""`` is the creation
#: edge (the first observation creates the account).  Further
#: observations preserve ``OBSERVED``; a late observation after
#: a reconciliation honestly reopens the account
#: (``RECONCILED -> OBSERVED``) so a NEW reconciliation record
#: must supersede the snapshot (append-only, history immutable).
#: ``BILLABLE_FINAL`` has outgoing edges ONLY to the three
#: compensating families (finality is immutable: no observation,
#: re-reconciliation, or second finality may follow).  Every
#: compensating state is terminal: no outgoing edges.
ACCOUNT_TRANSITIONS: Dict[str, frozenset] = {
    "": frozenset({UsageState.OBSERVED}),
    UsageState.OBSERVED: frozenset({UsageState.OBSERVED, UsageState.RECONCILED}),
    UsageState.RECONCILED: frozenset(
        {
            UsageState.OBSERVED,
            UsageState.RECONCILED,
            UsageState.BILLABLE_FINAL,
        }
    ),
    UsageState.BILLABLE_FINAL: frozenset(
        {UsageState.REFUNDED, UsageState.REVERSED, UsageState.DISPUTED}
    ),
    UsageState.REFUNDED: frozenset(),
    UsageState.REVERSED: frozenset(),
    UsageState.DISPUTED: frozenset(),
}


def transition_is_legal(from_state: str, to_state: str) -> bool:
    """True iff the account-transition table allows the edge.

    Unknown states fail closed (``False``): an out-of-vocabulary
    state can never transition anywhere, least of all into
    ``BILLABLE_FINAL`` or a compensating state.
    """
    if from_state not in ACCOUNT_TRANSITIONS:
        return False
    return to_state in ACCOUNT_TRANSITIONS[from_state]


class UsageAction:
    """The frozen journaled command/action vocabulary.

    ``INGEST_OBSERVATION`` is the usage-metering admission
    action (validates evidence, deduplicates, journals the
    observation fact).  ``RECONCILE`` appends an explicit
    reconciliation snapshot (observed delivery -> billable
    quantity/amount).  ``FINALIZE_BILLABLE`` appends the
    explicit, immutable billable finality record.  The three
    compensating actions append refund/reversal/dispute records
    (corrections are compensating records, never rewrites).
    """

    INGEST_OBSERVATION = "ingest_observation"
    RECONCILE = "reconcile"
    FINALIZE_BILLABLE = "finalize_billable"
    COMPENSATE_REFUND = "compensate_refund"
    COMPENSATE_REVERSAL = "compensate_reversal"
    COMPENSATE_DISPUTE = "compensate_dispute"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.INGEST_OBSERVATION,
            cls.RECONCILE,
            cls.FINALIZE_BILLABLE,
            cls.COMPENSATE_REFUND,
            cls.COMPENSATE_REVERSAL,
            cls.COMPENSATE_DISPUTE,
        )

    @classmethod
    def compensating_values(cls) -> Tuple[str, ...]:
        return (
            cls.COMPENSATE_REFUND,
            cls.COMPENSATE_REVERSAL,
            cls.COMPENSATE_DISPUTE,
        )


#: Which account state each action requires BEFORE it may run
#: (the fail-closed precondition gate; the manager enforces this
#: in addition to the transition table so duplicate, stale, and
#: out-of-order commands never silently succeed).
#: ``INGEST_OBSERVATION`` may create the account ("" -- the
#: creation edge) or run against an open account (``OBSERVED``
#: or ``RECONCILED``; a late arrival after reconciliation
#: honestly reopens it).
ACTION_REQUIRED_STATE: Dict[str, Tuple[str, ...]] = {
    UsageAction.INGEST_OBSERVATION: (
        "",
        UsageState.OBSERVED,
        UsageState.RECONCILED,
    ),
    UsageAction.RECONCILE: (UsageState.OBSERVED, UsageState.RECONCILED),
    UsageAction.FINALIZE_BILLABLE: (UsageState.RECONCILED,),
    UsageAction.COMPENSATE_REFUND: (UsageState.BILLABLE_FINAL,),
    UsageAction.COMPENSATE_REVERSAL: (UsageState.BILLABLE_FINAL,),
    UsageAction.COMPENSATE_DISPUTE: (UsageState.BILLABLE_FINAL,),
}


#: The target account state of each action (the table's to-state).
#: For ``INGEST_OBSERVATION`` the target is state-preserving
#: (``OBSERVED``) except on the ``RECONCILED -> OBSERVED`` late
#: arrival edge (computed by the manager from the current
#: account state; the transition table is the authority).
ACTION_TARGET_STATE: Dict[str, str] = {
    UsageAction.INGEST_OBSERVATION: UsageState.OBSERVED,
    UsageAction.RECONCILE: UsageState.RECONCILED,
    UsageAction.FINALIZE_BILLABLE: UsageState.BILLABLE_FINAL,
    UsageAction.COMPENSATE_REFUND: UsageState.REFUNDED,
    UsageAction.COMPENSATE_REVERSAL: UsageState.REVERSED,
    UsageAction.COMPENSATE_DISPUTE: UsageState.DISPUTED,
}


# ---------------------------------------------------------------------------
# Content-derived identities (fingerprints, never trust)
# ---------------------------------------------------------------------------


def command_content(
    command_id: str,
    action: str,
    transaction_id: str,
    observation_id: str,
    references: Tuple[EvidenceReference, ...],
    payload: Mapping[str, Any],
    actor: str,
    source: str,
) -> Dict[str, Any]:
    """The canonical command content (digest basis + journal DATA)."""
    return {
        "command_id": command_id,
        "action": action,
        "transaction_id": transaction_id,
        "observation_id": observation_id,
        "references": [reference.to_dict() for reference in references],
        "payload": dict(payload),
        "actor": actor,
        "source": source,
    }


def derive_command_digest(
    command_id: str,
    action: str,
    transaction_id: str,
    observation_id: str,
    references: Tuple[EvidenceReference, ...],
    payload: Mapping[str, Any],
    actor: str,
    source: str,
) -> str:
    """The content-derived command digest (idempotency ledger).

    Same command id + same content -> same digest (idempotent
    no-op on redelivery); same command id + different content ->
    ``COMMAND_CONFLICT`` (fail closed).
    """
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(
            command_content(
                command_id,
                action,
                transaction_id,
                observation_id,
                references,
                payload,
                actor,
                source,
            )
        )
    ).hexdigest()


def observation_content(
    observation_id: str,
    transaction_id: str,
    evidence_refs: Tuple[str, ...],
    session_ref: str,
    path_ref: str,
    quantity: int,
    unit: str,
    observed_at: str,
) -> Dict[str, Any]:
    """The canonical observation content (the observation-level
    idempotency basis -- the metering fact itself, independent of
    the delivery command id it arrived under)."""
    return {
        "observation_id": observation_id,
        "transaction_id": transaction_id,
        "evidence_refs": sorted(evidence_refs),
        "session_ref": session_ref,
        "path_ref": path_ref,
        "quantity": quantity,
        "unit": unit,
        "observed_at": observed_at,
    }


def derive_observation_digest(content: Mapping[str, Any]) -> str:
    """The content-derived observation digest (duplicate
    observations with a different command id are idempotent
    no-ops; conflicting reuse of an observation identity fails
    closed)."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(dict(content))
    ).hexdigest()


def derive_event_id(
    transaction_id: str,
    action: str,
    from_state: str,
    to_state: str,
    command_id: str,
    instant: str,
) -> str:
    """Content-derived usage event id (journal identity DATA)."""
    content = {
        "transaction_id": transaction_id,
        "action": action,
        "from_state": from_state,
        "to_state": to_state,
        "command_id": command_id,
        "instant": instant,
    }
    return "sha256:" + hashlib.sha256(canonical_json_bytes(content)).hexdigest()


# ---------------------------------------------------------------------------
# Usage command (the input record)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UsageCommand:
    """One caller-issued usage-ledger command.

    ``command_id`` is the caller's journal-level idempotency key
    (an external command identity, e.g. a platform message id):
    repeated delivery of the identical command (same content
    digest) is an idempotent no-op; a redelivery with different
    content fails closed as ``COMMAND_CONFLICT``.
    ``transaction_id`` is the WORK-051 commercial transaction id
    (the account key; authority-owned identity, cited never
    derived).  ``observation_id`` carries the metering-plane
    observation identity for ``ingest_observation`` (empty for
    every other action).  ``references`` are the causal external
    evidence references (delivery evidence, session, NetworkPath
    path, commercial window, and payment observations as attached
    DATA), resolved against the injected :class:`EvidenceIndex`
    -- the ledger never queries authorities live.  ``payload``
    is command-specific DATA (observation quantity/unit/instant,
    reconciliation unit price, compensation amount/reason).
    ``actor`` and ``source`` carry attribution.
    """

    command_id: str
    action: str
    transaction_id: str
    observation_id: str
    references: Tuple[EvidenceReference, ...]
    payload: Dict[str, Any]
    actor: str
    source: str

    def __post_init__(self) -> None:
        _require_text(self.command_id, "command_id")
        if self.action not in UsageAction.values():
            raise UsageLedgerError(
                UsageReasonCode.COMMAND_INVALID,
                "action %r must be one of %s"
                % (self.action, list(UsageAction.values())),
            )
        _require_text(self.transaction_id, "transaction_id")
        if self.action == UsageAction.INGEST_OBSERVATION:
            _require_text(self.observation_id, "observation_id")
        elif self.observation_id != "":
            raise UsageLedgerError(
                UsageReasonCode.COMMAND_INVALID,
                "observation_id is carried only by ingest_observation "
                "commands",
            )
        if not isinstance(self.references, tuple):
            raise UsageLedgerError(
                UsageReasonCode.COMMAND_INVALID,
                "references must be a tuple of EvidenceReference",
            )
        for reference in self.references:
            if not isinstance(reference, EvidenceReference):
                raise UsageLedgerError(
                    UsageReasonCode.COMMAND_INVALID,
                    "references must contain EvidenceReference values",
                )
        payload = _require_mapping(self.payload, "payload")
        # normalize the list-valued observation members to tuples so
        # live-constructed and deserialized commands are EQUAL values
        # (round-trip stability: a JSON round trip turns tuples into
        # lists; the canonical bytes are identical either way)
        if self.action == UsageAction.INGEST_OBSERVATION:
            for member in ("evidence_refs", "payment_refs"):
                if member in payload:
                    raw = payload[member]
                    if isinstance(raw, tuple):
                        raw = list(raw)
                    if not isinstance(raw, list) or not all(
                        isinstance(item, str) and item for item in raw
                    ):
                        raise UsageLedgerError(
                            UsageReasonCode.COMMAND_INVALID,
                            "payload member %r must be a list of non-empty "
                            "strings" % member,
                        )
                    payload[member] = tuple(sorted(set(raw)))
        object.__setattr__(self, "payload", payload)
        for key in payload:
            if not isinstance(key, str) or not key:
                raise UsageLedgerError(
                    UsageReasonCode.INVALID_INPUT,
                    "payload keys must be non-empty strings",
                )
        _require_text(self.actor, "actor")
        _require_text(self.source, "source")
        # the command content must be canonical-JSON representable
        # (fail closed on floats and other out-of-subset values --
        # usage quantities and billable amounts are integer DATA,
        # never floating-point)
        try:
            canonical_json_bytes(
                command_content(
                    self.command_id,
                    self.action,
                    self.transaction_id,
                    self.observation_id,
                    self.references,
                    self.payload,
                    self.actor,
                    self.source,
                )
            )
        except UsageLedgerError:
            raise
        except ValueError as error:
            raise UsageLedgerError(
                UsageReasonCode.INVALID_INPUT,
                "command payload is not canonical-JSON representable "
                "(floats and unsupported value kinds are rejected): %s" % error,
            ) from error

    def content(self) -> Dict[str, Any]:
        return command_content(
            self.command_id,
            self.action,
            self.transaction_id,
            self.observation_id,
            self.references,
            self.payload,
            self.actor,
            self.source,
        )

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return self.content()

    @classmethod
    def from_dict(cls, data: object) -> "UsageCommand":
        if not isinstance(data, Mapping):
            raise UsageLedgerError(
                UsageReasonCode.COMMAND_INVALID,
                "command must be a mapping",
            )
        required = (
            "command_id",
            "action",
            "transaction_id",
            "observation_id",
            "references",
            "payload",
            "actor",
            "source",
        )
        for key in required:
            if key not in data:
                raise UsageLedgerError(
                    UsageReasonCode.COMMAND_INVALID,
                    "command is missing required member %r" % key,
                )
        raw_refs = data["references"]
        if not isinstance(raw_refs, list):
            raise UsageLedgerError(
                UsageReasonCode.COMMAND_INVALID,
                "references must be a list",
            )
        references = tuple(
            EvidenceReference.from_dict(item) for item in raw_refs
        )
        return cls(
            command_id=data["command_id"],
            action=data["action"],
            transaction_id=data["transaction_id"],
            observation_id=data["observation_id"],
            references=references,
            payload=data["payload"],
            actor=data["actor"],
            source=data["source"],
        )


# ---------------------------------------------------------------------------
# Usage event (the append-only journaled fact)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UsageEvent:
    """One append-only journaled usage fact.

    Attribution (the W052 contract): every event identifies the
    PREVIOUS account state, the NEW account state, the ACTION,
    the causal COMMAND (``command_id``), the resolved causal
    evidence REFERENCES (external evidence ids with their
    index-authoritative families), and the authoritative
    ACTOR/SOURCE.  ``event_id`` is content-derived over
    (transaction, action, from, to, command, instant) and is
    mechanically verified at construction and deserialization,
    so a tampered event can never carry an attacker-chosen id.
    ``observation_id`` links an ``ingest_observation`` event to
    its metering identity (empty for every other action).

    The payment/usage separation is structural: an event IS the
    usage fact; it may REFERENCE delivery evidence but can never
    BE delivery evidence, and no payment-family reference can
    appear among the causal evidence references of an
    observation (family validation happens at command admission;
    payment observations attach as recorded DATA only).
    """

    event_id: str
    transaction_id: str
    action: str
    from_state: str
    to_state: str
    command_id: str
    observation_id: str
    causal_references: Tuple[EvidenceReference, ...]
    actor: str
    source: str
    instant: str

    def __post_init__(self) -> None:
        _require_text(self.event_id, "event_id")
        _require_text(self.transaction_id, "transaction_id")
        if self.action not in UsageAction.values():
            raise UsageLedgerError(
                UsageReasonCode.EVENT_INVALID,
                "action %r must be one of %s"
                % (self.action, list(UsageAction.values())),
            )
        for label, value in (
            ("from_state", self.from_state),
            ("to_state", self.to_state),
        ):
            if value != "" and value not in UsageState.values():
                raise UsageLedgerError(
                    UsageReasonCode.EVENT_INVALID,
                    "%s %r must be one of %s"
                    % (label, value, list(UsageState.values())),
                )
        if not transition_is_legal(self.from_state, self.to_state):
            raise UsageLedgerError(
                UsageReasonCode.EVENT_INVALID,
                "event transition %s -> %s is not in the frozen account "
                "transition table" % (self.from_state, self.to_state),
            )
        _require_text(self.command_id, "command_id")
        if self.action == UsageAction.INGEST_OBSERVATION:
            _require_text(self.observation_id, "observation_id")
        elif self.observation_id != "":
            raise UsageLedgerError(
                UsageReasonCode.EVENT_INVALID,
                "event observation_id is carried only by "
                "ingest_observation events",
            )
        if not isinstance(self.causal_references, tuple):
            raise UsageLedgerError(
                UsageReasonCode.EVENT_INVALID,
                "causal_references must be a tuple of EvidenceReference",
            )
        for reference in self.causal_references:
            if not isinstance(reference, EvidenceReference):
                raise UsageLedgerError(
                    UsageReasonCode.EVENT_INVALID,
                    "causal_references must contain EvidenceReference values",
                )
        _require_text(self.actor, "actor")
        _require_text(self.source, "source")
        _require_instant(self.instant, "instant")
        expected = derive_event_id(
            self.transaction_id,
            self.action,
            self.from_state,
            self.to_state,
            self.command_id,
            self.instant,
        )
        if self.event_id != expected:
            raise UsageLedgerError(
                UsageReasonCode.EVENT_INVALID,
                "event_id %s does not match the content-derived id %s "
                "(tampered or malformed event)" % (self.event_id, expected),
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "transaction_id": self.transaction_id,
            "action": self.action,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "command_id": self.command_id,
            "observation_id": self.observation_id,
            "causal_references": [
                reference.to_dict() for reference in self.causal_references
            ],
            "actor": self.actor,
            "source": self.source,
            "instant": self.instant,
        }

    @classmethod
    def from_dict(cls, data: object) -> "UsageEvent":
        if not isinstance(data, Mapping):
            raise UsageLedgerError(
                UsageReasonCode.EVENT_INVALID,
                "event must be a mapping",
            )
        required = (
            "event_id",
            "transaction_id",
            "action",
            "from_state",
            "to_state",
            "command_id",
            "observation_id",
            "causal_references",
            "actor",
            "source",
            "instant",
        )
        for key in required:
            if key not in data:
                raise UsageLedgerError(
                    UsageReasonCode.EVENT_INVALID,
                    "event is missing required member %r" % key,
                )
        raw_refs = data["causal_references"]
        if not isinstance(raw_refs, list):
            raise UsageLedgerError(
                UsageReasonCode.EVENT_INVALID,
                "causal_references must be a list",
            )
        references = tuple(
            EvidenceReference.from_dict(item) for item in raw_refs
        )
        return cls(
            event_id=data["event_id"],
            transaction_id=data["transaction_id"],
            action=data["action"],
            from_state=data["from_state"],
            to_state=data["to_state"],
            command_id=data["command_id"],
            observation_id=data["observation_id"],
            causal_references=references,
            actor=data["actor"],
            source=data["source"],
            instant=data["instant"],
        )


def event_list_digest(events: Tuple[UsageEvent, ...]) -> str:
    """Deterministic digest over the ordered journal event list."""
    content = {
        "kind": "usage-event-list",
        "events": [event.to_dict() for event in events],
    }
    return "sha256:" + hashlib.sha256(canonical_json_bytes(content)).hexdigest()


# ---------------------------------------------------------------------------
# Usage account (the fold projection)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UsageAccount:
    """The current projected usage state of one commercial
    transaction.

    This is a FOLD PROJECTION of the journaled history, not an
    independently mutable record: every field is derived from the
    appended journal records, replacement happens only through
    the journal (apply_record -> new projection), and an account
    in a compensating terminal state can never be re-projected
    (the transition table has no outgoing terminal edges).
    Delivery evidence and payment DATA stay separated by
    construction: ``evidence_refs`` accumulates only
    delivery-evidence-family citations; payment observations live
    in ``payment_refs`` (DATA only -- they can never justify
    usage).

    ``observations`` is the deterministically ordered observation
    summary (sorted by (observed_at, observation_id) -- arrival
    order independent): each entry is [observation_id,
    observed_at, quantity, evidence_digest].  ``total_quantity``
    is the deterministic sum.  ``reconciliation`` is the latest
    reconciliation snapshot (observation ids, total quantity,
    unit price, derived amount).  ``finality`` is the frozen
    billable fact.  ``compensations`` lists the compensating
    records and ``compensated_amount`` their refund/reversal sum.
    """

    transaction_id: str
    state: str
    actor: str
    source: str
    created_at: str
    session_ref: str
    path_ref: str
    unit: str
    observations: Tuple[Tuple[str, str, int, str], ...]
    total_quantity: int
    evidence_refs: Tuple[str, ...]
    payment_refs: Tuple[str, ...]
    reconciliation: Dict[str, Any]
    finality: Dict[str, Any]
    compensations: Tuple[Dict[str, Any], ...]
    compensated_amount: int
    last_action: str
    last_instant: str
    event_count: int

    def __post_init__(self) -> None:
        _require_text(self.transaction_id, "transaction_id")
        if self.state not in UsageState.values():
            raise UsageLedgerError(
                UsageReasonCode.EVENT_INVALID,
                "account state %r must be one of %s"
                % (self.state, list(UsageState.values())),
            )
        _require_text(self.actor, "actor")
        _require_text(self.source, "source")
        _require_instant(self.created_at, "created_at")
        _require_text(self.session_ref, "session_ref")
        _require_text(self.path_ref, "path_ref")
        _require_text(self.unit, "unit")
        if not isinstance(self.observations, tuple):
            raise UsageLedgerError(
                UsageReasonCode.EVENT_INVALID,
                "observations must be a tuple",
            )
        for entry in self.observations:
            if (
                not isinstance(entry, tuple)
                or len(entry) != 4
                or not isinstance(entry[0], str)
                or not entry[0]
                or not isinstance(entry[1], str)
                or not entry[1]
                or not isinstance(entry[2], int)
                or isinstance(entry[2], bool)
                or not isinstance(entry[3], str)
                or not entry[3]
            ):
                raise UsageLedgerError(
                    UsageReasonCode.EVENT_INVALID,
                    "observations entries must be (observation_id, "
                    "observed_at, quantity, evidence_digest) tuples",
                )
        if not isinstance(self.total_quantity, int) or isinstance(
            self.total_quantity, bool
        ):
            raise UsageLedgerError(
                UsageReasonCode.EVENT_INVALID,
                "total_quantity must be an integer",
            )
        for label, value in (
            ("evidence_refs", self.evidence_refs),
            ("payment_refs", self.payment_refs),
        ):
            if not isinstance(value, tuple):
                raise UsageLedgerError(
                    UsageReasonCode.EVENT_INVALID,
                    "%s must be a tuple" % label,
                )
            for item in value:
                if not isinstance(item, str) or not item:
                    raise UsageLedgerError(
                        UsageReasonCode.EVENT_INVALID,
                        "%s must contain non-empty strings" % label,
                    )
        for label, value in (
            ("reconciliation", self.reconciliation),
            ("finality", self.finality),
        ):
            if not isinstance(value, Mapping):
                raise UsageLedgerError(
                    UsageReasonCode.EVENT_INVALID,
                    "%s must be a mapping (or empty)" % label,
                )
        if not isinstance(self.compensations, tuple):
            raise UsageLedgerError(
                UsageReasonCode.EVENT_INVALID,
                "compensations must be a tuple of mappings",
            )
        for entry in self.compensations:
            if not isinstance(entry, Mapping):
                raise UsageLedgerError(
                    UsageReasonCode.EVENT_INVALID,
                    "compensations entries must be mappings",
                )
        if not isinstance(self.compensated_amount, int) or isinstance(
            self.compensated_amount, bool
        ):
            raise UsageLedgerError(
                UsageReasonCode.EVENT_INVALID,
                "compensated_amount must be an integer",
            )
        if self.last_action not in UsageAction.values():
            raise UsageLedgerError(
                UsageReasonCode.EVENT_INVALID,
                "last_action %r must be one of %s"
                % (self.last_action, list(UsageAction.values())),
            )
        _require_instant(self.last_instant, "last_instant")
        if not isinstance(self.event_count, int) or isinstance(
            self.event_count, bool
        ):
            raise UsageLedgerError(
                UsageReasonCode.EVENT_INVALID,
                "event_count must be an integer",
            )
        # canonical-JSON representability (the projection is
        # digestable evidence)
        try:
            canonical_json_bytes(self.content())
        except UsageLedgerError:
            raise
        except ValueError as error:
            raise UsageLedgerError(
                UsageReasonCode.EVENT_INVALID,
                "account projection is not canonical-JSON representable: %s"
                % error,
            ) from error

    def terminal(self) -> bool:
        return self.state in UsageState.terminal_values()

    def finalized(self) -> bool:
        return self.state == UsageState.BILLABLE_FINAL or self.terminal()

    def content(self) -> Dict[str, Any]:
        return {
            "transaction_id": self.transaction_id,
            "state": self.state,
            "actor": self.actor,
            "source": self.source,
            "created_at": self.created_at,
            "session_ref": self.session_ref,
            "path_ref": self.path_ref,
            "unit": self.unit,
            "observations": [
                [entry[0], entry[1], entry[2], entry[3]]
                for entry in self.observations
            ],
            "total_quantity": self.total_quantity,
            "evidence_refs": list(self.evidence_refs),
            "payment_refs": list(self.payment_refs),
            "reconciliation": dict(self.reconciliation),
            "finality": dict(self.finality),
            "compensations": [dict(entry) for entry in self.compensations],
            "compensated_amount": self.compensated_amount,
            "last_action": self.last_action,
            "last_instant": self.last_instant,
            "event_count": self.event_count,
        }

    def to_dict(self) -> Dict[str, Any]:
        return self.content()


def account_digest(account: UsageAccount) -> str:
    """Deterministic digest of one account projection."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(account.content())
    ).hexdigest()


def sorted_observation_summary(
    observations: Tuple[Tuple[str, str, int, str], ...]
) -> Tuple[Tuple[str, str, int, str], ...]:
    """The deterministic observation order: sorted by
    (observed_at, observation_id) -- arrival-order independent
    (delayed and out-of-order observations produce the same
    ordered summary and therefore the same billable facts)."""
    return tuple(sorted(observations, key=lambda entry: (entry[1], entry[0])))
