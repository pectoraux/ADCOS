"""WORK-044 payment-boundary append-only journal and durable
persistence seam.

The journal-first durable core of the payment history (the
W042 journal-first discipline the W044 contract requires
reused, mirroring the accepted W051/W052/W053 journals):

    immutable payment records
        + append-only file discipline
        + content-derived record ids
        + a hash chain over (sequence, content, previous link)
        = tamper-evident, deterministically replayable payment
          history

Discipline (battery-pinned, mirroring the accepted siblings):

- **atomic command records**: every executed command appends
  EXACTLY ONE journal record carrying the admitted command
  (input + content digest, the durable command-idempotency
  ledger), the resulting payment event (the fact with full
  attribution), and the durable identity digests the action
  owns: the intent-identity digest for ``create_intent``
  commands (derived from the command's OWN intent DATA, never
  from external citations, so the intent idempotency decision
  is made BEFORE live citation resolution), the payout-identity
  digest for ``emit_payout`` records (derived from the event's
  emission basis -- the resolved allocation citation's public
  split DATA), the callback-event digest for ``ingest_callback``
  records (the provider anti-replay key), and the
  capability-identity digest for ``record_capabilities``
  commands (the immutable declaration content).  One append =
  one atomic persist-then-ack; there is no intermediate state
  where a command is admitted without its fact.
- **content-derived ids**: every ``record_id`` is the
  fingerprint of (sequence, record content, previous record
  id) -- the hash chain; every ``event_id`` is the fingerprint
  of its content; every ``command_digest`` is the fingerprint
  of the command content.  All are mechanically verified at
  construction and on deserialization, so a tampered record
  can never carry an attacker-chosen id.
- **canonical serialization**: one canonical-JSON line per
  record (the WORK-003 profile); identical logical histories
  produce byte-identical journals.
- **immutable records**: there is NO API that modifies,
  rewrites, or removes a journal record; the file discipline
  is append-only (``ab``), so the journal can only grow --
  settled or historical payment facts can never be edited in
  place.
- **deterministic replay**: loading and folding the same
  journal bytes always reproduces the same payment state (the
  fold lives in :mod:`payment.lifecycle` and reuses the single
  apply function the gateway itself uses).
- **five-layer duplicate detection**: the command ledger, the
  intent ledger, the payout ledger, the callback-event ledger,
  and the capability ledger are all journaled with each
  relevant record (idempotency survives restart); a duplicate
  command id, intent id, payout usage-record id, callback
  event id, or capability key in a stored journal fails
  closed at load.
- **corruption/tamper detection**: load verifies every record
  id, the chain links, the contiguous 1..N sequence, every
  command digest, every action-owned identity digest, the
  command/event pairing, and duplicate ledger keys -- any
  tampered byte, reordered line, truncated tail, sequence gap,
  or duplicate pair fails closed ``journal-corrupt``.
- **persist-then-ack**: the journal is persisted BEFORE the
  in-memory record is acknowledged; a store failure leaves no
  phantom in-memory state (``store-failed``).

Callback records: the gateway synthesizes the journaled
command deterministically (``callback:<event_id>``, the
observation payload, the ingress attribution) so every journal
record carries the same (command, event) shape -- the
provider's event id remains the semantic anti-replay key in
the dedicated callback ledger.

The persistence seam (:class:`PaymentStore`) is injectable:
:class:`MemoryPaymentStore` keeps verification deterministic
and in-process; :class:`FilePaymentStore` is the real durable
store (the only filesystem-write site in the payment family,
battery-audited).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Tuple

from protocol.canonicalization import canonical_json_bytes

from .capabilities import ProviderCapabilities
from .errors import PaymentError, PaymentReasonCode
from .immutability import deep_freeze
from .model import (
    CallbackObservation,
    PaymentAction,
    PaymentCommand,
    PaymentEvent,
    derive_intent_digest,
    derive_payout_digest,
    intent_content,
    observation_digest,
    payout_content,
)

#: The record-kind vocabulary: one discriminated family.
JOURNAL_RECORD_KIND = "payment-record"

GENESIS_RECORD_ID = "sha256:" + "0" * 64


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise PaymentError(
            PaymentReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


def derive_record_id(
    sequence: int, record_content: Dict[str, Any], prev_record_id: str
) -> str:
    """The content-derived journal record fingerprint (hash chain).

    Binds the record to its position (sequence), its content
    (the admitted command + its event + the durable identity
    digests), and the ENTIRE preceding journal (prev link).
    """
    content = {
        "sequence": sequence,
        "record_kind": JOURNAL_RECORD_KIND,
        "record": record_content,
        "prev_record_id": prev_record_id,
    }
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(content)
    ).hexdigest()


def record_content(
    command: PaymentCommand,
    command_digest: str,
    event: PaymentEvent,
    intent_digest: str,
    payout_digest: str,
    callback_digest: str,
    capability_digest: str,
) -> Dict[str, Any]:
    """The canonical journal record content (command + fact + the
    action-owned durable identity digests)."""
    return {
        "command": command.to_dict(),
        "command_digest": command_digest,
        "event": event.to_dict(),
        "intent_digest": intent_digest,
        "payout_digest": payout_digest,
        "callback_digest": callback_digest,
        "capability_digest": capability_digest,
    }


def intent_digest_for_command(command: PaymentCommand) -> str:
    """The durable intent-identity digest of a ``create_intent``
    command (content-derived over the command's OWN intent DATA
    -- never over external citations, so the intent idempotency
    decision is made BEFORE live citation resolution).
    Non-creation commands carry the empty digest ``""``."""
    if command.action != PaymentAction.CREATE_INTENT:
        return ""
    payload = command.payload
    return derive_intent_digest(
        intent_content(
            command.entity_id,
            payload.get("transaction_id", ""),
            payload.get("usage_record_id", ""),
            payload.get("amount", 0),
            payload.get("currency", ""),
            payload.get("exponent", 0),
            payload.get("description", ""),
        )
    )


def payout_digest_for_event(event: PaymentEvent) -> str:
    """The durable payout-identity digest of an ``emit_payout``
    record (content-derived over the EVENT's emission basis --
    the resolved allocation citation's public split DATA, which
    lives in the event because the command's citations are thin
    and resolved live).  Non-payout events carry the empty
    digest ``""``.  A malformed stored payout payload fails
    closed ``journal-corrupt`` (the live admission path
    validates the emission basis BEFORE any journal record
    exists)."""
    if event.action != PaymentAction.EMIT_PAYOUT:
        return ""
    payload = event.payload
    try:
        return derive_payout_digest(
            payout_content(
                payload["usage_record_id"],
                payload["transaction_id"],
                payload["allocation_state"],
                payload["billable_amount"],
                payload["currency"],
                payload["exponent"],
                payload["developer_amount"],
                payload["provider_amount"],
                payload["adc_os_amount"],
                payload["tax_amount"],
            )
        )
    except (KeyError, TypeError) as error:
        raise PaymentError(
            PaymentReasonCode.JOURNAL_CORRUPT,
            "stored payout emission basis is malformed: %s" % error,
        ) from error


def capability_digest_for_command(command: PaymentCommand) -> str:
    """The durable capability-identity digest of a
    ``record_capabilities`` command (the immutable declaration
    content digest).  Non-capability commands carry the empty
    digest ``""``.  A malformed stored declaration fails closed
    ``journal-corrupt``."""
    if command.action != PaymentAction.RECORD_CAPABILITIES:
        return ""
    try:
        declaration = ProviderCapabilities.from_dict(dict(command.payload))
    except PaymentError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise PaymentError(
            PaymentReasonCode.JOURNAL_CORRUPT,
            "stored capability payload is malformed: %s" % error,
        ) from error
    return declaration.digest()


def observation_for_event(event: PaymentEvent) -> CallbackObservation:
    """Reconstruct the recorded observation of one
    ``ingest_callback`` event (the fold basis and the
    callback-anti-replay digest basis)."""
    if event.action != PaymentAction.INGEST_CALLBACK:
        raise PaymentError(
            PaymentReasonCode.JOURNAL_CORRUPT,
            "event %r is not an observation event" % event.event_id,
        )
    payload = event.payload
    try:
        return CallbackObservation(
            event_id=event.entity_id,
            provider_id=payload["provider_id"],
            provider_ref=payload["provider_ref"],
            kind=payload["kind"],
            canonical_status=payload["canonical_status"],
            amounts=dict(payload.get("amounts", {})),
            occurred_at=payload["occurred_at"],
            signature=payload["signature"],
            observed_at=event.instant,
            orphan=payload["orphan"],
            applied=False,
        )
    except (KeyError, TypeError) as error:
        raise PaymentError(
            PaymentReasonCode.JOURNAL_CORRUPT,
            "stored observation payload is malformed: %s" % error,
        ) from error


def callback_digest_for_event(event: PaymentEvent) -> str:
    """The durable callback anti-replay digest of an
    ``ingest_callback`` record (the observation digest of the
    recorded external observation).  Non-callback events carry
    the empty digest ``""``."""
    if event.action != PaymentAction.INGEST_CALLBACK:
        return ""
    return observation_digest(observation_for_event(event))


@dataclass(frozen=True)
class JournalRecord:
    """One append-only journal record: an admitted command, its
    resulting payment event, and the durable identity digests
    the action owns (intent / payout / callback-event /
    capability; ``""`` where the action owns none).

    ``record_id`` is the hash-chain fingerprint over (sequence,
    {command, command_digest, event, the four identity digests},
    prev) and is mechanically verified at construction and on
    deserialization.
    """

    sequence: int
    record_id: str
    command: PaymentCommand
    command_digest: str
    event: PaymentEvent
    intent_digest: str
    payout_digest: str
    callback_digest: str
    capability_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.sequence, int) or isinstance(
            self.sequence, bool
        ):
            raise PaymentError(
                PaymentReasonCode.JOURNAL_CORRUPT,
                "sequence must be an integer",
            )
        if self.sequence < 1:
            raise PaymentError(
                PaymentReasonCode.JOURNAL_CORRUPT,
                "sequence must be >= 1 (contiguous 1..N journal)",
            )
        _require_text(self.record_id, "record_id")
        if not isinstance(self.command, PaymentCommand):
            raise PaymentError(
                PaymentReasonCode.JOURNAL_CORRUPT,
                "record must carry a PaymentCommand",
            )
        _require_text(self.command_digest, "command_digest")
        if not isinstance(self.event, PaymentEvent):
            raise PaymentError(
                PaymentReasonCode.JOURNAL_CORRUPT,
                "record must carry a PaymentEvent",
            )
        if self.command.action != self.event.action:
            raise PaymentError(
                PaymentReasonCode.JOURNAL_CORRUPT,
                "record action %r does not match the event action %r"
                % (self.command.action, self.event.action),
            )
        if self.command.entity_id != self.event.entity_id:
            raise PaymentError(
                PaymentReasonCode.JOURNAL_CORRUPT,
                "record entity id %r does not match the event entity "
                "id %r"
                % (self.command.entity_id, self.event.entity_id),
            )
        for label, digest in (
            ("intent_digest", self.intent_digest),
            ("payout_digest", self.payout_digest),
            ("callback_digest", self.callback_digest),
            ("capability_digest", self.capability_digest),
        ):
            if not isinstance(digest, str):
                raise PaymentError(
                    PaymentReasonCode.JOURNAL_CORRUPT,
                    "%s must be a string" % label,
                )
        expected_intent_digest = intent_digest_for_command(self.command)
        if self.intent_digest != expected_intent_digest:
            raise PaymentError(
                PaymentReasonCode.JOURNAL_CORRUPT,
                "record %d intent digest %s does not match the "
                "recomputed digest %s (tampered intent identity)"
                % (
                    self.sequence,
                    self.intent_digest,
                    expected_intent_digest,
                ),
            )
        expected_payout_digest = payout_digest_for_event(self.event)
        if self.payout_digest != expected_payout_digest:
            raise PaymentError(
                PaymentReasonCode.JOURNAL_CORRUPT,
                "record %d payout digest %s does not match the "
                "recomputed digest %s (tampered payout basis)"
                % (
                    self.sequence,
                    self.payout_digest,
                    expected_payout_digest,
                ),
            )
        expected_capability_digest = capability_digest_for_command(
            self.command
        )
        if self.capability_digest != expected_capability_digest:
            raise PaymentError(
                PaymentReasonCode.JOURNAL_CORRUPT,
                "record %d capability digest %s does not match the "
                "recomputed digest %s (tampered declaration)"
                % (
                    self.sequence,
                    self.capability_digest,
                    expected_capability_digest,
                ),
            )
        expected_callback_digest = callback_digest_for_event(self.event)
        if self.callback_digest != expected_callback_digest:
            raise PaymentError(
                PaymentReasonCode.JOURNAL_CORRUPT,
                "record %d callback digest %s does not match the "
                "recomputed digest %s (tampered observation)"
                % (
                    self.sequence,
                    self.callback_digest,
                    expected_callback_digest,
                ),
            )

    def content(self) -> Dict[str, Any]:
        return record_content(
            self.command,
            self.command_digest,
            self.event,
            self.intent_digest,
            self.payout_digest,
            self.callback_digest,
            self.capability_digest,
        )

    def verify_id(self, prev_record_id: str) -> None:
        """Mechanical content binding (the hash-chain gate)."""
        expected = derive_record_id(
            self.sequence, self.content(), prev_record_id
        )
        if self.record_id != expected:
            raise PaymentError(
                PaymentReasonCode.JOURNAL_CORRUPT,
                "record %d id %s does not match the content-derived id %s "
                "(tampered journal record)"
                % (self.sequence, self.record_id, expected),
            )

    def verify_command_digest(self) -> None:
        """The command digest must recompute from the command
        (a tampered command in a stored journal fails closed)."""
        expected = self.command.digest()
        if self.command_digest != expected:
            raise PaymentError(
                PaymentReasonCode.JOURNAL_CORRUPT,
                "record %d command digest %s does not match the "
                "recomputed digest %s (tampered command)"
                % (self.sequence, self.command_digest, expected),
            )

    def to_dict(self) -> Dict[str, Any]:
        content = self.content()
        content["sequence"] = self.sequence
        content["record_id"] = self.record_id
        return content

    @classmethod
    def from_dict(cls, data: object) -> "JournalRecord":
        if not isinstance(data, Mapping):
            raise PaymentError(
                PaymentReasonCode.JOURNAL_CORRUPT,
                "journal record must be a mapping",
            )
        for member in (
            "sequence",
            "record_id",
            "command",
            "command_digest",
            "event",
            "intent_digest",
            "payout_digest",
            "callback_digest",
            "capability_digest",
        ):
            if member not in data:
                raise PaymentError(
                    PaymentReasonCode.JOURNAL_CORRUPT,
                    "journal record is missing required member %r"
                    % member,
                )
        command = PaymentCommand.from_dict(data["command"])
        event_payload = dict(data["event"])
        event = PaymentEvent(
            event_id=event_payload["event_id"],
            action=event_payload["action"],
            entity_kind=event_payload["entity_kind"],
            entity_id=event_payload["entity_id"],
            outcome=event_payload["outcome"],
            from_state=event_payload["from_state"],
            to_state=event_payload["to_state"],
            payload=event_payload.get("payload", {}),
            instant=event_payload["instant"],
            actor=event_payload["actor"],
            source=event_payload["source"],
        )
        return cls(
            sequence=data["sequence"],
            record_id=data["record_id"],
            command=command,
            command_digest=data["command_digest"],
            event=event,
            intent_digest=data["intent_digest"],
            payout_digest=data["payout_digest"],
            callback_digest=data["callback_digest"],
            capability_digest=data["capability_digest"],
        )


def journal_bytes_for(record: JournalRecord) -> bytes:
    """One canonical-JSON line for one record (the persist
    basis)."""
    return canonical_json_bytes(record.to_dict()) + b"\n"


class PaymentStore:
    """The injectable durable persistence seam (fail closed)."""

    def append(self, record_bytes: bytes) -> None:
        raise NotImplementedError

    def load_bytes(self) -> Tuple[bytes, ...]:
        raise NotImplementedError


class MemoryPaymentStore(PaymentStore):
    """The deterministic in-process store (verification and
    batteries)."""

    def __init__(self) -> None:
        self._chunks: List[bytes] = []

    def append(self, record_bytes: bytes) -> None:
        if not isinstance(record_bytes, (bytes, bytearray)):
            raise PaymentError(
                PaymentReasonCode.STORE_FAILED,
                "record bytes must be bytes",
            )
        self._chunks.append(bytes(record_bytes))

    def load_bytes(self) -> Tuple[bytes, ...]:
        return tuple(self._chunks)


class FilePaymentStore(PaymentStore):
    """The real durable store: an append-only file, one
    canonical-JSON record per line (the only filesystem-write
    site in the payment family, battery-audited)."""

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path):
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "path must be a pathlib.Path",
            )
        self._path = path

    def append(self, record_bytes: bytes) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("ab") as handle:
                handle.write(bytes(record_bytes))
                handle.flush()
        except OSError as error:
            raise PaymentError(
                PaymentReasonCode.STORE_FAILED,
                "persist failed before acknowledgement: %s" % error,
            ) from error

    def load_bytes(self) -> Tuple[bytes, ...]:
        if not self._path.exists():
            return ()
        try:
            raw = self._path.read_bytes()
        except OSError as error:
            raise PaymentError(
                PaymentReasonCode.STORE_FAILED,
                "store read failed: %s" % error,
            ) from error
        lines = [line for line in raw.split(b"\n") if line.strip()]
        return tuple(lines)


class AppendOnlyPaymentJournal:
    """The append-only, hash-chained payment journal (the ONLY
    history the payment boundary owns).

    Construction verifies the ENTIRE stored journal (record
    ids, chain links, contiguous sequence, command digests,
    action-owned identity digests, command/event pairing, and
    the five duplicate-ledger keys) -- a tampered or corrupt
    store fails closed ``journal-corrupt`` and constructs
    nothing.
    """

    def __init__(self, *, store: PaymentStore) -> None:
        if not isinstance(store, PaymentStore):
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "store must be a PaymentStore",
            )
        self._store = store
        self._records: List[JournalRecord] = []
        self._command_ledger: Dict[str, Dict[str, str]] = {}
        self._intent_ledger: Dict[str, Dict[str, str]] = {}
        self._payout_ledger: Dict[str, Dict[str, str]] = {}
        self._callback_ledger: Dict[str, Dict[str, str]] = {}
        self._capability_ledger: Dict[str, Dict[str, str]] = {}
        prev = GENESIS_RECORD_ID
        expected_sequence = 1
        for line in store.load_bytes():
            try:
                payload = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise PaymentError(
                    PaymentReasonCode.JOURNAL_CORRUPT,
                    "journal line is not canonical JSON: %s" % error,
                ) from error
            record = JournalRecord.from_dict(payload)
            if record.sequence != expected_sequence:
                raise PaymentError(
                    PaymentReasonCode.JOURNAL_CORRUPT,
                    "journal sequence gap: expected %d, found %d"
                    % (expected_sequence, record.sequence),
                )
            record.verify_id(prev)
            record.verify_command_digest()
            self._register(record)
            self._records.append(record)
            prev = record.record_id
            expected_sequence += 1

    def _register(self, record: JournalRecord) -> None:
        """Populate the five durable idempotency ledgers (a
        duplicate key in a stored journal fails closed)."""
        command = record.command
        existing = self._command_ledger.get(command.command_id)
        if existing is not None:
            raise PaymentError(
                PaymentReasonCode.JOURNAL_CORRUPT,
                "duplicate command id %r in the stored journal"
                % command.command_id,
            )
        self._command_ledger[command.command_id] = deep_freeze({
            "command_digest": record.command_digest,
            "event_id": record.event.event_id,
        })
        if record.intent_digest:
            existing_intent = self._intent_ledger.get(command.entity_id)
            if existing_intent is not None:
                raise PaymentError(
                    PaymentReasonCode.JOURNAL_CORRUPT,
                    "duplicate intent identity %r in the stored journal"
                    % command.entity_id,
                )
            self._intent_ledger[command.entity_id] = deep_freeze({
                "intent_digest": record.intent_digest,
                "event_id": record.event.event_id,
            })
        if record.payout_digest:
            existing_payout = self._payout_ledger.get(command.entity_id)
            if existing_payout is not None:
                raise PaymentError(
                    PaymentReasonCode.JOURNAL_CORRUPT,
                    "duplicate payout identity %r in the stored journal"
                    % command.entity_id,
                )
            self._payout_ledger[command.entity_id] = deep_freeze({
                "payout_digest": record.payout_digest,
                "event_id": record.event.event_id,
            })
        if record.callback_digest:
            existing_event = self._callback_ledger.get(command.entity_id)
            if existing_event is not None:
                raise PaymentError(
                    PaymentReasonCode.JOURNAL_CORRUPT,
                    "duplicate callback event id %r in the stored journal"
                    % command.entity_id,
                )
            self._callback_ledger[command.entity_id] = deep_freeze({
                "callback_digest": record.callback_digest,
                "event_id": record.event.event_id,
            })
        if record.capability_digest:
            existing_capability = self._capability_ledger.get(
                command.entity_id
            )
            if existing_capability is not None:
                raise PaymentError(
                    PaymentReasonCode.JOURNAL_CORRUPT,
                    "duplicate capability key %r in the stored journal"
                    % command.entity_id,
                )
            self._capability_ledger[command.entity_id] = deep_freeze({
                "capability_digest": record.capability_digest,
                "event_id": record.event.event_id,
            })

    def append(self, record: JournalRecord) -> None:
        """Persist-then-ack: the record is written to the store
        BEFORE the in-memory ledger is updated; a store failure
        leaves no phantom in-memory state."""
        record.verify_id(self.tail_record_id())
        record.verify_command_digest()
        payload = journal_bytes_for(record)
        self._store.append(payload)
        self._register(record)
        self._records.append(record)

    def records(self) -> Tuple[JournalRecord, ...]:
        return tuple(self._records)

    def journal_bytes(self) -> bytes:
        return b"".join(journal_bytes_for(r) for r in self._records)

    def journal_digest(self) -> str:
        """The tamper-evident fingerprint of the whole journal."""
        return "sha256:" + hashlib.sha256(self.journal_bytes()).hexdigest()

    def tail_sequence(self) -> int:
        return len(self._records)

    def tail_record_id(self) -> str:
        if not self._records:
            return GENESIS_RECORD_ID
        return self._records[-1].record_id

    def __len__(self) -> int:
        return len(self._records)

    # -----------------------------------------------------------------
    # durable idempotency lookups (the five layers)
    # -----------------------------------------------------------------

    def known_command(self, command_id: str) -> Optional[Dict[str, str]]:
        return self._command_ledger.get(command_id)

    def known_intent(self, intent_id: str) -> Optional[Dict[str, str]]:
        return self._intent_ledger.get(intent_id)

    def known_payout(self, usage_record_id: str) -> Optional[Dict[str, str]]:
        return self._payout_ledger.get(usage_record_id)

    def known_callback(self, event_id: str) -> Optional[Dict[str, str]]:
        return self._callback_ledger.get(event_id)

    def known_capability(self, key: str) -> Optional[Dict[str, str]]:
        return self._capability_ledger.get(key)

    # -----------------------------------------------------------------
    # read-only live views
    # -----------------------------------------------------------------

    def command_ledger(self) -> Mapping[str, Mapping[str, str]]:
        """The durable command-idempotency ledger (a live,
        deeply-frozen read-only view -- in-place mutation
        raises; reads stay live with the journal)."""
        return MappingProxyType(self._command_ledger)

    def intent_ledger(self) -> Mapping[str, Mapping[str, str]]:
        """The durable intent-identity ledger (a live,
        deeply-frozen read-only view)."""
        return MappingProxyType(self._intent_ledger)

    def payout_ledger(self) -> Mapping[str, Mapping[str, str]]:
        """The durable payout-identity ledger (a live,
        deeply-frozen read-only view)."""
        return MappingProxyType(self._payout_ledger)

    def callback_ledger(self) -> Mapping[str, Mapping[str, str]]:
        """The durable callback anti-replay ledger (a live,
        deeply-frozen read-only view)."""
        return MappingProxyType(self._callback_ledger)

    def capability_ledger(self) -> Mapping[str, Mapping[str, str]]:
        """The durable capability-identity ledger (a live,
        deeply-frozen read-only view)."""
        return MappingProxyType(self._capability_ledger)


def record_list_digest(records: Tuple[JournalRecord, ...]) -> str:
    """Deterministic digest over a record sequence (record ids
    in journal order)."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(
            {
                "kind": "payment-journal-records",
                "record_ids": [r.record_id for r in records],
            }
        )
    ).hexdigest()
