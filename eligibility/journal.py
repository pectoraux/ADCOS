"""WORK-045 append-only eligibility journal (hash-chained,
tamper-evident, replayable).

Mirrors the ACCEPTED W044 journal invariant exactly: ONE durable
journal record represents ONE admitted command together with
its resulting event and all action-owned identity data.  The
admitted command and its event are persisted ATOMICALLY as a
single append-only record -- there is no persisted intermediate
state in which a command exists without its event, so a crash
at any point can never strand an admitted command as a
"duplicate forever" with no resulting event.

The record carries, beyond the (command, event) pair, the
action-owned durable identity digests: the declaration digest
(the immutable registration/declaration identity the action
owns) and the decision digest (the evaluation decision
identity).  Both are recomputed and verified at construction
and on every deserialization, so a tampered identity basis
fails closed ``journal-corrupt``.

The eligibility family owns exactly ONE journal -- the
append-only, hash-chained eligibility history.  Every record's
identity is content-and-chain derived; every append updates the
durable idempotency ledgers IN THE SAME ATOMIC STEP (the
command ledger entry is created WITH its event id); every load
replays the bytes into the identical ledgers (journal-first
recovery).

The FIVE durable idempotency ledgers (all fully derived from
the journaled records, so replay rebuilds them byte-identically):
commands (command id -> digest/event), decisions (decision id
-> event), providers (provider_id -> trust-record event),
declarations (declaration key -> event), and citations
(citation id -> first referencing decision event).

Tamper detection covers byte flips, reordering, truncation,
sequence gaps, and duplicated lines -- all fail closed
``journal-corrupt``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import EligibilityError, EligibilityReasonCode
from .immutability import deep_freeze, deep_materialize
from .model import EligibilityCommand, EligibilityEvent
from .states import ActionKind

#: The record-kind vocabulary: one discriminated family (the
#: W044 single-record shape -- each record is one admitted
#: command + its event + the action-owned identity digests).
JOURNAL_RECORD_KIND = "eligibility-record"

#: The chain anchor (the virtual predecessor of record 1).
GENESIS_RECORD_ID = "sha256:" + "0" * 64

#: The declaration-event actions (whose event fact payload
#: carries a versioned declaration record).
DECLARATION_ACTIONS = (
    "declare-capabilities",
    "register-offer",
    "register-device",
    "enroll-policy",
)


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise EligibilityError(
            EligibilityReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


def _content_digest(payload: Any) -> str:
    """The canonical content digest of one identity basis (the
    declaration/registration/decision digests for the
    idempotency ledgers)."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(deep_materialize(payload))
    ).hexdigest()


def record_content(
    command: EligibilityCommand,
    command_digest: str,
    event: EligibilityEvent,
    declaration_digest: str,
    decision_digest: str,
) -> Dict[str, Any]:
    """The canonical journal record content: the admitted
    command + its event + the action-owned durable identity
    digests (ONE atomic persistence unit)."""
    return {
        "command": command.to_dict(),
        "command_digest": command_digest,
        "event": event.to_dict(),
        "declaration_digest": declaration_digest,
        "decision_digest": decision_digest,
    }


def derive_record_id(
    sequence: int, record_content: Dict[str, Any], prev_record_id: str
) -> str:
    """The content-derived journal record fingerprint (hash
    chain).

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


def declaration_digest_for_event(event: EligibilityEvent) -> str:
    """The durable declaration/registration identity digest of
    one event (content-derived over the action's OWN record
    DATA).

    ``register-provider`` owns the registration identity (the
    provider's registered facts); the four declaration actions
    own the versioned declaration record identity.  Every other
    action carries the empty digest ``""``.
    """
    if event.action == ActionKind.REGISTER_PROVIDER:
        return _content_digest(event.payload)
    if event.action in DECLARATION_ACTIONS:
        fact = event.payload
        record = fact.get("record", None)
        if record is None:
            raise EligibilityError(
                EligibilityReasonCode.JOURNAL_CORRUPT,
                "declaration event fact carries no versioned record",
            )
        return _content_digest(record)
    return ""


def decision_digest_for_event(event: EligibilityEvent) -> str:
    """The durable decision identity digest of one ``evaluate``
    event (content-derived over the journaled decision record).
    Non-evaluation events carry the empty digest ``""``.
    A malformed stored evaluation fact fails closed
    ``journal-corrupt`` (the live admission path validates the
    decision BEFORE any journal record exists)."""
    if event.action != ActionKind.EVALUATE:
        return ""
    fact = event.payload
    decision = fact.get("decision", None)
    if decision is None:
        raise EligibilityError(
            EligibilityReasonCode.JOURNAL_CORRUPT,
            "evaluation event fact carries no decision record",
        )
    return _content_digest(decision)


@dataclass(frozen=True)
class JournalRecord:
    """One immutable append-only journal record: an admitted
    command, its resulting eligibility event, and the
    action-owned durable identity digests (declaration /
    decision; ``""`` where the action owns none).

    ``record_id`` is the hash-chain fingerprint over (sequence,
    {command, command_digest, event, declaration_digest,
    decision_digest}, prev) and is mechanically verified at
    deserialization and on every append (``verify_id``).
    """

    sequence: int
    record_id: str
    command: EligibilityCommand
    command_digest: str
    event: EligibilityEvent
    declaration_digest: str
    decision_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.sequence, int) or isinstance(
            self.sequence, bool
        ):
            raise EligibilityError(
                EligibilityReasonCode.JOURNAL_CORRUPT,
                "sequence must be an integer",
            )
        if self.sequence < 1:
            raise EligibilityError(
                EligibilityReasonCode.JOURNAL_CORRUPT,
                "sequence must be >= 1 (contiguous 1..N journal)",
            )
        _require_text(self.record_id, "record_id")
        if not isinstance(self.command, EligibilityCommand):
            raise EligibilityError(
                EligibilityReasonCode.JOURNAL_CORRUPT,
                "record must carry an EligibilityCommand",
            )
        _require_text(self.command_digest, "command_digest")
        if not isinstance(self.event, EligibilityEvent):
            raise EligibilityError(
                EligibilityReasonCode.JOURNAL_CORRUPT,
                "record must carry an EligibilityEvent",
            )
        if self.command.action != self.event.action:
            raise EligibilityError(
                EligibilityReasonCode.JOURNAL_CORRUPT,
                "record action %r does not match the event action %r"
                % (self.command.action, self.event.action),
            )
        if self.event.command_digest != self.command_digest:
            raise EligibilityError(
                EligibilityReasonCode.JOURNAL_CORRUPT,
                "record %d event cites command digest %r, expected %r"
                % (
                    self.sequence,
                    self.event.command_digest,
                    self.command_digest,
                ),
            )
        for label, digest in (
            ("declaration_digest", self.declaration_digest),
            ("decision_digest", self.decision_digest),
        ):
            if not isinstance(digest, str):
                raise EligibilityError(
                    EligibilityReasonCode.JOURNAL_CORRUPT,
                    "%s must be a string" % label,
                )
        expected_declaration = declaration_digest_for_event(self.event)
        if self.declaration_digest != expected_declaration:
            raise EligibilityError(
                EligibilityReasonCode.JOURNAL_CORRUPT,
                "record %d declaration digest %s does not match the "
                "recomputed digest %s (tampered declaration identity)"
                % (
                    self.sequence,
                    self.declaration_digest,
                    expected_declaration,
                ),
            )
        expected_decision = decision_digest_for_event(self.event)
        if self.decision_digest != expected_decision:
            raise EligibilityError(
                EligibilityReasonCode.JOURNAL_CORRUPT,
                "record %d decision digest %s does not match the "
                "recomputed digest %s (tampered decision identity)"
                % (
                    self.sequence,
                    self.decision_digest,
                    expected_decision,
                ),
            )

    def content(self) -> Dict[str, Any]:
        return record_content(
            self.command,
            self.command_digest,
            self.event,
            self.declaration_digest,
            self.decision_digest,
        )

    def verify_id(self, prev_record_id: str) -> None:
        """Mechanical content binding (the hash-chain gate)."""
        expected = derive_record_id(
            self.sequence, self.content(), prev_record_id
        )
        if self.record_id != expected:
            raise EligibilityError(
                EligibilityReasonCode.JOURNAL_CORRUPT,
                "record %d id %s does not match the content-derived "
                "id %s (tampered journal record)"
                % (self.sequence, self.record_id, expected),
            )

    def verify_command_digest(self) -> None:
        """The command digest must recompute from the command (a
        tampered command in a stored journal fails closed)."""
        expected = self.command.digest()
        if self.command_digest != expected:
            raise EligibilityError(
                EligibilityReasonCode.JOURNAL_CORRUPT,
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
        if not isinstance(data, dict):
            raise EligibilityError(
                EligibilityReasonCode.JOURNAL_CORRUPT,
                "journal record must be a mapping",
            )
        for member in (
            "sequence",
            "record_id",
            "command",
            "command_digest",
            "event",
            "declaration_digest",
            "decision_digest",
        ):
            if member not in data:
                raise EligibilityError(
                    EligibilityReasonCode.JOURNAL_CORRUPT,
                    "journal record is missing required member %r"
                    % member,
                )
        command = EligibilityCommand.from_dict(data["command"])
        event = EligibilityEvent.from_dict(data["event"])
        return cls(
            sequence=data["sequence"],
            record_id=data["record_id"],
            command=command,
            command_digest=data["command_digest"],
            event=event,
            declaration_digest=data["declaration_digest"],
            decision_digest=data["decision_digest"],
        )

    @classmethod
    def build(
        cls,
        *,
        sequence: int,
        prev_record_id: str,
        command: EligibilityCommand,
        command_digest: str,
        event: EligibilityEvent,
    ) -> "JournalRecord":
        """Build one record with the content-derived identity and
        the action-owned identity digests (the only construction
        path: command + event are admitted TOGETHER or not at
        all)."""
        content = record_content(
            command,
            command_digest,
            event,
            declaration_digest_for_event(event),
            decision_digest_for_event(event),
        )
        record_id = derive_record_id(sequence, content, prev_record_id)
        return cls(
            sequence=sequence,
            record_id=record_id,
            command=command,
            command_digest=command_digest,
            event=event,
            declaration_digest=declaration_digest_for_event(event),
            decision_digest=decision_digest_for_event(event),
        )


def journal_bytes_for(record: JournalRecord) -> bytes:
    """One canonical-JSON line for one record (the persist
    basis)."""
    return canonical_json_bytes(record.to_dict()) + b"\n"


def record_list_digest(records: Tuple[JournalRecord, ...]) -> str:
    """Deterministic digest over a record sequence (record ids
    in journal order)."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(
            {
                "kind": "eligibility-journal-records",
                "record_ids": [r.record_id for r in records],
            }
        )
    ).hexdigest()


class EligibilityStore:
    """The injectable persistence seam (journal-first)."""

    def append(self, record_bytes: bytes) -> None:
        raise NotImplementedError

    def load_bytes(self) -> Tuple[bytes, ...]:
        raise NotImplementedError


class MemoryEligibilityStore(EligibilityStore):
    """The in-memory store (deterministic tests and default)."""

    def __init__(self) -> None:
        self._chunks: List[bytes] = []

    def append(self, record_bytes: bytes) -> None:
        if not isinstance(record_bytes, (bytes, bytearray)):
            raise EligibilityError(
                EligibilityReasonCode.STORE_FAILED,
                "memory store appends bytes only",
            )
        self._chunks.append(bytes(record_bytes))

    def load_bytes(self) -> Tuple[bytes, ...]:
        return tuple(self._chunks)


class FileEligibilityStore(EligibilityStore):
    """The file-backed store (persist-then-ack durability)."""

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path):
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "file store path must be a pathlib.Path",
            )
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, record_bytes: bytes) -> None:
        if not isinstance(record_bytes, (bytes, bytearray)):
            raise EligibilityError(
                EligibilityReasonCode.STORE_FAILED,
                "file store appends bytes only",
            )
        with self._path.open("ab") as handle:
            handle.write(bytes(record_bytes))
            handle.flush()

    def load_bytes(self) -> Tuple[bytes, ...]:
        if not self._path.exists():
            return ()
        with self._path.open("rb") as handle:
            data = handle.read()
        if not data:
            return ()
        return tuple(line + b"\n" for line in data.split(b"\n") if line)


class AppendOnlyEligibilityJournal:
    """The append-only, hash-chained eligibility journal with the
    FIVE durable idempotency ledgers (all derived from the
    journaled records).

    Construction verifies the ENTIRE stored journal (record ids,
    chain links, contiguous sequence, command digests, action
    identity digests, command/event pairing, and the duplicate
    ledger keys) -- a tampered or corrupt store fails closed
    ``journal-corrupt`` and constructs nothing.

    Append is persist-then-ack over ONE atomic record: the
    admitted command, its event, and the identity data hit the
    store as a single write, and the in-memory ledgers are
    populated from that record only AFTER the write succeeds --
    so a crash can persist either NOTHING for a command or the
    COMPLETE (command + event) pair, never the command without
    its event.
    """

    def __init__(self, *, store: EligibilityStore) -> None:
        if not isinstance(store, EligibilityStore):
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "the journal requires an EligibilityStore",
            )
        self._store = store
        self._records: List[JournalRecord] = []
        self._command_ledger: Dict[str, Dict[str, str]] = {}
        self._decision_ledger: Dict[str, Dict[str, str]] = {}
        self._provider_ledger: Dict[str, Dict[str, str]] = {}
        self._declaration_ledger: Dict[str, Dict[str, str]] = {}
        self._citation_ledger: Dict[str, Dict[str, str]] = {}
        prev = GENESIS_RECORD_ID
        expected_sequence = 1
        for chunk in store.load_bytes():
            record = _record_from_bytes(chunk)
            if record.sequence != expected_sequence:
                raise EligibilityError(
                    EligibilityReasonCode.JOURNAL_CORRUPT,
                    "replay: sequence gap: expected %d, found %d"
                    % (expected_sequence, record.sequence),
                )
            record.verify_id(prev)
            record.verify_command_digest()
            self._register(record)
            self._records.append(record)
            prev = record.record_id
            expected_sequence += 1

    # -- append ---------------------------------------------------

    def append(self, record: JournalRecord) -> None:
        """Persist-then-ack append of ONE atomic (command +
        event + identity) record: the store write happens BEFORE
        any in-memory registration, so a store failure leaves no
        phantom in-memory state and a crash after the write
        leaves the COMPLETE pair recoverable by replay."""
        if not isinstance(record, JournalRecord):
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "the journal appends JournalRecord values only",
            )
        expected_sequence = len(self._records) + 1
        if record.sequence != expected_sequence:
            raise EligibilityError(
                EligibilityReasonCode.EVENT_INVALID,
                "record sequence %d does not continue the journal "
                "(expected %d)" % (record.sequence, expected_sequence),
            )
        record.verify_id(self.tail_record_id())
        record.verify_command_digest()
        self._store.append(journal_bytes_for(record))
        self._register(record)
        self._records.append(record)

    def _register(self, record: JournalRecord) -> None:
        """Populate the FIVE durable idempotency ledgers from ONE
        record (the atomic registration: the command ledger entry
        is born WITH its event id -- a command can never be
        registered without its event; a duplicate key in a
        stored journal fails closed)."""
        command = record.command
        event = record.event
        existing = self._command_ledger.get(command.command_id)
        if existing is not None:
            raise EligibilityError(
                EligibilityReasonCode.JOURNAL_CORRUPT,
                "duplicate command id %r in the stored journal"
                % command.command_id,
            )
        self._command_ledger[command.command_id] = {
            "digest": record.command_digest,
            "event_id": event.event_id,
        }
        entry = {
            "event_id": event.event_id,
            "record_id": record.record_id,
        }
        action = event.action
        fact = event.payload
        if action == ActionKind.EVALUATE:
            decision = fact.get("decision", {})
            decision_id = str(decision.get("decision_id", ""))
            if decision_id:
                if decision_id in self._decision_ledger:
                    raise EligibilityError(
                        EligibilityReasonCode.JOURNAL_CORRUPT,
                        "duplicate decision id %r in the stored "
                        "journal" % decision_id,
                    )
                self._decision_ledger[decision_id] = dict(entry)
            for citation in list(decision.get("citations", ())) + list(
                [decision.get("payment_reference", "")]
            ):
                if isinstance(citation, str) and citation:
                    self._citation_ledger.setdefault(
                        citation, dict(entry)
                    )
        elif action == ActionKind.REGISTER_PROVIDER:
            if event.entity_id in self._provider_ledger:
                raise EligibilityError(
                    EligibilityReasonCode.JOURNAL_CORRUPT,
                    "duplicate provider registration %r in the "
                    "stored journal" % event.entity_id,
                )
            self._provider_ledger[event.entity_id] = dict(
                entry, digest=record.declaration_digest
            )
        elif action in DECLARATION_ACTIONS:
            if event.entity_id in self._declaration_ledger:
                raise EligibilityError(
                    EligibilityReasonCode.JOURNAL_CORRUPT,
                    "duplicate declaration key %r in the stored "
                    "journal" % event.entity_id,
                )
            self._declaration_ledger[event.entity_id] = dict(
                entry, digest=record.declaration_digest
            )
        elif action in (
            ActionKind.SUSPEND,
            ActionKind.REINSTATE,
            ActionKind.REVOKE,
            ActionKind.EXPIRE,
        ):
            self._provider_ledger[event.entity_id] = dict(
                entry,
                digest=self._provider_ledger.get(
                    event.entity_id, {}
                ).get("digest", ""),
            )

    # -- reads ----------------------------------------------------

    def records(self) -> Tuple[JournalRecord, ...]:
        return tuple(self._records)

    def journal_bytes(self) -> bytes:
        return b"".join(
            journal_bytes_for(record) for record in self._records
        )

    def journal_digest(self) -> str:
        """The tamper-evident fingerprint of the whole journal."""
        return "sha256:" + hashlib.sha256(
            self.journal_bytes()
        ).hexdigest()

    def tail_sequence(self) -> int:
        return len(self._records)

    def tail_record_id(self) -> str:
        if not self._records:
            return GENESIS_RECORD_ID
        return self._records[-1].record_id

    def __len__(self) -> int:
        return len(self._records)

    # -- idempotency ledgers (public read-only mappings) ---------

    def command_ledger(self) -> Dict[str, Dict[str, str]]:
        return {
            key: dict(value)
            for key, value in sorted(self._command_ledger.items())
        }

    def decision_ledger(self) -> Dict[str, Dict[str, str]]:
        return {
            key: dict(value)
            for key, value in sorted(self._decision_ledger.items())
        }

    def provider_ledger(self) -> Dict[str, Dict[str, str]]:
        return {
            key: dict(value)
            for key, value in sorted(self._provider_ledger.items())
        }

    def declaration_ledger(self) -> Dict[str, Dict[str, str]]:
        return {
            key: dict(value)
            for key, value in sorted(
                self._declaration_ledger.items()
            )
        }

    def citation_ledger(self) -> Dict[str, Dict[str, str]]:
        return {
            key: dict(value)
            for key, value in sorted(self._citation_ledger.items())
        }

    def known_command(self, command_id: str) -> Optional[Dict[str, str]]:
        entry = self._command_ledger.get(command_id)
        return dict(entry) if entry else None

    def known_decision(self, decision_id: str) -> Optional[Dict[str, str]]:
        entry = self._decision_ledger.get(decision_id)
        return dict(entry) if entry else None

    def known_provider(self, provider_id: str) -> Optional[Dict[str, str]]:
        entry = self._provider_ledger.get(provider_id)
        return dict(entry) if entry else None

    def known_declaration(
        self, declaration_key: str
    ) -> Optional[Dict[str, str]]:
        entry = self._declaration_ledger.get(declaration_key)
        return dict(entry) if entry else None

    # -- integrity ------------------------------------------------

    def verify_integrity(self) -> None:
        """Full tamper verification (chain, identities,
        sequences, command/event pairing)."""
        previous = GENESIS_RECORD_ID
        expected_sequence = 1
        for record in self._records:
            if record.sequence != expected_sequence:
                raise EligibilityError(
                    EligibilityReasonCode.JOURNAL_CORRUPT,
                    "sequence gap: record %d out of order"
                    % record.sequence,
                )
            record.verify_id(previous)
            record.verify_command_digest()
            previous = record.record_id
            expected_sequence += 1

    @classmethod
    def load(
        cls, store: EligibilityStore
    ) -> "AppendOnlyEligibilityJournal":
        """Journal-first recovery: rebuild the journal (and its
        idempotency ledgers) from the persisted bytes, verifying
        integrity while replaying (byte-identical replay)."""
        return cls(store=store)


def _record_from_bytes(chunk: bytes) -> JournalRecord:
    """Parse one persisted record line (fail closed)."""
    try:
        data = json.loads(chunk.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as error:
        raise EligibilityError(
            EligibilityReasonCode.JOURNAL_CORRUPT,
            "persisted record is not valid canonical JSON: %s" % error,
        ) from error
    return JournalRecord.from_dict(data)
