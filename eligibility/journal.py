"""WORK-045 append-only eligibility journal (hash-chained,
tamper-evident, replayable).

Mirrors the W051/W053/W044 journal discipline: the eligibility
family owns exactly ONE journal -- the append-only,
hash-chained eligibility history (commands + events, atomic per
record, persist-then-ack, tamper-evident, replayable).  Every
record's identity is content-and-chain derived; every append
updates the durable idempotency ledgers; every load replays the
bytes into the identical ledgers (journal-first recovery).

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
from .states import EventOutcome

#: The genesis record id (the chain anchor).
GENESIS_RECORD_ID = "sha256:" + "0" * 64

#: The frozen journal record kinds.
JOURNAL_RECORD_KIND = ("genesis", "command", "event")

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


def record_content(
    sequence: int,
    record_id: str,
    prev_record_id: str,
    kind: str,
    command_digest: str,
    entity_kind: str,
    entity_id: str,
    payload: Any,
    instant: str,
) -> Dict[str, Any]:
    """The canonical content basis of one journal record."""
    return {
        "sequence": sequence,
        "record_id": record_id,
        "prev_record_id": prev_record_id,
        "kind": kind,
        "command_digest": command_digest,
        "entity_kind": entity_kind,
        "entity_id": entity_id,
        "payload": payload,
        "instant": instant,
    }


def derive_record_id(content: Dict[str, Any]) -> str:
    """The content-and-chain derived record identity (excluding
    the id itself)."""
    basis = {
        key: value for key, value in content.items()
        if key != "record_id"
    }
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(deep_materialize(basis))
    ).hexdigest()


def command_digest_of_payload(payload: Any) -> str:
    """The command digest of one COMMAND record's payload (the
    canonical command content digest)."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(deep_materialize(payload))
    ).hexdigest()


def _content_digest(payload: Any) -> str:
    """The canonical content digest of one event fact record
    (declaration/registration digests for the idempotency
    ledgers)."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(deep_materialize(payload))
    ).hexdigest()


@dataclass(frozen=True)
class JournalRecord:
    """One immutable journaled record.

    ``kind`` is ``genesis`` / ``command`` / ``event``; the
    COMMAND record's payload is the command content; the EVENT
    record's payload is the event content (which itself carries
    the fact payload).  ``payload`` is deeply frozen at
    construction.
    """

    sequence: int
    record_id: str
    prev_record_id: str
    kind: str
    command_digest: str
    entity_kind: str
    entity_id: str
    payload: Any
    instant: str

    def __post_init__(self) -> None:
        if not isinstance(self.sequence, int) or isinstance(
            self.sequence, bool
        ):
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "sequence must be an integer",
            )
        if self.sequence < 0:
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "sequence must be non-negative",
            )
        _require_text(self.record_id, "record_id")
        if self.kind not in JOURNAL_RECORD_KIND:
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "record kind %r must be one of %s"
                % (self.kind, list(JOURNAL_RECORD_KIND)),
            )
        if self.kind == "genesis":
            if self.sequence != 0:
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "the genesis record must be sequence 0",
                )
            if self.prev_record_id != "":
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "the genesis record has no predecessor",
                )
            if self.command_digest != "":
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "the genesis record carries no command digest",
                )
        else:
            _require_text(self.prev_record_id, "prev_record_id")
            _require_text(self.command_digest, "command_digest")
            _require_text(self.entity_kind, "entity_kind")
            _require_text(self.entity_id, "entity_id")
            _require_text(self.instant, "instant")
        expected = derive_record_id(self.content())
        if self.record_id != expected:
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "record id %r does not match the content-derived "
                "identity %r" % (self.record_id, expected),
            )

    def content(self) -> Dict[str, Any]:
        return record_content(
            self.sequence,
            self.record_id,
            self.prev_record_id,
            self.kind,
            self.command_digest,
            self.entity_kind,
            self.entity_id,
            self.payload,
            self.instant,
        )

    def verify_id(self, prev_record_id: str) -> None:
        """Verify the chain link and the content-derived
        identity (tamper-evidence)."""
        if self.prev_record_id != prev_record_id:
            raise EligibilityError(
                EligibilityReasonCode.JOURNAL_CORRUPT,
                "record %d breaks the hash chain (prev %r, expected %r)"
                % (self.sequence, self.prev_record_id, prev_record_id),
            )
        expected = derive_record_id(self.content())
        if self.record_id != expected:
            raise EligibilityError(
                EligibilityReasonCode.JOURNAL_CORRUPT,
                "record %d content does not match its identity"
                % self.sequence,
            )

    def to_dict(self) -> Dict[str, Any]:
        return deep_materialize(self.content())

    @classmethod
    def from_dict(cls, data: object) -> "JournalRecord":
        if not isinstance(data, dict):
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "journal record must be a mapping",
            )
        required = (
            "sequence",
            "record_id",
            "prev_record_id",
            "kind",
            "command_digest",
            "entity_kind",
            "entity_id",
            "payload",
            "instant",
        )
        for member in required:
            if member not in data:
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "journal record is missing %r" % member,
                )
        return cls(
            sequence=data["sequence"],
            record_id=data["record_id"],
            prev_record_id=data["prev_record_id"],
            kind=data["kind"],
            command_digest=data["command_digest"],
            entity_kind=data["entity_kind"],
            entity_id=data["entity_id"],
            payload=deep_freeze(data["payload"]),
            instant=data["instant"],
        )

    @classmethod
    def build(
        cls,
        *,
        sequence: int,
        prev_record_id: str,
        kind: str,
        command_digest: str,
        entity_kind: str,
        entity_id: str,
        payload: Any,
        instant: str,
    ) -> "JournalRecord":
        """Build one record with the content-derived identity
        (the only construction path)."""
        content = record_content(
            sequence,
            "",
            prev_record_id,
            kind,
            command_digest,
            entity_kind,
            entity_id,
            deep_freeze(payload),
            instant,
        )
        record_id = derive_record_id(content)
        return cls(
            sequence=sequence,
            record_id=record_id,
            prev_record_id=prev_record_id,
            kind=kind,
            command_digest=command_digest,
            entity_kind=entity_kind,
            entity_id=entity_id,
            payload=deep_freeze(payload),
            instant=instant,
        )


def journal_bytes_for(record: JournalRecord) -> bytes:
    """The canonical persistence bytes of one record (one line
    per record)."""
    return canonical_json_bytes(
        deep_materialize(record.content())
    ) + b"\n"


def record_list_digest(records: Tuple[JournalRecord, ...]) -> str:
    """The deterministic digest over a record sequence."""
    digest = hashlib.sha256()
    for record in records:
        digest.update(journal_bytes_for(record))
    return "sha256:" + digest.hexdigest()


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
    """The append-only hash-chained eligibility journal with the
    FIVE durable idempotency ledgers (all derived from the
    journaled records).  Append is persist-then-ack: the store
    write happens BEFORE the in-memory registration, so a crash
    between the two recovers by replay.
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
        self._command_by_digest: Dict[str, str] = {}
        self._decision_ledger: Dict[str, Dict[str, str]] = {}
        self._provider_ledger: Dict[str, Dict[str, str]] = {}
        self._declaration_ledger: Dict[str, Dict[str, str]] = {}
        self._citation_ledger: Dict[str, Dict[str, str]] = {}
        genesis = JournalRecord.build(
            sequence=0,
            prev_record_id="",
            kind="genesis",
            command_digest="",
            entity_kind="",
            entity_id="",
            payload={},
            instant="",
        )
        self._store.append(journal_bytes_for(genesis))
        self._records.append(genesis)

    # -- append ---------------------------------------------------

    def append(self, record: JournalRecord) -> None:
        """Persist-then-ack append (atomic per record)."""
        if not isinstance(record, JournalRecord):
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "the journal appends JournalRecord values only",
            )
        expected_sequence = len(self._records)
        if record.sequence != expected_sequence:
            raise EligibilityError(
                EligibilityReasonCode.EVENT_INVALID,
                "record sequence %d does not continue the journal "
                "(expected %d)" % (record.sequence, expected_sequence),
            )
        record.verify_id(self.tail_record_id())
        self._store.append(journal_bytes_for(record))
        self._records.append(record)
        self._register(record)

    def _register(self, record: JournalRecord) -> None:
        if record.kind == "command":
            digest = command_digest_of_payload(record.payload)
            self._command_ledger[record.entity_id] = {
                "digest": digest,
                "status": "appended",
                "event_id": "",
            }
            self._command_by_digest[digest] = record.entity_id
            return
        if record.kind != "event":
            return
        payload = record.payload
        entry = {
            "event_id": str(payload.get("event_id", "")),
            "record_id": record.record_id,
        }
        action = str(payload.get("action", ""))
        fact = payload.get("payload", {})
        # link the event back to its command ledger entry
        command_id = self._command_by_digest.get(
            str(payload.get("command_digest", ""))
        )
        if command_id is not None:
            self._command_ledger[command_id]["event_id"] = entry[
                "event_id"
            ]
        if action == "evaluate":
            decision = fact.get("decision", {})
            decision_id = str(decision.get("decision_id", ""))
            if decision_id:
                self._decision_ledger[decision_id] = dict(entry)
            for citation in list(decision.get("citations", ())) + list(
                [decision.get("payment_reference", "")]
            ):
                if isinstance(citation, str) and citation:
                    self._citation_ledger.setdefault(
                        citation, dict(entry)
                    )
        elif action == "register-provider":
            self._provider_ledger[record.entity_id] = dict(
                entry, digest=_content_digest(fact.get("record", {}))
            )
        elif action in DECLARATION_ACTIONS:
            self._declaration_ledger[record.entity_id] = dict(
                entry, digest=_content_digest(fact.get("record", {}))
            )
        elif action in ("suspend", "reinstate", "revoke", "expire"):
            self._provider_ledger[record.entity_id] = dict(
                entry, digest=self._provider_ledger.get(
                    record.entity_id, {}
                ).get("digest", "")
            )

    # -- reads ----------------------------------------------------

    def records(self) -> Tuple[JournalRecord, ...]:
        return tuple(self._records)

    def journal_bytes(self) -> bytes:
        chunks = b""
        for record in self._records:
            chunks += journal_bytes_for(record)
        return chunks

    def journal_digest(self) -> str:
        return record_list_digest(tuple(self._records))

    def tail_sequence(self) -> int:
        return self._records[-1].sequence if self._records else 0

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
        sequences, genesis)."""
        previous = ""
        expected_sequence = 0
        for record in self._records:
            if record.sequence != expected_sequence:
                raise EligibilityError(
                    EligibilityReasonCode.JOURNAL_CORRUPT,
                    "sequence gap: record %d out of order"
                    % record.sequence,
                )
            record.verify_id(previous)
            previous = record.record_id
            expected_sequence += 1
        if self._records and self._records[0].kind != "genesis":
            raise EligibilityError(
                EligibilityReasonCode.JOURNAL_CORRUPT,
                "the journal does not begin with the genesis record",
            )

    @classmethod
    def load(
        cls, store: EligibilityStore
    ) -> "AppendOnlyEligibilityJournal":
        """Journal-first recovery: rebuild the journal (and its
        idempotency ledgers) from the persisted bytes, verifying
        integrity while replaying (byte-identical replay)."""
        journal = cls.__new__(cls)
        journal._store = store
        journal._records = []
        journal._command_ledger = {}
        journal._command_by_digest = {}
        journal._decision_ledger = {}
        journal._provider_ledger = {}
        journal._declaration_ledger = {}
        journal._citation_ledger = {}
        previous = ""
        for chunk in store.load_bytes():
            record = _record_from_bytes(chunk)
            expected_sequence = len(journal._records)
            if record.sequence != expected_sequence:
                raise EligibilityError(
                    EligibilityReasonCode.JOURNAL_CORRUPT,
                    "replay: sequence mismatch at record %d"
                    % record.sequence,
                )
            record.verify_id(previous)
            previous = record.record_id
            journal._records.append(record)
            journal._register(record)
        if not journal._records or journal._records[0].kind != "genesis":
            raise EligibilityError(
                EligibilityReasonCode.JOURNAL_CORRUPT,
                "replay: the journal does not begin with the genesis "
                "record",
            )
        return journal


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
