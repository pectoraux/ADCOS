"""WORK-053 EconomicAllocation append-only journal and durable
persistence seam.

The journal-first durable core of the allocation history (the
W042 journal-first discipline the W053 contract requires reused,
mirroring the accepted W051/W052 journals):

    immutable allocation records
        + append-only file discipline
        + content-derived record ids
        + a hash chain over (sequence, content, previous link)
        = tamper-evident, deterministically replayable economic
          history

Discipline (battery-pinned, mirroring the accepted W052 usage
journal):

- **atomic command records**: every executed command appends
  EXACTLY ONE journal record carrying the admitted command
  (input + content digest, the durable command-idempotency
  ledger), the resulting allocation event (the fact with full
  attribution), and -- for allocate commands -- the
  allocation-intent digest (the durable usage-record-idempotency
  ledger: an exact redelivery of the same allocation intent under
  a different command id is an idempotent no-op, decided from the
  STORED ledger BEFORE live fact resolution) and -- for policy
  registrations -- the policy content digest (the durable
  policy-identity ledger: a conflicting re-registration of the
  same (policy_id, version) fails closed).  One append = one
  atomic persist-then-ack; there is no intermediate state where a
  command is admitted without its fact.
- **content-derived ids**: every ``record_id`` is the fingerprint
  of (sequence, record content, previous record id) -- the hash
  chain; every ``event_id`` is the fingerprint of its allocation
  content; every ``command_digest`` is the fingerprint of the
  command content.  All are mechanically verified at construction
  and on deserialization, so a tampered record can never carry an
  attacker-chosen id.
- **canonical serialization**: one canonical-JSON line per record
  (the WORK-003 profile); identical logical histories produce
  byte-identical journals.
- **immutable records**: there is NO API that modifies,
  rewrites, or removes a journal record; the file discipline is
  append-only (``ab``), so the journal can only grow -- settled
  or historical allocation facts can never be edited in place.
- **deterministic replay**: loading and folding the same journal
  bytes always reproduces the same allocation state (the fold
  lives in :mod:`allocation.lifecycle` and reuses the single
  apply function the manager itself uses).
- **three-layer duplicate detection**: the command ledger is
  journaled with each record (command idempotency survives
  restart); the usage-record ledger is journaled with each
  allocate record (usage-record idempotency survives restart; a
  duplicate command id, a duplicate usage-record id, or a
  duplicate policy key in a stored journal fails closed at
  load).
- **corruption/tamper detection**: load verifies every record id,
  the chain links, the contiguous 1..N sequence, every command
  digest, every allocation-intent digest, every policy digest,
  and duplicate command ids / usage-record ids / policy keys --
  any tampered byte, reordered line, truncated tail, sequence
  gap, or duplicate pair fails closed with ``JOURNAL_CORRUPT``.
- **persist-then-ack**: the journal is persisted BEFORE the
  in-memory record is acknowledged; a store failure leaves no
  phantom in-memory state (``STORE_FAILED``).

The persistence seam (:class:`AllocationStore`) is injectable:
:class:`MemoryAllocationStore` keeps verification deterministic
and in-process; :class:`FileAllocationStore` is the real durable
store (the only filesystem-write site in the allocation family,
battery-audited).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import AllocationError, AllocationReasonCode
from .immutability import deep_freeze
from .model import (
    AllocationAction,
    AllocationCommand,
    AllocationEvent,
    EconomicPolicy,
    policy_key,
)

#: The record-kind vocabulary: one discriminated family.
JOURNAL_RECORD_KIND = "allocation-record"

GENESIS_RECORD_ID = "sha256:" + "0" * 64


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise AllocationError(
            AllocationReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


def derive_record_id(
    sequence: int,
    record_content: Dict[str, Any],
    prev_record_id: str,
) -> str:
    """The content-derived journal record fingerprint (hash chain).

    Binds the record to its position (sequence), its content (the
    admitted command + its event + the durable identity digests),
    and the ENTIRE preceding journal (prev link).
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
    command: AllocationCommand,
    command_digest: str,
    event: AllocationEvent,
    allocation_digest: str,
    policy_digest: str,
) -> Dict[str, Any]:
    """The canonical journal record content (command + fact)."""
    return {
        "command": command.to_dict(),
        "command_digest": command_digest,
        "event": event.to_dict(),
        "allocation_digest": allocation_digest,
        "policy_digest": policy_digest,
    }


def allocation_digest_for_command(command: AllocationCommand) -> str:
    """The durable allocation-intent digest of an ``allocate``
    command (content-derived over the command's own allocation
    DATA -- never over external facts, so the usage-record
    idempotency decision is made BEFORE live fact resolution).
    Non-allocation commands carry the empty digest ``""``.
    """
    return command.allocation_intent_digest()


def policy_digest_for_command(command: AllocationCommand) -> str:
    """The durable policy-identity digest of a ``register_policy``
    command (the immutable policy-version content digest).
    Non-policy commands carry the empty digest ``""``.  A
    malformed stored policy payload fails closed
    ``JOURNAL_CORRUPT`` (the live admission path validates the
    policy record shape BEFORE any journal record exists).
    """
    if command.action != AllocationAction.REGISTER_POLICY:
        return ""
    try:
        policy = EconomicPolicy(
            policy_id=command.policy_id,
            version=command.policy_version,
            currency=command.payload["currency"],
            exponent=command.payload["exponent"],
            rounding=command.payload["rounding"],
            effective_from=command.payload["effective_from"],
            effective_until=command.payload["effective_until"],
            adc_os_share_bps=command.payload["adc_os_share_bps"],
            tax_bps=command.payload["tax_bps"],
            developer_share_min_bps=command.payload[
                "developer_share_min_bps"
            ],
            developer_share_max_bps=command.payload[
                "developer_share_max_bps"
            ],
        )
    except AllocationError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise AllocationError(
            AllocationReasonCode.JOURNAL_CORRUPT,
            "stored policy payload is malformed: %s" % error,
        ) from error
    return policy.digest()


@dataclass(frozen=True)
class JournalRecord:
    """One append-only journal record: an admitted command, its
    resulting allocation event, and the durable identity digests
    (the allocation-intent digest for allocate commands; the
    policy content digest for policy registrations).

    ``record_id`` is the hash-chain fingerprint over (sequence,
    {command, command_digest, event, allocation_digest,
    policy_digest}, prev) and is mechanically verified at
    construction and deserialization.
    """

    sequence: int
    record_id: str
    command: AllocationCommand
    command_digest: str
    event: AllocationEvent
    allocation_digest: str
    policy_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.sequence, int) or isinstance(
            self.sequence, bool
        ):
            raise AllocationError(
                AllocationReasonCode.JOURNAL_CORRUPT,
                "sequence must be an integer",
            )
        if self.sequence < 1:
            raise AllocationError(
                AllocationReasonCode.JOURNAL_CORRUPT,
                "sequence must be >= 1 (contiguous 1..N journal)",
            )
        _require_text(self.record_id, "record_id")
        if not isinstance(self.command, AllocationCommand):
            raise AllocationError(
                AllocationReasonCode.JOURNAL_CORRUPT,
                "record must carry an AllocationCommand",
            )
        _require_text(self.command_digest, "command_digest")
        if not isinstance(self.event, AllocationEvent):
            raise AllocationError(
                AllocationReasonCode.JOURNAL_CORRUPT,
                "record must carry an AllocationEvent",
            )
        if self.command.command_id != self.event.command_id:
            raise AllocationError(
                AllocationReasonCode.JOURNAL_CORRUPT,
                "record command id %r does not match the event command "
                "id %r"
                % (self.command.command_id, self.event.command_id),
            )
        if self.command.action != self.event.action:
            raise AllocationError(
                AllocationReasonCode.JOURNAL_CORRUPT,
                "record action %r does not match the event action %r"
                % (self.command.action, self.event.action),
            )
        if self.command.usage_record_id != self.event.usage_record_id:
            raise AllocationError(
                AllocationReasonCode.JOURNAL_CORRUPT,
                "record usage record id %r does not match the event usage "
                "record id %r"
                % (
                    self.command.usage_record_id,
                    self.event.usage_record_id,
                ),
            )
        if self.command.policy_id != self.event.policy_id or (
            self.command.policy_version != self.event.policy_version
        ):
            raise AllocationError(
                AllocationReasonCode.JOURNAL_CORRUPT,
                "record policy citation %r#%d does not match the event "
                "policy citation %r#%d"
                % (
                    self.command.policy_id,
                    self.command.policy_version,
                    self.event.policy_id,
                    self.event.policy_version,
                ),
            )
        expected_allocation_digest = allocation_digest_for_command(
            self.command
        )
        if self.allocation_digest != expected_allocation_digest:
            raise AllocationError(
                AllocationReasonCode.JOURNAL_CORRUPT,
                "record %d allocation digest %s does not match the "
                "recomputed digest %s (tampered allocation intent)"
                % (
                    self.sequence,
                    self.allocation_digest,
                    expected_allocation_digest,
                ),
            )
        expected_policy_digest = policy_digest_for_command(self.command)
        if self.policy_digest != expected_policy_digest:
            raise AllocationError(
                AllocationReasonCode.JOURNAL_CORRUPT,
                "record %d policy digest %s does not match the recomputed "
                "digest %s (tampered policy content)"
                % (
                    self.sequence,
                    self.policy_digest,
                    expected_policy_digest,
                ),
            )

    def content(self) -> Dict[str, Any]:
        return record_content(
            self.command,
            self.command_digest,
            self.event,
            self.allocation_digest,
            self.policy_digest,
        )

    def verify_id(self, prev_record_id: str) -> None:
        """Mechanical content binding (the hash-chain gate)."""
        expected = derive_record_id(
            self.sequence, self.content(), prev_record_id
        )
        if self.record_id != expected:
            raise AllocationError(
                AllocationReasonCode.JOURNAL_CORRUPT,
                "record %d id %s does not match the content-derived id %s "
                "(tampered journal record)"
                % (self.sequence, self.record_id, expected),
            )

    def verify_command_digest(self) -> None:
        """The command digest must recompute from the command
        content (tamper detection on the idempotency ledger)."""
        expected = self.command.digest()
        if self.command_digest != expected:
            raise AllocationError(
                AllocationReasonCode.JOURNAL_CORRUPT,
                "record %d command digest %s does not match the recomputed "
                "digest %s (tampered command content)"
                % (self.sequence, self.command_digest, expected),
            )

    def to_line(self) -> bytes:
        """One canonical-JSON journal line (deterministic bytes)."""
        payload = {
            "sequence": self.sequence,
            "record_id": self.record_id,
            "command": self.command.to_dict(),
            "command_digest": self.command_digest,
            "event": self.event.to_dict(),
            "allocation_digest": self.allocation_digest,
            "policy_digest": self.policy_digest,
        }
        return canonical_json_bytes(payload) + b"\n"

    @classmethod
    def build(
        cls,
        sequence: int,
        prev_record_id: str,
        command: AllocationCommand,
        command_digest: str,
        event: AllocationEvent,
        allocation_digest: str,
        policy_digest: str,
    ) -> "JournalRecord":
        record = cls(
            sequence=sequence,
            record_id=GENESIS_RECORD_ID,
            command=command,
            command_digest=command_digest,
            event=event,
            allocation_digest=allocation_digest,
            policy_digest=policy_digest,
        )
        record_id = derive_record_id(
            sequence,
            record_content(
                command,
                command_digest,
                event,
                allocation_digest,
                policy_digest,
            ),
            prev_record_id,
        )
        object.__setattr__(record, "record_id", record_id)
        return record

    @classmethod
    def from_dict(cls, data: object) -> "JournalRecord":
        if not isinstance(data, dict):
            raise AllocationError(
                AllocationReasonCode.JOURNAL_CORRUPT,
                "journal record must be a mapping",
            )
        required = (
            "sequence",
            "record_id",
            "command",
            "command_digest",
            "event",
            "allocation_digest",
            "policy_digest",
        )
        for key in required:
            if key not in data:
                raise AllocationError(
                    AllocationReasonCode.JOURNAL_CORRUPT,
                    "journal record is missing required member %r" % key,
                )
        try:
            command = AllocationCommand.from_dict(data["command"])
            event = AllocationEvent.from_dict(data["event"])
        except AllocationError as error:
            # a malformed command/event payload inside the STORED
            # journal is journal corruption, fail closed.
            raise AllocationError(
                AllocationReasonCode.JOURNAL_CORRUPT,
                "journal record payload invalid: %s" % error.detail,
            ) from error
        return cls(
            sequence=data["sequence"],
            record_id=data["record_id"],
            command=command,
            command_digest=data["command_digest"],
            event=event,
            allocation_digest=data["allocation_digest"],
            policy_digest=data["policy_digest"],
        )


def record_list_digest(records: Tuple[JournalRecord, ...]) -> str:
    """Deterministic digest over the full ordered journal."""
    content = {
        "kind": "allocation-journal",
        "records": [
            {
                "sequence": record.sequence,
                "record_id": record.record_id,
                "command_digest": record.command_digest,
                "allocation_digest": record.allocation_digest,
                "policy_digest": record.policy_digest,
                "event_id": record.event.event_id,
            }
            for record in records
        ],
        "count": len(records),
    }
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(content)
    ).hexdigest()


class AllocationStore:
    """The injectable persistence seam (abstract)."""

    def append_journal_line(self, line: bytes) -> None:
        raise NotImplementedError

    def journal_bytes(self) -> bytes:
        raise NotImplementedError


class MemoryAllocationStore(AllocationStore):
    """The in-memory store (deterministic verification)."""

    def __init__(self) -> None:
        self._lines: List[bytes] = []

    def append_journal_line(self, line: bytes) -> None:
        self._lines.append(bytes(line))

    def journal_bytes(self) -> bytes:
        return b"".join(self._lines)


class FileAllocationStore(AllocationStore):
    """The real durable store: an append-only journal file.

    The only filesystem-write site in the allocation family; the
    file is opened append-binary so history can only grow.  A
    store failure raises ``STORE_FAILED`` (persist-then-ack
    leaves no phantom state).
    """

    def __init__(self, directory: Path) -> None:
        if not isinstance(directory, Path):
            raise AllocationError(
                AllocationReasonCode.INVALID_INPUT,
                "directory must be a Path",
            )
        self._directory = directory
        self._journal_path = directory / "allocation-journal.jsonl"

    @property
    def journal_path(self) -> Path:
        return self._journal_path

    def append_journal_line(self, line: bytes) -> None:
        try:
            self._directory.mkdir(parents=True, exist_ok=True)
            with self._journal_path.open("ab") as handle:
                handle.write(bytes(line))
                handle.flush()
        except OSError as error:
            raise AllocationError(
                AllocationReasonCode.STORE_FAILED,
                "journal append failed: %s" % error,
            ) from error

    def journal_bytes(self) -> bytes:
        try:
            if not self._journal_path.exists():
                return b""
            with self._journal_path.open("rb") as handle:
                return handle.read()
        except OSError as error:
            raise AllocationError(
                AllocationReasonCode.STORE_FAILED,
                "journal read failed: %s" % error,
            ) from error


def journal_bytes_for(records: Tuple[JournalRecord, ...]) -> bytes:
    """Deterministic journal bytes for an ordered record list."""
    return b"".join(record.to_line() for record in records)


class AppendOnlyAllocationJournal:
    """The append-only, hash-chained allocation journal.

    Responsibilities (all fail-closed):

    - append atomic command+event records with contiguous
      sequence and hash-chain verification (persist-then-ack);
    - load a journal from store bytes with full integrity
      verification (ids, chain, sequence, command digests,
      allocation-intent digests, policy digests, duplicate
      command ids, duplicate usage-record ids, duplicate policy
      keys);
    - expose the ordered records and the THREE durable
      idempotency ledgers (command, usage-record, policy) for
      replay.
    """

    def __init__(self, *, store: AllocationStore) -> None:
        if not isinstance(store, AllocationStore):
            raise AllocationError(
                AllocationReasonCode.INVALID_INPUT,
                "store must be an AllocationStore",
            )
        self._store = store
        self._records: List[JournalRecord] = []
        self._command_ledger: Dict[str, Dict[str, str]] = {}
        self._usage_record_ledger: Dict[str, Dict[str, str]] = {}
        self._policy_ledger: Dict[str, Dict[str, str]] = {}
        self._load_and_verify()

    @property
    def store(self) -> AllocationStore:
        return self._store

    def _load_and_verify(self) -> None:
        """Load + verify the persisted journal (if any)."""
        data = self._store.journal_bytes()
        if not data:
            return
        if not data.endswith(b"\n"):
            raise AllocationError(
                AllocationReasonCode.JOURNAL_CORRUPT,
                "journal tail is truncated (last line is not "
                "newline-terminated)",
            )
        prev_record_id = GENESIS_RECORD_ID
        expected_sequence = 1
        for line_no, raw_line in enumerate(
            data.split(b"\n")[:-1], start=1
        ):
            try:
                payload = json.loads(raw_line.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as error:
                raise AllocationError(
                    AllocationReasonCode.JOURNAL_CORRUPT,
                    "journal line %d is not valid JSON: %s"
                    % (line_no, error),
                ) from error
            record = JournalRecord.from_dict(payload)
            if record.sequence != expected_sequence:
                raise AllocationError(
                    AllocationReasonCode.JOURNAL_CORRUPT,
                    "journal sequence gap at line %d: expected %d, found %d"
                    % (line_no, expected_sequence, record.sequence),
                )
            record.verify_command_digest()
            record.verify_id(prev_record_id)
            if record.command.command_id in self._command_ledger:
                raise AllocationError(
                    AllocationReasonCode.JOURNAL_CORRUPT,
                    "duplicate command id %r in the stored journal"
                    % record.command.command_id,
                )
            self._command_ledger[record.command.command_id] = deep_freeze({
                "command_digest": record.command_digest,
                "event_id": record.event.event_id,
            })
            if record.event.action == AllocationAction.ALLOCATE:
                if record.event.usage_record_id in self._usage_record_ledger:
                    raise AllocationError(
                        AllocationReasonCode.JOURNAL_CORRUPT,
                        "duplicate usage record id %r in the stored journal "
                        "(a usage record allocates exactly once)"
                        % record.event.usage_record_id,
                    )
                self._usage_record_ledger[
                    record.event.usage_record_id
                ] = deep_freeze({
                    "allocation_digest": record.allocation_digest,
                    "event_id": record.event.event_id,
                })
            if record.event.action == AllocationAction.REGISTER_POLICY:
                key = policy_key(
                    record.command.policy_id,
                    record.command.policy_version,
                )
                if key in self._policy_ledger:
                    raise AllocationError(
                        AllocationReasonCode.JOURNAL_CORRUPT,
                        "duplicate policy key %r in the stored journal "
                        "(a policy version registers exactly once)" % key,
                    )
                self._policy_ledger[key] = deep_freeze({
                    "policy_digest": record.policy_digest,
                    "event_id": record.event.event_id,
                })
            prev_record_id = record.record_id
            expected_sequence += 1
            self._records.append(record)

    def append(self, record: JournalRecord) -> None:
        """Append one record (persist-then-ack, fail closed)."""
        expected_sequence = len(self._records) + 1
        if record.sequence != expected_sequence:
            raise AllocationError(
                AllocationReasonCode.JOURNAL_CORRUPT,
                "append sequence %d is not the next journal sequence %d"
                % (record.sequence, expected_sequence),
            )
        prev_record_id = (
            self._records[-1].record_id
            if self._records
            else GENESIS_RECORD_ID
        )
        record.verify_command_digest()
        record.verify_id(prev_record_id)
        if record.command.command_id in self._command_ledger:
            raise AllocationError(
                AllocationReasonCode.JOURNAL_CORRUPT,
                "duplicate command id %r rejected at append (duplicates "
                "are no-ops at admission, never double-journaled)"
                % record.command.command_id,
            )
        if record.event.action == AllocationAction.ALLOCATE:
            if (
                record.event.usage_record_id
                in self._usage_record_ledger
            ):
                raise AllocationError(
                    AllocationReasonCode.JOURNAL_CORRUPT,
                    "duplicate usage record id %r rejected at append (a "
                    "usage record allocates exactly once)"
                    % record.event.usage_record_id,
                )
        if record.event.action == AllocationAction.REGISTER_POLICY:
            key = policy_key(
                record.command.policy_id,
                record.command.policy_version,
            )
            if key in self._policy_ledger:
                raise AllocationError(
                    AllocationReasonCode.JOURNAL_CORRUPT,
                    "duplicate policy key %r rejected at append (a policy "
                    "version registers exactly once)" % key,
                )
        # persist BEFORE acknowledge (no phantom in-memory state)
        self._store.append_journal_line(record.to_line())
        self._command_ledger[record.command.command_id] = deep_freeze({
            "command_digest": record.command_digest,
            "event_id": record.event.event_id,
        })
        if record.event.action == AllocationAction.ALLOCATE:
            self._usage_record_ledger[record.event.usage_record_id] = (
                deep_freeze({
                    "allocation_digest": record.allocation_digest,
                    "event_id": record.event.event_id,
                })
            )
        if record.event.action == AllocationAction.REGISTER_POLICY:
            key = policy_key(
                record.command.policy_id,
                record.command.policy_version,
            )
            self._policy_ledger[key] = deep_freeze({
                "policy_digest": record.policy_digest,
                "event_id": record.event.event_id,
            })
        self._records.append(record)

    def known_command(self, command_id: str):
        """The recorded (digest, event_id) for an admitted command
        id, or None (the durable command-idempotency ledger; the
        entry is a deeply frozen read-only view)."""
        return self._command_ledger.get(command_id)

    def known_usage_record(self, usage_record_id: str):
        """The recorded (digest, event_id) for an allocated usage
        record id, or None (the durable usage-record-idempotency
        ledger: a usage record allocates exactly once; the entry
        is a deeply frozen read-only view)."""
        return self._usage_record_ledger.get(usage_record_id)

    def known_policy(self, key: str):
        """The recorded (digest, event_id) for a registered policy
        key, or None (the durable policy-identity ledger; the
        entry is a deeply frozen read-only view)."""
        return self._policy_ledger.get(key)

    def command_ledger(self) -> Mapping[str, Mapping[str, str]]:
        """The durable command-idempotency ledger as a LIVE
        read-only view (deeply frozen: the outer mapping and
        every entry reject in-place mutation -- the W053
        review-cycle correction; reads stay live with the
        journal)."""
        return MappingProxyType(self._command_ledger)

    def usage_record_ledger(self) -> Mapping[str, Mapping[str, str]]:
        """The durable usage-record-idempotency ledger as a live
        read-only (deeply frozen) view."""
        return MappingProxyType(self._usage_record_ledger)

    def policy_ledger(self) -> Mapping[str, Mapping[str, str]]:
        """The durable policy-identity ledger as a live read-only
        (deeply frozen) view."""
        return MappingProxyType(self._policy_ledger)

    def records(self) -> Tuple[JournalRecord, ...]:
        return tuple(self._records)

    def events(self) -> Tuple[AllocationEvent, ...]:
        return tuple(record.event for record in self._records)

    def __len__(self) -> int:
        return len(self._records)

    def tail_sequence(self) -> int:
        return len(self._records)

    def journal_digest(self) -> str:
        return record_list_digest(tuple(self._records))
