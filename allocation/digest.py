"""WORK-053 EconomicAllocation deterministic digest helpers.

The evidence chain of the allocation layer: every digest is
content-derived over canonical JSON (WORK-003) from recorded
facts only -- identical logical histories produce byte-identical
digests, with no clock, randomness, or environment dependence.

- :func:`state_digest` -- the folded allocation state (sorted
  usage record ids; per-account projection digests);
- :func:`policy_state_digest` -- the folded immutable
  economic-policy registry (sorted policy keys; per-version
  digests);
- :func:`command_ledger_digest` -- the durable command
  idempotency ledger (admitted command ids and digests, in
  journal order);
- :func:`usage_record_ledger_digest` -- the durable
  usage-record idempotency ledger (allocated usage records and
  their allocation-intent digests);
- :func:`policy_ledger_digest` -- the durable policy-identity
  ledger (registered policy keys and digests);
- :func:`fact_index_digest` -- the injected fact index snapshot;
- :func:`assemble_digest_stream` -- the canonical evidence
  document (journal digest, state digest, policy registry
  digest, the three idempotency-ledger digests, event list
  digest, fact index digest) used by the two-run and hash-seed
  determinism proofs.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Iterable, Mapping, Tuple

from protocol.canonicalization import canonical_json_bytes

from .journal import AppendOnlyAllocationJournal
from .model import (
    AllocationEvent,
    EconomicPolicy,
    account_digest,
    event_list_digest,
)
from .evidence import FactIndex


def state_digest(accounts: Iterable[Any]) -> str:
    """Deterministic digest over the folded allocation state.

    Iteration is over sorted usage record ids, so the digest is
    insertion-order independent and byte-identical for identical
    logical states.
    """
    items = [
        {
            "usage_record_id": account.usage_record_id,
            "digest": account_digest(account),
        }
        for account in accounts
    ]
    items.sort(key=lambda item: item["usage_record_id"])
    content = {"kind": "allocation-state", "accounts": items}
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(content)
    ).hexdigest()


def policy_state_digest(policies: Iterable[EconomicPolicy]) -> str:
    """Deterministic digest over the folded immutable
    economic-policy registry (sorted (policy_id, version)
    keys)."""
    items = [
        {"policy_key": policy.key(), "digest": policy.digest()}
        for policy in policies
    ]
    items.sort(key=lambda item: item["policy_key"])
    content = {"kind": "allocation-policy-registry", "policies": items}
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(content)
    ).hexdigest()


def command_ledger_digest(
    ledger: Mapping[str, Mapping[str, str]]
) -> str:
    """Deterministic digest over the durable command ledger (the
    public :meth:`AllocationLedger.command_ledger` mapping)."""
    entries = [
        {
            "command_id": command_id,
            "command_digest": entry["command_digest"],
            "event_id": entry["event_id"],
        }
        for command_id, entry in sorted(ledger.items())
    ]
    content = {"kind": "allocation-command-ledger", "commands": entries}
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(content)
    ).hexdigest()


def usage_record_ledger_digest(
    ledger: Mapping[str, Mapping[str, str]]
) -> str:
    """Deterministic digest over the durable usage-record ledger
    (the public :meth:`AllocationLedger.usage_record_ledger`
    mapping -- a usage record allocates exactly once)."""
    entries = [
        {
            "usage_record_id": usage_record_id,
            "allocation_digest": entry["allocation_digest"],
            "event_id": entry["event_id"],
        }
        for usage_record_id, entry in sorted(ledger.items())
    ]
    content = {
        "kind": "allocation-usage-record-ledger",
        "usage_records": entries,
    }
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(content)
    ).hexdigest()


def policy_ledger_digest(
    ledger: Mapping[str, Mapping[str, str]]
) -> str:
    """Deterministic digest over the durable policy-identity
    ledger (the public :meth:`AllocationLedger.policy_ledger`
    mapping -- a policy version registers exactly once)."""
    entries = [
        {
            "policy_key": key,
            "policy_digest": entry["policy_digest"],
            "event_id": entry["event_id"],
        }
        for key, entry in sorted(ledger.items())
    ]
    content = {"kind": "allocation-policy-ledger", "policies": entries}
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(content)
    ).hexdigest()


def fact_index_digest(index: FactIndex) -> str:
    """Deterministic digest over the injected fact index snapshot
    (sorted reference ids)."""
    content = {"kind": "allocation-fact-index", **index.to_dict()}
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(content)
    ).hexdigest()


def assemble_digest_stream(
    *,
    journal: AppendOnlyAllocationJournal,
    policies: Iterable[EconomicPolicy],
    accounts: Iterable[Any],
    index: FactIndex,
) -> str:
    """The canonical deterministic evidence document.

    One canonical JSON document binding: the journal digest, the
    folded allocation-state digest, the folded policy-registry
    digest, the command-ledger digest, the usage-record-ledger
    digest, the policy-ledger digest, the event list digest, and
    the fact index digest.  Two runs of the identical command
    history over the identical injected clock produce
    byte-identical documents (the battery proves this in-process
    and under PYTHONHASHSEED 0/1/7919/unset).
    """
    events: Tuple[AllocationEvent, ...] = journal.events()
    content: Dict[str, Any] = {
        "kind": "allocation-digest-stream",
        "record_count": len(journal),
        "journal_digest": journal.journal_digest(),
        "state_digest": state_digest(accounts),
        "policy_state_digest": policy_state_digest(policies),
        "command_ledger_digest": command_ledger_digest(
            journal.command_ledger()
        ),
        "usage_record_ledger_digest": usage_record_ledger_digest(
            journal.usage_record_ledger()
        ),
        "policy_ledger_digest": policy_ledger_digest(
            journal.policy_ledger()
        ),
        "event_list_digest": event_list_digest(events),
        "fact_index_digest": fact_index_digest(index),
    }
    return canonical_json_bytes(content).decode("utf-8")


def digest_of(text: str) -> str:
    """A plain sha256 hex digest of a UTF-8 document (battery
    helper for byte-equality proofs)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
