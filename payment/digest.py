"""WORK-044 payment-boundary deterministic digest helpers.

The evidence chain of the payment gateway: every digest is
content-derived over canonical JSON (WORK-003) from recorded
facts only -- identical logical histories produce byte-identical
digests, with no clock, randomness, or environment dependence.

- :func:`state_digest` -- the folded payment-intent state
  (sorted intent ids; per-intent projection digests);
- :func:`payout_state_digest` -- the folded payout-instruction
  state (sorted usage-record ids; per-instruction digests);
- :func:`observation_log_digest` -- the recorded callback
  observations (sorted event ids; per-observation digests);
- :func:`capability_registry_digest` -- the folded immutable
  versioned capability registry (sorted keys);
- :func:`report_log_digest` -- the recorded reconciliation
  reports (journaled order; per-report digests);
- :func:`command_ledger_digest` / :func:`intent_ledger_digest` /
  :func:`payout_ledger_digest` /
  :func:`callback_ledger_digest` /
  :func:`capability_ledger_digest` -- the five durable
  idempotency ledgers (journal order);
- :func:`snapshot_digest` -- the injected commercial snapshot;
- :func:`event_list_digest` -- the journaled event chain;
- :func:`assemble_digest_stream` -- the canonical evidence
  document (journal digest, state digests, registry digests,
  the five idempotency-ledger digests, event list digest,
  snapshot digest) used by the two-run and hash-seed
  determinism proofs.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Iterable, Mapping, Tuple

from protocol.canonicalization import canonical_json_bytes

from .journal import AppendOnlyPaymentJournal
from .model import (
    CallbackObservation,
    PaymentIntent,
    PayoutInstruction,
    ReconciliationReport,
    event_list_digest,
    intent_digest,
    observation_digest,
    payout_instruction_digest,
    report_digest,
)


def _digest(kind: str, content: Any) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes({"kind": kind, **content})
    ).hexdigest()


def state_digest(intents: Iterable[PaymentIntent]) -> str:
    """Deterministic digest over the folded intent state (sorted
    intent ids; insertion-order independent)."""
    items = [
        {"intent_id": intent.intent_id, "digest": intent_digest(intent)}
        for intent in intents
    ]
    items.sort(key=lambda item: item["intent_id"])
    return _digest("payment-intent-state", {"intents": items})


def payout_state_digest(
    payouts: Iterable[PayoutInstruction],
) -> str:
    """Deterministic digest over the folded payout-instruction
    state (sorted usage-record ids)."""
    items = [
        {
            "usage_record_id": instruction.usage_record_id,
            "digest": payout_instruction_digest(instruction),
        }
        for instruction in payouts
    ]
    items.sort(key=lambda item: item["usage_record_id"])
    return _digest("payment-payout-state", {"payouts": items})


def observation_log_digest(
    observations: Iterable[CallbackObservation],
) -> str:
    """Deterministic digest over the recorded observations
    (sorted event ids)."""
    items = [
        {
            "event_id": observation.event_id,
            "digest": observation_digest(observation),
        }
        for observation in observations
    ]
    items.sort(key=lambda item: item["event_id"])
    return _digest("payment-observations", {"observations": items})


def capability_registry_digest(
    capabilities: Iterable[Any],
) -> str:
    """Deterministic digest over the folded immutable versioned
    capability registry (sorted capability keys)."""
    items = [
        {"capability_key": record.key(), "digest": record.digest()}
        for record in capabilities
    ]
    items.sort(key=lambda item: item["capability_key"])
    return _digest("payment-capabilities", {"capabilities": items})


def report_log_digest(reports: Iterable[ReconciliationReport]) -> str:
    """Deterministic digest over the recorded reconciliation
    reports (journaled order)."""
    items = [
        {"report_id": report.report_id, "digest": report_digest(report)}
        for report in reports
    ]
    return _digest("payment-reports", {"reports": items})


def command_ledger_digest(
    ledger: Mapping[str, Mapping[str, str]],
) -> str:
    """The durable command-idempotency ledger digest (admitted
    command ids and digests, in journal order)."""
    items = [
        {
            "command_id": command_id,
            "command_digest": ledger[command_id]["command_digest"],
        }
        for command_id in sorted(ledger)
    ]
    return _digest("payment-command-ledger", {"commands": items})


def intent_ledger_digest(
    ledger: Mapping[str, Mapping[str, str]],
) -> str:
    """The durable intent-identity ledger digest (created intent
    ids and identity digests, in journal order)."""
    items = [
        {
            "intent_id": intent_id,
            "intent_digest": ledger[intent_id]["intent_digest"],
        }
        for intent_id in sorted(ledger)
    ]
    return _digest("payment-intent-ledger", {"intents": items})


def payout_ledger_digest(
    ledger: Mapping[str, Mapping[str, str]],
) -> str:
    """The durable payout-identity ledger digest (emitted usage
    record ids and basis digests)."""
    items = [
        {
            "usage_record_id": usage_record_id,
            "payout_digest": ledger[usage_record_id]["payout_digest"],
        }
        for usage_record_id in sorted(ledger)
    ]
    return _digest("payment-payout-ledger", {"payouts": items})


def callback_ledger_digest(
    ledger: Mapping[str, Mapping[str, str]],
) -> str:
    """The durable callback anti-replay ledger digest (observed
    event ids and observation digests)."""
    items = [
        {
            "event_id": event_id,
            "callback_digest": ledger[event_id]["callback_digest"],
        }
        for event_id in sorted(ledger)
    ]
    return _digest("payment-callback-ledger", {"callbacks": items})


def capability_ledger_digest(
    ledger: Mapping[str, Mapping[str, str]],
) -> str:
    """The durable capability-identity ledger digest (declared
    keys and declaration digests)."""
    items = [
        {
            "capability_key": key,
            "capability_digest": ledger[key]["capability_digest"],
        }
        for key in sorted(ledger)
    ]
    return _digest("payment-capability-ledger", {"capabilities": items})


def snapshot_digest(snapshot: Any) -> str:
    """The injected commercial snapshot digest (sorted citation
    ids over the citation contents)."""
    items = [
        {"reference_id": entry.reference_id, "content": entry.content()}
        for entry in snapshot.entries()
    ]
    items.sort(key=lambda item: item["reference_id"])
    return _digest("payment-snapshot", {"citations": items})


def assemble_digest_stream(
    *,
    journal: AppendOnlyPaymentJournal,
    capabilities: Iterable[Any],
    intents: Iterable[PaymentIntent],
    payouts: Iterable[PayoutInstruction],
    observations: Iterable[CallbackObservation],
    reports: Iterable[ReconciliationReport],
) -> str:
    """The canonical deterministic evidence document (the
    golden digest stream basis).

    Composes the journal digest, the state digests, the
    immutable capability registry digest, the report log
    digest, the FIVE idempotency-ledger digests, the event
    list digest, and the tail sequence -- identical logical
    histories produce byte-identical streams.
    """
    events = [record.event for record in journal.records()]
    content: Dict[str, Any] = {
        "kind": "payment-digest-stream",
        "tail_sequence": journal.tail_sequence(),
        "journal_digest": journal.journal_digest(),
        "state_digest": state_digest(intents),
        "payout_state_digest": payout_state_digest(payouts),
        "observation_log_digest": observation_log_digest(observations),
        "capability_registry_digest": capability_registry_digest(
            capabilities
        ),
        "report_log_digest": report_log_digest(reports),
        "command_ledger_digest": command_ledger_digest(
            journal.command_ledger()
        ),
        "intent_ledger_digest": intent_ledger_digest(
            journal.intent_ledger()
        ),
        "payout_ledger_digest": payout_ledger_digest(
            journal.payout_ledger()
        ),
        "callback_ledger_digest": callback_ledger_digest(
            journal.callback_ledger()
        ),
        "capability_ledger_digest": capability_ledger_digest(
            journal.capability_ledger()
        ),
        "event_list_digest": event_list_digest(events),
    }
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(content)
    ).hexdigest()
