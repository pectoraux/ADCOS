"""WORK-053 EconomicAllocation external usage-fact boundary.

The authority-reference model of the economic allocation layer
(W053 contract invariants 1, 2, 6, 8, 10; the W051
``commercial.references`` and W052 ``usage.evidence`` discipline
mirrored):

- The allocation layer may REFERENCE the WORK-052 UsageLedger's
  billable-final usage records (the immutable, addressable
  ``finality.record_id`` facts -- the ONLY economic source of
  usage truth, accepted-merged by DEC-0060), the WORK-051
  commercial transaction projections (public DATA read through
  the CommercialCore public surface), and external
  payment-provider intent/transfer/reference observations plus
  external settlement confirmations (DATA only, never commercial
  truth).
- It must NEVER own, mutate, query, or instantiate those
  authorities: there is no authority object, client, manager, or
  private accessor anywhere in the allocation family.  A
  :class:`FactIndex` is an immutable snapshot mapping reference
  ids to family descriptors, BUILT BY THE CALLER from the
  authorities' PUBLIC interfaces (the UsageLedger's public
  account projections, the CommercialCore's public transaction
  projections, and the external provider planes) and INJECTED
  into the allocation ledger.
- Fail-closed fact integrity: a command citing an id the index
  does not carry is rejected ``FACT_UNKNOWN`` (a fabricated
  usage-final, commercial, provider, or settlement citation can
  never enter allocation state); a citation of the wrong family
  for its slot is rejected by the family-rules table
  (:mod:`allocation.validation`); a payment-provider citation can
  never satisfy an allocation or settlement requirement
  (``PAYMENT_NOT_ALLOCATION`` / ``PAYMENT_NOT_SETTLEMENT`` -- the
  payment/allocation separation is family-table-driven, not
  caller-honor-driven); a non-``BILLABLE_FINAL`` usage citation is
  rejected ``USAGE_NOT_FINAL`` (allocation consumes only
  billable-final usage facts).

Facts are DATA (id + family + provenance + the public-read facts
the family needs): they carry no authority semantics, no trust,
and no mutation surface.  ``usage_state``/``transaction_id``/
``amount``/``quantity``/``unit``/``finalized_at`` carry the W052
billable-final projection facts a public
``UsageLedger.accounts()`` read yields, so allocation admission
can gate on the REAL finality facts without ever touching the
usage authority.  ``commercial_state``/``session_ref``/
``path_ref`` carry the WORK-051 transaction projection facts a
public ``CommercialCore.transaction()`` read yields (DATA only --
attribution, never justification).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Iterable, Mapping, Tuple

from .errors import AllocationError, AllocationReasonCode


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise AllocationError(
            AllocationReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


def _optional_instant(value: object, label: str) -> str:
    if value == "":
        return ""
    if not isinstance(value, str):
        raise AllocationError(
            AllocationReasonCode.INSTANT_INVALID,
            "%s must be an RFC 3339 UTC instant string or empty" % label,
        )
    from agent.clock import parse_utc

    try:
        parse_utc(value)
    except Exception as error:  # noqa: BLE001 - re-wrapped typed
        raise AllocationError(
            AllocationReasonCode.INSTANT_INVALID,
            "%s %r is not RFC 3339 UTC: %s" % (label, value, error),
        ) from error
    return value


def _require_optional_text(value: object, label: str) -> None:
    if value == "":
        return
    if not isinstance(value, str) or not value:
        raise AllocationError(
            AllocationReasonCode.INVALID_INPUT,
            "%s must be a non-empty string or empty" % label,
        )


def _require_int_at_least(value: object, minimum: int, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise AllocationError(
            AllocationReasonCode.INVALID_INPUT,
            "%s must be an integer (quantities and amounts are integer "
            "DATA; floats are rejected)" % label,
        )
    if value < minimum:
        raise AllocationError(
            AllocationReasonCode.INVALID_INPUT,
            "%s must be >= %d" % (label, minimum),
        )
    return value


class FactFamily:
    """The frozen external-fact family vocabulary (W053).

    The usage-final family carries the W052 billable-final usage
    records (the only economic source of usage truth the layer may
    consume).  The commercial family carries WORK-051 transaction
    projections cited as DATA (attribution only).  The
    payment-provider and settlement families are explicitly
    external: payment-provider intent/transfer/reference
    observations and external settlement confirmations are
    recorded DATA and can never justify allocation.
    """

    USAGE_FINAL = "usage-final"
    COMMERCIAL = "commercial"
    PAYMENT_PROVIDER = "payment-provider"
    SETTLEMENT = "settlement"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.USAGE_FINAL,
            cls.COMMERCIAL,
            cls.PAYMENT_PROVIDER,
            cls.SETTLEMENT,
        )

    @classmethod
    def authority_families(cls) -> Tuple[str, ...]:
        """The authority-owned families the layer may cite but
        never own (W052 usage facts; W051 commercial DATA)."""
        return (cls.USAGE_FINAL, cls.COMMERCIAL)

    @classmethod
    def external_families(cls) -> Tuple[str, ...]:
        """The external-plane families (provider/settlement DATA
        only, never commercial truth)."""
        return (cls.PAYMENT_PROVIDER, cls.SETTLEMENT)


@dataclass(frozen=True)
class FactReference:
    """One external fact reference (id + family + provenance +
    public-read facts, DATA only).

    ``reference_id`` is the authority-owned identity string: for
    the usage-final family it is the W052 billable-final record id
    (the immutable, addressable ``finality.record_id``) for final
    accounts, or the commercial transaction id for an open
    (non-final) account snapshot (the honest public identity of an
    account that has no finality record yet -- citing it fails
    closed ``USAGE_NOT_FINAL`` at admission).  ``provenance``
    records which authority surface produced it (a label, never a
    live object).  ``usage_state``/``transaction_id``/``amount``/
    ``quantity``/``unit``/``finalized_at`` are the W052 public
    projection facts (usage-final family only);
    ``commercial_state``/``session_ref``/``path_ref`` are the W051
    public projection facts (commercial family only).  A reference
    is a citation, not a capability: holding one grants no
    authority access.
    """

    reference_id: str
    family: str
    provenance: str
    usage_state: str = ""
    transaction_id: str = ""
    amount: int = 0
    quantity: int = 0
    unit: str = ""
    finalized_at: str = ""
    commercial_state: str = ""
    session_ref: str = ""
    path_ref: str = ""

    def __post_init__(self) -> None:
        _require_text(self.reference_id, "reference_id")
        if self.family not in FactFamily.values():
            raise AllocationError(
                AllocationReasonCode.FACT_FAMILY_INVALID,
                "family %r must be one of %s"
                % (self.family, list(FactFamily.values())),
            )
        _require_text(self.provenance, "provenance")
        # family-scoped facts: only usage-final references carry
        # the W052 projection facts; only commercial references
        # carry the W051 transaction facts; provider/settlement
        # references carry ids only (pure external DATA).  The
        # usage-final/commercial facts are OPTIONAL at
        # construction: a thin command citation carries
        # id+family+provenance only, and resolution replaces it
        # with the INDEX-AUTHORITATIVE record (the caller-built
        # index entries carry the full public projection facts;
        # admission validates the resolved facts).  Non-empty
        # members must still be well-formed, and no other family
        # may carry them at all.
        if self.family != FactFamily.USAGE_FINAL:
            for label, value in (
                ("usage_state", self.usage_state),
                ("transaction_id", self.transaction_id),
                ("unit", self.unit),
                ("finalized_at", self.finalized_at),
            ):
                if value != "":
                    raise AllocationError(
                        AllocationReasonCode.FACT_FAMILY_INVALID,
                        "only usage-final references carry %s" % label,
                    )
            if self.amount != 0 or self.quantity != 0:
                raise AllocationError(
                    AllocationReasonCode.FACT_FAMILY_INVALID,
                    "only usage-final references carry amount/quantity",
                )
        else:
            for label, value in (
                ("usage_state", self.usage_state),
                ("transaction_id", self.transaction_id),
                ("unit", self.unit),
            ):
                _require_optional_text(value, label)
            _require_int_at_least(self.amount, 0, "amount")
            _require_int_at_least(self.quantity, 0, "quantity")
            _optional_instant(self.finalized_at, "finalized_at")
        if self.family != FactFamily.COMMERCIAL and (
            self.commercial_state != ""
            or self.session_ref != ""
            or self.path_ref != ""
        ):
            raise AllocationError(
                AllocationReasonCode.FACT_FAMILY_INVALID,
                "only commercial references carry transaction facts",
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reference_id": self.reference_id,
            "family": self.family,
            "provenance": self.provenance,
            "usage_state": self.usage_state,
            "transaction_id": self.transaction_id,
            "amount": self.amount,
            "quantity": self.quantity,
            "unit": self.unit,
            "finalized_at": self.finalized_at,
            "commercial_state": self.commercial_state,
            "session_ref": self.session_ref,
            "path_ref": self.path_ref,
        }

    @classmethod
    def from_dict(cls, data: object) -> "FactReference":
        if not isinstance(data, Mapping):
            raise AllocationError(
                AllocationReasonCode.FACT_FAMILY_INVALID,
                "fact reference must be a mapping",
            )
        for key in (
            "reference_id",
            "family",
            "provenance",
            "usage_state",
            "transaction_id",
            "amount",
            "quantity",
            "unit",
            "finalized_at",
            "commercial_state",
            "session_ref",
            "path_ref",
        ):
            if key not in data:
                raise AllocationError(
                    AllocationReasonCode.FACT_FAMILY_INVALID,
                    "fact reference is missing required member %r" % key,
                )
        return cls(
            reference_id=data["reference_id"],
            family=data["family"],
            provenance=data["provenance"],
            usage_state=data["usage_state"],
            transaction_id=data["transaction_id"],
            amount=data["amount"],
            quantity=data["quantity"],
            unit=data["unit"],
            finalized_at=data["finalized_at"],
            commercial_state=data["commercial_state"],
            session_ref=data["session_ref"],
            path_ref=data["path_ref"],
        )


class FactIndex:
    """An immutable snapshot of resolvable external facts.

    Built by the CALLER from the accepted authorities' PUBLIC
    interfaces (the W052 UsageLedger's public account projections,
    the WORK-051 CommercialCore's public transaction projections,
    and the external payment-provider/settlement planes) and
    INJECTED into the allocation ledger.  The ledger resolves
    command citations against the index and never against a live
    authority: allocation state can cite an authority identity
    only if the caller has already read it through that
    authority's public surface.

    The index is frozen at construction (a snapshot, not a live
    view): fact sets change only by building a new index, which
    keeps command admission deterministic and replay-safe.
    """

    def __init__(self, references: Iterable[FactReference]) -> None:
        table: Dict[str, FactReference] = {}
        for reference in references:
            if not isinstance(reference, FactReference):
                raise AllocationError(
                    AllocationReasonCode.INVALID_INPUT,
                    "index entries must be FactReference values",
                )
            existing = table.get(reference.reference_id)
            if existing is not None:
                if existing.to_dict() != reference.to_dict():
                    raise AllocationError(
                        AllocationReasonCode.FACT_FAMILY_INVALID,
                        "conflicting index entries for reference %s"
                        % reference.reference_id,
                    )
                continue
            table[reference.reference_id] = reference
        self._table: Dict[str, FactReference] = dict(table)

    def __len__(self) -> int:
        return len(self._table)

    def contains(self, reference_id: str) -> bool:
        return reference_id in self._table

    def get(self, reference_id: str) -> FactReference:
        reference = self._table.get(reference_id)
        if reference is None:
            raise AllocationError(
                AllocationReasonCode.FACT_UNKNOWN,
                "external fact %r is not resolvable in the fact index "
                "(fabricated or evicted reference)" % reference_id,
            )
        return reference

    def families(self) -> FrozenSet[str]:
        return frozenset(ref.family for ref in self._table.values())

    def by_family(self, family: str) -> Tuple[FactReference, ...]:
        if family not in FactFamily.values():
            raise AllocationError(
                AllocationReasonCode.FACT_FAMILY_INVALID,
                "family %r must be one of %s"
                % (family, list(FactFamily.values())),
            )
        return tuple(
            self._table[key] for key in sorted(self._table)
            if self._table[key].family == family
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "references": [
                self._table[key].to_dict() for key in sorted(self._table)
            ]
        }


def resolve_facts(
    index: FactIndex,
    references: Tuple[FactReference, ...],
) -> Tuple[FactReference, ...]:
    """Resolve every cited reference against the index.

    Fail-closed: an unknown reference id (fabricated usage-final /
    commercial / provider / settlement citation) raises
    ``FACT_UNKNOWN`` BEFORE any allocation state changes.
    Resolution returns the INDEX-AUTHORITATIVE records (the index
    is the family authority): a citation claiming one family while
    the index records another is judged by the index family in
    command admission (the payment/allocation separation in
    :mod:`allocation.validation` -- a payment-provider id cited in
    a usage-final slot resolves as payment-provider family and
    fails closed ``PAYMENT_NOT_ALLOCATION``).  Duplicate ids in one
    citation collapse deterministically (sorted, unique);
    admission additionally requires the usage-final citation set
    to be UNAMBIGUOUS (exactly one distinct id) and BOUND to the
    command's own usage record id (fail closed ``FACT_AMBIGUOUS``
    / ``USAGE_RECORD_MISMATCH`` in
    :func:`allocation.validation.validate_fact_integrity`).
    """
    resolved: Dict[str, FactReference] = {}
    for reference in references:
        known = index.get(reference.reference_id)
        resolved[reference.reference_id] = known
    return tuple(resolved[key] for key in sorted(resolved))


def fact_family_counts(
    references: Tuple[FactReference, ...]
) -> Dict[str, int]:
    """Deterministic family histogram of a resolved reference tuple."""
    counts: Dict[str, int] = {}
    for reference in references:
        counts[reference.family] = counts.get(reference.family, 0) + 1
    return counts
