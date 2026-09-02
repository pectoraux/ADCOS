"""WORK-044 commercial-citation boundary (the injected snapshot).

The authority-consumption model of the payment boundary
(mirrors the W051 ReferenceIndex / W052 EvidenceIndex / W053
FactIndex discipline):

- The payment boundary may REFERENCE WORK-051 commercial
  transaction ids (transaction projections), WORK-052 usage
  account/finality record ids, and WORK-053 allocation account
  ids (usage-record keys) -- all authority-owned identities,
  cited never derived.
- It must NEVER own, mutate, query, or instantiate those
  authorities: there is no authority object, client, manager,
  or private accessor anywhere in the payment family (the
  import discipline is battery-audited: the payment package
  imports stdlib + the WORK-003 canonicalization + the WORK-033
  clock seam ONLY).  A :class:`CommercialSnapshot` is an
  immutable snapshot mapping citation ids to family
  descriptors, BUILT BY THE CALLER from the authorities'
  PUBLIC interfaces and INJECTED into the gateway.
- Fail-closed citation integrity: a command citing an id the
  snapshot does not carry is rejected ``citation-unknown`` (a
  fabricated transaction or allocation can never enter payment
  state); a citation of the wrong family for the command's
  causal requirement is rejected ``citation-family-invalid``.

Citations are DATA (id + family + provenance + the public
projection fields the boundary legitimately consumes as DATA):
they carry no authority semantics, no trust, and no mutation
surface.  Payment success never implies delivery success, and
nothing in the citation model lets payment state change usage,
commercial, or allocation state.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Tuple

from .errors import PaymentError, PaymentReasonCode


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise PaymentError(
            PaymentReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


def _optional_text(value: object, label: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise PaymentError(
            PaymentReasonCode.INVALID_INPUT,
            "%s must be a string" % label,
        )
    return value


def _optional_int(value: object, label: str) -> int:
    if value is None:
        return 0
    if not isinstance(value, int) or isinstance(value, bool):
        raise PaymentError(
            PaymentReasonCode.INVALID_INPUT,
            "%s must be an integer" % label,
        )
    return value


class CitationFamily:
    """The frozen commercial-citation family vocabulary (W044).

    The three authority families the payment boundary may cite:
    the WORK-051 commercial transaction projection, the WORK-052
    usage account (billable-final finality record, or the
    honest open identity of an unfinalized account), and the
    W053 allocation account.  There is NO payment-internal
    family here: gateway-owned payment identities (intents,
    payouts, observations) are journaled facts, not citations.
    """

    COMMERCIAL = "commercial"
    USAGE_FINAL = "usage-final"
    ALLOCATION = "allocation"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.COMMERCIAL, cls.USAGE_FINAL, cls.ALLOCATION)

    @classmethod
    def authority_families(cls) -> Tuple[str, ...]:
        """All three families are authority-owned citation
        families (the boundary cites; it never owns)."""
        return cls.values()


@dataclass(frozen=True)
class CommercialCitation:
    """One immutable external-authority citation record (DATA).

    ``reference_id`` is the authority-owned identity (WORK-051
    transaction id, WORK-052 finality record id / honest open
    account id, or WORK-053 allocation usage-record id).
    ``family`` and ``provenance`` identify the citing family
    and the public source it was read from.  The projection
    members carry ONLY the public fields the payment boundary
    consumes as DATA: the commercial state (transaction
    correlation), the usage state/amount/quantity/unit/
    finalized_at (billable context), and the allocation
    state/split amounts/currency/exponent (payout emission
    basis).  A citation never implies payment, delivery, or
    settlement truth in either direction.
    """

    reference_id: str
    family: str
    provenance: str
    commercial_state: str = ""
    transaction_id: str = ""
    usage_state: str = ""
    amount: int = 0
    quantity: int = 0
    unit: str = ""
    finalized_at: str = ""
    allocation_state: str = ""
    billable_amount: int = 0
    currency: str = ""
    exponent: int = 0
    developer_amount: int = 0
    provider_amount: int = 0
    adc_os_amount: int = 0
    tax_amount: int = 0

    def __post_init__(self) -> None:
        _require_text(self.reference_id, "reference_id")
        if self.family not in CitationFamily.values():
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "citation family %r must be one of %s"
                % (self.family, list(CitationFamily.values())),
            )
        _require_text(self.provenance, "provenance")
        for label, value in (
            ("commercial_state", self.commercial_state),
            ("transaction_id", self.transaction_id),
            ("usage_state", self.usage_state),
            ("unit", self.unit),
            ("finalized_at", self.finalized_at),
            ("allocation_state", self.allocation_state),
            ("currency", self.currency),
        ):
            if not isinstance(value, str):
                raise PaymentError(
                    PaymentReasonCode.INVALID_INPUT,
                    "%s must be a string" % label,
                )
        for label, value in (
            ("amount", self.amount),
            ("quantity", self.quantity),
            ("billable_amount", self.billable_amount),
            ("exponent", self.exponent),
            ("developer_amount", self.developer_amount),
            ("provider_amount", self.provider_amount),
            ("adc_os_amount", self.adc_os_amount),
            ("tax_amount", self.tax_amount),
        ):
            if not isinstance(value, int) or isinstance(value, bool):
                raise PaymentError(
                    PaymentReasonCode.INVALID_INPUT,
                    "%s must be an integer" % label,
                )
            if value < 0:
                raise PaymentError(
                    PaymentReasonCode.INVALID_INPUT,
                    "%s must be non-negative" % label,
                )

    def content(self) -> Dict[str, Any]:
        return {
            "reference_id": self.reference_id,
            "family": self.family,
            "provenance": self.provenance,
            "commercial_state": self.commercial_state,
            "transaction_id": self.transaction_id,
            "usage_state": self.usage_state,
            "amount": self.amount,
            "quantity": self.quantity,
            "unit": self.unit,
            "finalized_at": self.finalized_at,
            "allocation_state": self.allocation_state,
            "billable_amount": self.billable_amount,
            "currency": self.currency,
            "exponent": self.exponent,
            "developer_amount": self.developer_amount,
            "provider_amount": self.provider_amount,
            "adc_os_amount": self.adc_os_amount,
            "tax_amount": self.tax_amount,
        }

    def to_dict(self) -> Dict[str, Any]:
        return self.content()


class CommercialSnapshot:
    """The immutable injected citation index (fail-closed).

    Built by the CALLER from the WORK-051/W052/W053 PUBLIC
    surfaces (transaction projections, usage accounts, allocation
    accounts) and injected into the gateway.  One authority
    identity may appear under SEVERAL family views -- the W052
    billable-final finality record id IS the W053 allocation
    account key, read through two public surfaces -- so the
    index maps each id to its family views and resolution is by
    EXACT (id, expected family) pair: a wrong-family resolution
    fails closed exactly like an unknown id.  A duplicate
    (id, family) pair fails closed at construction (an
    ambiguous index can never admit a command).
    """

    def __init__(self, entries: Any) -> None:
        if not isinstance(entries, (list, tuple)):
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "snapshot entries must be a sequence of CommercialCitation",
            )
        index: Dict[str, Dict[str, CommercialCitation]] = {}
        for entry in entries:
            if not isinstance(entry, CommercialCitation):
                raise PaymentError(
                    PaymentReasonCode.INVALID_INPUT,
                    "snapshot entries must be CommercialCitation values",
                )
            views = index.setdefault(entry.reference_id, {})
            existing = views.get(entry.family)
            if existing is not None:
                raise PaymentError(
                    PaymentReasonCode.INVALID_INPUT,
                    "duplicate citation id %r in family %r in the snapshot"
                    % (entry.reference_id, entry.family),
                )
            views[entry.family] = entry
        self._index: Dict[str, Dict[str, CommercialCitation]] = {
            key: dict(views) for key, views in index.items()
        }

    def entries(self) -> Tuple[CommercialCitation, ...]:
        return tuple(
            self._index[reference_id][family]
            for reference_id in sorted(self._index)
            for family in sorted(self._index[reference_id])
        )

    def by_family(self, family: str) -> Tuple[CommercialCitation, ...]:
        if family not in CitationFamily.values():
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "family %r is not a citation family" % family,
            )
        return tuple(
            self._index[reference_id][family]
            for reference_id in sorted(self._index)
            if family in self._index[reference_id]
        )

    def citation(self, reference_id: str) -> CommercialCitation:
        views = self._index.get(reference_id, {})
        if not views:
            raise PaymentError(
                PaymentReasonCode.CITATION_UNKNOWN,
                "citation %r is not carried by the injected snapshot"
                % reference_id,
            )
        if len(views) > 1:
            raise PaymentError(
                PaymentReasonCode.CITATION_FAMILY_INVALID,
                "citation %r carries several family views; resolve with the "
                "expected family" % reference_id,
            )
        return next(iter(views.values()))

    def resolve(
        self, reference_id: str, expected_family: str
    ) -> CommercialCitation:
        """Resolve one citation by exact id AND expected family
        (fail closed on unknown id or wrong family)."""
        views = self._index.get(reference_id, {})
        entry = views.get(expected_family)
        if entry is None:
            if not views:
                raise PaymentError(
                    PaymentReasonCode.CITATION_UNKNOWN,
                    "citation %r is not carried by the injected snapshot"
                    % reference_id,
                )
            raise PaymentError(
                PaymentReasonCode.CITATION_FAMILY_INVALID,
                "citation %r is family %r, not the required %r"
                % (
                    reference_id,
                    sorted(views),
                    expected_family,
                ),
            )
        return entry

    def __len__(self) -> int:
        return len(self._index)
