"""WORK-045 authority-citation boundary (the injected snapshot).

The authority-consumption model of the eligibility boundary
(mirrors the W051 ReferenceIndex / W052 EvidenceIndex / W053
FactIndex / W044 CommercialSnapshot discipline):

- The eligibility boundary may REFERENCE WORK-051 commercial
  transaction identities, WORK-053 finalized allocation account
  identities, and WORK-044 payment intent / provider-capability
  identities -- all authority-owned identities, cited never
  derived, consumed never mutated.
- It must NEVER own, mutate, query, or instantiate those
  authorities: there is no authority object, client, manager,
  or private accessor anywhere in the eligibility family (the
  import discipline is battery-audited: the eligibility package
  imports stdlib + the WORK-003 canonicalization + the WORK-033
  clock seam ONLY).  An :class:`AuthoritySnapshot` is an
  immutable snapshot mapping citation ids to family
  descriptors, BUILT BY THE CALLER from the authorities'
  PUBLIC interfaces and INJECTED into the eligibility
  authority.
- Fail-closed citation integrity: a command citing an id the
  snapshot does not carry is rejected ``citation-unknown`` (a
  fabricated transaction, allocation, or payment fact can
  never enter eligibility state); a citation of the wrong
  family for the command's requirement is rejected
  ``citation-family-invalid``.

Citations are DATA (id + family + provenance + the public
projection fields the boundary legitimately consumes as DATA):
they carry no authority semantics, no trust, and no mutation
surface.  CRITICALLY, the payment-family citation members are
REFERENCE-ONLY DATA: the eligibility evaluator reads the
citation's EXISTENCE and its recorded reference metadata, never
its payment state as connectivity truth, and never confers or
derives payment authorization in either direction (the
mandatory W045 independence boundary).  The citation model also
carries NO identity/KYC document content anywhere: a KYC
reference is exactly an opaque reference id string -- the
regulated provider keeps the documents.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Tuple

from .errors import EligibilityError, EligibilityReasonCode


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise EligibilityError(
            EligibilityReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


def _optional_text(value: object, label: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise EligibilityError(
            EligibilityReasonCode.INVALID_INPUT,
            "%s must be a string" % label,
        )
    return value


class CitationFamily:
    """The frozen authority-citation family vocabulary (W045).

    The three authority families the eligibility boundary may
    cite: the WORK-051 commercial transaction projection, the
  WORK-053 finalized allocation account (historical
    settlement-reference preservation through suspension and
    revocation), and the WORK-044 payment-provider boundary
    (payment intent and provider capability declaration
    identities -- REFERENCE-ONLY DATA, never payment truth).
    There is NO eligibility-internal citation family.
    """

    COMMERCIAL = "commercial"
    ALLOCATION = "allocation"
    PAYMENT_PROVIDER = "payment-provider"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.COMMERCIAL, cls.ALLOCATION, cls.PAYMENT_PROVIDER)

    @classmethod
    def authority_families(cls) -> Tuple[str, ...]:
        """All three families are authority-owned citation
        families (the boundary cites; it never owns)."""
        return cls.values()


@dataclass(frozen=True)
class AuthorityCitation:
    """One immutable external-authority citation record (DATA).

    ``reference_id`` is the authority-owned identity (WORK-051
    transaction id, WORK-053 allocation usage-record id, or
    WORK-044 payment intent id / capability declaration key).
    ``family`` and ``provenance`` identify the citing family
    and the public source it was read from.  The projection
    members carry ONLY the public fields the eligibility
    boundary consumes as DATA: the commercial state (offer/
    transaction correlation), the allocation state (historical
    settlement-reference preservation), and the payment intent
    state / capability key / provider identity (the payment
    REFERENCE dimension -- recorded, never decided here).

    A citation never implies connectivity eligibility, payment
    eligibility, delivery, or settlement truth in either
    direction, and never carries KYC document content (the
    ``kyc_reference`` member, when present, is an opaque
    reference id string only).
    """

    reference_id: str
    family: str
    provenance: str
    commercial_state: str = ""
    offer_id: str = ""
    provider_id: str = ""
    allocation_state: str = ""
    currency: str = ""
    payment_state: str = ""
    capability_key: str = ""
    kyc_reference: str = ""

    def __post_init__(self) -> None:
        _require_text(self.reference_id, "reference_id")
        if self.family not in CitationFamily.values():
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "citation family %r must be one of %s"
                % (self.family, list(CitationFamily.values())),
            )
        _require_text(self.provenance, "provenance")
        for label, value in (
            ("commercial_state", self.commercial_state),
            ("offer_id", self.offer_id),
            ("provider_id", self.provider_id),
            ("allocation_state", self.allocation_state),
            ("currency", self.currency),
            ("payment_state", self.payment_state),
            ("capability_key", self.capability_key),
            ("kyc_reference", self.kyc_reference),
        ):
            if not isinstance(value, str):
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "%s must be a string" % label,
                )

    def content(self) -> Dict[str, Any]:
        return {
            "reference_id": self.reference_id,
            "family": self.family,
            "provenance": self.provenance,
            "commercial_state": self.commercial_state,
            "offer_id": self.offer_id,
            "provider_id": self.provider_id,
            "allocation_state": self.allocation_state,
            "currency": self.currency,
            "payment_state": self.payment_state,
            "capability_key": self.capability_key,
            "kyc_reference": self.kyc_reference,
        }

    def to_dict(self) -> Dict[str, Any]:
        return self.content()


class AuthoritySnapshot:
    """The immutable injected citation index (fail-closed).

    Built by the CALLER from the WORK-051/W053/W044 PUBLIC
    surfaces (transaction projections, allocation accounts,
    payment intents and capability declarations) and injected
    into the eligibility authority.  One authority identity may
    appear under SEVERAL family views, so the index maps each
    id to its family views and resolution is by EXACT (id,
    expected family) pair: a wrong-family resolution fails
    closed exactly like an unknown id.  A duplicate (id,
    family) pair fails closed at construction (an ambiguous
    index can never admit a command).
    """

    def __init__(self, entries: Any) -> None:
        if not isinstance(entries, (list, tuple)):
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "snapshot entries must be a sequence of "
                "AuthorityCitation",
            )
        index: Dict[str, Dict[str, AuthorityCitation]] = {}
        for entry in entries:
            if not isinstance(entry, AuthorityCitation):
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "snapshot entries must be AuthorityCitation values",
                )
            views = index.setdefault(entry.reference_id, {})
            existing = views.get(entry.family)
            if existing is not None:
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "duplicate citation id %r in family %r in the snapshot"
                    % (entry.reference_id, entry.family),
                )
            views[entry.family] = entry
        self._index: Dict[str, Dict[str, AuthorityCitation]] = {
            key: dict(views) for key, views in index.items()
        }

    def entries(self) -> Tuple[AuthorityCitation, ...]:
        return tuple(
            self._index[reference_id][family]
            for reference_id in sorted(self._index)
            for family in sorted(self._index[reference_id])
        )

    def by_family(self, family: str) -> Tuple[AuthorityCitation, ...]:
        if family not in CitationFamily.values():
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "family %r is not a citation family" % family,
            )
        return tuple(
            self._index[reference_id][family]
            for reference_id in sorted(self._index)
            if family in self._index[reference_id]
        )

    def citation(self, reference_id: str) -> AuthorityCitation:
        views = self._index.get(reference_id, {})
        if not views:
            raise EligibilityError(
                EligibilityReasonCode.CITATION_UNKNOWN,
                "citation %r is not carried by the injected snapshot"
                % reference_id,
            )
        if len(views) > 1:
            raise EligibilityError(
                EligibilityReasonCode.CITATION_FAMILY_INVALID,
                "citation %r carries several family views; resolve with "
                "the expected family" % reference_id,
            )
        return next(iter(views.values()))

    def resolve(
        self, reference_id: str, expected_family: str
    ) -> AuthorityCitation:
        """Resolve one citation by exact id AND expected family
        (fail closed on unknown id or wrong family)."""
        views = self._index.get(reference_id, {})
        entry = views.get(expected_family)
        if entry is None:
            if not views:
                raise EligibilityError(
                    EligibilityReasonCode.CITATION_UNKNOWN,
                    "citation %r is not carried by the injected snapshot"
                    % reference_id,
                )
            raise EligibilityError(
                EligibilityReasonCode.CITATION_FAMILY_INVALID,
                "citation %r is family %r, not the required %r"
                % (
                    reference_id,
                    sorted(views),
                    expected_family,
                ),
            )
        return entry

    def has(self, reference_id: str, family: str = "") -> bool:
        """Existence check only (never a truth assertion)."""
        views = self._index.get(reference_id, {})
        if not views:
            return False
        if family == "":
            return True
        return family in views

    def __len__(self) -> int:
        return len(self._index)
