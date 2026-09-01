"""WORK-052 UsageLedger external evidence boundary.

The authority-reference model of the usage ledger (W052 contract
invariants 3, 9, 10, 11; the W051 ``commercial.references``
discipline mirrored):

- The usage ledger may REFERENCE delivery-plane evidence ids
  (the accepted WORK-042 platform journal's public event ids),
  the logical session id and NetworkPath id a delivered
  commercial transaction is correlated to (WORK-012 / WORK-041
  authority-owned), the WORK-051 CommercialCore transaction id
  whose delivery window authorizes the usage, and external
  payment observations (DATA only, never delivery proof).
- It must NEVER own, mutate, query, or instantiate those
  authorities: there is no authority object, client, manager, or
  private accessor anywhere in the usage family.  An
  :class:`EvidenceIndex` is an immutable snapshot mapping
  evidence ids to family descriptors, BUILT BY THE CALLER from
  the authorities' PUBLIC interfaces and INJECTED into the
  ledger.
- Fail-closed evidence integrity: a command citing an id the
  index does not carry is rejected ``EVIDENCE_UNKNOWN`` (a
  fabricated delivery-evidence, session, path, or commercial
  citation can never enter usage state); a citation of the
  wrong family for its slot is rejected
  ``EVIDENCE_FAMILY_INVALID``; a payment-family citation can
  never satisfy a delivery-evidence requirement
  (``PAYMENT_NOT_DELIVERY`` -- the payment/usage separation is
  family-table-driven, not caller-honor-driven); a stale
  delivery citation (evidence recorded AFTER the observation
  instant) is rejected ``EVIDENCE_STALE``; a commercial
  citation outside the delivery window is rejected
  (``RESERVATION_NOT_DELIVERY`` before delivery starts,
  ``EVIDENCE_UNAUTHORIZED`` after the window closed).

References are DATA (id + family + provenance + the public-read
facts the family needs): they carry no authority semantics, no
trust, and no mutation surface.  ``instant`` carries the
delivery-evidence observation instant (the platform journal's
public ``observed_at``); ``commercial_state``/``session_ref``/
``path_ref`` carry the WORK-051 transaction projection facts a
public ``CommercialCore.transaction()`` read yields, so usage
admission can gate on the real delivery window and the real
session/path correlation without ever touching the commercial
authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Iterable, Mapping, Tuple

from .errors import UsageLedgerError, UsageReasonCode


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise UsageLedgerError(
            UsageReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


def _optional_instant(value: object, label: str) -> str:
    if value == "":
        return ""
    if not isinstance(value, str):
        raise UsageLedgerError(
            UsageReasonCode.INSTANT_INVALID,
            "%s must be an RFC 3339 UTC instant string or empty" % label,
        )
    from agent.clock import parse_utc

    try:
        parse_utc(value)
    except Exception as error:  # noqa: BLE001 - re-wrapped typed
        raise UsageLedgerError(
            UsageReasonCode.INSTANT_INVALID,
            "%s %r is not RFC 3339 UTC: %s" % (label, value, error),
        ) from error
    return value


class EvidenceFamily:
    """The frozen external-evidence family vocabulary (W052).

    Delivery-evidence, session, NetworkPath, and commercial
    references are the authority-owned families the ledger may
    cite but never own (the commercial family cites WORK-051
    transaction ids -- delivery-window DATA read through the
    CommercialCore public surface).  The payment family is
    explicitly separate: payment observations are recorded DATA
    and can never justify usage.
    """

    DELIVERY_EVIDENCE = "delivery-evidence"
    COMMERCIAL = "commercial"
    SESSION = "session"
    NETWORK_PATH = "network-path"
    PAYMENT = "payment"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.DELIVERY_EVIDENCE,
            cls.COMMERCIAL,
            cls.SESSION,
            cls.NETWORK_PATH,
            cls.PAYMENT,
        )

    @classmethod
    def authority_families(cls) -> Tuple[str, ...]:
        """The authority-owned families the ledger may cite but
        never own."""
        return (
            cls.DELIVERY_EVIDENCE,
            cls.COMMERCIAL,
            cls.SESSION,
            cls.NETWORK_PATH,
        )

    @classmethod
    def external_families(cls) -> Tuple[str, ...]:
        """The external-plane families (payment DATA only)."""
        return (cls.PAYMENT,)


def _require_optional_text(value: object, label: str) -> None:
    if value == "":
        return
    if not isinstance(value, str) or not value:
        raise UsageLedgerError(
            UsageReasonCode.INVALID_INPUT,
            "%s must be a non-empty string or empty" % label,
        )


@dataclass(frozen=True)
class EvidenceReference:
    """One external evidence reference (id + family + provenance +
    public-read facts, DATA only).

    ``reference_id`` is the authority-owned identity string (a
    WORK-042 platform journal event id, a WORK-012 ``session_id``
    fingerprint, a W041 ``network_path_id`` fingerprint, or a
    WORK-051 commercial transaction id).  ``provenance`` records
    which authority surface produced it (a label, never a live
    object).  ``instant`` is the delivery-evidence observation
    instant (public read; empty for other families).
    ``commercial_state``/``session_ref``/``path_ref`` are the
    WORK-051 transaction projection facts for the commercial
    family (public read; empty for other families).  A reference
    is a citation, not a capability: holding one grants no
    authority access.
    """

    reference_id: str
    family: str
    provenance: str
    instant: str = ""
    commercial_state: str = ""
    session_ref: str = ""
    path_ref: str = ""

    def __post_init__(self) -> None:
        _require_text(self.reference_id, "reference_id")
        if self.family not in EvidenceFamily.values():
            raise UsageLedgerError(
                UsageReasonCode.EVIDENCE_FAMILY_INVALID,
                "family %r must be one of %s"
                % (self.family, list(EvidenceFamily.values())),
            )
        _require_text(self.provenance, "provenance")
        _optional_instant(self.instant, "instant")
        _require_optional_text(self.commercial_state, "commercial_state")
        _require_optional_text(self.session_ref, "session_ref")
        _require_optional_text(self.path_ref, "path_ref")
        # family-scoped facts: only delivery evidence carries an
        # observation instant; only commercial references carry
        # the transaction projection facts.
        if self.family != EvidenceFamily.DELIVERY_EVIDENCE and self.instant != "":
            raise UsageLedgerError(
                UsageReasonCode.EVIDENCE_FAMILY_INVALID,
                "only delivery-evidence references carry an instant",
            )
        if self.family != EvidenceFamily.COMMERCIAL and (
            self.commercial_state != ""
            or self.session_ref != ""
            or self.path_ref != ""
        ):
            raise UsageLedgerError(
                UsageReasonCode.EVIDENCE_FAMILY_INVALID,
                "only commercial references carry transaction facts",
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reference_id": self.reference_id,
            "family": self.family,
            "provenance": self.provenance,
            "instant": self.instant,
            "commercial_state": self.commercial_state,
            "session_ref": self.session_ref,
            "path_ref": self.path_ref,
        }

    @classmethod
    def from_dict(cls, data: object) -> "EvidenceReference":
        if not isinstance(data, Mapping):
            raise UsageLedgerError(
                UsageReasonCode.EVIDENCE_FAMILY_INVALID,
                "evidence reference must be a mapping",
            )
        for key in (
            "reference_id",
            "family",
            "provenance",
            "instant",
            "commercial_state",
            "session_ref",
            "path_ref",
        ):
            if key not in data:
                raise UsageLedgerError(
                    UsageReasonCode.EVIDENCE_FAMILY_INVALID,
                    "evidence reference is missing required member %r" % key,
                )
        return cls(
            reference_id=data["reference_id"],
            family=data["family"],
            provenance=data["provenance"],
            instant=data["instant"],
            commercial_state=data["commercial_state"],
            session_ref=data["session_ref"],
            path_ref=data["path_ref"],
        )




class EvidenceIndex:
    """An immutable snapshot of resolvable external evidence.

    Built by the CALLER from the accepted authorities' PUBLIC
    interfaces (the platform journal's delivery-plane event ids
    with their observed instants, the session authority's
    established session ids, the NetworkPathManager's active
    path ids, and the CommercialCore's public transaction
    projections) and INJECTED into the usage ledger.  The ledger
    resolves command citations against the index and never
    against a live authority: usage state can cite an authority
    identity only if the caller has already read it through that
    authority's public surface.

    The index is frozen at construction (a snapshot, not a live
    view): evidence sets change only by building a new index,
    which keeps command admission deterministic and replay-safe.
    """

    def __init__(self, references: Iterable[EvidenceReference]) -> None:
        table: Dict[str, EvidenceReference] = {}
        for reference in references:
            if not isinstance(reference, EvidenceReference):
                raise UsageLedgerError(
                    UsageReasonCode.INVALID_INPUT,
                    "index entries must be EvidenceReference values",
                )
            existing = table.get(reference.reference_id)
            if existing is not None:
                if existing.to_dict() != reference.to_dict():
                    raise UsageLedgerError(
                        UsageReasonCode.EVIDENCE_FAMILY_INVALID,
                        "conflicting index entries for reference %s"
                        % reference.reference_id,
                    )
                continue
            table[reference.reference_id] = reference
        self._table: Dict[str, EvidenceReference] = dict(table)

    def __len__(self) -> int:
        return len(self._table)

    def contains(self, reference_id: str) -> bool:
        return reference_id in self._table

    def get(self, reference_id: str) -> EvidenceReference:
        reference = self._table.get(reference_id)
        if reference is None:
            raise UsageLedgerError(
                UsageReasonCode.EVIDENCE_UNKNOWN,
                "external evidence %r is not resolvable in the evidence "
                "index (fabricated or evicted reference)" % reference_id,
            )
        return reference

    def families(self) -> FrozenSet[str]:
        return frozenset(ref.family for ref in self._table.values())

    def by_family(self, family: str) -> Tuple[EvidenceReference, ...]:
        if family not in EvidenceFamily.values():
            raise UsageLedgerError(
                UsageReasonCode.EVIDENCE_FAMILY_INVALID,
                "family %r must be one of %s"
                % (family, list(EvidenceFamily.values())),
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


def resolve_references(
    index: EvidenceIndex,
    references: Tuple[EvidenceReference, ...],
) -> Tuple[EvidenceReference, ...]:
    """Resolve every cited reference against the index.

    Fail-closed: an unknown reference id (fabricated session /
    NetworkPath / delivery-evidence / commercial citation)
    raises ``EVIDENCE_UNKNOWN`` BEFORE any usage state changes.
    Resolution returns the INDEX-AUTHORITATIVE records (the
    index is the family authority): a citation claiming one
    family while the index records another is judged by the
    index family in command admission (the payment/usage
    separation in :mod:`usage.validation` -- a payment id cited
    in a delivery-evidence slot resolves as payment-family and
    fails closed ``PAYMENT_NOT_DELIVERY``).  Duplicate ids in
    one citation collapse deterministically (sorted, unique).
    """
    resolved: Dict[str, EvidenceReference] = {}
    for reference in references:
        known = index.get(reference.reference_id)
        resolved[reference.reference_id] = known
    return tuple(resolved[key] for key in sorted(resolved))


def evidence_family_counts(
    references: Tuple[EvidenceReference, ...]
) -> Dict[str, int]:
    """Deterministic family histogram of a resolved reference tuple."""
    counts: Dict[str, int] = {}
    for reference in references:
        counts[reference.family] = counts.get(reference.family, 0) + 1
    return counts
