"""WORK-045 risk/compliance decision records.

A :class:`DecisionRecord` is the deterministic, independently
auditable risk/compliance decision: the attributable answer to
the W045 eligibility question.  There is deliberately NO
generic mutable ``trusted = true`` flag anywhere in this
family: every approval is attributable to

    which policy       (policy_key + policy_digest)
    which facts        (input_digest over the canonical input)
    which version      (policy_version inside the policy cite)
    which evidence     (citations: authority-owned ids, DATA)
    when               (issued_at / effective_at)
    until when         (valid_until)

The decision identity is content-derived (``decision_id`` is
the canonical-content digest), so the same canonical inputs at
the same evaluation instant produce the byte-identical
decision, and any input change produces a different decision.
Historical decision records are immutable: a policy update
never rewrites them (a new evaluation under the new version
produces a NEW decision record; the prior record stays
byte-identical forever).

Authorization-domain discipline (the mandatory independence):
every decision carries ``authorization_domain``; the evaluator
emits ``connectivity``-domain decisions ONLY.  The
``payment_reference`` member is the recorded
payment-authorization REFERENCE (a citation id, or ``""``
meaning explicitly NO payment authorization is recorded): its
presence never asserts payment approval, its absence never
asserts payment denial, and no decision ever derives one
domain from the other.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import EligibilityError, EligibilityReasonCode
from .states import AuthorizationDomain, DecisionResult, SubjectKind


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


def decision_content(
    decision_id: str,
    subject_kind: str,
    subject_ref: str,
    authorization_domain: str,
    provider_id: str,
    offer_id: str,
    device_id: str,
    jurisdiction: str,
    network_sharing_mode: str,
    policy_key: str,
    policy_version: int,
    policy_digest: str,
    result: str,
    reason_codes: Tuple[str, ...],
    issued_at: str,
    effective_at: str,
    valid_until: str,
    payment_reference: str,
    citations: Tuple[str, ...],
    input_digest: str,
    provenance: str,
) -> Dict[str, Any]:
    """The canonical content basis of one decision record."""
    return {
        "decision_id": decision_id,
        "subject_kind": subject_kind,
        "subject_ref": subject_ref,
        "authorization_domain": authorization_domain,
        "provider_id": provider_id,
        "offer_id": offer_id,
        "device_id": device_id,
        "jurisdiction": jurisdiction,
        "network_sharing_mode": network_sharing_mode,
        "policy_key": policy_key,
        "policy_version": policy_version,
        "policy_digest": policy_digest,
        "result": result,
        "reason_codes": list(reason_codes),
        "issued_at": issued_at,
        "effective_at": effective_at,
        "valid_until": valid_until,
        "payment_reference": payment_reference,
        "citations": list(citations),
        "input_digest": input_digest,
        "provenance": provenance,
    }


def derive_decision_id(content: Dict[str, Any]) -> str:
    """The content-derived decision identity (the canonical
    content digest, EXCLUDING the id itself)."""
    basis = {
        key: value for key, value in content.items()
        if key != "decision_id"
    }
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(basis)
    ).hexdigest()


@dataclass(frozen=True)
class DecisionRecord:
    """One immutable risk/compliance decision record.

    ``subject_ref`` is the primary subject identity (provider
    id, offer id, or device id per ``subject_kind``).
    ``citations`` are the authority-owned reference ids the
    decision's evidence chain cites (WORK-051 transaction ids,
    WORK-053 allocation ids, WORK-044 payment references --
    DATA only, resolved against the injected snapshot at
    admission).  ``payment_reference`` is the independent
    payment-authorization reference dimension (``""`` =
    explicitly none recorded; never an approval assertion).
    """

    decision_id: str
    subject_kind: str
    subject_ref: str
    authorization_domain: str
    provider_id: str
    offer_id: str
    device_id: str
    jurisdiction: str
    network_sharing_mode: str
    policy_key: str
    policy_version: int
    policy_digest: str
    result: str
    reason_codes: Tuple[str, ...]
    issued_at: str
    effective_at: str
    valid_until: str
    payment_reference: str
    citations: Tuple[str, ...]
    input_digest: str
    provenance: str

    def __post_init__(self) -> None:
        _require_text(self.decision_id, "decision_id")
        if self.subject_kind not in SubjectKind.values():
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "subject kind %r must be one of %s"
                % (self.subject_kind, list(SubjectKind.values())),
            )
        _require_text(self.subject_ref, "subject_ref")
        if self.authorization_domain not in AuthorizationDomain.values():
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "authorization domain %r must be one of %s"
                % (
                    self.authorization_domain,
                    list(AuthorizationDomain.values()),
                ),
            )
        if self.result not in DecisionResult.values():
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "decision result %r must be one of %s"
                % (self.result, list(DecisionResult.values())),
            )
        for code in self.reason_codes:
            if code not in EligibilityReasonCode.denial_values():
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "decision reason %r is not a denial reason code"
                    % (code,),
                )
        if self.result == DecisionResult.ELIGIBLE and self.reason_codes:
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "an eligible decision cannot carry denial reason codes",
            )
        if self.result == DecisionResult.NOT_ELIGIBLE and not (
            self.reason_codes
        ):
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "a not-eligible decision must carry at least one "
                "denial reason code",
            )
        if len(set(self.reason_codes)) != len(self.reason_codes):
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "decision reason codes must not repeat",
            )
        if self.authorization_domain != AuthorizationDomain.CONNECTIVITY:
            raise EligibilityError(
                EligibilityReasonCode.DOMAIN_FORBIDDEN,
                "the eligibility evaluator decides the connectivity "
                "domain ONLY (payment authorization is the accepted "
                "WORK-044 boundary's truth; W045 records the "
                "reference, never the decision)",
            )
        if not isinstance(self.policy_version, int) or isinstance(
            self.policy_version, bool
        ):
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "policy_version must be an integer",
            )
        if self.policy_version < 1:
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "policy_version must be >= 1",
            )
        for label, value in (
            ("provider_id", self.provider_id),
            ("offer_id", self.offer_id),
            ("device_id", self.device_id),
            ("jurisdiction", self.jurisdiction),
            ("network_sharing_mode", self.network_sharing_mode),
            ("policy_key", self.policy_key),
            ("policy_digest", self.policy_digest),
            ("issued_at", self.issued_at),
            ("effective_at", self.effective_at),
            ("valid_until", self.valid_until),
            ("payment_reference", self.payment_reference),
            ("input_digest", self.input_digest),
            ("provenance", self.provenance),
        ):
            if not isinstance(value, str):
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "%s must be a string" % label,
                )
        if not isinstance(self.citations, tuple):
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "citations must be a tuple of reference ids",
            )
        for ref in self.citations:
            if not isinstance(ref, str) or not ref:
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "citation members must be non-empty strings",
                )
        # the content-derived identity must match the content
        expected = derive_decision_id(self.content())
        if self.decision_id != expected:
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "decision id %r does not match the content-derived "
                "identity %r" % (self.decision_id, expected),
            )

    def eligible(self) -> bool:
        return self.result == DecisionResult.ELIGIBLE

    def content(self) -> Dict[str, Any]:
        return decision_content(
            self.decision_id,
            self.subject_kind,
            self.subject_ref,
            self.authorization_domain,
            self.provider_id,
            self.offer_id,
            self.device_id,
            self.jurisdiction,
            self.network_sharing_mode,
            self.policy_key,
            self.policy_version,
            self.policy_digest,
            self.result,
            self.reason_codes,
            self.issued_at,
            self.effective_at,
            self.valid_until,
            self.payment_reference,
            self.citations,
            self.input_digest,
            self.provenance,
        )

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return self.content()

    @classmethod
    def build(
        cls,
        *,
        subject_kind: str,
        subject_ref: str,
        provider_id: str,
        offer_id: str,
        device_id: str,
        jurisdiction: str,
        network_sharing_mode: str,
        policy_key: str,
        policy_version: int,
        policy_digest: str,
        result: str,
        reason_codes: Tuple[str, ...],
        issued_at: str,
        effective_at: str,
        valid_until: str,
        payment_reference: str,
        citations: Tuple[str, ...],
        input_digest: str,
        provenance: str,
    ) -> "DecisionRecord":
        """Build one decision record with the content-derived
        identity computed over the canonical content (the only
        construction path -- there is no way to mint an
        arbitrary decision id)."""
        content = decision_content(
            "",
            subject_kind,
            subject_ref,
            AuthorizationDomain.CONNECTIVITY,
            provider_id,
            offer_id,
            device_id,
            jurisdiction,
            network_sharing_mode,
            policy_key,
            policy_version,
            policy_digest,
            result,
            tuple(reason_codes),
            issued_at,
            effective_at,
            valid_until,
            payment_reference,
            tuple(citations),
            input_digest,
            provenance,
        )
        decision_id = derive_decision_id(content)
        return cls(
            decision_id=decision_id,
            subject_kind=subject_kind,
            subject_ref=subject_ref,
            authorization_domain=AuthorizationDomain.CONNECTIVITY,
            provider_id=provider_id,
            offer_id=offer_id,
            device_id=device_id,
            jurisdiction=jurisdiction,
            network_sharing_mode=network_sharing_mode,
            policy_key=policy_key,
            policy_version=policy_version,
            policy_digest=policy_digest,
            result=result,
            reason_codes=tuple(reason_codes),
            issued_at=issued_at,
            effective_at=effective_at,
            valid_until=valid_until,
            payment_reference=payment_reference,
            citations=tuple(citations),
            input_digest=input_digest,
            provenance=provenance,
        )

    @classmethod
    def from_dict(cls, data: object) -> "DecisionRecord":
        if not isinstance(data, Mapping):
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "decision record must be a mapping",
            )
        required = (
            "decision_id",
            "subject_kind",
            "subject_ref",
            "authorization_domain",
            "provider_id",
            "offer_id",
            "device_id",
            "jurisdiction",
            "network_sharing_mode",
            "policy_key",
            "policy_version",
            "policy_digest",
            "result",
            "reason_codes",
            "issued_at",
            "effective_at",
            "valid_until",
            "payment_reference",
            "citations",
            "input_digest",
            "provenance",
        )
        for member in required:
            if member not in data:
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "decision record is missing %r" % member,
                )
        return cls(
            decision_id=data["decision_id"],
            subject_kind=data["subject_kind"],
            subject_ref=data["subject_ref"],
            authorization_domain=data["authorization_domain"],
            provider_id=data["provider_id"],
            offer_id=data["offer_id"],
            device_id=data["device_id"],
            jurisdiction=data["jurisdiction"],
            network_sharing_mode=data["network_sharing_mode"],
            policy_key=data["policy_key"],
            policy_version=data["policy_version"],
            policy_digest=data["policy_digest"],
            result=data["result"],
            reason_codes=tuple(data["reason_codes"]),
            issued_at=data["issued_at"],
            effective_at=data["effective_at"],
            valid_until=data["valid_until"],
            payment_reference=data["payment_reference"],
            citations=tuple(data["citations"]),
            input_digest=data["input_digest"],
            provenance=data["provenance"],
        )
