"""Authority-owned revalidation primitive (WORK-010).

The ONLINE policy authority's revalidation boundary, introduced by the
PR #28 review B2 round-3 correction (WORK-027's ``OfflinePolicyCache``
must not accept a caller-supplied raw ``PolicyDecision`` as proof of
reauthorization after a recovery).

The problem being solved: a :class:`~policy.model.PolicyDecision` is
PURE DATA with a content-derived digest.  ``decision_id ==
sha256(canonical_bytes)`` proves only that the object matches its own
fingerprint -- anyone can construct a new, self-consistent ALLOW with
an arbitrary ``evaluation_instant`` and recompute the digest.  A
content digest is tamper evidence, NEVER provenance: fields inside a
caller-provided object can always be chosen by the caller, so no
field-level check (freshness timestamps included) can distinguish
"the authority evaluated this" from "someone wrote this down".

The fix is architectural: revalidation must CROSS the actual
policy-authority boundary.  This module is that boundary.

- :class:`PolicyRevalidationAuthority` -- the ONLINE authority
  object.  It owns an immutable policy-set snapshot and the
  deterministic :class:`~policy.evaluation.PolicyEngine`.
  :meth:`~PolicyRevalidationAuthority.revalidate` performs a FRESH
  evaluation of a submitted context and mints an
  :class:`RevalidationReceipt` binding the exact resulting decision.
  Every mint is recorded in the authority's internal MINT LEDGER (a
  hash chain over its own issuance history, with a strictly-advancing
  sequence number); the ``receipt_id`` is derived over the receipt
  content PLUS the authority-internal chain root, so a valid-looking
  id is not computable from the receipt's public fields alone.

- :class:`RevalidationReceipt` -- pure DATA (frozen, field-validated,
  digest-bound), vouching "THIS authority freshly evaluated the
  decision with this id at this instant, as mint number N".  Like a
  bank check, anyone can print the paper; only the issuing ledger
  makes it worth anything.

- :meth:`PolicyRevalidationAuthority.verify_revalidation_receipt` --
  the ONLY validity check, performed BY the authority against its own
  mint ledger: the receipt must be byte-identical to a ledger entry of
  THIS authority instance, and it must vouch for exactly the supplied
  decision (decision-id binding + canonical-bytes digest binding).
  A fabricated receipt (however self-consistent), a receipt minted by
  a DIFFERENT authority instance, and a genuine receipt paired with
  the wrong decision all fail verification.

The acceptance-critical property: a verifying (decision, receipt)
pair is obtainable ONLY by submitting a context to THIS authority
instance -- the authority evaluates the context itself and mints the
receipt for its OWN output.  An arbitrary caller holding an old
``PolicyDecision`` (or able to forge new self-consistent ones) cannot
manufacture a receipt that verifies: the proof is the recorded
authority interaction, not any field inside a caller-supplied object.

Determinism: the authority is instance state, all clocks are injected
(the context's ``evaluation_instant``), and the ledger/chain are pure
functions of the mint sequence -- the same revalidation history
always produces the same receipts and chain state.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from protocol.canonicalization import CanonicalizationError, canonical_json_bytes
from protocol.temporal import TemporalError, parse_instant

from .evaluation import PolicyEngine
from .model import (
    PolicyContext,
    PolicyDecision,
    PolicyError,
    PolicySet,
    is_valid_content_digest,
)
from .validation import validate_policy_set

#: Stable content kind for the receipt digest derivation (deliberately
#: namespaced so a receipt id can never collide with any other
#: content-derived id family).
RECEIPT_KIND = "adcos:policy:revalidation-receipt:v1"

#: The genesis chain root (no receipts minted yet).
GENESIS_CHAIN_ROOT = "0" * 64


def _receipt_id(
    decision_id: str,
    evaluation_instant: str,
    authority_sequence: int,
    chain_root: str,
) -> str:
    """Derive the receipt id over the receipt content PLUS the
    authority-internal chain root.  The chain root is never published
    in the receipt, so the id is not computable from the receipt's
    public fields alone (unlike ``PolicyDecision.decision_id``, which
    is pure content addressing)."""
    payload = {
        "kind": RECEIPT_KIND,
        "decision_id": decision_id,
        "evaluation_instant": evaluation_instant,
        "authority_sequence": authority_sequence,
        "chain_root": chain_root,
    }
    try:
        return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    except CanonicalizationError as error:  # pragma: no cover - defensive
        raise PolicyError(
            "canonical",
            "revalidation receipt is not canonically representable: %s" % error,
        ) from error


@dataclass(frozen=True)
class RevalidationReceipt:
    """Authority-minted proof that a :class:`PolicyDecision` was
    freshly evaluated by a specific ONLINE
    :class:`PolicyRevalidationAuthority` instance.

    Fields:
    - ``decision_id`` -- the decision this receipt vouches for;
    - ``evaluation_instant`` -- the decision's (injected) evaluation
      instant;
    - ``authority_sequence`` -- the strictly-advancing mint number
      within the authority's ledger;
    - ``receipt_id`` -- digest over the content above PLUS the
      authority-internal chain root at mint time.

    Pure DATA: constructing an instance proves NOTHING.  Validity is
    decided exclusively by
    :meth:`PolicyRevalidationAuthority.verify_revalidation_receipt`
    (mint-ledger membership), never by inspecting the fields.
    """

    decision_id: str
    evaluation_instant: str
    authority_sequence: int
    receipt_id: str

    def __post_init__(self) -> None:
        if not is_valid_content_digest(self.decision_id):
            raise PolicyError(
                "receipt-decision-id",
                "receipt decision_id %r must be a 64-lowercase-hex content digest"
                % (self.decision_id,),
            )
        if not is_valid_content_digest(self.receipt_id):
            raise PolicyError(
                "receipt-id",
                "receipt_id %r must be a 64-lowercase-hex content digest"
                % (self.receipt_id,),
            )
        if not isinstance(self.evaluation_instant, str):
            raise PolicyError(
                "receipt-instant",
                "receipt evaluation_instant must be a string (got %s)"
                % type(self.evaluation_instant).__name__,
            )
        try:
            parse_instant(self.evaluation_instant)
        except TemporalError as error:
            raise PolicyError(
                "receipt-instant",
                "receipt evaluation_instant %r is not RFC 3339 UTC: %s"
                % (self.evaluation_instant, error),
            ) from error
        if (
            isinstance(self.authority_sequence, bool)
            or not isinstance(self.authority_sequence, int)
            or self.authority_sequence < 1
        ):
            raise PolicyError(
                "receipt-sequence",
                "authority_sequence must be a positive integer (got %r)"
                % (self.authority_sequence,),
            )

    def content_dict(self) -> Dict[str, Any]:
        """The public (auditable) receipt content -- everything except
        the digest itself.  The authority-internal chain root is
        deliberately NOT part of the public content: it exists only
        inside the minting authority."""
        return {
            "decision_id": self.decision_id,
            "evaluation_instant": self.evaluation_instant,
            "authority_sequence": self.authority_sequence,
        }


@dataclass(frozen=True)
class RevalidationResult:
    """The envelope returned by
    :meth:`PolicyRevalidationAuthority.revalidate` (mirrors
    :class:`~policy.model.PolicyEvaluationResult`).

    ``ok=True`` means the authority evaluated the context and minted
    a receipt for the resulting decision (which may be a DENY -- the
    authority revalidates the demand, it does not guarantee an
    ALLOW).  ``ok=False`` means the evaluation itself failed
    (malformed input); no decision and no receipt exist.
    """

    ok: bool
    code: str
    detail: str
    decision: Optional[PolicyDecision]
    receipt: Optional[RevalidationReceipt]

    def __post_init__(self) -> None:
        if not isinstance(self.ok, bool):
            raise PolicyError("result-ok", "ok must be a bool")
        if not isinstance(self.code, str) or not self.code:
            raise PolicyError("result-code", "code must be a non-empty string")
        if not isinstance(self.detail, str):
            raise PolicyError(
                "result-detail",
                "detail must be a string (got %s)" % type(self.detail).__name__,
            )
        if self.ok:
            if self.decision is None or self.receipt is None:
                raise PolicyError(
                    "result-shape",
                    "an ok revalidation must carry both the decision and the receipt",
                )
        else:
            if self.decision is not None or self.receipt is not None:
                raise PolicyError(
                    "result-shape",
                    "a failed revalidation carries neither decision nor receipt",
                )


class PolicyRevalidationAuthority:
    """The ONLINE policy authority's revalidation boundary.

    Constructed by the composition root over an immutable
    :class:`PolicySet` snapshot and INJECTED into the consumer (the
    WORK-027 ``OfflinePolicyCache`` verifies every post-recovery
    recording against ITS OWN injected authority instance -- a receipt
    minted by any other instance, however genuine-looking, never
    verifies).

    The authority is the sole minter of valid receipts:

    - :meth:`revalidate` performs a FRESH deterministic
      :class:`PolicyEngine` evaluation of the submitted context
      against the authority's own policy set and mints a receipt
      binding the exact output decision;
    - :meth:`verify_revalidation_receipt` checks a (receipt,
      decision) pair against the authority's own mint ledger.

    An arbitrary caller CANNOT manufacture a verifying pair: every
    ledger entry is created exclusively inside :meth:`revalidate`,
    for decisions the authority itself just evaluated.  Fields inside
    a caller-supplied decision are never consulted as proof.
    """

    def __init__(self, policy_set: PolicySet) -> None:
        try:
            validate_policy_set(policy_set)
        except PolicyError as error:
            raise PolicyError(
                "policy-set",
                "the revalidation authority requires a valid policy set: %s"
                % error.detail,
            ) from error
        self._policy_set = policy_set
        self._engine = PolicyEngine()
        # The mint ledger: receipt_id -> the exact minted receipt.
        self._minted: Dict[str, RevalidationReceipt] = {}
        # The hash chain over this authority's issuance history.
        self._chain_root: str = GENESIS_CHAIN_ROOT
        # The strictly-advancing mint sequence number.
        self._sequence: int = 0

    # -- the fresh-evaluation boundary -----------------------------------

    def revalidate(self, context: PolicyContext) -> RevalidationResult:
        """Freshly evaluate ``context`` against the authority's policy
        set and mint a receipt for the resulting decision.

        The context's ``evaluation_instant`` is the INJECTED clock (no
        wall-clock reads).  The returned decision is exactly what the
        deterministic engine produced for this context -- the caller
        cannot influence it except through the context itself, and
        the receipt vouches for THAT decision, byte for byte.

        A failing evaluation (malformed input) produces ``ok=False``
        with no decision and no receipt: nothing was evaluated, so
        nothing can be proven.
        """
        evaluation = self._engine.evaluate(self._policy_set, context)
        if not evaluation.ok or evaluation.decision is None:
            return RevalidationResult(
                ok=False,
                code=evaluation.code,
                detail=evaluation.detail,
                decision=None,
                receipt=None,
            )
        decision = evaluation.decision
        receipt = self._mint(decision)
        return RevalidationResult(
            ok=True,
            code=evaluation.code,
            detail=evaluation.detail,
            decision=decision,
            receipt=receipt,
        )

    def _mint(self, decision: PolicyDecision) -> RevalidationReceipt:
        """Mint the receipt for a decision THIS authority just
        evaluated, and append it to the mint ledger (chain advance
        included).  Private by design: there is no other path into
        the ledger."""
        self._sequence += 1
        receipt = RevalidationReceipt(
            decision_id=decision.decision_id,
            evaluation_instant=decision.evaluation_instant,
            authority_sequence=self._sequence,
            receipt_id=_receipt_id(
                decision.decision_id,
                decision.evaluation_instant,
                self._sequence,
                self._chain_root,
            ),
        )
        self._minted[receipt.receipt_id] = receipt
        self._chain_root = hashlib.sha256(
            ("%s:%s" % (self._chain_root, receipt.receipt_id)).encode("ascii")
        ).hexdigest()
        return receipt

    # -- the verification boundary ---------------------------------------

    def verify_revalidation_receipt(
        self, receipt: RevalidationReceipt, decision: PolicyDecision
    ) -> None:
        """Raise :class:`PolicyError` unless THIS authority minted
        ``receipt`` for exactly ``decision``.

        This is the ONLY way a receipt is validated -- the check is a
        membership lookup against the authority's own mint ledger
        (plus the decision's canonical digest binding), never an
        inspection of caller-supplied fields for self-consistency.
        """
        if not isinstance(receipt, RevalidationReceipt):
            raise PolicyError(
                "receipt",
                "receipt must be a policy.revalidation.RevalidationReceipt "
                "minted by the online policy authority (got %s)"
                % type(receipt).__name__,
            )
        if not isinstance(decision, PolicyDecision):
            raise PolicyError(
                "decision",
                "decision must be a policy.model.PolicyDecision instance",
            )
        expected_digest = hashlib.sha256(decision.canonical_bytes()).hexdigest()
        if decision.decision_id != expected_digest:
            raise PolicyError(
                "decision-digest",
                "decision %r does not bind to its canonical bytes (tampered "
                "or rebound decision)" % (decision.decision_id[:16],),
            )
        recorded = self._minted.get(receipt.receipt_id)
        if recorded is None:
            raise PolicyError(
                "receipt-unknown",
                "receipt %r was not minted by THIS authority (its mint "
                "ledger has no such entry) -- a receipt is valid only "
                "against the authority instance that minted it"
                % (receipt.receipt_id[:16],),
            )
        if recorded != receipt:
            raise PolicyError(
                "receipt-conflict",
                "receipt %r conflicts with the mint-ledger entry for the "
                "same id" % (receipt.receipt_id[:16],),
            )
        if receipt.decision_id != decision.decision_id:
            raise PolicyError(
                "receipt-binding",
                "the receipt vouches for decision %r, not %r"
                % (receipt.decision_id[:16], decision.decision_id[:16]),
            )
        if receipt.evaluation_instant != decision.evaluation_instant:
            raise PolicyError(
                "receipt-instant",
                "the receipt records evaluation instant %r but the decision "
                "carries %r"
                % (receipt.evaluation_instant, decision.evaluation_instant),
            )

    # -- audit reads -------------------------------------------------------

    def minted_receipt_ids(self) -> Tuple[str, ...]:
        """The ids of every receipt this authority minted
        (deterministic sorted order)."""
        return tuple(sorted(self._minted))

    def chain_root(self) -> str:
        """The current mint-chain root (audit; changes on every mint)."""
        return self._chain_root


__all__ = [
    "GENESIS_CHAIN_ROOT",
    "RECEIPT_KIND",
    "PolicyRevalidationAuthority",
    "RevalidationReceipt",
    "RevalidationResult",
]
