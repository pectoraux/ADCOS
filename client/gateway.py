"""WORK-049 canonical gateway — the client's ONLY read window.

The client core reaches canonical state EXCLUSIVELY through this
bounded read surface (public accessor reads of the injected
authorities — never private internals, never table/store writes,
never an authority construction).  Mutating operations are driven
through the authorities' public mutating surfaces (injected per
mode); the gateway owns the CONNECTION MODEL:

- ``reachable`` — whether the canonical authority surface is
  currently reachable (the offline seam);
- while unreachable, EVERY read fails closed with the typed
  OFFLINE error (resolution UNKNOWN): the client never fabricates
  a canonical read result and never presents cache as current.

Every read returns a :class:`GatewayRead` — the canonical state
string AS READ, the read instant, the owning authority, and the
binding references the caller's context verification needs
(authenticated responses must be bound to the correct
user/device/application context; mismatches fail closed).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import ClientError, ClientReasonCode, FailClosedResolution
from .model import ReasonRef

#: The canonical authorities the gateway may read (frozen labels).
GATEWAY_AUTHORITIES: Tuple[str, ...] = (
    "sharing",
    "commercial",
    "networkpath",
    "usage",
)


@dataclass(frozen=True)
class GatewayRead:
    """One bounded canonical read result (a projection input)."""

    authority: str
    subject: str
    state: str
    observed_at: str
    #: context-binding references the read carries (subject names
    #: to values; e.g. buyer/provider refs on a sharing session)
    bindings: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        for label, value in (
            ("authority", self.authority),
            ("subject", self.subject),
            ("state", self.state),
            ("observed_at", self.observed_at),
        ):
            if not isinstance(value, str) or not value:
                raise ClientError(
                    ClientReasonCode.INVALID_INPUT,
                    "gateway read %s must be a non-empty string" % label,
                )
        if self.authority not in GATEWAY_AUTHORITIES:
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "gateway read authority %r is outside the frozen set"
                % (self.authority,),
            )
        if not isinstance(self.bindings, tuple) or any(
            not isinstance(pair, tuple)
            or len(pair) != 2
            or not isinstance(pair[0], str)
            or not isinstance(pair[1], str)
            for pair in self.bindings
        ):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "gateway read bindings must be (string, string) pairs",
            )

    def binding(self, name: str) -> str:
        for key, value in self.bindings:
            if key == name:
                return value
        return ""


class CanonicalGateway:
    """The canonical read-window contract.

    Concrete gateways wrap INJECTED authority objects and perform
    ONLY public-accessor reads.  The base class defines the frozen
    surface; the connection seam (``reachable`` /
    ``set_reachable``) is part of the contract because offline
    behavior is part of the frozen W049 semantics.
    """

    def __init__(self) -> None:
        self._reachable = True

    # -- the connection model ------------------------------------------------

    @property
    def reachable(self) -> bool:
        return self._reachable

    def set_reachable(self, reachable: bool) -> None:
        """The connection seam (battery/app controlled).

        Disconnecting models loss of contact with the canonical
        authority surface; the gateway never fabricates reads
        while unreachable."""
        self._reachable = bool(reachable)

    def _require_reachable(self) -> None:
        if not self._reachable:
            raise ClientError(
                ClientReasonCode.OFFLINE,
                "the canonical authority surface is unreachable: no read "
                "is fabricated and no cached value becomes current truth "
                "(reconnect and reconcile before acting)",
                resolution=FailClosedResolution.UNKNOWN,
            )

    # -- the bounded read surface ---------------------------------------------

    def read_clock(self) -> str:
        """One clock read through the injected seam (never a wall
        clock; the deterministic batteries inject StepClock)."""
        raise NotImplementedError

    def read_sharing_session(self, sharing_session_id: str) -> GatewayRead:
        raise NotImplementedError

    def read_consent(self, consent_id: str) -> GatewayRead:
        raise NotImplementedError

    def read_lease(self, transaction_id: str) -> GatewayRead:
        raise NotImplementedError

    def read_path(self, path_id: str) -> GatewayRead:
        raise NotImplementedError

    def read_usage_account(self, transaction_id: str) -> GatewayRead:
        raise NotImplementedError


def _require_non_empty(value: str, label: str) -> None:
    if not isinstance(value, str) or not value:
        raise ClientError(
            ClientReasonCode.INVALID_INPUT, "%s must be non-empty" % label
        )


def _wrap_read_error(error: Exception, authority: str, subject: str) -> ClientError:
    """Normalize one canonical read failure fail-closed.

    The canonical reason is preserved verbatim (code + source);
    an unreadable subject is an UNKNOWN condition — never a
    fabricated state."""
    return ClientError(
        ClientReasonCode.CANONICAL_DENIED,
        "the canonical %s read for %r failed (%s: %s) — the state is "
        "UNKNOWN and the client fails closed (never fabricated)"
        % (authority, subject, getattr(error, "reason", "error"), error),
        resolution="UNKNOWN",
        canonical_reason=ReasonRef(
            code=str(getattr(error, "reason", "%s-error" % authority)),
            source=authority,
            severity="error",
        ),
    )


class ComposedGateway(CanonicalGateway):
    """The composed read gateway over injected authority objects.

    Wraps the public read accessors of the W048 sharing runtime
    (``session``/``consent``), the W051 CommercialCore
    (``transaction``), the W041 NetworkPath manager (``path``),
    and the W052 UsageLedger (``account``) — read-only, public,
    and nothing else.  The gateway holds no authority of its own
    and constructs none.
    """

    def __init__(
        self,
        *,
        clock: Any = None,
        sharing: Any = None,
        core: Any = None,
        paths: Any = None,
        usage: Any = None,
    ) -> None:
        super().__init__()
        self._clock = clock
        self._sharing = sharing
        self._core = core
        self._paths = paths
        self._usage = usage

    def read_clock(self) -> str:
        """One clock read through the injected seam (the client core
        never reads a wall clock; the gateway carries the composed
        clock)."""
        if self._clock is None:
            raise ClientError(
                ClientReasonCode.STALE_STATE,
                "no clock seam is wired into this gateway (never "
                "fabricated; deterministic batteries always wire one)",
            )
        return self._clock.now()

    def _now(self) -> str:
        return self._clock.now()

    def read_sharing_session(self, sharing_session_id: str) -> GatewayRead:
        _require_non_empty(sharing_session_id, "sharing_session_id")
        self._require_reachable()
        if self._sharing is None:
            raise ClientError(
                ClientReasonCode.STALE_STATE,
                "no sharing runtime is wired into this gateway (UNKNOWN; "
                "never fabricated)",
            )
        try:
            session = self._sharing.session(sharing_session_id)
        except Exception as error:
            raise _wrap_read_error(error, "sharing", sharing_session_id) from error
        return GatewayRead(
            authority="sharing",
            subject=sharing_session_id,
            state=str(session.state),
            observed_at=self._now(),
            bindings=(
                ("buyer_ref", str(session.buyer_ref)),
                ("provider_ref", str(session.provider_ref)),
                ("session_ref", str(session.session_ref)),
                ("consent_ref", str(session.consent_ref)),
                ("termination_reason", str(session.termination_reason)),
                ("path_ref", str(session.path_ref)),
            ),
        )

    def read_consent(self, consent_id: str) -> GatewayRead:
        _require_non_empty(consent_id, "consent_id")
        self._require_reachable()
        if self._sharing is None:
            raise ClientError(
                ClientReasonCode.STALE_STATE,
                "no sharing runtime is wired into this gateway (UNKNOWN; "
                "never fabricated)",
            )
        try:
            consent = self._sharing.consent(consent_id)
        except Exception as error:
            raise _wrap_read_error(error, "sharing", consent_id) from error
        return GatewayRead(
            authority="sharing",
            subject=consent_id,
            state=str(consent.state),
            observed_at=self._now(),
            bindings=(
                ("provider_ref", str(consent.provider_ref)),
                ("buyer_ref", str(consent.buyer_ref)),
            ),
        )

    def read_lease(self, transaction_id: str) -> GatewayRead:
        _require_non_empty(transaction_id, "transaction_id")
        self._require_reachable()
        if self._core is None:
            raise ClientError(
                ClientReasonCode.STALE_STATE,
                "no commercial core is wired into this gateway (UNKNOWN; "
                "never fabricated)",
            )
        try:
            transaction = self._core.transaction(transaction_id)
        except Exception as error:
            raise _wrap_read_error(error, "commercial", transaction_id) from error
        buyer = ""
        intent = getattr(transaction, "intent", None)
        if isinstance(intent, dict):
            buyer = str(intent.get("buyer", ""))
        offer = getattr(transaction, "offer", None)
        # P1-2: the canonical economic terms travel as a binding —
        # the CANONICAL serialization of the W051 transaction's
        # own offer record (exactly as the authority journaled it).
        # This is the ONLY economic-result source the consent
        # presentation may project; it is never caller-supplied.
        offer_terms = ""
        if isinstance(offer, dict):
            try:
                offer_terms = canonical_json_bytes(
                    {key: offer[key] for key in sorted(offer)}
                ).decode("utf-8")
            except Exception as error:  # noqa: BLE001 - shape guard
                raise ClientError(
                    ClientReasonCode.CANONICAL_DENIED,
                    "the canonical %s read for %r failed (offer terms are "
                    "not canonically serializable: %s) — the state is "
                    "UNKNOWN and the client fails closed (never fabricated)"
                    % ("commercial", transaction_id, error),
                    resolution="UNKNOWN",
                    canonical_reason=ReasonRef(
                        code="commercial-offer-unreadable",
                        source="commercial",
                        severity="error",
                    ),
                ) from error
        return GatewayRead(
            authority="commercial",
            subject=transaction_id,
            state=str(transaction.state),
            observed_at=self._now(),
            bindings=(
                ("buyer_ref", buyer),
                ("session_ref", str(getattr(transaction, "session_ref", "") or "")),
                ("offer_terms", offer_terms),
            ),
        )

    def read_path(self, path_id: str) -> GatewayRead:
        _require_non_empty(path_id, "path_id")
        self._require_reachable()
        if self._paths is None:
            raise ClientError(
                ClientReasonCode.STALE_STATE,
                "no NetworkPath machinery is wired into this gateway "
                "(UNKNOWN; never fabricated)",
            )
        try:
            path = self._paths.path(path_id)
        except Exception as error:
            raise _wrap_read_error(error, "networkpath", path_id) from error
        return GatewayRead(
            authority="networkpath",
            subject=path_id,
            state=str(path.state),
            observed_at=self._now(),
            bindings=(
                ("session_ref", str(path.session_id)),
                ("interface", str(path.interface_name)),
            ),
        )

    def read_usage_account(self, transaction_id: str) -> GatewayRead:
        _require_non_empty(transaction_id, "transaction_id")
        self._require_reachable()
        if self._usage is None:
            raise ClientError(
                ClientReasonCode.STALE_STATE,
                "no usage ledger is wired into this gateway (UNKNOWN; "
                "never fabricated)",
            )
        try:
            account = self._usage.account(transaction_id)
        except Exception as error:
            raise _wrap_read_error(error, "usage", transaction_id) from error
        return GatewayRead(
            authority="usage",
            subject=transaction_id,
            state=str(account.state),
            observed_at=self._now(),
            bindings=(("total_quantity", str(account.total_quantity)),),
        )
