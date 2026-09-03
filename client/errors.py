"""WORK-049 client boundary typed errors.

The client is a CONSUMER/PROJECTION boundary (WORK-049-CORE-001 /
DEC-0076, baseline reconciled by DEC-0077): it owns no canonical
truth, so its typed failure vocabulary is deliberately minimal and
STRUCTURAL — it never re-encodes canonical business semantics.

Reason-code policy (frozen, docs/WORK-049-handoff.md): existing
canonical reason codes are reused.  Whenever a client operation
fails because a canonical authority denied something, the failure
carries the canonical code verbatim in a
:class:`~client.model.ReasonRef` (code + source + severity
preserved; presentation may translate to UX text but never alters
the canonical triple).  The ``client-*`` values below are local
structural failure modes of the boundary itself (the same
package-local convention every family in this repository follows);
no new CANONICAL reason family is introduced.

The frozen fail-closed rule: any unresolved ambiguity that could
produce unauthorized connectivity resolves to
``DENY / STOP / UNKNOWN`` (:class:`FailClosedResolution`).
"""

from __future__ import annotations

from typing import Optional


class FailClosedResolution:
    """The frozen fail-closed resolution vocabulary (W049 contract).

    Any ambiguity that could produce unauthorized connectivity
    resolves to one of these — never to a fabricated success.
    """

    DENY = "DENY"
    STOP = "STOP"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def values(cls) -> tuple:
        return (cls.DENY, cls.STOP, cls.UNKNOWN)


class ClientReasonCode:
    """The client-boundary structural reason vocabulary.

    LOCAL structural modes only (the package convention): every
    canonical denial surfaces the canonical code through
    :class:`~client.model.ReasonRef`, never through these values.
    """

    #: malformed input at a public client boundary
    INVALID_INPUT = "client-invalid-input"
    #: a client lifecycle transition outside the frozen tables
    LIFECYCLE_ILLEGAL = "client-lifecycle-illegal"
    #: the canonical authority surface is unreachable (offline);
    #: NEVER fabricate success
    OFFLINE = "client-offline"
    #: platform capability is unknown/unsupported (fail closed) or
    #: the requested operation exceeds a restricted capability set
    CAPABILITY_DENIED = "client-capability-denied"
    #: an authenticated canonical response is not bound to this
    #: client's user/device/application context
    BINDING_MISMATCH = "client-binding-mismatch"
    #: a canonical authority denied the operation (the canonical
    #: reason is preserved verbatim in ``canonical_reason``)
    CANONICAL_DENIED = "client-canonical-denied"
    #: local state cannot be trusted to represent canonical truth
    #: (stale/unverifiable projection)
    STALE_STATE = "client-stale-state"
    #: a privacy-bounded presentation input carried a forbidden
    #: sensitive field (fail closed)
    PRIVACY_DENIED = "client-privacy-denied"

    @classmethod
    def values(cls) -> tuple:
        return (
            cls.INVALID_INPUT,
            cls.LIFECYCLE_ILLEGAL,
            cls.OFFLINE,
            cls.CAPABILITY_DENIED,
            cls.BINDING_MISMATCH,
            cls.CANONICAL_DENIED,
            cls.STALE_STATE,
            cls.PRIVACY_DENIED,
        )


class ClientError(Exception):
    """One typed client-boundary failure.

    ``reason`` is a :class:`ClientReasonCode` value (structural).
    ``resolution`` is the frozen fail-closed resolution applied
    (DENY/STOP/UNKNOWN).  ``canonical_reason`` — when set — is the
    verbatim canonical reason (code + source + severity) the
    underlying authority returned; it is never rewritten, never
    re-worded, and never replaced by friendlier text.
    """

    def __init__(
        self,
        reason: str,
        message: str,
        *,
        resolution: str = FailClosedResolution.DENY,
        canonical_reason=None,
    ) -> None:
        if reason not in ClientReasonCode.values():
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "client failure reason %r is outside the frozen structural "
                "vocabulary" % (reason,),
                resolution=FailClosedResolution.UNKNOWN,
            )
        if resolution not in FailClosedResolution.values():
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "fail-closed resolution %r is outside the frozen vocabulary"
                % (resolution,),
                resolution=FailClosedResolution.UNKNOWN,
            )
        if not isinstance(message, str) or not message:
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "client failure message must be a non-empty string",
                resolution=FailClosedResolution.UNKNOWN,
            )
        if canonical_reason is not None:
            # the canonical reason must itself be well-formed
            canonical_reason.code  # noqa: B018 - shape check
            canonical_reason.source  # noqa: B018 - shape check
            canonical_reason.severity  # noqa: B018 - shape check
        super().__init__(message)
        self.reason = reason
        self.resolution = resolution
        self.message = message
        self.canonical_reason: Optional[object] = canonical_reason
