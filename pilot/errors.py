"""WORK-040 pilot deployment-plane error vocabulary.

The pilot family is DEPLOYMENT/CONTROL code: it composes the accepted
production authorities (WORK-003 .. WORK-039) exclusively through their
public contracts and never re-decides anything they own.  These reason
codes describe failures of the DEPLOYMENT PLANE itself (wiring,
framing, marshalling, orchestration, evidence capture) -- never
protocol semantics, which surface through the production families'
own typed errors unchanged.
"""

from __future__ import annotations


class PilotError(Exception):
    """A typed pilot deployment-plane failure."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__("%s: %s" % (reason, detail))
        self.reason = reason
        self.detail = detail

    def __str__(self) -> str:  # pragma: no cover - display only
        return "%s: %s" % (self.reason, self.detail)


class PilotReasonCode:
    """The frozen pilot deployment-plane reason vocabulary."""

    WIRE_INVALID = "pilot.wire-invalid"
    WIRE_TIMEOUT = "pilot.wire-timeout"
    WIRE_CLOSED = "pilot.wire-closed"
    WIRE_OVERSIZED = "pilot.wire-oversized"
    MARSHAL_INVALID = "pilot.marshal-invalid"
    MANIFEST_INVALID = "pilot.manifest-invalid"
    NODE_INVALID = "pilot.node-invalid"
    NODE_FAILED = "pilot.node-failed"
    PROBE_FAILED = "pilot.probe-failed"
    EVIDENCE_INVALID = "pilot.evidence-invalid"
    EVIDENCE_TAMPERED = "pilot.evidence-tampered"
    SECRETS_IN_EVIDENCE = "pilot.secrets-in-evidence"
    PROMOTION_FORBIDDEN = "pilot.promotion-forbidden"
    CONDUCTOR_FAILED = "pilot.conductor-failed"

    @classmethod
    def values(cls) -> tuple:
        return (
            cls.WIRE_INVALID,
            cls.WIRE_TIMEOUT,
            cls.WIRE_CLOSED,
            cls.WIRE_OVERSIZED,
            cls.MARSHAL_INVALID,
            cls.MANIFEST_INVALID,
            cls.NODE_INVALID,
            cls.NODE_FAILED,
            cls.PROBE_FAILED,
            cls.EVIDENCE_INVALID,
            cls.EVIDENCE_TAMPERED,
            cls.SECRETS_IN_EVIDENCE,
            cls.PROMOTION_FORBIDDEN,
            cls.CONDUCTOR_FAILED,
        )


__all__ = ["PilotError", "PilotReasonCode"]
