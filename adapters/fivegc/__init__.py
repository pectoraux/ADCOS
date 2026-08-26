"""ADCOS 5G Core integration adapter package (WORK-019).

A new sub-package WITHIN the frozen ``/adapters`` module boundary
(``spec/architecture.md`` §29; LOCK-002: 5G is an adapter -- 3GPP
RAN/core functions remain outside the ADCOS core domain; LOCK-016:
external core implementations remain behind adapter/provider
interfaces).  Peer of ``adapters.ip`` (WORK-018) -- it defines its OWN
:class:`FiveGCoreContract` ABC (NOT a subtype of the WORK-016
:class:`adapters.contract.AdapterContract`), because the 5G Core
domain has its own vocabulary (PDU session / SUPI / S-NSSAI / DNN /
5QI / SBi / NGAP), distinct from the W016 allocate/release/bearer
vocabulary and the W018 flow/prefix/packet vocabulary.

The boundary (mirrors the W016/W017/W018 seams)::

    ADCOS Session (W012, session_id sacred)
          |
          |  adapters/fivegc/contract.py: FiveGCoreContract
          |  + FiveGCoreContext least-authority facade
          v
    5G Core PDU session (pdu_session_id, route identity,
                         distinct from session_id -- R1 invariant)
          |
          v  5G Core NF state (subscriber/PDU/AUSF/SMF/UPF state)
             lives in the adapter/conformance peer, NEVER in core
             (LOCK-016/017 -- 5G Core state remains outside ADCOS
             core authority)

Package (adapters/fivegc/):
- contract.py    FiveGCoreContract ABC + FiveGCoreContext
                 immutable least-authority facade (integration_id +
                 injected instant + step budget + read-only
                 SessionReader/SubscriberReader); 10 operations
                 (open, provision_subscriber, bind_session,
                 authenticate, establish_pdu_session, egress_pdu,
                 release_pdu_session, app_session, health, close)
- model.py       Supi/Suci/Snssai/Dnn/Qfi/QosFlowSpec/NfEndpoint/
                 PduSessionId/CredentialSlot/SubscriberRecord/
                 PduSessionBinding/PduSessionView/AuthResult/
                 FiveGCEvent (3GPP TS 23.501/33.501/29.500 shapes as
                 DATA; content-derived ids; no crypto, no vendor SDK)
- engine.py      Reference5GCoreEngine -- deterministic 5G Core NF
                 reference model; honest non-confidential (no real
                 Open5GS, no vendor SDK, no SCTP/NGAP, no radio)
- open5gs.py     Open5GSAdapter -- PRODUCTION-SHAPED real-HTTP adapter
                 targeting real Open5GS SBi (TS 29.503/29.509/29.502)
                 + NGAP (SCTP) endpoints; subclasses the reference
                 engine + overrides only the real-network ops
- open5gs_interop.py  The B1 real-Open5GS interop gate -- environment-
                 gated (OPEN5GS_INTEROP=1); exercises real Open5GS SBI
                 + real PDU session establishment + real user-plane
                 path against a REAL Open5GS; SKIPS with a transparent
                 verification-environment blocker when Open5GS is not
                 reachable (no in-repo simulator fallback)
- conformance.py Reference5GCoreConformanceServer -- a REAL 3GPP
                 SBi-over-HTTP NF peer that runs as user z (no root,
                 no Docker); the WORK-018 LoopbackIPv6ConformanceEngine
                 analog (real sockets, real 3GPP JSON, real bytes)
- session.py     AppSession -- ordinary app facade (connect/send/recv/
                 close with a standard destination string; NO ADCOS/5G
                 API in the app path -- LOCK-019 analog)
- sandbox.py     SandboxedFiveGCore -- BaseException->typed value,
                 contract-shape validation, step budget, leaky-
                 AppSession rejection; per-binding ownership captured
                 at bind_session (B2 mirror)
- manager.py     FiveGCoreManager -- register_implementation swaps
                 DEFAULT sandbox only (future establishments); live
                 bindings keep their sandbox/impl (B2); byte-stable
                 snapshot; cross-impl byte-identical public contract
- validation.py  3GPP-shape validators (SUPI/S-NSSAI/DNN/QFI/credential
                 slot name -- LOCK-023 rejects secret-resembling names)
- serialization.py  canonical-JSON for the outward-facing state
- errors.py      FiveGCoreError + FiveGCoreReasonCode + FiveGCoreFailure
"""

from __future__ import annotations

from .conformance import Reference5GCoreConformanceServer
from .contract import (
    CONTEXT_SURFACE,
    CONTRACT_OPERATIONS,
    FiveGCoreContext,
    FiveGCoreContract,
    SessionReader,
    SessionView,
    SubscriberProfileView,
    SubscriberReader,
)
from .engine import Reference5GCoreEngine
from .errors import FIVEGC_PREFIX, FiveGCoreError, FiveGCoreFailure, FiveGCoreReasonCode
from .manager import FiveGCoreManager
from .model import (
    AuthResult,
    CredentialSlot,
    Dnn,
    ExternalPduSessionEvidence,
    FiveGCEvent,
    LinkMetricsSample,
    NfEndpoint,
    PduSessionBinding,
    PduSessionId,
    PduSessionView,
    Qfi,
    QosFlowSpec,
    Snssai,
    SubscriberRecord,
    Suci,
    Supi,
)
from .open5gs import Open5GSAdapter
from .interop_env_probe import (
    CapabilityReport,
    Check,
    EnvProbeConfig,
    probe_open5gs_interop_capability,
)
from .open5gs_interop import (
    DEFAULT_OPEN5GS_INTEROP_PAYLOAD,
    DEFAULT_OPEN5GS_SBI_URL,
    InteropConfig,
    InteropOutcome,
    gate_enabled,
    run_open5gs_interop,
)
from .sandbox import (
    DEFAULT_STEP_BUDGET,
    FiveGCoreOpResult,
    SandboxedFiveGCore,
)
from .session import AppSession
from .serialization import to_canonical_bytes

__all__ = [
    # Contract surface
    "FiveGCoreContract",
    "FiveGCoreContext",
    "CONTEXT_SURFACE",
    "CONTRACT_OPERATIONS",
    "SessionReader",
    "SubscriberReader",
    "SessionView",
    "SubscriberProfileView",
    # Implementations
    "Reference5GCoreEngine",
    "Open5GSAdapter",
    "Reference5GCoreConformanceServer",
    # B1 real-Open5GS interop gate
    "DEFAULT_OPEN5GS_SBI_URL",
    "DEFAULT_OPEN5GS_INTEROP_PAYLOAD",
    "InteropConfig",
    "InteropOutcome",
    "gate_enabled",
    "run_open5gs_interop",
    # B1 gate hardening (env-capability matrix + anti-faking guard)
    "CapabilityReport",
    "Check",
    "EnvProbeConfig",
    "probe_open5gs_interop_capability",
    # Runtime
    "FiveGCoreManager",
    "SandboxedFiveGCore",
    "FiveGCoreOpResult",
    "DEFAULT_STEP_BUDGET",
    # App facade
    "AppSession",
    # Model
    "Supi",
    "Suci",
    "Snssai",
    "Dnn",
    "ExternalPduSessionEvidence",
    "Qfi",
    "QosFlowSpec",
    "NfEndpoint",
    "PduSessionId",
    "CredentialSlot",
    "SubscriberRecord",
    "PduSessionBinding",
    "PduSessionView",
    "AuthResult",
    "LinkMetricsSample",
    "FiveGCEvent",
    # Errors
    "FiveGCoreError",
    "FiveGCoreFailure",
    "FiveGCoreReasonCode",
    "FIVEGC_PREFIX",
    # Serialization
    "to_canonical_bytes",
]
