"""ADCOS Wi-Fi/non-3GPP access adapter package (WORK-021).

A new sub-package WITHIN the frozen ``/adapters`` module boundary
(``spec/architecture.md`` §29; LOCK-002's discipline generalized by
LOCK-001: the ADCOS core encodes no single access technology --
Wi-Fi/non-3GPP access enters through an adapter; LOCK-016: external
access implementations remain behind adapter/provider interfaces).
Peer of ``adapters.ip`` (WORK-018, accepted) and ``adapters.fivegc``
(WORK-019, accepted) -- it defines its OWN :class:`WifiContract` ABC
(NOT a subtype of the WORK-016
:class:`adapters.contract.AdapterContract`), because the Wi-Fi/
non-3GPP domain has its own vocabulary (association / tunnel / AP /
SSID / station / N3IWF), distinct from the W016 allocate/release/
bearer vocabulary, the W018 flow/prefix/packet vocabulary, and the
W019 PDU-session/SUPI/S-NSSAI vocabulary.  A later WORK-021 bridge
task subclasses the W016 AdapterContract to expose this family on
the generic nine-op SDK surface.

The boundary (mirrors the W016/W017/W018/W019 seams)::

    ADCOS Session (W012, session_id sacred, access-independent)
          |
          |  adapters/wifi/contract.py: WifiContract
          |  + WifiContext least-authority facade
          v
    Wi-Fi/non-3GPP access path (association identity, N3IWF tunnel
    identity, IPsec/NAS identity -- all adapter-side opaque data,
    distinct from session_id -- the W021 identity invariant)
          |
          v  Wi-Fi/N3IWF state (stations, associations, tunnels, IPsec
             SAs, vendor/chipset state) lives in the adapter/conformance
             peer, NEVER in core (LOCK-002/016/017)

Discipline carried by the whole family:

- LOCK-002 (access technology neutrality via adapters): no Wi-Fi
  chipset/vendor API or non-3GPP implementation type crosses into
  core; LOCK-016 (external technology behind the adapter/provider
  interface); LOCK-017 (no vendor authority).
- LOCK-018 (standards leverage over reinvention): IEEE 802.11-2020,
  IEEE 802.1X-2020, RFC 3748, 3GPP TS 23.316/TS 24.302, RFC 7296,
  and RFC 4301 reference shapes are used as DATA with citations --
  the family never reinvents Wi-Fi, EAP, or IPsec standards.
- LOCK-023 (credential slot names only): Wi-Fi/802.1X/N3IWF
  credential MATERIAL never crosses the boundary; only slot NAMES.
- LOCK-024 (conformance is architectural): interoperating with a
  real Wi-Fi path is never sufficient by itself -- the ADCOS
  boundary semantics are verified by the WORK-021 selftest.
- W020 independence: this family does not import or depend on the
  unaccepted WORK-020 ``adapters.ran`` branch and carries no RAN
  vocabulary.

Package (adapters/wifi/) -- foundation + mediation/reference stage
(W021-a1 + W021-a2 + W021-a3):
- contract.py    WifiContract ABC + WifiContext immutable
                 least-authority facade (integration_id + injected
                 instant + step budget + read-only SessionReader/
                 ApProfileReader); 12 operations (open, provision_ap,
                 bind_session, attach_external_association,
                 observe_external_association, authenticate,
                 establish_tunnel, egress_frame, release_tunnel,
                 app_session, health, close)
- model.py       SecurityPolicy/ApState/AssociationState/TunnelState/
                 LinkMetricName vocabularies + SsidProfile/
                 ApDescriptor/StationDescriptor/CredentialSlot/ApView/
                 AssociationBinding/TunnelBinding/AssociationView/
                 TunnelView/ExternalAssociationEvidence/AuthResult/
                 Non3GppAccessObservation/WifiEvent (IEEE 802.11-2020
                 / IEEE 802.1X-2020 / 3GPP TS 23.316 shapes as DATA;
                 content-derived ids; no crypto, no vendor SDK, no
                 chipset API; LinkMetricName added in W021-a3 -- the
                 sanctioned additive extension mirroring WORK-016
                 adapters.model.LinkMetricName for the SDK bridge)
- validation.py  Opaque-ref grammar (wifi:assoc/tunnel/ap:<hex>),
                 the ref/session separation enforcer (W021 identity
                 invariant), LOCK-023 credential-like text rejection,
                 SSID/station/AP-name/band/count validators
- sandbox.py     SandboxedWifi -- BaseException->typed value,
                 contract-shape validation (incl. the W021 identity
                 separation re-asserted at the seam + leaky
                 app-session rejection + the exact WifiAppSession
                 facade type), deterministic step budget
                 with the frozen module-level STEP_CHARGES table (the
                 family's pinnable surface), consecutive-failure
                 health accounting; NO capability-escape surface of
                 any kind onto the implementation (no getattr hooks,
                 no data-path accessors)
- engine.py      ReferenceWifiEngine -- deterministic Wi-Fi/non-3GPP
                 access reference model; honest non-confidential (no
                 real Wi-Fi stack, no real N3IWF, no IPsec, no radio,
                 no vendor SDK); per-SSID station + per-association
                 tunnel capacity accounting (fail closed); SSID/AP
                 availability ladders (degrade loudly, never kill
                 silently); honest capability ladder
- manager.py     WifiManager -- register_implementation swaps the
                 DEFAULT sandbox only for NEW work (make_default);
                 live bindings keep their owning sandbox/impl
                 (B2 per-binding ownership); the W021 identity
                 guards (requirements-map identity smuggling and
                 cross-binding session collapse rejected caller-side
                 fail-closed); tunnel-scoped ops dispatch through
                 the owning binding's sandbox; app_session returns
                 the implementation's sandbox-validated facade
                 VERBATIM (with the egress routing bound -- never a
                 manager-constructed second facade, never a
                 data-path extraction); byte-stable snapshot
                 (implementation labels stay out -- B2)
- session.py     WifiAppSession -- ordinary app facade (connect/send/
                 recv/close with a standard destination string; NO
                 ADCOS/Wi-Fi API in the app path -- LOCK-019 analog);
                 the manager-routed byte path
                 App->WifiAppSession->WifiManager->SandboxedWifi->
                 implementation->recv.  The facade is the
                 IMPLEMENTATION'S AUTHORITATIVE object (the sandbox
                 validates it isinstance-exactly; the manager returns
                 it verbatim with the egress routing bound); a real
                 tunnel data path is ENCAPSULATED INSIDE the facade
                 via the documented `_bind_data_path` internal
                 protocol (attached by the owning implementation
                 before the facade crosses the seam -- the accepted
                 WORK-019 `_bind_real_socket` pattern; NO bare socket
                 ever crosses a seam)
- bridge.py      WifiTechnologyAdapter -- the WORK-016 Adapter SDK
                 bridge: subclasses the accepted
                 adapters.contract.AdapterContract (the frozen
                 nine-op surface) over the family RUNTIME
                 (WifiManager) -- the architect-reviewed authority
                 path AdapterRuntime -> bridge -> manager -> sandbox
                 -> implementation; the bridge holds a MANAGER
                 reference and NOTHING else (no implementation
                 reference, no contexts, no state beyond the label);
                 the ONLY import crossing the family boundary is
                 ``from ..contract import AdapterContext,
                 AdapterContract``
- conformance.py ReferenceWifiConformanceServer -- a REAL
                 N3IWF-shaped peer: real UDP control plane (RFC 7296
                 IKE_SA_INIT/IKE_AUTH/CREATE_CHILD_SA message-schema
                 SHAPES + OBSERVE surface) + real TCP tunnel-data
                 echo; honest non-confidential (no real radio, no
                 real IKEv2 crypto, no IPsec)
- n3iwf.py      N3IWFAdapter -- the production-shaped adapter (the
                 Open5GSAdapter analog): subclasses the reference
                 engine, overrides the real-network ops
                 (authenticate/establish_tunnel/egress_frame/
                 app_session/observe_external_association/close) with
                 REAL UDP control exchanges + REAL TCP tunnel-data
                 writes; the real data path is ENCAPSULATED INSIDE
                 the WifiAppSession facade the adapter returns
                 (documented `_bind_data_path` internal protocol;
                 NO private capability-escape hooks onto the
                 adapter)
- wifi_interop.py  the B1 real-Wi-Fi/N3IWF interop gate
                 (run_wifi_interop; environment-gated by
                 WIFI_INTEROP=1; PASSED only with real end-to-end
                 bytes; UNREACHABLE is an honest SKIP, never a
                 fabricated PASS)
- interop_env_probe.py  the environment-capability probe + HARD
                 anti-faking WIFI_PEER_KIND guard (FORBIDDEN on an
                 explicit in-repo-simulator assertion; SKIP never
                 converts to acceptance)
- serialization.py  canonical-JSON for the outward-facing state
- errors.py      WifiError + WifiReasonCode + WifiFailure

The WORK-021 selftest (tools/wifi_selftest.py) verifies the whole
family per the frozen brief (the nine verification bullets),
including mixed-access session continuity with the accepted
WORK-019 5G Core family over both families' real conformance
peers.
"""

from __future__ import annotations

from .bridge import WifiTechnologyAdapter
from .conformance import ReferenceWifiConformanceServer
from .contract import (
    ApProfileReader,
    ApProfileView,
    CONTEXT_SURFACE,
    CONTRACT_OPERATIONS,
    SessionReader,
    SessionView,
    WifiContext,
    WifiContract,
)
from .engine import ReferenceWifiEngine
from .errors import WIFI_PREFIX, WifiError, WifiFailure, WifiReasonCode
from .interop_env_probe import (
    CapabilityReport,
    Check,
    EnvProbeConfig as WifiEnvProbeConfig,
    probe_wifi_interop_capability,
)
from .manager import DEFAULT_INTEGRATION_ID, WifiManager
from .model import (
    ApDescriptor,
    ApState,
    ApView,
    AssociationBinding,
    AssociationState,
    AssociationView,
    AuthResult,
    CredentialSlot,
    ExternalAssociationEvidence,
    LinkMetricName,
    Non3GppAccessObservation,
    SecurityPolicy,
    SsidProfile,
    StationDescriptor,
    TunnelBinding,
    TunnelState,
    TunnelView,
    WifiEvent,
    derive_ap_ref,
    derive_assoc_ref,
    derive_binding_id,
    derive_integration_id,
    derive_tunnel_ref,
)
from .n3iwf import N3IWFAdapter
from .sandbox import (
    DEFAULT_STEP_BUDGET,
    STEP_CHARGES,
    SandboxedWifi,
    WifiOpResult,
)
from .serialization import to_canonical_bytes
from .session import WifiAppSession
from .validation import (
    assert_ref_session_separation,
    reject_credential_like_text,
    validate_ap_name,
    validate_band,
    validate_credential_slot_name,
    validate_opaque_ref,
    validate_ssid_name,
    validate_station_count,
    validate_station_label,
)
from .wifi_interop import (
    InteropConfig as WifiInteropConfig,
    InteropOutcome as WifiInteropOutcome,
    gate_enabled as wifi_gate_enabled,
    run_wifi_interop,
)

# Foundation surface (W021-a1) + mediation/reference surface
# (W021-a2) + runtime/session/SDK-bridge surface (W021-a3) +
# conformance/real-interop surface (W021-a4).  Later WORK-021 tasks
# extend these exports -- never narrow them.
__all__ = [
    # Contract surface
    "WifiContract",
    "WifiContext",
    "CONTEXT_SURFACE",
    "CONTRACT_OPERATIONS",
    "SessionReader",
    "ApProfileReader",
    "SessionView",
    "ApProfileView",
    # WORK-016 SDK bridge
    "WifiTechnologyAdapter",
    # Implementations
    "ReferenceWifiEngine",
    "N3IWFAdapter",
    # Conformance / real interop (a4)
    "ReferenceWifiConformanceServer",
    "WifiInteropConfig",
    "WifiInteropOutcome",
    "wifi_gate_enabled",
    "run_wifi_interop",
    "WifiEnvProbeConfig",
    "Check",
    "CapabilityReport",
    "probe_wifi_interop_capability",
    # Runtime / mediation
    "WifiManager",
    "DEFAULT_INTEGRATION_ID",
    "SandboxedWifi",
    "WifiOpResult",
    "STEP_CHARGES",
    "DEFAULT_STEP_BUDGET",
    # Application session facade
    "WifiAppSession",
    # Model
    "SecurityPolicy",
    "ApState",
    "AssociationState",
    "TunnelState",
    "LinkMetricName",
    "SsidProfile",
    "ApDescriptor",
    "StationDescriptor",
    "CredentialSlot",
    "ApView",
    "AssociationBinding",
    "TunnelBinding",
    "AssociationView",
    "TunnelView",
    "ExternalAssociationEvidence",
    "AuthResult",
    "Non3GppAccessObservation",
    "WifiEvent",
    "derive_assoc_ref",
    "derive_binding_id",
    "derive_tunnel_ref",
    "derive_ap_ref",
    "derive_integration_id",
    # Errors
    "WifiError",
    "WifiFailure",
    "WifiReasonCode",
    "WIFI_PREFIX",
    # Validation
    "validate_opaque_ref",
    "assert_ref_session_separation",
    "reject_credential_like_text",
    "validate_credential_slot_name",
    "validate_ssid_name",
    "validate_station_label",
    "validate_ap_name",
    "validate_band",
    "validate_station_count",
    # Serialization
    "to_canonical_bytes",
]
