"""ADCOS backhaul adapter package (WORK-022).

A new sub-package WITHIN the frozen ``/adapters`` module boundary
(``spec/architecture.md`` §29; LOCK-001: the ADCOS core encodes no
single access technology -- Ethernet/fiber/microwave/satellite
backhaul enters through an adapter; LOCK-016: external access
implementations remain behind adapter/provider interfaces).
Peer of ``adapters.ip`` (WORK-018, accepted), ``adapters.fivegc``
(WORK-019, accepted), and ``adapters.wifi`` (WORK-021, accepted) --
it defines its OWN :class:`BackhaulContract` ABC (NOT a subtype of
the WORK-016 :class:`adapters.contract.AdapterContract`), because the
backhaul domain has its own vocabulary (link / allocation / bearer /
endpoint / profile), distinct from the W016 allocate/release/bearer
vocabulary, the W018 flow/prefix/packet vocabulary, the W019
PDU-session/SUPI/S-NSSAI vocabulary, and the W021 association/tunnel
vocabulary.  The WORK-022 bridge task subclasses the W016
AdapterContract to expose this family on the generic nine-op SDK
surface.

The boundary (mirrors the W016/W017/W018/W019/W021 seams)::

    ADCOS Session (W012, session_id sacred, access-independent)
          |
          |  adapters/backhaul/contract.py: BackhaulContract
          |  + BackhaulContext least-authority facade
          v
    Backhaul path (link identity, bearer identity, allocation
    identity -- all adapter-side opaque data, distinct from
    session_id -- the W022 identity invariant)
          |
          v  Backhaul state (ports, circuits, trails, radio links,
             terminal/modem state, vendor element management) lives
             in the adapter/conformance peer, NEVER in core
             (LOCK-002/016/017)

Discipline carried by the whole family:

- LOCK-002 (access technology neutrality via adapters): no vendor,
  modem, or chipset API crosses into core; LOCK-016 (external
  technology behind the adapter/provider interface); LOCK-017 (no
  vendor authority).
- LOCK-018 (standards leverage over reinvention): IEEE 802.3-2018
  (Ethernet frames), IEEE 802.1Q-2022 (bridged LANs), ITU-T G.709
  (optical transport), ITU-R microwave radio-relay, and ITU-R
  satellite transport reference shapes are used as DATA with
  citations -- the family never reinvents transport standards.
- LOCK-023 (credential slot names only): backhaul credential
  MATERIAL (management-plane secrets, terminal/modem credentials,
  protected-backhaul keys) never crosses the boundary; only slot
  NAMES.
- WORK-008 reuse: link capacity maps into the canonical resource
  kinds/units (the ``backhaul``/``bandwidth`` bps base units) by
  REFERENCE -- never a second capacity/accounting authority.
- WORK-011 consumption: path references cross as opaque DATA; the
  family never re-derives or scores paths (no second routing
  engine).
- WORK-018 delegation: IPv6/IP/NAT semantics are the IP integration
  layer's authority -- the backhaul family carries
  frames/bytes-between-endpoints, never IP addresses.
- LOCK-024 (conformance is architectural): interoperating with a
  real backhaul path is never sufficient by itself -- the ADCOS
  boundary semantics are verified by the WORK-022 selftest.
- W020 independence: this family does not import or depend on the
  unaccepted WORK-020 ``adapters.ran`` branch and carries no RAN
  vocabulary.

Package (adapters/backhaul/) -- foundation + mediation/reference
stage + runtime/session/SDK-bridge stage + conformance/real-interop
stage + the PR #23 production-path stage (the element-client seam,
the REAL SNMPv2c client, and the REAL Ethernet frame writer):
- contract.py    BackhaulContract ABC + BackhaulContext immutable
                 least-authority facade (integration_id + injected
                 instant + step budget + read-only SessionReader);
                 11 operations (open, provision_link, allocate,
                 release, bind_session, unbind_session, observe_link,
                 egress_frame, app_session, health, close)
- model.py       BackhaulProfile/LinkState/BearerState/
                 AllocationState/LinkMetricName vocabularies +
                 LinkDescriptor/CredentialSlot/LinkView/
                 BackhaulAllocation/BackhaulBinding/
                 BackhaulLinkObservation/BackhaulEvent
                 (IEEE 802.3-2018 / ITU-T G.709 / ITU-R reference
                 shapes as DATA; content-derived ids; no crypto, no
                 vendor SDK, no modem API)
- validation.py  Opaque-ref grammar
                 (backhaul:link/bearer/alloc:<hex>), the
                 ref/session separation enforcer (the W022 identity
                 invariant), LOCK-023 credential-like text rejection,
                 link-name/endpoint-label/profile/path-ref/capacity/
                 bearer-count validators
- sandbox.py     SandboxedBackhaul -- BaseException->typed value,
                 contract-shape validation (incl. the W022 identity
                 separation re-asserted at the seam + leaky
                 app-session rejection + the exact BackhaulAppSession
                 facade type), deterministic step budget with the
                 frozen module-level STEP_CHARGES table (the
                 family's pinnable surface), consecutive-failure
                 health accounting; NO capability-escape surface of
                 any kind onto the implementation (no getattr hooks,
                 no data-path accessors)
- engine.py      ReferenceBackhaulEngine -- deterministic backhaul
                 reference model; honest non-confidential (no real
                 switch, no optical/microwave/satellite terminal, no
                 modem, no vendor SDK, no PHY); per-link capacity
                 accounting in the WORK-008 canonical bps units (fail
                 closed); per-link bearer accounting; one live bearer
                 per session (access change = replacement after
                 release); availability ladders (degrade loudly,
                 never kill silently); honest capability ladder; the
                 _validate_*/_commit_* split (the transactional
                 foundation -- public behavior unchanged)
- manager.py     BackhaulManager -- register_implementation swaps
                 the DEFAULT sandbox only for NEW work
                 (make_default); live bindings, links, and
                 allocations keep their owning sandbox/impl (B2
                 per-binding ownership); the W022 identity guards
                 (requirements-map identity smuggling and
                 cross-binding session collapse rejected
                 caller-side fail-closed); bearer/allocation/link-
                 scoped ops dispatch through the owning resource's
                 sandbox; app_session returns the implementation's
                 sandbox-validated facade VERBATIM (with the egress
                 routing bound -- never a manager-constructed second
                 facade, never a data-path extraction); byte-stable
                 snapshot (implementation labels stay out -- B2)
- session.py     BackhaulAppSession -- ordinary app facade
                 (connect/send/recv/close with a standard
                 destination string; NO ADCOS/backhaul API in the
                 app path -- LOCK-019 analog); the manager-routed
                 byte path App->BackhaulAppSession->BackhaulManager->
                 SandboxedBackhaul->implementation->recv.  The facade
                 is the IMPLEMENTATION'S AUTHORITATIVE object (the
                 sandbox validates it isinstance-exactly; the manager
                 returns it verbatim with the egress routing bound);
                 a real wire data path is ENCAPSULATED INSIDE the
                 facade via the documented `_bind_data_path`
                 internal protocol (attached by the owning
                 implementation before the facade crosses the seam --
                 the accepted WORK-019/021 pattern; NO bare socket
                 ever crosses a seam)
- bridge.py      BackhaulTechnologyAdapter -- the WORK-016 Adapter
                 SDK bridge: subclasses the accepted
                 adapters.contract.AdapterContract (the frozen
                 nine-op surface) over the family RUNTIME
                 (BackhaulManager) -- the architect-anchored
                 authority path AdapterRuntime -> bridge -> manager
                 -> sandbox -> implementation; the bridge holds a
                 MANAGER reference and NOTHING else (no
                 implementation reference, no contexts, no state
                 beyond the label); the ONLY import crossing the
                 family boundary is ``from ..contract import
                 AdapterContext, AdapterContract``
- conformance.py ReferenceBackhaulConformanceServer -- a REAL
                 managed-element-shaped peer: real TCP control plane
                 (LINK_UP/ALLOCATE/BIND/UNBIND/RELEASE/LINK_DOWN/
                 OBSERVE_LINK message-schema SHAPES) + real TCP wire
                 far-end echo carrying IEEE 802.3-2018 Ethernet-II
                 frames; honest non-confidential (no real switch, no
                 optical/microwave/satellite terminal, no vendor
                 element management) -- the SEPARATE conformance path,
                 never the claimed production interop protocol
- ethernet.py   The REAL Ethernet data plane + frame-shape DATA:
                 IEEE 802.3-2018 Ethernet-II headers, IEEE 802.1Q-2022
                 VLAN tags (TPID 0x8100), content-derived locally
                 administered MAC-shaped addresses, the
                 AF_PACKET/SOCK_RAW frame writer BOUND TO THE TAGGED
                 WIRE FORMAT (protocol = the outer TPID 0x8100 -- the
                 kernel demuxes on the frame's outermost
                 EtherType-position field; 0x88B5 appears only INSIDE
                 the tag as the inner EtherType; PR #23 second-review
                 Blocker 1) writing 802.1Q-tagged frames (the actual
                 L2 egress toward the switch; CAP_NET_RAW-gated,
                 fails CLOSED), and the packet-socket facade for the
                 app session's read side
- snmp.py        The REAL SNMPv2c management-plane client in pure
                 stdlib: the ASN.1/BER transfer syntax (RFC 2578),
                 RFC 3416/3417 community framing over UDP, request-id
                 correlation, error-status + varbind-exception
                 decoding, and the standard MIB objects (IF-MIB
                 RFC 2863, Q-BRIDGE-MIB RFC 4363 / PortList RFC 2674,
                 SNMPv2-MIB sysUpTime RFC 3418)
- element.py     The element-client seam -- ONE concrete real
                 production target (PR #23 Blocker 1):
                 BackhaulElementClient (one method = one external
                 operation; supports_element_side_capacity declares
                 whether the element's REAL interface reserves
                 bandwidth -- honest default NO;
                 reports_real_port_speed declares whether link_up
                 really reports the port's real capacity -- honest
                 default NO, and a ZERO/unknown speed on a declaring
                 client is UNAVAILABLE grounding that fails CLOSED,
                 never satisfying a positive declared bps capacity
                 (PR #23 third review)) +
                 SnmpEthernetElementClient (the real SNMP-managed
                 IEEE 802.1Q Ethernet switch: link lifecycle on
                 ifAdminStatus/ifOperStatus + the real ifSpeed/
                 ifHighSpeed port-capacity read, bearer binding as
                 the bearer's OWN 802.1Q VLAN segmentation
                 (dot1qVlanStaticTable row + egress PortList,
                 created at bind and destroyed at unbind),
                 observation on the IF-MIB counters, data plane on
                 the 802.1Q frame writer; capacity allocation
                 FAMILY-NATIVE -- a VLAN row is L2 segmentation,
                 never a bps reservation (PR #23 second-review
                 Blocker 2)) + JsonConformanceElementClient (the
                 conformance protocol client -- the JSON/TCP peer
                 above, never the production interop protocol)
- managed.py     ManagedBackhaulAdapter -- the TRANSACTIONAL
                 production-shaped adapter (the Open5GSAdapter/
                 N3IWFAdapter analog): constructed over a
                 BackhaulElementClient, every mutating operation runs
                 validate -> REAL external element operation ->
                 commit local, with compensating rollback where an
                 external operation can succeed before the local
                 commit (PR #23 Blocker 2); the real data path is
                 ENCAPSULATED INSIDE the BackhaulAppSession facade
                 the adapter returns (documented `_bind_data_path`
                 internal protocol; NO private capability-escape
                 hooks onto the adapter)
- backhaul_interop.py  the B1 real-backhaul interop gate
                 (run_backhaul_interop; environment-gated by
                 BACKHAUL_INTEROP=1; drives the PRODUCTION SNMP
                 Ethernet path with the REAL WORK-012 session
                 authority -- an actual SessionStore composed through
                 the real RoutingEngine/PolicyDecision/TopologyGraph
                 with read-only reader + gate negative controls;
                 PASSED only with real end-to-end bytes; the DISTINCT
                 DATA_PEER_UNREACHABLE status for a verified
                 management plane with a non-carrying data plane;
                 UNREACHABLE is an honest SKIP, never a fabricated
                 PASS)
- interop_env_probe.py  the environment-capability probe + HARD
                 anti-faking BACKHAUL_PEER_KIND guard (FORBIDDEN on
                 an explicit in-repo-simulator assertion; SKIP never
                 converts to acceptance); the preflight SEPARATES
                 the hard management-plane prerequisite (a REAL SNMP
                 GET sysUpTime round-trip) from the data-plane
                 capability prerequisites (packet socket / egress
                 interface / far-end MAC) and the never-blocking
                 diagnostics (wired interfaces, management userspace,
                 terminal daemons)
- serialization.py  canonical-JSON for the outward-facing state
- errors.py      BackhaulError + BackhaulReasonCode + BackhaulFailure

The WORK-022 selftest (tools/backhaul_selftest.py) verifies the
whole family per the frozen brief (the twelve verification bullets).
"""

from __future__ import annotations

from .bridge import BackhaulTechnologyAdapter
from .conformance import ReferenceBackhaulConformanceServer
from .contract import (
    CONTEXT_SURFACE,
    CONTRACT_OPERATIONS,
    BackhaulContext,
    BackhaulContract,
    SessionReader,
    SessionView,
)
from .element import (
    BackhaulElementClient,
    ElementAllocation,
    ElementBearer,
    ElementLink,
    ElementObservation,
    JsonConformanceElementClient,
    SnmpEthernetElementClient,
)
from .engine import MAX_BEARERS_PER_SESSION, RATE_KINDS_BPS, ReferenceBackhaulEngine
from .errors import (
    BACKHAUL_PREFIX,
    BackhaulError,
    BackhaulFailure,
    BackhaulReasonCode,
)
from .ethernet import (
    ETHERTYPE_EXPERIMENTAL,
    PACKET_SOCKET_PROTOCOL,
    TPID_8021Q,
    check_packet_socket_capability,
    derive_local_mac,
    encode_8021q_frame,
    encode_ethernet_ii_frame,
    parse_8021q_frame,
    parse_ethernet_ii_header,
)
from .interop_env_probe import (
    CapabilityReport,
    Check,
    EnvProbeConfig as BackhaulEnvProbeConfig,
    probe_backhaul_interop_capability,
)
from .managed import ManagedBackhaulAdapter
from .manager import DEFAULT_INTEGRATION_ID, BackhaulManager
from .model import (
    AllocationState,
    BackhaulAllocation,
    BackhaulBinding,
    BackhaulEvent,
    BackhaulLinkObservation,
    BackhaulProfile,
    BearerState,
    CredentialSlot,
    LinkDescriptor,
    LinkMetricName,
    LinkState,
    LinkView,
    derive_allocation_ref,
    derive_binding_id,
    derive_bearer_ref,
    derive_integration_id,
    derive_link_ref,
)
from .sandbox import (
    DEFAULT_STEP_BUDGET,
    STEP_CHARGES,
    BackhaulOpResult,
    SandboxedBackhaul,
)
from .serialization import to_canonical_bytes
from .session import BackhaulAppSession
from .snmp import (
    OID_DOT1Q_VLAN_STATIC_EGRESS_PORTS,
    OID_DOT1Q_VLAN_STATIC_ROW_STATUS,
    OID_IF_ADMIN_STATUS,
    OID_IF_HIGH_SPEED,
    OID_IF_OPER_STATUS,
    OID_IF_SPEED,
    OID_SYS_UPTIME,
    SnmpV2cClient,
    SnmpValue,
    oid_decode,
    oid_encode,
    port_list_clear,
    port_list_set,
    port_list_test,
)
from .backhaul_interop import (
    InteropConfig as BackhaulInteropConfig,
    InteropOutcome as BackhaulInteropOutcome,
    SessionAuthority as BackhaulSessionAuthority,
    gate_enabled as backhaul_gate_enabled,
    real_session_authority,
    run_backhaul_interop,
)
from .validation import (
    assert_ref_session_separation,
    reject_credential_like_text,
    validate_bearer_count,
    validate_capacity_bps,
    validate_credential_slot_name,
    validate_endpoint_label,
    validate_link_name,
    validate_opaque_ref,
    validate_path_ref,
    validate_profile,
)

# Foundation surface + mediation/reference surface + runtime/session/
# SDK-bridge surface + conformance/real-interop surface.  Later
# WORK-022 tasks extend these exports -- never narrow them.
__all__ = [
    # Contract surface
    "BackhaulContract",
    "BackhaulContext",
    "CONTEXT_SURFACE",
    "CONTRACT_OPERATIONS",
    "SessionReader",
    "SessionView",
    # WORK-016 SDK bridge
    "BackhaulTechnologyAdapter",
    # Implementations
    "ReferenceBackhaulEngine",
    "ManagedBackhaulAdapter",
    # The element-client seam (the production SNMP Ethernet target +
    # the conformance JSON/TCP client)
    "BackhaulElementClient",
    "SnmpEthernetElementClient",
    "JsonConformanceElementClient",
    "ElementLink",
    "ElementAllocation",
    "ElementBearer",
    "ElementObservation",
    # Real SNMPv2c client (RFC 3416/3417 in stdlib)
    "SnmpV2cClient",
    "SnmpValue",
    "oid_encode",
    "oid_decode",
    "port_list_set",
    "port_list_clear",
    "port_list_test",
    "OID_IF_ADMIN_STATUS",
    "OID_IF_OPER_STATUS",
    "OID_IF_SPEED",
    "OID_IF_HIGH_SPEED",
    "OID_SYS_UPTIME",
    "OID_DOT1Q_VLAN_STATIC_EGRESS_PORTS",
    "OID_DOT1Q_VLAN_STATIC_ROW_STATUS",
    # Conformance / real interop
    "ReferenceBackhaulConformanceServer",
    "BackhaulInteropConfig",
    "BackhaulInteropOutcome",
    "BackhaulSessionAuthority",
    "real_session_authority",
    "backhaul_gate_enabled",
    "run_backhaul_interop",
    "BackhaulEnvProbeConfig",
    "Check",
    "CapabilityReport",
    "probe_backhaul_interop_capability",
    # Runtime / mediation
    "BackhaulManager",
    "DEFAULT_INTEGRATION_ID",
    "SandboxedBackhaul",
    "BackhaulOpResult",
    "STEP_CHARGES",
    "DEFAULT_STEP_BUDGET",
    # Application session facade
    "BackhaulAppSession",
    # Model
    "BackhaulProfile",
    "LinkState",
    "BearerState",
    "AllocationState",
    "LinkMetricName",
    "LinkDescriptor",
    "CredentialSlot",
    "LinkView",
    "BackhaulAllocation",
    "BackhaulBinding",
    "BackhaulLinkObservation",
    "BackhaulEvent",
    "derive_link_ref",
    "derive_binding_id",
    "derive_bearer_ref",
    "derive_allocation_ref",
    "derive_integration_id",
    # Engine constants (WORK-008 rate-kind reuse, bearer bound)
    "RATE_KINDS_BPS",
    "MAX_BEARERS_PER_SESSION",
    # Wire frame helpers (adapter/peer-side DATA; IEEE 802.3-2018 +
    # IEEE 802.1Q-2022)
    "ETHERTYPE_EXPERIMENTAL",
    "TPID_8021Q",
    "PACKET_SOCKET_PROTOCOL",
    "encode_ethernet_ii_frame",
    "parse_ethernet_ii_header",
    "encode_8021q_frame",
    "parse_8021q_frame",
    "derive_local_mac",
    "check_packet_socket_capability",
    # Errors
    "BackhaulError",
    "BackhaulFailure",
    "BackhaulReasonCode",
    "BACKHAUL_PREFIX",
    # Validation
    "validate_opaque_ref",
    "assert_ref_session_separation",
    "reject_credential_like_text",
    "validate_credential_slot_name",
    "validate_link_name",
    "validate_endpoint_label",
    "validate_profile",
    "validate_path_ref",
    "validate_capacity_bps",
    "validate_bearer_count",
    # Serialization
    "to_canonical_bytes",
]
