"""ADCOS real backhaul interop gate (WORK-022 B1).

The environment-gated REAL interoperability suite.  The frozen
WORK-022 brief's verification bullet 11: "An environment-gated real
interoperability path for at least one concrete backhaul
implementation where the environment permits; never convert
SKIP/UNREACHABLE into acceptance."

The PR #23 architect review reshaped this gate (Blockers 1 + 3 +
secondary correction 4):

* **Blocker 1 -- one concrete real production target.**  The gate
  drives the PRODUCTION path: a real SNMP-managed IEEE 802.1Q
  Ethernet switch through its ACTUAL external interfaces -- real
  SNMPv2c management over UDP (IF-MIB ifAdminStatus/ifOperStatus +
  Q-BRIDGE-MIB dot1qVlanStaticTable, via
  :class:`adapters.backhaul.element.SnmpEthernetElementClient`) and
  real IEEE 802.1Q-tagged Ethernet-II frames on the wire
  (``AF_PACKET``/``SOCK_RAW``).  The in-repo JSON/TCP conformance
  peer is NOT this gate's peer and can never close it (the
  anti-faking ``BACKHAUL_PEER_KIND`` guard fires ``FORBIDDEN``
  before any probe when the operator explicitly tags the peer as an
  in-repo simulator).

* **Blocker 3 -- REAL WORK-012 session authority.**  The gate
  composes the REAL application-path session authority -- an actual
  ``SessionStore`` driven by a real ``RoutingEngine``/``PolicyEngine``
  ``RouteDecision`` over a ``TopologyGraph`` (the same composition
  the application path and the WORK-016 ``AdapterRuntime`` use),
  with the session transitioned REQUESTED -> AUTHORIZED ->
  ESTABLISHED -- and hands the manager a read-only
  :class:`~adapters.backhaul.contract.SessionReader` facade backed
  by that REAL store.  The fabricated universal secureable-reader
  of the first submission is gone: unknown session ids and
  non-bindable (TERMINATED) sessions are REJECTED, proven by the
  gate's own negative controls before the positive bind.

* **Secondary correction 4 -- the distinct DATA_PEER_UNREACHABLE
  status.**  A healthy real element (management plane verified over
  real SNMP) whose DATA plane cannot carry in this environment (no
  ``CAP_NET_RAW`` / no egress interface / no far-end L2 echo within
  the timeout) reports ``DATA_PEER_UNREACHABLE`` -- distinct from
  ``PEER_FAILED`` (a real management-plane operation failed) and
  never a fabricated PASS.

Gate behavior (acceptance semantics -- a SKIP is never a PASS):

* ``BACKHAUL_INTEROP`` unset -> the gate is OFF.  The selftest case
  reports a transparent SKIP disclosure.
* ``BACKHAUL_INTEROP=1`` + the real element's SNMP endpoint not
  configured / not answering a real SNMP GET -> ``UNREACHABLE`` (a
  transparent verification-environment blocker disclosure with the
  explicit capability matrix).
* ``BACKHAUL_INTEROP=1`` + element reachable + a real
  management-plane operation fails -> ``PEER_FAILED``.
* ``BACKHAUL_INTEROP=1`` + element reachable + management plane
  verified + the data plane cannot carry -> ``DATA_PEER_UNREACHABLE``
  (management-plane interop is still exercised and disclosed in the
  detail).
* ``BACKHAUL_INTEROP=1`` + full path + echoed bytes != sent bytes
  -> ``BYTE_MISMATCH``.
* ``BACKHAUL_INTEROP=1`` + the application's bytes traverse the
  full mediated path over the REAL element and wire and come back
  byte-identical -> ``PASSED`` (the outcome that closes the gate).

The suite drives the FULL boundary path -- nothing is stubbed::

    BackhaulManager -> SandboxedBackhaul -> ManagedBackhaulAdapter
        -> SnmpEthernetElementClient
        -> REAL SNMP-managed Ethernet switch (real SNMPv2c over UDP)
        -> REAL wire (802.1Q-tagged Ethernet-II frames via AF_PACKET)

with a REAL WORK-012 established session (the sacred,
access-independent ``session_id`` crossing EXACTLY as given --
LOCK-006; the W022 identity invariant holds on the real path too:
the adapter's link/bearer refs stay adapter-side opaque data, and
the element mints its OWN VLAN/port state -- the sacred session_id
never crosses to the element).
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Optional, Tuple

from .contract import SessionReader, SessionView
from .element import SnmpEthernetElementClient
from .interop_env_probe import (
    EnvProbeConfig,
    probe_backhaul_interop_capability,
)
from .managed import ManagedBackhaulAdapter
from .manager import BackhaulManager
from .model import BackhaulProfile, LinkDescriptor

__all__ = [
    "InteropConfig",
    "InteropOutcome",
    "gate_enabled",
    "real_session_authority",
    "run_backhaul_interop",
]

#: The deterministic instant the gate composes the real session
#: authority at (the application path's injected-now analog; no wall
#: clock anywhere in the mediated path).
_GATE_NOW = "2026-06-01T12:00:00Z"

#: States a REAL WORK-012 session may be bound from (the read-only
#: authority's secureable projection; mirrors the composition-root
#: wiring the WORK-016 AdapterRuntime and the family selftest use).
_SECUREABLE_STATES = ("ESTABLISHED", "DEGRADED")


def gate_enabled() -> bool:
    """True when the operator explicitly enabled the B1 real interop
    gate (``BACKHAUL_INTEROP=1``)."""
    return os.environ.get("BACKHAUL_INTEROP", "").strip() == "1"


# ---------------------------------------------------------------------------
# The REAL WORK-012 session authority (Blocker 3 correction)
# ---------------------------------------------------------------------------


class StoreSessionReader(SessionReader):
    """A read-only :class:`SessionReader` facade backed by a REAL
    WORK-012 ``SessionStore`` (the application-path composition the
    WORK-016 ``AdapterRuntime`` and the family SDK bridge use).

    ``lookup`` answers from REAL session state: ``None`` for an
    unknown session id; ``secureable`` only for the bindable active
    states (ESTABLISHED/DEGRADED).  It fabricates NOTHING -- a
    TERMINATED/FAILED/SUSPENDED/... session is not secureable, and
    an unknown id does not exist.
    """

    __slots__ = ("_store",)

    def __init__(self, store) -> None:
        self._store = store

    def lookup(self, session_id: str) -> Optional[SessionView]:
        session = self._store.get(session_id)
        if session is None:
            return None
        return SessionView(
            session_id=session.session_id,
            secureable=session.state in _SECUREABLE_STATES,
            initiator_node_id=session.binding.source_node_id,
            responder_node_id=session.binding.destination_node_id,
        )


@dataclass(frozen=True)
class SessionAuthority:
    """The real composed session authority handed to the gate's
    manager: the store, the read-only reader facade, one LIVE
    (ESTABLISHED) session id, and one TERMINATED session id (the
    negative-control identity)."""

    store: object
    reader: StoreSessionReader
    live_session_id: str
    terminated_session_id: str


def _build_real_session(store, now: str, variant: str) -> str:
    """Create ONE real WORK-012 session driven by a real routing
    decision over a real topology graph (the application-path
    composition; identical construction to the WORK-016/021
    composition roots).  ``variant`` varies the endpoint node material
    so distinct sessions derive DISTINCT content-based session ids
    (the WORK-012 identity is content-derived -- identical binding
    material is idempotently the SAME session)."""
    from policy.model import PolicyDecision
    from resources import ResourceStore
    from routing import LinkMetrics, RoutingContext, RoutingEngine
    from sessions import SessionState
    from topology import (
        ClaimType,
        SourceClass,
        TopologyClaim,
        TopologyGraph,
        make_link_subject,
    )

    node_a = "adcos:node:test.profile.v1:" + ("c" if variant == "live" else "e") * 64
    node_b = "adcos:node:test.profile.v1:" + ("d" if variant == "live" else "f") * 64

    def policy_decision(instant: str) -> PolicyDecision:
        probe = PolicyDecision(
            decision_id="0" * 64, effect="allow", code="allow",
            detail="interop-gate", matched_rule_ids=("r1",),
            policy_set_id="ps-1", policy_set_version=2,
            evaluation_instant=instant,
        )
        digest = hashlib.sha256(probe.canonical_bytes()).hexdigest()
        return PolicyDecision(
            decision_id=digest, effect="allow", code="allow",
            detail="interop-gate", matched_rule_ids=("r1",),
            policy_set_id="ps-1", policy_set_version=2,
            evaluation_instant=instant,
        )

    graph = TopologyGraph()
    graph.merge(TopologyClaim(
        subject=make_link_subject(node_a, node_b), reporter=node_a,
        claim_type=ClaimType.LINK_STATE, value="up",
        source_class=SourceClass.SELF_ADVERTISEMENT,
        issued_at=now, freshness_until="2026-12-31T23:59:59Z",
        sequence=1, provenance="",
    ))
    graph.merge(TopologyClaim(
        subject=node_b, reporter=node_a,
        claim_type=ClaimType.REACHABLE, value="true",
        source_class=SourceClass.DIRECT_OBSERVATION,
        issued_at=now, freshness_until="2026-12-31T23:59:59Z",
        sequence=1, provenance="",
    ))
    ctx = RoutingContext(
        source_node_id=node_a, destination_node_id=node_b,
        topology=graph, resources=ResourceStore(),
        evaluation_instant=now, policy_decision=policy_decision(now),
        link_metrics={
            make_link_subject(node_a, node_b): LinkMetrics(
                latency_ms=10, loss_basis_points=0, capacity_bps=1_000_000,
                energy_cost_millijoules=100,
                confidence_basis_points=10_000,
                observed_at=now, freshness_until="2026-12-31T23:59:59Z",
            ),
        },
    )
    result = RoutingEngine().evaluate(ctx)
    if result.decision is None or result.decision.selected is None:
        raise RuntimeError("real routing decision could not be composed")
    created = store.create(
        result.decision, policy_decision(now), source_node_id=node_a,
        destination_node_id=node_b, creation_instant=now,
    )
    if not created.ok or created.session is None:
        raise RuntimeError("real session creation failed")
    sid = created.session.session_id
    store.transition(sid, SessionState.AUTHORIZED, event_instant=now)
    store.transition(sid, SessionState.ESTABLISHED, event_instant=now)
    return sid


def real_session_authority(now: str = _GATE_NOW) -> SessionAuthority:
    """Compose the REAL WORK-012 session authority for the gate: a
    real ``SessionStore`` with one ESTABLISHED session (driven by a
    real routing/policy decision over a real topology graph) and one
    TERMINATED session (the non-bindable negative control), plus the
    read-only reader facade over that real store."""
    from sessions import SessionState, SessionStore

    store = SessionStore()
    live_sid = _build_real_session(store, now, variant="live")
    # A second real session, driven through its full lifecycle to
    # TERMINATED: the non-bindable negative-control identity (distinct
    # endpoint material -> a DISTINCT content-derived session id).
    terminated_sid = _build_real_session(store, now, variant="terminated")
    store.transition(
        terminated_sid, SessionState.TERMINATING, event_instant=now
    )
    store.transition(
        terminated_sid, SessionState.TERMINATED, event_instant=now
    )
    return SessionAuthority(
        store=store,
        reader=StoreSessionReader(store),
        live_session_id=live_sid,
        terminated_session_id=terminated_sid,
    )


# ---------------------------------------------------------------------------
# Gate configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InteropConfig:
    """Env-driven configuration for the real backhaul interop gate
    (the PRODUCTION target's real coordinates -- an SNMP-managed
    IEEE 802.1Q Ethernet switch)."""

    snmp_endpoint: str = ""  # host[:port] -- the switch's SNMP agent (UDP)
    community: str = "public"  # the SNMPv2c community value (credential MATERIAL)
    if_index: int = 1  # the switch port's IF-MIB ifIndex
    bridge_port: int = 1  # the IEEE 802.1Q bridge port number
    egress_if: str = ""  # the local egress interface for the L2 frames
    far_mac: str = ""  # the far-end frame destination MAC (aa:bb:..)
    timeout_s: float = 2.0

    @classmethod
    def from_env(cls) -> "InteropConfig":
        endpoint = os.environ.get("BACKHAUL_SNMP_ENDPOINT", "").strip()
        community = os.environ.get(
            "BACKHAUL_SNMP_COMMUNITY", "public"
        ).strip() or "public"
        if_index = _parse_int_env("BACKHAUL_IFINDEX", 1)
        bridge_port = _parse_int_env("BACKHAUL_BRIDGE_PORT", 1)
        egress_if = os.environ.get("BACKHAUL_EGRESS_IF", "").strip()
        far_mac = os.environ.get("BACKHAUL_L2_FAR_MAC", "").strip()
        timeout_s = 2.0
        raw_timeout = os.environ.get("BACKHAUL_PROBE_TIMEOUT_S", "").strip()
        if raw_timeout:
            try:
                timeout_s = float(raw_timeout)
            except ValueError:
                timeout_s = 2.0
        return cls(
            snmp_endpoint=endpoint,
            community=community,
            if_index=if_index,
            bridge_port=bridge_port,
            egress_if=egress_if,
            far_mac=far_mac,
            timeout_s=timeout_s,
        )


def _parse_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class InteropOutcome:
    """The gate outcome (PASSED only with real end-to-end bytes).

    ``status`` is one of:

    * ``"FORBIDDEN"`` -- the operator explicitly tagged the peer as
      an in-repo reference simulator (``BACKHAUL_PEER_KIND`` in
      ``reference|inrepo|conformance_server|simulator``); the
      anti-faking guard fired BEFORE any probe.  A hard
      non-acceptance outcome.
    * ``"UNREACHABLE"`` -- the gate is enabled but the real
      element's MANAGEMENT plane (SNMP endpoint) is not configured
      or not answering.  A verification-environment blocker, NOT a
      fake-pass; the detail carries the explicit
      environment-capability matrix.
    * ``"PEER_FAILED"`` -- the element's management plane was
      reachable but a REAL management-plane operation (link
      provisioning / bearer VLAN segmentation / bearer binding /
      teardown) failed, or a mediated boundary operation failed for
      a non-data-plane reason, or the gate's session-authority
      negative controls did not hold.
    * ``"DATA_PEER_UNREACHABLE"`` -- the element's management plane
      was verified over real SNMP, but the DATA plane cannot carry
      in this environment (no ``CAP_NET_RAW`` / no egress interface
      / no far-end L2 echo within the timeout).  Distinct from
      ``PEER_FAILED`` (secondary correction 4) and never a
      fabricated PASS.
    * ``"BYTE_MISMATCH"`` -- bytes traversed the real path but the
      far-end echo's returned payload != sent payload.
    * ``"PASSED"`` -- real element reachable + the application's
      bytes traversed the full BackhaulAppSession ->
      BackhaulManager -> SandboxedBackhaul -> ManagedBackhaulAdapter
      -> SNMP-managed switch -> real 802.1Q wire path and were
      received back byte-identical.  The outcome that closes the
      gate.
    """

    status: str
    detail: str


def _hostport(text: str, default_port: int) -> Optional[Tuple[str, int]]:
    """Parse ``host[:port]`` (None when malformed/empty)."""
    if not text:
        return None
    host, sep, port_text = text.rpartition(":")
    if not sep or not host:
        # A bare host (no port) is acceptable.
        return (text, default_port) if "/" not in text else None
    try:
        port = int(port_text)
    except ValueError:
        return None
    if not (0 < port < 65536):
        return None
    return (host, port)


def _parse_mac(text: str) -> Optional[bytes]:
    """Parse a ``aa:bb:cc:dd:ee:ff``-shaped MAC text (None when
    malformed/empty)."""
    if not text:
        return None
    try:
        raw = bytes.fromhex(text.replace(":", "").replace("-", ""))
    except ValueError:
        return None
    if len(raw) != 6:
        return None
    return raw


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------


def run_backhaul_interop(
    config: Optional[InteropConfig] = None,
) -> InteropOutcome:
    """Run the B1 real backhaul interop gate (the PRODUCTION path).

    ``PASSED`` requires REAL evidence end-to-end: the full mediated
    byte path against the REAL SNMP-managed Ethernet switch with the
    REAL WORK-012 session authority, the application's 802.1Q-framed
    bytes carried over the real wire, and the far-end echo received
    back byte-identical.  Nothing is stubbed, no in-repo simulator is
    substituted (the anti-faking ``BACKHAUL_PEER_KIND`` guard fires
    ``FORBIDDEN`` at the probe layer before this suite runs when the
    operator explicitly tags the peer as in-repo).
    """
    cfg = config if config is not None else InteropConfig.from_env()
    # Phase 0 (anti-faking hardening): independence guard + explicit
    # environment-capability matrix (hard management-plane checks,
    # data-plane capability checks, and non-blocking diagnostics --
    # the PR #23 review's secondary correction 3 separation).
    probe_report = probe_backhaul_interop_capability(
        EnvProbeConfig(
            snmp_endpoint=cfg.snmp_endpoint,
            community=cfg.community,
            egress_if=cfg.egress_if,
            far_mac=cfg.far_mac,
            timeout_s=cfg.timeout_s,
        )
    )
    if probe_report.forbidden_substitution is not None:
        return InteropOutcome(
            "FORBIDDEN",
            "%s -- the gate does NOT fall back to the in-repo "
            "conformance peer (Architect anti-faking rule); set "
            "BACKHAUL_PEER_KIND=real_element against a real, "
            "independent managed backhaul element to proceed"
            % probe_report.forbidden_substitution,
        )
    endpoint = _hostport(cfg.snmp_endpoint, 161)
    if endpoint is None:
        return InteropOutcome(
            "UNREACHABLE",
            "BACKHAUL_SNMP_ENDPOINT not configured (expected host[:port] "
            "of a REAL SNMP-managed Ethernet switch's agent, UDP/161 by "
            "default; the gate does not run against the in-repo "
            "conformance peer).  Environment-capability matrix:\n%s"
            % probe_report.summary(),
        )
    # Phase 1: management-plane reachability (the probe performed a
    # REAL SNMP GET sysUpTime round-trip; a hard gate prerequisite).
    if not probe_report.reachable:
        return InteropOutcome(
            "UNREACHABLE",
            "real SNMP-managed element not reachable at %s "
            "(management plane; the probe's real SNMP GET sysUpTime "
            "round-trip failed) -- verification-environment blocker "
            "(the gate does NOT fall back to the in-repo conformance "
            "peer; set BACKHAUL_SNMP_ENDPOINT to a reachable real "
            "element to close the gate).  Environment-capability "
            "matrix:\n%s" % (cfg.snmp_endpoint, probe_report.summary()),
        )
    # Phase 2: the full mediated path against the REAL element with
    # the REAL WORK-012 session authority.
    now = _GATE_NOW
    far_mac = _parse_mac(cfg.far_mac)
    if far_mac is None:
        return InteropOutcome(
            "DATA_PEER_UNREACHABLE",
            "BACKHAUL_L2_FAR_MAC not configured/invalid -- the real "
            "data-plane frames need the far-end destination MAC "
            "(the management plane is NOT probed further without a "
            "complete data-plane configuration).  "
            "Environment-capability matrix:\n%s" % probe_report.summary(),
        )
    authority = real_session_authority(now)
    adapter = ManagedBackhaulAdapter(
        element=SnmpEthernetElementClient(
            host=endpoint[0],
            port=endpoint[1],
            community=cfg.community,
            if_index=cfg.if_index,
            bridge_port=cfg.bridge_port,
            egress_if=cfg.egress_if,
            far_mac=far_mac,
            timeout_s=cfg.timeout_s,
            label="snmp-ethernet-real-interop",
        )
    )
    manager = BackhaulManager(
        integration_id="adcos:backhaul:interop",
        session_reader=authority.reader,
    )
    payload = b"adcospktpath-backhaul-interop-v1"
    # Teardown bookkeeping (always attempted; best-effort).
    state = {"link_ref": "", "alloc_ref": "", "bearer_ref": ""}

    def _teardown() -> None:
        if state["bearer_ref"]:
            manager.unbind_session(now=now, bearer_ref=state["bearer_ref"])
        if state["alloc_ref"]:
            manager.release(now=now, allocation_ref=state["alloc_ref"])
        if state["link_ref"]:
            manager.close_link(now=now, link_ref=state["link_ref"])
        manager.close()

    try:
        result = manager.register_implementation(
            adapter, label="managed-element-real-interop",
            make_default=True, now=now,
        )
        if not result.ok:
            return InteropOutcome(
                "PEER_FAILED",
                "register/health probe failed: %s" % result.detail,
            )
        prov = manager.provision_link(
            now=now,
            descriptor=LinkDescriptor(
                name="interop-link",
                profile=BackhaulProfile.ETHERNET,
                capacity_bps=1_000_000_000,
                max_bearers=4,
                endpoint_labels=("backhaul-sdk-endpoint",),
            ),
            credential_slot_name="backhaul-technology-credentials",
        )
        if not prov.ok:
            return InteropOutcome(
                "PEER_FAILED",
                "real element link_up (SNMP ifAdminStatus/ifOperStatus) "
                "failed: %s" % prov.detail,
            )
        state["link_ref"] = prov.value.link_ref
        alloc = manager.allocate(
            now=now,
            link_ref=prov.value.link_ref,
            kind="backhaul",
            quantity_base=10_000_000,
            purpose="interop-reservation",
        )
        if not alloc.ok:
            return InteropOutcome(
                "PEER_FAILED",
                "capacity allocation (FAMILY-NATIVE WORK-008 ledger "
                "admission on this target -- the SNMP-managed 802.1Q "
                "switch exposes no bandwidth-reservation MIB object; "
                "bounded by the element-reported ifSpeed) failed: %s"
                % alloc.detail,
            )
        state["alloc_ref"] = alloc.value.allocation_ref
        # ---- session-authority negative controls (Blocker 3) -------
        # The gate's REAL read-only reader must reject an UNKNOWN
        # session id and a TERMINATED session BEFORE any external
        # operation (the transactional validate phase checks session
        # authority first; no element state may move for them).
        for label, bad_sid in (
            ("unknown session id", "sha256:" + "e" * 64),
            ("TERMINATED session", authority.terminated_session_id),
        ):
            rejected = manager.bind_session(
                now=now, session_id=bad_sid,
                link_ref=prov.value.link_ref,
                endpoint_label="backhaul-sdk-endpoint",
            )
            if rejected.ok:
                return InteropOutcome(
                    "PEER_FAILED",
                    "session-authority negative control FAILED: the gate "
                    "accepted a bind for %s -- the authority would be "
                    "fabricated (Blocker 3 regression)" % label,
                )
        # ---- the positive bind (the REAL established session) ------
        bound = manager.bind_session(
            now=now,
            session_id=authority.live_session_id,
            link_ref=prov.value.link_ref,
            endpoint_label="backhaul-sdk-endpoint",
        )
        if not bound.ok:
            return InteropOutcome(
                "PEER_FAILED",
                "real element BIND (SNMP bearer VLAN segmentation: "
                "dot1qVlanStaticRowStatus createAndGo + egress "
                "PortList) failed: %s" % bound.detail,
            )
        state["bearer_ref"] = bound.value.bearer_ref
        # ---- the data-plane phase -----------------------------------
        if not probe_report.data_plane_ready:
            # The management plane IS verified (real SNMP exchanges
            # above); the data plane cannot carry HERE.  Tear down
            # cleanly over the real management plane and report the
            # DISTINCT status (secondary correction 4).
            _teardown()
            return InteropOutcome(
                "DATA_PEER_UNREACHABLE",
                "real SNMP management-plane interop verified "
                "(ifAdminStatus up + ifOperStatus confirm + real "
                "ifSpeed capacity read + bearer VLAN segmentation "
                "(dot1qVlanStaticRowStatus createAndGo + egress "
                "PortList), all over real SNMPv2c/UDP; capacity "
                "allocation is family-native WORK-008 ledger admission "
                "on this target), but the DATA plane cannot carry in "
                "this environment -- never a fabricated PASS.  "
                "Environment-capability matrix:\n%s"
                % probe_report.summary(),
            )
        app = manager.app_session(
            now=now, session_id=authority.live_session_id
        )
        if not app.ok:
            return InteropOutcome(
                "PEER_FAILED",
                "app_session failed: %s" % app.detail,
            )
        session = app.value
        try:
            session.connect("backhaul-interop")
            if session.send(payload) != len(payload):
                return InteropOutcome(
                    "PEER_FAILED", "send returned wrong length"
                )
            echoed = b""
            while len(echoed) < len(payload):
                chunk = session.recv()
                if not chunk:
                    break
                echoed += chunk
        except Exception as exc:  # noqa: BLE001 -- data-plane isolation
            _teardown()
            return InteropOutcome(
                "DATA_PEER_UNREACHABLE",
                "the real data plane failed to carry the application's "
                "bytes (%s isolated at the gate boundary; the management "
                "plane interop above remains real evidence)"
                % exc.__class__.__name__,
            )
        finally:
            try:
                session.close()
            except Exception:  # noqa: BLE001
                pass
        if not echoed:
            _teardown()
            return InteropOutcome(
                "DATA_PEER_UNREACHABLE",
                "no far-end L2 echo within the timeout -- the wire "
                "carried the frames but no far-end responder answered "
                "(configure the far-end echo responder per the runbook); "
                "never a fabricated PASS",
            )
        if echoed != payload:
            _teardown()  # a mismatched echo still restores the element
            return InteropOutcome(
                "BYTE_MISMATCH",
                "real wire data path returned %r (expected %r)"
                % (echoed[:64], payload[:64]),
            )
        _teardown()
        return InteropOutcome(
            "PASSED",
            "real SNMP-managed Ethernet-switch interop: real SNMPv2c "
            "management plane (ifAdminStatus/ifOperStatus link_up + "
            "real ifSpeed capacity read + bearer VLAN segmentation "
            "(dot1qVlanStaticRowStatus createAndGo at bind + egress "
            "PortList); capacity allocation family-native per the "
            "PR #23 second-review Blocker 2 rule) + %d payload bytes "
            "carried end-to-end as 802.1Q-tagged Ethernet-II frames "
            "(outer TPID 0x8100, inner EtherType 0x88B5) on the real "
            "wire and received back byte-identical through the "
            "standard session facade with the REAL WORK-012 session "
            "authority (payload=%r)" % (len(payload), payload),
        )
    except Exception as exc:  # noqa: BLE001 -- gate-level isolation
        try:
            _teardown()
        except Exception:  # noqa: BLE001
            pass
        return InteropOutcome(
            "PEER_FAILED",
            "gate raised %s (isolated; no acceptance)"
            % exc.__class__.__name__,
        )
