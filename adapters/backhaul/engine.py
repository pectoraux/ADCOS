"""ADCOS backhaul reference engine (WORK-022): the deterministic
reference model.

:class:`ReferenceBackhaulEngine` is the in-repo deterministic
backhaul implementation -- honest NON-confidential: no real Ethernet
switch, no optical/microwave/satellite terminal, no modem, no vendor
SDK, no PHY (LOCK-016/017; the frozen work item keeps modem firmware
out of scope).  The technology profiles are standards families cited
as DATA (LOCK-018): Ethernet per IEEE 802.3-2018, fiber/optical
transport per ITU-T G.709, microwave radio-relay per ITU-R F-series,
satellite transport per ITU-R -- the engine implements none of their
PHY/management, only the technology-neutral link semantics.  It
models:

* profile-based link provisioning (Ethernet / fiber / microwave /
  satellite as registry DATA -- one code path, no per-technology
  branching);
* per-link capacity accounting in the WORK-008 canonical bps base
  units (fail closed on exhaustion, never silently dropping a
  reservation);
* per-link session-bearer accounting (fail closed at
  ``max_bearers``);
* one live bearer per session (an access change is a REPLACEMENT
  after release, never a duplication -- the W022 identity
  invariant);
* the deterministic data path (payload bytes echo byte-identically
  through the mediated egress_frame operation; the conformance peer
  carries the real bytes over a real socket);
* generic link observations (deterministic tx/rx counters in the
  WORK-016 link-metric vocabulary);
* honest availability ladders (a deactivated link degrades loudly
  and fails the data path CLOSED -- never a silent drop);
* honest capability ladder.

The reference engine charges the frozen module-level
:data:`~adapters.backhaul.sandbox.STEP_CHARGES` against the context
budget at each operation entry (the family's pinnable surface).

The WORK-008 resource vocabulary is REUSED BY REFERENCE (never
duplicated): ``allocate`` accepts exactly the two WORK-008 rate kinds
whose integer base unit is bps (``bandwidth`` and ``backhaul`` per
the WORK-008 unit registry) and accounts reservations against the
link's capacity in those same base units -- mapping DATA into the
canonical resource model, never a second accounting authority.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional, Tuple

from resources import ResourceKind

from .contract import BackhaulContext, BackhaulContract
from .errors import BackhaulError, BackhaulReasonCode
from .model import (
    AllocationState,
    BackhaulAllocation,
    BackhaulBinding,
    BackhaulLinkObservation,
    BackhaulProfile,
    BearerState,
    LinkDescriptor,
    LinkMetricName,
    LinkState,
    LinkView,
    derive_allocation_ref,
    derive_binding_id,
    derive_bearer_ref,
    derive_link_ref,
)
from .sandbox import STEP_CHARGES
from .session import BackhaulAppSession
from .validation import (
    reject_credential_like_text,
    validate_credential_slot_name,
    validate_endpoint_label,
    validate_link_name,
    validate_opaque_ref,
    validate_path_ref,
)

__all__ = ["ReferenceBackhaulEngine", "RATE_KINDS_BPS", "MAX_BEARERS_PER_SESSION"]


#: The WORK-008 resource kinds whose integer base unit is bps (the
#: unit registry: bandwidth and backhaul are rate kinds measured in
#: bps).  A link capacity reservation maps into exactly these kinds
#: -- REUSED BY REFERENCE from WORK-008 (no second registry, no
#: second accounting authority).  A caller asking to reserve, e.g.,
#: ``compute`` against a link's capacity fails closed (the reference
#: model honestly has no such link resource; a concrete adapter maps
#: its own technology resources behind the seam).
RATE_KINDS_BPS: Tuple[str, ...] = (
    ResourceKind.BANDWIDTH,
    ResourceKind.BACKHAUL,
)

#: Per-session live-bearer bound in the reference model.  A session
#: holds at most ONE live backhaul bearer at a time; a backhaul
#: change (Ethernet -> satellite, circuit re-homing) releases and
#: re-binds (the SAME sacred session_id gets a NEW bearer_ref) --
#: the W022 identity invariant (mirrors the wifi family's
#: one-live-association-per-session discipline).
MAX_BEARERS_PER_SESSION = 1

#: Deterministic bound on the requirements smuggling scan (fail
#: closed on absurdly deep/large caller payloads instead of scanning
#: unboundedly; a real policy engine lives behind the seam).
_REQUIREMENTS_SCAN_BOUND = 500

#: Hex alphabet for the digest-fragment smuggling guard (lowercase,
#: matching the ref grammar).
_HEX_FRAGMENT = re.compile(r"^[0-9a-f]+$")


def _is_hex_fragment(text: str) -> bool:
    return len(text) >= 16 and bool(_HEX_FRAGMENT.fullmatch(text))


class _LinkEntry:
    """Adapter-private per-link state (NEVER crosses the seam)."""

    __slots__ = (
        "link_view", "credential_slot_name", "active",
        "tx_bytes", "rx_bytes", "allocations", "bearers",
    )

    def __init__(self, link_view: LinkView, credential_slot_name: str) -> None:
        self.link_view = link_view
        self.credential_slot_name = credential_slot_name
        self.active = True
        self.tx_bytes = 0
        self.rx_bytes = 0
        # allocation_ref -> live reservation quantity (bps).
        self.allocations: Dict[str, int] = {}
        # bearer_ref -> session_id (live bearers on this link).
        self.bearers: Dict[str, str] = {}

    @property
    def reserved_bps(self) -> int:
        return sum(self.allocations.values())


class _AllocationEntry:
    __slots__ = ("allocation", "released")

    def __init__(self, allocation: BackhaulAllocation) -> None:
        self.allocation = allocation
        self.released = False


class _BindingEntry:
    __slots__ = ("binding", "state")

    def __init__(self, binding: BackhaulBinding) -> None:
        self.binding = binding
        self.state = BearerState.BOUND


class ReferenceBackhaulEngine(BackhaulContract):
    """The deterministic backhaul reference model.

    Implements the 11-operation :class:`~adapters.backhaul.contract.
    BackhaulContract` honestly with in-memory state: no real switch,
    no optical/microwave/satellite terminal, no modem, no vendor SDK,
    no PHY (LOCK-016/017).  All ids are content-derived (no
    randomness); all instants are injected; the step charges are the
    frozen module-level table.  A concrete backhaul path (a managed
    Ethernet switch, an optical transport terminal, a microwave
    radio, a satellite terminal) plugs in behind the SAME contract.
    """

    label = "reference-backhaul"

    def __init__(self) -> None:
        self._sequence = 0
        self._open = False
        self._links: Dict[str, _LinkEntry] = {}
        self._allocations: Dict[str, _AllocationEntry] = {}
        self._bindings: Dict[str, _BindingEntry] = {}

    # ------------------------------------------------------------------
    # Internal lookups
    # ------------------------------------------------------------------

    def _require_open(self) -> None:
        if not self._open:
            raise BackhaulError(
                BackhaulReasonCode.NOT_OPEN,
                "backhaul technology is not open",
            )

    def _require_link(self, link_ref: str) -> _LinkEntry:
        validate_opaque_ref(link_ref, "link")
        entry = self._links.get(link_ref)
        if entry is None:
            raise BackhaulError(
                BackhaulReasonCode.LINK_UNKNOWN,
                "link %s not found" % link_ref,
            )
        return entry

    def _require_active(self, link: _LinkEntry, *, operation: str) -> None:
        if not link.active:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "link %r is deactivated (%s fails closed -- the "
                "availability ladder degrades loudly, never silently)"
                % (link.link_view.name, operation),
            )

    def _live_binding_for_session(
        self, session_id: str
    ) -> Optional[_BindingEntry]:
        for entry in self._bindings.values():
            if (
                entry.binding.session_id == session_id
                and entry.state == BearerState.BOUND
            ):
                return entry
        return None

    def _live_bearer(self, bearer_ref: str) -> _BindingEntry:
        validate_opaque_ref(bearer_ref, "bearer")
        entry = self._bindings.get(bearer_ref)
        if entry is None or entry.state != BearerState.BOUND:
            raise BackhaulError(
                BackhaulReasonCode.BEARER_UNKNOWN,
                "bearer %s not found (already unbound?)" % bearer_ref,
            )
        return entry

    def _active_link_count(self) -> int:
        return sum(1 for entry in self._links.values() if entry.active)

    # ------------------------------------------------------------------
    # Identity-smuggling rejection (the W022 identity invariant)
    # ------------------------------------------------------------------

    @staticmethod
    def _reject_smuggled_text(
        text: str, session_id: str, *, label: str
    ) -> None:
        """Reject text that smuggles session identity or credential
        material (mirrors the WORK-019/021 engines)."""
        if not isinstance(text, str):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "%s must be a string" % label,
            )
        reject_credential_like_text(text, label=label)
        if not session_id:
            return
        lowered = text.lower()
        digest = (
            session_id.split(":", 1)[1]
            if ":" in session_id and _is_hex_fragment(
                session_id.split(":", 1)[1]
            )
            else ""
        )
        if session_id in text or session_id.lower() in lowered:
            raise BackhaulError(
                BackhaulReasonCode.ACCESS_SESSION_COLLAPSE,
                "%s must not embed the session_id (W022 identity "
                "invariant; LOCK-006)" % label,
            )
        if digest and digest in lowered:
            raise BackhaulError(
                BackhaulReasonCode.ACCESS_SESSION_COLLAPSE,
                "%s must not embed session-digest material (W022 "
                "identity invariant; LOCK-006)" % label,
            )
        # Truncated-digest smuggling (the a1/W021 fragment guard,
        # mirrored for arbitrary text): any >=16-hex-char fragment of
        # the text that appears inside the session digest is
        # session-authority material.  Shorter fragments are not
        # flagged (a 64-bit collision cannot occur by accident
        # between honest content-derived values).
        if len(digest) >= 16:
            for start in range(0, max(0, len(text) - 15)):
                fragment = text[start:start + 16]
                if _is_hex_fragment(fragment) and fragment in digest:
                    raise BackhaulError(
                        BackhaulReasonCode.ACCESS_SESSION_COLLAPSE,
                        "%s must not embed session-digest fragments "
                        "(W022 identity invariant; LOCK-006)" % label,
                    )

    def _reject_identity_smuggling(
        self,
        session_id: str,
        *,
        endpoint_label: str,
        path_ref: str,
        requirements: Optional[Mapping[str, Any]],
    ) -> None:
        """The bounded caller-payload scan (keys/values and the
        endpoint label must never re-identify the session or carry
        credential-like material)."""
        self._reject_smuggled_text(
            endpoint_label, session_id, label="endpoint_label"
        )
        if path_ref:
            validate_path_ref(path_ref)
        if requirements is None:
            return
        if not isinstance(requirements, Mapping):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "requirements must be a mapping or None",
            )
        scanned = 0
        stack: List[Any] = [requirements]
        while stack:
            node = stack.pop()
            scanned += 1
            if scanned > _REQUIREMENTS_SCAN_BOUND:
                raise BackhaulError(
                    BackhaulReasonCode.INVALID_INPUT,
                    "requirements exceed the deterministic smuggling-scan "
                    "bound (%d nodes)" % _REQUIREMENTS_SCAN_BOUND,
                )
            if isinstance(node, Mapping):
                for key, value in node.items():
                    if not isinstance(key, str) or not key:
                        raise BackhaulError(
                            BackhaulReasonCode.INVALID_INPUT,
                            "requirement keys must be non-empty strings",
                        )
                    ReferenceBackhaulEngine._reject_smuggled_text(
                        key, session_id, label="requirements key"
                    )
                    stack.append(value)
            elif isinstance(node, (list, tuple)):
                stack.extend(node)
            elif isinstance(node, str):
                ReferenceBackhaulEngine._reject_smuggled_text(
                    node, session_id, label="requirements value"
                )
            elif (
                isinstance(node, bool)
                or isinstance(node, int)
                or node is None
            ):
                continue
            else:
                raise BackhaulError(
                    BackhaulReasonCode.INVALID_INPUT,
                    "requirements values must be strings, integers, "
                    "booleans, None, or nested mappings/lists",
                )

    # ------------------------------------------------------------------
    # Contract operations
    # ------------------------------------------------------------------

    def open(self, context: BackhaulContext) -> None:
        context.charge(STEP_CHARGES["open"])
        if self._open:
            raise BackhaulError(
                BackhaulReasonCode.ALREADY_OPEN, "engine already open"
            )
        self._open = True

    def provision_link(
        self,
        context: BackhaulContext,
        *,
        descriptor: LinkDescriptor,
        credential_slot_name: str,
    ) -> LinkView:
        context.charge(STEP_CHARGES["provision_link"])
        self._require_open()
        if not isinstance(descriptor, LinkDescriptor):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "descriptor must be a LinkDescriptor "
                "(technology-neutral profile shape)",
            )
        # LOCK-023: the slot NAME only (credential material stays in
        # the adapter's private store); credential-LIKE names are
        # rejected so a key cannot be smuggled through the slot name.
        validate_credential_slot_name(credential_slot_name)
        reject_credential_like_text(descriptor.name, label="link name")
        for label in descriptor.endpoint_labels:
            validate_endpoint_label(label)
        link_ref = derive_link_ref(descriptor)
        if link_ref in self._links:
            raise BackhaulError(
                BackhaulReasonCode.BINDING_EXISTS,
                "link profile already provisioned (identical canonical "
                "content)",
            )
        link_view = LinkView(
            link_ref=link_ref,
            name=descriptor.name,
            profile=descriptor.profile,
            capacity_bps=descriptor.capacity_bps,
            max_bearers=descriptor.max_bearers,
            endpoint_labels=descriptor.endpoint_labels,
            state=LinkState.ACTIVE,
        )
        self._links[link_ref] = _LinkEntry(link_view, credential_slot_name)
        return link_view

    def allocate(
        self,
        context: BackhaulContext,
        *,
        link_ref: str,
        kind: str,
        quantity_base: int,
        purpose: str,
    ) -> BackhaulAllocation:
        context.charge(STEP_CHARGES["allocate"])
        self._require_open()
        link = self._require_link(link_ref)
        if not isinstance(kind, str) or kind not in RATE_KINDS_BPS:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "kind must be one of the WORK-008 bps-based rate kinds "
                "%s (canonical resource units reused by reference; the "
                "link capacity maps into exactly these kinds)"
                % (list(RATE_KINDS_BPS),),
            )
        if isinstance(quantity_base, bool) or not isinstance(
            quantity_base, int
        ):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "quantity_base must be an integer (WORK-008 base units)",
            )
        if quantity_base <= 0:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "quantity_base must be > 0 (a reservation of nothing is "
                "not a reservation)",
            )
        if not isinstance(purpose, str) or not purpose:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "purpose must be a non-empty string",
            )
        self._require_active(link, operation="allocate")
        # Resource accounting in the WORK-008 canonical bps base
        # units (fail closed, never silently drop).
        reserved = link.reserved_bps
        if reserved + quantity_base > link.link_view.capacity_bps:
            raise BackhaulError(
                BackhaulReasonCode.CAPACITY_EXHAUSTED,
                "link %r capacity exhausted (%d + %d > %d bps; the "
                "capacity bound is mapping DATA into the WORK-008 "
                "canonical units -- a production element enforces its "
                "own admission behind the seam)"
                % (
                    link.link_view.name, reserved, quantity_base,
                    link.link_view.capacity_bps,
                ),
            )
        self._sequence += 1
        allocation_ref = derive_allocation_ref(
            link_ref, kind, quantity_base, purpose, self._sequence
        )
        allocation = BackhaulAllocation(
            allocation_ref=allocation_ref,
            link_ref=link_ref,
            kind=kind,
            quantity_base=quantity_base,
            purpose=purpose,
            state=AllocationState.RESERVED,
        )
        if allocation_ref in self._allocations:
            raise BackhaulError(
                BackhaulReasonCode.BINDING_EXISTS,
                "allocation already exists",
            )
        self._allocations[allocation_ref] = _AllocationEntry(allocation)
        link.allocations[allocation_ref] = quantity_base
        return allocation

    def release(
        self,
        context: BackhaulContext,
        *,
        allocation_ref: str,
    ) -> None:
        context.charge(STEP_CHARGES["release"])
        validate_opaque_ref(allocation_ref, "alloc")
        entry = self._allocations.get(allocation_ref)
        if entry is None or entry.released:
            raise BackhaulError(
                BackhaulReasonCode.ALLOCATION_UNKNOWN,
                "allocation %s not found (already released?)"
                % allocation_ref,
            )
        link = self._links.get(entry.allocation.link_ref)
        if link is not None:
            link.allocations.pop(allocation_ref, None)
        entry.released = True

    def bind_session(
        self,
        context: BackhaulContext,
        *,
        session_id: str,
        link_ref: str,
        endpoint_label: str,
        path_ref: str = "",
        requirements: Optional[Mapping[str, Any]] = None,
    ) -> BackhaulBinding:
        context.charge(STEP_CHARGES["bind_session"])
        self._require_open()
        if not isinstance(session_id, str) or not session_id:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "session_id must be a non-empty string",
            )
        # Verify the WORK-012 session exists AND is secureable (the
        # boundary NEVER binds a nonexistent or non-secureable
        # session; mirrors the WORK-018/019/021 discipline).  The
        # reader is the secret-free SessionReader facade.
        session_view = context.session_reader().lookup(session_id)
        if session_view is None:
            raise BackhaulError(
                BackhaulReasonCode.SESSION_NOT_SECUREABLE,
                "session %s does not exist (read-only WORK-012 lookup)"
                % session_id,
            )
        if not session_view.secureable:
            raise BackhaulError(
                BackhaulReasonCode.SESSION_NOT_SECUREABLE,
                "session %s is not secureable" % session_id,
            )
        validate_endpoint_label(endpoint_label)
        link = self._require_link(link_ref)
        if endpoint_label not in link.link_view.endpoint_labels:
            raise BackhaulError(
                BackhaulReasonCode.ENDPOINT_UNKNOWN,
                "endpoint %r is not among the link's endpoints %s"
                % (endpoint_label, list(link.link_view.endpoint_labels)),
            )
        self._reject_identity_smuggling(
            session_id,
            endpoint_label=endpoint_label,
            path_ref=path_ref,
            requirements=requirements,
        )
        self._require_active(link, operation="bind_session")
        # Strict same-state transition: a session holds at most ONE
        # live bearer in the reference model; a backhaul change
        # releases/rebinds (the SAME session_id gets a NEW
        # bearer_ref).
        if self._live_binding_for_session(session_id) is not None:
            raise BackhaulError(
                BackhaulReasonCode.BINDING_EXISTS,
                "session already has a live bearer (unbind it before "
                "rebinding; a backhaul change re-binds the SAME "
                "session_id to a NEW bearer_ref)",
            )
        # Resource accounting (fail closed, never silently drop).
        live_bearers = len(link.bearers)
        if live_bearers >= link.link_view.max_bearers:
            raise BackhaulError(
                BackhaulReasonCode.CAPACITY_EXHAUSTED,
                "link %r bearer capacity exhausted (%d/%d)"
                % (
                    link.link_view.name, live_bearers,
                    link.link_view.max_bearers,
                ),
            )
        # Content-derive the backhaul BEARER identity (the W022
        # identity invariant: distinct from the sacred session_id by
        # construction -- the session_id is hash INPUT, never ref
        # text).
        self._sequence += 1
        bearer_ref = derive_bearer_ref(
            session_id, link_ref, endpoint_label, self._sequence
        )
        binding_id = derive_binding_id(session_id, bearer_ref)
        binding = BackhaulBinding(
            session_id=session_id,
            bearer_ref=bearer_ref,
            binding_id=binding_id,
            link_ref=link_ref,
            endpoint_label=endpoint_label,
            profile=link.link_view.profile,
            path_ref=path_ref,
            closed=False,
        )
        if bearer_ref in self._bindings:
            raise BackhaulError(
                BackhaulReasonCode.BINDING_EXISTS,
                "bearer already exists for session",
            )
        self._bindings[bearer_ref] = _BindingEntry(binding)
        link.bearers[bearer_ref] = session_id
        return binding

    def unbind_session(
        self,
        context: BackhaulContext,
        *,
        bearer_ref: str,
    ) -> None:
        context.charge(STEP_CHARGES["unbind_session"])
        entry = self._live_bearer(bearer_ref)
        entry.state = BearerState.RELEASED
        link = self._links.get(entry.binding.link_ref)
        if link is not None:
            link.bearers.pop(bearer_ref, None)

    def observe_link(
        self,
        context: BackhaulContext,
        *,
        link_ref: str,
    ) -> BackhaulLinkObservation:
        context.charge(STEP_CHARGES["observe_link"])
        self._require_open()
        link = self._require_link(link_ref)
        return BackhaulLinkObservation(
            samples=(
                (LinkMetricName.LINK_UP, 1 if link.active else 0),
                (LinkMetricName.RX_BYTES_TOTAL, link.rx_bytes),
                (LinkMetricName.TX_BYTES_TOTAL, link.tx_bytes),
                (LinkMetricName.RX_ERROR_COUNT, 0),
                (LinkMetricName.TX_ERROR_COUNT, 0),
                (LinkMetricName.RETRANSMIT_COUNT, 0),
            )
        )

    def egress_frame(
        self,
        context: BackhaulContext,
        *,
        bearer_ref: str,
        payload: bytes,
    ) -> bytes:
        context.charge(STEP_CHARGES["egress_frame"])
        self._require_open()
        if not isinstance(payload, (bytes, bytearray)):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT, "payload must be bytes"
            )
        entry = self._live_bearer(bearer_ref)
        link = self._require_link(entry.binding.link_ref)
        # Availability semantics: a deactivated link fails the data
        # path CLOSED (BACKHAUL_UNAVAILABLE) -- the backhaul path
        # degrades loudly and never drops frames silently.
        self._require_active(link, operation="egress_frame")
        # Deterministic measured counters (generic WORK-016 vocabulary).
        link.tx_bytes += len(payload)
        link.rx_bytes += len(payload)
        # In-memory model: return the payload bytes byte-identical
        # (the deterministic data path; the conformance peer carries
        # the real bytes over a real backhaul path).
        return bytes(payload)

    def app_session(
        self,
        context: BackhaulContext,
        *,
        session_id: str,
    ) -> Any:
        context.charge(STEP_CHARGES["app_session"])
        entry = self._live_binding_for_session(session_id)
        if entry is None:
            raise BackhaulError(
                BackhaulReasonCode.BINDING_UNKNOWN,
                "no live bearer for session %s" % session_id,
            )
        # The family's application-session facade
        # (adapters.backhaul.session).  The MANAGER binds itself + the
        # injected instant later (the documented _bind_manager /
        # _set_now internal protocol), so the facade's standard send()
        # routes through the binding's OWNING sandbox; the facade the
        # implementation returns is the AUTHORITATIVE application
        # object (the manager returns it verbatim -- it never
        # constructs a second facade).  Mirrors the accepted
        # WORK-019/021 reference engines' facade construction.
        return BackhaulAppSession(
            destination=entry.binding.endpoint_label,
            bearer_ref=entry.binding.bearer_ref,
        )

    def health(self) -> str:
        # Availability aggregate over the link activation states
        # (mirrors the fivegc/wifi engine ladders):
        #   NOT_RUNNING  -- the backhaul path is not open
        #   HEALTHY      -- at least one ACTIVE link can carry
        #   DEGRADED     -- provisioned but nothing active
        #   FAILED       -- open with an empty link store: the
        #                   backhaul path is down (nothing can carry)
        if not self._open:
            return "NOT_RUNNING"
        if self._active_link_count() >= 1:
            return "HEALTHY"
        if self._links:
            return "DEGRADED"
        return "FAILED"

    def close(
        self,
        context: BackhaulContext,
        *,
        link_ref: str,
    ) -> None:
        context.charge(STEP_CHARGES["close"])
        link = self._require_link(link_ref)
        # Fails closed while outstanding: live bearers and live
        # reservations are never silently discarded -- the caller
        # releases them first.
        live_bearers = len(link.bearers)
        if live_bearers:
            raise BackhaulError(
                BackhaulReasonCode.ILLEGAL_STATE,
                "link has %d outstanding bearer(s); unbind them before "
                "closing (close fails closed while bearers are "
                "outstanding)" % live_bearers,
            )
        live_allocations = len(link.allocations)
        if live_allocations:
            raise BackhaulError(
                BackhaulReasonCode.ILLEGAL_STATE,
                "link has %d outstanding allocation(s); release them "
                "before closing (close fails closed while allocations "
                "are outstanding)" % live_allocations,
            )
        del self._links[link_ref]

    # ------------------------------------------------------------------
    # Informational surfaces (NOT contract operations)
    # ------------------------------------------------------------------

    def capabilities(self) -> Tuple[str, ...]:
        """The honest capability ladder (informational; LOCK-017:
        reported, never authoritative).

        Mirrors the WORK-016 ``GenericAdapter.capabilities()`` ladder
        shape with honest backhaul specifics: ``()`` while the
        backhaul path is down; the boundary capabilities when open;
        the data-path capability additionally requires at least one
        ACTIVE link (a fully deactivated backhaul path honestly
        cannot carry frames).
        """
        if not self._open:
            return ()
        caps: Tuple[str, ...] = (
            "capability.profile.backhaul.link",
            "capability.profile.backhaul.capacity",
            "capability.profile.backhaul.bearer",
        )
        if self._active_link_count() >= 1:
            caps = caps + ("capability.profile.backhaul.data-path",)
        return caps

    # ------------------------------------------------------------------
    # Reference-model availability controls (NOT contract operations)
    # ------------------------------------------------------------------

    def set_link_state(self, link_ref: str, *, active: bool) -> None:
        """Reference-model availability control: move a provisioned
        link between active and inactive (the deterministic stand-in
        for an operator availability transition such as a fiber cut
        or a rain-faded microwave path; NOT a contract operation).

        Strict same-state transition: activating an ACTIVE link (or
        deactivating an INACTIVE one) is an ILLEGAL_STATE rejection.
        Deactivating never kills live state silently -- existing
        bearers/allocations stay (their egress fails CLOSED).
        """
        entry = self._require_link(link_ref)
        if entry.active == active:
            raise BackhaulError(
                BackhaulReasonCode.ILLEGAL_STATE,
                "link is already %s" % (
                    "active" if active else "inactive"
                ),
            )
        entry.active = active
