"""ADCOS mesh/relay adapter input validators (WORK-023).

Pure, stdlib-only validators for the mesh/relay domain value types.
No vendor SDK, no relay-firmware API, no radio/PHY state machine, no
cryptographic material.  The validators check SHAPES only (generic
mesh relay, 3GPP IAB/sidelink relay reference shapes as DATA); they
never decode, decrypt, or store credentials (LOCK-023: credential
slot NAMES only, never material).

Standards leverage (LOCK-018, mirroring the W017/W018/W019/W021/W022
discipline): the validators use the Python standard library ``re``
module for shape checking -- the stdlib is a standard implementation,
not a reinvention.  3GPP TS 38.300 (IAB) and TS 38.174/23.303
(sidelink relay) reference shapes appear as DATA with citations in
docstrings; no invented mesh/crypto primitive exists in this module.

The W023 identity invariant is enforced here
(:func:`assert_ref_session_separation`):

    ADCOS session_id != mesh link identity != route identity (the
    WORK-011 path fingerprint, consumed as DATA) != bearer identity !=
    bundle identity != allocation identity != external relay
    identifier

The technology refs (``mesh:link:<hex>`` / ``mesh:bearer:<hex>`` /
``mesh:bundle:<hex>`` / ``mesh:alloc:<hex>``) are OPAQUE handles
minted over canonical content; the underlying radio-link, relay-node
firmware, IAB donor/child, and sidelink-group identity material is
NEVER modeled (adapter-side opaque).

NOTE (selftest audit): this module is the enforcement-vocabulary file
-- its forbidden-token list exists to REJECT secret-like text.  The
WORK-023 selftest's credential scan excludes this file from its own
scan (the tokens appear here as rejection vocabulary, never as data),
mirroring how the WORK-019/021/022 selftests treat their validators.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

from .errors import MeshError, MeshReasonCode

#: Opaque technology-ref grammar (WORK-023): ``mesh:<kind>:<32
#: lowercase hex>``, kind in {link, bearer, bundle, alloc}.  The hex is
#: the leading 128 bits of a SHA-256 digest over canonical content
#: (mirrors the fivegc/wifi/backhaul ref convention).  Structurally
#: disjoint from the WORK-012 session_id (``sha256:<64 hex>``), the
#: WORK-011 path fingerprint (``sha256:<64 hex>``), and the WORK-004
#: NodeID (``adcos:node:...``) by construction.
_OPAQUE_REF_KINDS: Tuple[str, ...] = ("link", "bearer", "bundle", "alloc")
_OPAQUE_REF_PATTERN = re.compile(
    r"^mesh:(link|bearer|bundle|alloc):[0-9a-f]{32}$"
)

#: WORK-011 path-reference grammar (the ROUTE identity, consumed as
#: DATA).  A routing path id is a content-derived ``sha256:<64 hex>``
#: fingerprint (WORK-011 ``routing.model.derive_path_id``); the mesh
#: family CONSUMES it as the route's existing path reference and never
#: re-scores or re-selects paths (no second routing authority).  The
#: WORK-023 route identity IS the ordinary path reference -- the
#: family deliberately mints NO parallel mesh-only route identity.
_PATH_REF_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")

#: WORK-004 NodeID grammar (consumed as opaque DATA).  The mesh family
#: never creates node identities; relay/endpoint node ids are
#: WORK-004 material carried as DATA across the seam.
_NODE_ID_PATTERN = re.compile(
    r"^adcos:node:((?:[a-z0-9][a-z0-9-]*\.)+[a-z0-9][a-z0-9-]*):([0-9a-f]{64})$"
)

#: Relay-link name (1..64 printable ASCII, no control characters).
_LINK_NAME_PATTERN = re.compile(r"^[\x21-\x7e][\x20-\x7e]{0,63}$")

#: Ordinary-Path hop id (the directed link id carried by a WORK-011
#: Path's ``hops`` tuple -- a topology link subject such as
#: ``link:<NodeID>:<NodeID>``, up to ~192 characters over full
#: WORK-004 NodeIDs).  1..512 printable ASCII, no control
#: characters; opaque DATA, never parsed.
_HOP_ID_PATTERN = re.compile(r"^[\x21-\x7e][\x20-\x7e]{0,511}$")

#: External relay identifier (the 3GPP IAB/sidelink integration seam).
#: 1..128 printable ASCII.  MUST NOT match any ADCOS identifier
#: grammar (NodeID / path fingerprint / family ref prefixes) so an
#: external identifier can never collapse onto a core identity axis --
#: external identifiers are DATA, never identity.
_EXTERNAL_ID_PATTERN = re.compile(r"^[\x21-\x7e][\x20-\x7e]{0,127}$")
_EXTERNAL_ID_FORBIDDEN_PREFIXES: Tuple[str, ...] = (
    "adcos:",
    "mesh:",
    "sha256:",
    "backhaul:",
    "wifi:",
    "fivegc:",
    "transport:",
)

#: Mesh/relay technology classification -- frozen vocabulary (registry
#: DATA, never core branching).  Generic mesh relay; 3GPP TS 38.300
#: integrated access and backhaul (IAB) relay; 3GPP TS 38.174/23.303
#: sidelink relay (the frozen ``access.3gpp.iab`` and
#: ``access.3gpp.sidelink`` registry identifiers classify the same
#: families in the access-profile registry -- the mesh family carries
#: the classification as DATA and never imports registry semantics).
_TECHNOLOGY_VALUES: Tuple[str, ...] = ("mesh", "iab", "sidelink")

#: LOCK-023 -- credential-like text rejection vocabulary.  The token
#: list covers relay/mesh management credentials (management-plane
#: community strings and shared secrets, relay-node admin passphrases,
#: sidelink protection keys / PC5 K keys, IAB donor authentication
#: material).  A string carrying any of these fragments is rejected so
#: an implementation cannot smuggle secret material through names,
#: labels, or refs.  Matching runs against the lowered text AND a
#: separator-normalized form (hyphen/underscore/dot/space collapsed to
#: ``-``), so both ``shared_secret`` and ``shared-secret`` spellings
#: are caught.
_CREDENTIAL_LIKE_FORBIDDEN: Tuple[str, ...] = (
    "private_key", "secret_key", "password", "passphrase", "token",
    "api_key", "shared_secret", "community_string", "psk",
    "pre_shared_key", "preshared", "sim_pin", "session_key",
    "sidelink_key", "pc5_key", "protection_key", "relay_password",
    "donor_credential", "snmp_community", "mgmt_secret",
)

_SEPARATOR_RUN = re.compile(r"[-_.\s]+")

#: RFC 3339 UTC instant shape (WORK-003 grammar, shape check only).
_INSTANT_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$"
)


def _normalized(text: str) -> str:
    return _SEPARATOR_RUN.sub("-", text.lower())


def validate_opaque_ref(value: str, expected_kind: Optional[str] = None) -> str:
    """Validate an opaque mesh/relay technology ref.

    Grammar: ``mesh:(link|bearer|bundle|alloc):[0-9a-f]{32}`` (hex
    lowercase, 32 digits).  When ``expected_kind`` is given, the ref's
    kind segment must match it (a link view must carry a ``link`` ref,
    a binding a ``bearer`` ref, a bundle a ``bundle`` ref, an
    allocation an ``alloc`` ref).  Raises :class:`MeshError` for any
    other shape.  The ref is an OPAQUE handle: the underlying
    radio-link, relay-node, IAB donor/child, or sidelink-group
    identity material is NEVER carried in it.
    """
    if not isinstance(value, str) or not value:
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "opaque ref must be a non-empty string",
        )
    match = _OPAQUE_REF_PATTERN.fullmatch(value)
    if match is None:
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "opaque ref must match "
            "mesh:(link|bearer|bundle|alloc):<32 lowercase hex>",
        )
    if expected_kind is not None:
        if expected_kind not in _OPAQUE_REF_KINDS:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "expected_kind must be one of %s"
                % (list(_OPAQUE_REF_KINDS),),
            )
        if match.group(1) != expected_kind:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "opaque ref %s must be of kind %r" % (value, expected_kind),
            )
    return value


def validate_path_ref(value: str) -> str:
    """Validate a WORK-011 path reference (the ROUTE identity, opaque
    DATA).

    Grammar: ``sha256:<64 lowercase hex>`` -- the WORK-011
    content-derived path fingerprint
    (``routing.model.derive_path_id``).  The mesh family CONSUMES the
    ordinary path reference as the route's identity (W023: "multi-hop
    paths are represented as ordinary Paths"; existing path references
    rather than a parallel mesh-only path identity model); it never
    re-scores or re-selects paths (no second routing authority -- the
    WORK-011 engine stays the single routing authority).
    """
    if not isinstance(value, str) or not value:
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "path_ref must be a non-empty string",
        )
    if not _PATH_REF_PATTERN.fullmatch(value):
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "path_ref must match sha256:<64 lowercase hex> (the WORK-011 "
            "content-derived path fingerprint, consumed as the ordinary "
            "route identity)",
        )
    return value


def validate_node_id(value: str) -> str:
    """Validate a WORK-004 NodeID (consumed as opaque DATA).

    Shape: ``adcos:node:<dotted.profile.id>:<64 lowercase hex>``.
    The mesh family never creates or derives node identities; relay
    and endpoint node ids are WORK-004 material carried as DATA (the
    same grammar check WORK-018/019/021/022 apply at their seams).
    """
    if not isinstance(value, str) or not value:
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "node id must be a non-empty string (a WORK-004 NodeID)",
        )
    if _NODE_ID_PATTERN.fullmatch(value) is None:
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "node id must match the WORK-004 NodeID grammar "
            "adcos:node:<dotted.profile.id>:<64 lowercase hex>",
        )
    return value


def validate_hop_id(value: str) -> str:
    """Validate an ordinary-Path hop id (opaque DATA).

    1..128 printable ASCII.  The hop id is the directed link id a
    WORK-011 ``Path`` carries in its ``hops`` tuple (e.g. a topology
    link subject); the mesh family matches it against provisioned
    relay links EXACTLY (string equality) and never parses, scores, or
    branches on its internal structure.
    """
    if not isinstance(value, str) or not value:
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "hop id must be a non-empty string (an ordinary Path hop)",
        )
    if not _HOP_ID_PATTERN.fullmatch(value):
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "hop id must be 1..512 printable ASCII characters "
            "(no control characters)",
        )
    return value


def validate_external_relay_id(value: str) -> str:
    """Validate an EXTERNAL relay identifier (the IAB/sidelink seam).

    The 3GPP IAB/sidelink integration seam carries EXTERNAL
    identifiers (an operator's IAB donor/child node names, sidelink
    group ids, relay service codes) as opaque DATA.  The identifier
    must NOT match any ADCOS identifier grammar (NodeID, path
    fingerprint, or any adapter-family ref prefix) so an external
    identifier can never collapse onto a core identity axis: external
    identifiers are DATA at the core boundary, never identity
    (LOCK-016/017; the W023 standard: external identifiers remain
    opaque DATA).
    """
    if not isinstance(value, str) or not value:
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "external relay id must be a non-empty string (opaque DATA "
            "on the IAB/sidelink integration seam)",
        )
    if not _EXTERNAL_ID_PATTERN.fullmatch(value):
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "external relay id must be 1..128 printable ASCII "
            "characters (no control characters)",
        )
    lowered = value.lower()
    for prefix in _EXTERNAL_ID_FORBIDDEN_PREFIXES:
        if lowered.startswith(prefix):
            raise MeshError(
                MeshReasonCode.ACCESS_SESSION_COLLAPSE,
                "external relay id %r must not match the ADCOS "
                "identifier grammar %r -- external identifiers are DATA "
                "at the core boundary, never identity"
                % (value[:60], prefix),
            )
    return value


def assert_ref_session_separation(mesh_ref: str, session_id: str) -> None:
    """Enforce the W023 identity invariant at the ref/session seam.

    A mesh/relay technology ref (link/bearer/bundle/allocation
    identity) must NEVER embed WORK-012 ``session_id`` material, and a
    ``session_id`` must NEVER embed a technology ref: session identity
    and mesh identity are distinct axes.  ``session_id`` is sacred and
    hop/relay/bundle-independent; a relay change, route change, or
    bundle re-establishment re-binds the SAME ``session_id`` to a NEW
    bearer/bundle ref; the boundary NEVER collapses them (the mesh
    analog of the WORK-019 R1, WORK-021, and WORK-022 separation
    mechanics).

    Raises :class:`MeshError` with reason
    ``MeshReasonCode.ACCESS_SESSION_COLLAPSE`` when either value
    embeds the other: full-string containment either way, the digest
    portion of a ``sha256:<hex>`` session id embedded in the ref, or
    the ref's hex tail embedded in the session digest (which catches
    truncated-digest smuggling such as a ref minted from the leading
    32 hex of a session id).  Fragments shorter than 16 hex digits are
    not flagged (a 64-bit collision cannot occur by accident between
    honest content-derived values).
    """
    if not isinstance(mesh_ref, str) or not mesh_ref:
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "mesh ref must be a non-empty string",
        )
    if not isinstance(session_id, str) or not session_id:
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "session_id must be a non-empty string",
        )
    session_digest = (
        session_id.split(":", 1)[1] if ":" in session_id else ""
    )
    ref_hex = (
        mesh_ref.rsplit(":", 1)[1] if ":" in mesh_ref else ""
    )
    ref_hex = (
        ref_hex if re.fullmatch(r"[0-9a-f]+", ref_hex or "") else ""
    )
    collapsed = (
        mesh_ref == session_id
        or mesh_ref in session_id
        or session_id in mesh_ref
        or (len(session_digest) >= 16 and session_digest in mesh_ref)
        or (len(ref_hex) >= 16 and ref_hex in session_digest)
    )
    if collapsed:
        raise MeshError(
            MeshReasonCode.ACCESS_SESSION_COLLAPSE,
            "mesh ref %r and session_id collapse onto each other "
            "(W023 identity invariant: session_id is sacred and "
            "hop/relay/bundle-independent; the mesh ref must stay "
            "distinct)" % mesh_ref[:80],
        )


def reject_credential_like_text(text: str, *, label: str = "text") -> None:
    """Reject text carrying secret-like material (LOCK-023).

    Mesh/relay credential material (management-plane community
    strings, relay-node admin credentials, sidelink protection keys,
    IAB donor authentication material) lives ONLY in the adapter's
    private credential store.  Any caller-supplied string that
    RESEMBLES secret material (contains a forbidden token such as
    ``psk``/``password``/``sidelink_key``) is rejected fail-closed so
    an implementation cannot smuggle a key through a name, label, or
    ref.
    """
    if not isinstance(text, str):
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "%s must be a string" % label,
        )
    lowered = text.lower()
    normalized = _normalized(text)
    for forbidden in _CREDENTIAL_LIKE_FORBIDDEN:
        if forbidden in lowered or _normalized(forbidden) in normalized:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "%s must not resemble secret material "
                "(LOCK-023; forbidden token: %s)" % (label, forbidden),
            )


def validate_credential_slot_name(name: str) -> str:
    """Validate a credential slot NAME (LOCK-023).

    A slot NAME carries NO material -- it is a label the adapter uses
    to look up its OWN private credential store (relay/mesh
    management credentials, sidelink protection key slots).  The
    boundary rejects names that LOOK like secret material so an
    implementation cannot smuggle a key through the slot name
    (mirrors the WORK-016/019/021/022 discipline).
    """
    if not isinstance(name, str) or not name:
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "credential_slot_name must be a non-empty string",
        )
    reject_credential_like_text(name, label="credential_slot_name")
    return name


def validate_link_name(value: str) -> str:
    """Validate a relay-link name (the provisionable link profile's
    name)."""
    if not isinstance(value, str) or not value:
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "link name must be a non-empty string",
        )
    if not _LINK_NAME_PATTERN.fullmatch(value):
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "link name must be 1..64 printable ASCII characters "
            "(no control characters)",
        )
    return value


def validate_technology(value: str) -> str:
    """Validate a mesh/relay technology classification (DATA).

    One of ``mesh`` / ``iab`` / ``sidelink``.  The classification is
    REGISTRY DATA classifying a relay link's technology family
    (generic mesh relay; 3GPP TS 38.300 IAB; 3GPP TS 38.174/23.303
    sidelink relay as citations); it never becomes core branching
    (the same contract path serves every technology).
    """
    if not isinstance(value, str) or not value:
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "technology must be a non-empty string",
        )
    if value not in _TECHNOLOGY_VALUES:
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "technology must be one of %s (mesh/relay technology "
            "classification DATA; generic mesh / 3GPP TS 38.300 IAB / "
            "3GPP TS 38.174 sidelink relay reference families)"
            % (list(_TECHNOLOGY_VALUES),),
        )
    return value


def validate_instant(value: str, *, label: str = "instant") -> str:
    """Validate a WORK-003 RFC 3339 UTC instant (shape check)."""
    if not isinstance(value, str) or not value:
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "%s must be a non-empty RFC 3339 UTC instant string" % label,
        )
    if not _INSTANT_PATTERN.fullmatch(value):
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "%s must match RFC 3339 UTC (YYYY-MM-DDTHH:MM:SS[.f]Z)"
            % label,
        )
    return value


def validate_queue_bytes(value: int) -> int:
    """Validate a queue-capacity / bundle-size quantity in integer
    BYTES.

    1..(1 TiB) expressed in the WORK-008 ``storage`` resource kind's
    integer BASE unit (bytes).  DATA only: the boundary does not
    schedule storage or enforce admission control beyond its own
    configured store-and-forward limits (a production relay node
    enforces its own buffer sizes behind the adapter boundary); the
    value maps into the WORK-008 canonical resource units and never
    creates a second accounting authority.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "queue byte quantity must be an integer (WORK-008 "
            "storage-kind base unit)",
        )
    if not (1 <= value <= 1_099_511_627_776):
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "queue byte quantity must be in [1, 2^40] bytes "
            "(integer base units)",
        )
    return value


def validate_bundle_count(value: int) -> int:
    """Validate a bundle-count bound.

    1..65535 -- a deterministic concurrent-bundle bound for the
    store-and-forward queue (a production relay node enforces its own
    queue-table sizes behind the seam; the bound is configuration
    DATA, never a second accounting authority).
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "bundle count must be an integer",
        )
    if not (1 <= value <= 65535):
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "bundle count must be in [1, 65535] "
            "(deterministic queue-table bound, DATA)",
        )
    return value


def validate_ttl_seconds(value: int) -> int:
    """Validate a store-and-forward TTL in integer seconds.

    1..2**31-1 -- the deterministic bundle lifetime window.  Expiry is
    evaluated against injected WORK-003 instants (enqueue instant +
    TTL); no wall clock exists anywhere in this layer.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "ttl_seconds must be an integer",
        )
    if not (1 <= value <= 2_147_483_647):
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "ttl_seconds must be in [1, 2^31-1] seconds "
            "(deterministic lifetime window)",
        )
    return value


def validate_hop_budget(value: int) -> int:
    """Validate a hop budget (the maximum hops a bundle may traverse).

    1..64 -- the same bound family as the WORK-011 routing engine's
    ``max_hops`` (1..64).  A bundle that exhausts its hop budget
    before reaching the logical destination is dropped as expired
    (fail closed; never a ghost delivery).
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "hop budget must be an integer",
        )
    if not (1 <= value <= 64):
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "hop budget must be in [1, 64] hops (mirrors the WORK-011 "
            "max_hops bound; exhaustion drops the bundle as expired)",
        )
    return value


__all__ = [
    "validate_opaque_ref",
    "validate_path_ref",
    "validate_node_id",
    "validate_hop_id",
    "validate_external_relay_id",
    "assert_ref_session_separation",
    "reject_credential_like_text",
    "validate_credential_slot_name",
    "validate_link_name",
    "validate_technology",
    "validate_instant",
    "validate_queue_bytes",
    "validate_bundle_count",
    "validate_ttl_seconds",
    "validate_hop_budget",
]
