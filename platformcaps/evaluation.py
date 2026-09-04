"""WORK-050 deterministic compatibility evaluation (W050.2).

The EVALUATION layer of the versioned platform capability
registry: given a registry version, a platform id, a
participation role, a sharing-mode class, and (optionally) an
explicit isolation requirement, compose — purely from the
DECLARED rows — the declared compatibility:

    (profile x role x sharing mode x isolation requirement)
        ->  supported | restricted | unsupported | unknown
            + typed findings (the frozen evaluation vocabulary)

The composition lattice (frozen, deterministic, no fallback and
no downgrade anywhere): the composed state is the WEAKEST
declared component state among the role declaration, the
sharing-mode declaration, and every required isolation
primitive (the mode's declared requirements UNION the caller's
explicit requirement):

    unsupported  — a declared hard negative anywhere makes the
                   composition a declared no (the known no is
                   reported, never concealed behind an unknown)
    unknown      — else, any undeclared or unknown component
                   makes the conclusion fail closed (the DEFAULT;
                   never supported)
    restricted   — else, any restricted component constrains the
                   composition, carrying the sorted+deduplicated
                   union of the restricted components' declared
                   restriction sets (only a restricted outcome
                   carries restrictions — the W048/W049 coupling
                   preserved exactly)
    supported    — else, every component is declared supported

Fail-closed rules (frozen):

1. An UNREGISTERED platform evaluates to ``unknown`` — the
   DEFAULT, never ``supported``.  No platform label, OS name,
   socket capability, or tethering-API presence is ever
   converted into a capability state: the identity DATA labels
   are never inputs to the composition at all (the only
   capability source is an explicit registry declaration).
2. An UNDECLARED sharing mode (no declaration row in the
   profile) reads ``unknown`` — absence of a declaration is not
   a declaration of absence, and it is never silently treated
   as either supported or unsupported.
3. An UNDECLARED isolation primitive (no row for a required
   mechanism) reads ``unknown`` — same rule, same honesty.
4. Malformed evaluation INPUT (wrong types, an unknown role, an
   unknown sharing-mode class, a mechanism label outside the
   frozen vocabulary) raises a typed
   :class:`~platformcaps.errors.PlatformCapabilityError` —
   validation failures are distinct from evaluation outcomes
   and are never coerced.

Semantics red lines (frozen — the W050 boundary, unchanged by
this stage): a ``supported``/``restricted`` evaluation outcome
is a DECLARATION-LEVEL statement — what this registry version
declares about the platform — advisory input that the canonical
enforcement owners (W048 containment, W049 client, NetworkPath)
MAY consume.  It is NOT permission, NOT authorization, NOT
proven enforcement, NOT active connectivity, and NOT physical
evidence.  This module never implements the consumers' gates:
W049's frozen mapping is documented for reference only (its
UNKNOWN/UNSUPPORTED are denials at ITS gate; its RESTRICTED is
constrained within the declared set; its SUPPORTED is eligible
only subject to canonical authority checks) — the consumer
decides with its own frozen rules, and W050 never becomes
their dependency.

What this module deliberately does NOT contain (the W050.2
stop boundary): versioned auditable HISTORY (append-only
journals, content-derived decision ids, replay of historical
decisions) belongs to the later history stage — this module
emits canonical, content-addressed results (``to_dict`` +
``content_digest``) that a history stage MAY preserve, but it
neither journals nor replays them, and it defines no
``from_dict`` (deserialization/replay is the history stage's
concern, not the evaluation's); the deterministic battery and
CI wiring belong to the later stages; W048/W049 integration,
OS/platform adapters, and platform enforcement are forbidden
territory.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import PlatformCapabilityError, PlatformCapabilityReasonCode
from .model import (
    EVIDENCE_CLASS_SOFTWARE,
    ISOLATION_MECHANISMS,
    ROLE_BUYER,
    ROLE_PROVIDER,
    ROLES,
    SCHEMA_VERSION,
    CapabilityState,
    IsolationPrimitive,
    PlatformProfile,
    SharingModeClass,
    SharingModeDeclaration,
)
from .registry import PlatformCapabilityRegistry

_REGISTRY_VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+$")
_SHA256_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class EvaluationFinding:
    """The frozen typed evaluation-findings vocabulary (W050.2).

    Findings are the typed reasons an evaluation outcome is what
    it is.  They are namespaced ``platformcaps-eval-`` — distinct
    from the error reason taxonomy
    (:class:`~platformcaps.errors.PlatformCapabilityReasonCode`)
    because a finding EXPLAINS a data outcome, it is not a
    failure.  The emission order inside a result is frozen:
    platform-level default first, then the role slot, then the
    sharing-mode slot, then each required isolation primitive in
    canonical mechanism order, then the single positive finding
    last.
    """

    #: the platform id is not registered in the consulted
    #: registry version — the fail-closed DEFAULT (never
    #: supported); the sole finding of an unregistered platform
    PLATFORM_UNKNOWN = "platformcaps-eval-platform-unknown"
    #: the profile carries no declaration row for the requested
    #: sharing-mode class (absence of a declaration is not a
    #: declaration of absence)
    MODE_UNDECLARED = "platformcaps-eval-mode-undeclared"
    #: the role capability declaration is unsupported
    ROLE_UNSUPPORTED = "platformcaps-eval-role-unsupported"
    #: the role capability declaration is unknown
    ROLE_UNKNOWN = "platformcaps-eval-role-unknown"
    #: the role capability declaration is restricted (within its
    #: declared set)
    ROLE_RESTRICTED = "platformcaps-eval-role-restricted"
    #: the sharing-mode declaration is unsupported
    MODE_UNSUPPORTED = "platformcaps-eval-mode-unsupported"
    #: the sharing-mode declaration is unknown
    MODE_UNKNOWN = "platformcaps-eval-mode-unknown"
    #: the sharing-mode declaration is restricted (within its
    #: declared set)
    MODE_RESTRICTED = "platformcaps-eval-mode-restricted"
    #: a required isolation mechanism has no primitive row in
    #: the profile (absence of a declaration is not a
    #: declaration of absence)
    MECHANISM_UNDECLARED = "platformcaps-eval-mechanism-undeclared"
    #: a required isolation primitive is declared unsupported
    MECHANISM_UNSUPPORTED = "platformcaps-eval-mechanism-unsupported"
    #: a required isolation primitive is declared unknown
    MECHANISM_UNKNOWN = "platformcaps-eval-mechanism-unknown"
    #: a required isolation primitive is declared restricted
    #: (within its declared set)
    MECHANISM_RESTRICTED = "platformcaps-eval-mechanism-restricted"
    #: every composed component is declared supported — the sole
    #: positive finding, and still a DECLARATION (never
    #: permission, never authorization, never proven
    #: enforcement, never active connectivity, never physical
    #: evidence)
    DECLARED_SUPPORTED = "platformcaps-eval-declared-supported"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        """The frozen findings vocabulary, explicitly
        enumerated (the only findings a result may carry)."""
        return (
            cls.PLATFORM_UNKNOWN,
            cls.MODE_UNDECLARED,
            cls.ROLE_UNSUPPORTED,
            cls.ROLE_UNKNOWN,
            cls.ROLE_RESTRICTED,
            cls.MODE_UNSUPPORTED,
            cls.MODE_UNKNOWN,
            cls.MODE_RESTRICTED,
            cls.MECHANISM_UNDECLARED,
            cls.MECHANISM_UNSUPPORTED,
            cls.MECHANISM_UNKNOWN,
            cls.MECHANISM_RESTRICTED,
            cls.DECLARED_SUPPORTED,
        )


#: the frozen membership set used to validate constructed results
_FINDINGS = frozenset(EvaluationFinding.values())

#: the frozen non-supported component-state finding map (the
#: composition vocabulary: unsupported, unknown, restricted —
#: a supported component contributes no finding; the composed
#: positive is DECLARED_SUPPORTED)
_COMPONENT_FINDINGS = {
    ("role", CapabilityState.UNSUPPORTED): (
        EvaluationFinding.ROLE_UNSUPPORTED
    ),
    ("role", CapabilityState.UNKNOWN): EvaluationFinding.ROLE_UNKNOWN,
    ("role", CapabilityState.RESTRICTED): (
        EvaluationFinding.ROLE_RESTRICTED
    ),
    ("mode", CapabilityState.UNSUPPORTED): (
        EvaluationFinding.MODE_UNSUPPORTED
    ),
    ("mode", CapabilityState.UNKNOWN): EvaluationFinding.MODE_UNKNOWN,
    ("mode", CapabilityState.RESTRICTED): (
        EvaluationFinding.MODE_RESTRICTED
    ),
    ("mechanism", CapabilityState.UNSUPPORTED): (
        EvaluationFinding.MECHANISM_UNSUPPORTED
    ),
    ("mechanism", CapabilityState.UNKNOWN): (
        EvaluationFinding.MECHANISM_UNKNOWN
    ),
    ("mechanism", CapabilityState.RESTRICTED): (
        EvaluationFinding.MECHANISM_RESTRICTED
    ),
}


def _require_str(value: object, label: str) -> str:
    """A non-empty string field (fail closed; never coerced)."""
    if not isinstance(value, str) or not value:
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


def _require_state(value: object, label: str) -> str:
    """A value in the frozen ACR-012 vocabulary (never coerced)."""
    if not isinstance(value, str) or value not in CapabilityState.values():
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.CAPABILITY_INVALID,
            "%s %r is outside the frozen ACR-012 capability vocabulary "
            "%s (reused from containment.state; never coerced)"
            % (label, value, list(CapabilityState.values())),
        )
    return value


def _token_tuple(value: object, label: str) -> Tuple[str, ...]:
    """A sequence of non-empty string tokens, normalized to the
    canonical sorted+deduplicated form (the content-addressing
    discipline: identical content yields identical canonical
    bytes regardless of authoring order)."""
    if isinstance(value, (str, bytes)) or not isinstance(value, (tuple, list)):
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.INVALID_INPUT,
            "%s must be a sequence of non-empty string tokens" % label,
        )
    for item in value:
        if not isinstance(item, str) or not item:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "%s tokens must be non-empty strings" % label,
            )
    return tuple(sorted(set(value)))


@dataclass(frozen=True)
class CompatibilityEvaluation:
    """One deterministic, content-addressed compatibility
    evaluation result (W050.2).

    The request echo (``platform_id`` / ``role`` /
    ``sharing_mode``) plus the composed declared compatibility:
    ``state`` (the frozen ACR-012 vocabulary), ``restrictions``
    (present exactly when the state is RESTRICTED — the merged,
    canonical declared envelope; the W048/W049 coupling preserved
    exactly), ``findings`` (the frozen typed findings vocabulary,
    in the frozen emission order), and the component audit trail
    (``role_state``, ``sharing_mode_state``,
    ``mechanism_states``) — the declared facts the composition
    consumed, never a summary that hides them.

    Provenance (frozen): every result carries the exact registry
    ``registry_version`` and ``registry_digest`` it was composed
    from, so a result is auditable against the exact declaration
    content that produced it, plus the profile's opaque
    ``evidence_references`` and the SOFTWARE-only
    ``evidence_class`` (an evaluation result is never a PHYSICAL
    platform claim).

    Determinism (frozen): ``to_dict`` emits the canonical form —
    mechanisms in canonical sorted order, restrictions and
    evidence references in their canonical sorted form, findings
    in the frozen emission order — so identical evaluation
    inputs over identical registry content yield byte-identical
    serialization and ``content_digest`` regardless of authoring
    order, repeat count, or hash-seed configuration.

    A declaration, never a decision: this object grants no
    permission, authorizes nothing, proves no enforcement, and
    asserts no connectivity — it records what ONE registry
    version DECLARES.  Constructed results are shape-validated
    fail closed (frozen vocabularies, RESTRICTED coupling,
    mechanism alignment, canonical digests); the composition
    logic itself lives in
    :func:`evaluate_sharing_compatibility`.  Deserialization
    (``from_dict``) is deliberately absent — the replay of
    preserved results is the later history stage's concern, not
    this stage's.
    """

    platform_id: str
    role: str
    sharing_mode: str
    state: str
    role_state: str
    sharing_mode_state: str
    registry_version: str
    registry_digest: str
    restrictions: Tuple[str, ...] = ()
    findings: Tuple[str, ...] = ()
    required_mechanisms: Tuple[str, ...] = ()
    mechanism_states: Tuple[Tuple[str, str], ...] = ()
    mechanism_minimum_properties: Tuple[Tuple[str, Tuple[str, ...]], ...] = ()
    evidence_references: Tuple[str, ...] = ()
    evidence_class: str = EVIDENCE_CLASS_SOFTWARE

    def __post_init__(self) -> None:
        _require_str(self.platform_id, "evaluation platform_id")
        if self.role not in ROLES:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.ROLE_INVALID,
                "evaluation role %r must be one of %s (the frozen "
                "participation roles; never coerced)"
                % (self.role, list(ROLES)),
            )
        if self.sharing_mode not in SharingModeClass.values():
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.SHARING_MODE_INVALID,
                "evaluation sharing mode %r must be one of %s (the "
                "frozen sharing-mode capability classes; never coerced)"
                % (self.sharing_mode, list(SharingModeClass.values())),
            )
        state = _require_state(self.state, "evaluation state")
        role_state = _require_state(
            self.role_state, "evaluation role_state"
        )
        mode_state = _require_state(
            self.sharing_mode_state, "evaluation sharing_mode_state"
        )
        restrictions = _token_tuple(
            self.restrictions, "evaluation restrictions"
        )
        if state == CapabilityState.RESTRICTED and not restrictions:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.RESTRICTION_INVALID,
                "evaluation state is RESTRICTED and requires a "
                "non-empty merged restriction set (the set is the "
                "constrained-operation envelope — an empty set would "
                "silently mean unrestricted)",
            )
        if state != CapabilityState.RESTRICTED and restrictions:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.RESTRICTION_INVALID,
                "evaluation state is %s and must carry NO restrictions "
                "(only a RESTRICTED outcome carries the merged "
                "declared envelope)" % state,
            )
        findings = self.findings
        if isinstance(findings, (str, bytes)) or not isinstance(
            findings, (tuple, list)
        ):
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "evaluation findings must be a sequence of typed "
                "finding codes",
            )
        findings = tuple(findings)
        for finding in findings:
            if not isinstance(finding, str) or finding not in _FINDINGS:
                raise PlatformCapabilityError(
                    PlatformCapabilityReasonCode.INVALID_INPUT,
                    "evaluation finding %r is outside the frozen "
                    "EvaluationFinding vocabulary (typed findings only; "
                    "fail closed)" % (finding,),
                )
        required = _token_tuple(
            self.required_mechanisms,
            "evaluation required_mechanisms",
        )
        for mechanism in required:
            if mechanism not in ISOLATION_MECHANISMS:
                raise PlatformCapabilityError(
                    PlatformCapabilityReasonCode.MECHANISM_INVALID,
                    "evaluation required mechanism %r is outside the "
                    "frozen mechanism vocabulary %s (DATA labels; never "
                    "coerced)"
                    % (mechanism, list(ISOLATION_MECHANISMS)),
                )
        mechanism_states = self._require_mechanism_pairs(
            self.mechanism_states, required
        )
        mechanism_properties = self._require_mechanism_properties(
            self.mechanism_minimum_properties, required, mechanism_states
        )
        evidence_references = _token_tuple(
            self.evidence_references, "evaluation evidence_references"
        )
        if self.evidence_class != EVIDENCE_CLASS_SOFTWARE:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.EVIDENCE_INVALID,
                "evaluation evidence_class %r is invalid: an evaluation "
                "result is SOFTWARE-class only (never a PHYSICAL "
                "platform claim)" % (self.evidence_class,),
            )
        if (
            not isinstance(self.registry_version, str)
            or not _REGISTRY_VERSION_PATTERN.match(self.registry_version)
        ):
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.VERSION_INVALID,
                "evaluation registry_version %r must match the frozen "
                "grammar 'major.minor'" % (self.registry_version,),
            )
        if (
            not isinstance(self.registry_digest, str)
            or not _SHA256_DIGEST_PATTERN.match(self.registry_digest)
        ):
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "evaluation registry_digest %r must be a canonical "
                "sha256 content digest" % (self.registry_digest,),
            )
        object.__setattr__(self, "restrictions", restrictions)
        object.__setattr__(self, "findings", findings)
        object.__setattr__(self, "role_state", role_state)
        object.__setattr__(self, "sharing_mode_state", mode_state)
        object.__setattr__(self, "required_mechanisms", required)
        object.__setattr__(self, "mechanism_states", mechanism_states)
        object.__setattr__(
            self, "mechanism_minimum_properties", mechanism_properties
        )
        object.__setattr__(
            self, "evidence_references", evidence_references
        )

    def _require_mechanism_pairs(
        self, value: object, required: Tuple[str, ...]
    ) -> Tuple[Tuple[str, str], ...]:
        """The (mechanism, state) audit trail: aligned with the
        canonical required-mechanism order, states in the frozen
        vocabulary, never duplicated, never arbitrary."""
        if isinstance(value, (str, bytes)) or not isinstance(
            value, (tuple, list)
        ):
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "evaluation mechanism_states must be a sequence of "
                "(mechanism, state) pairs",
            )
        pairs: List[Tuple[str, str]] = []
        for pair in value:
            if (
                isinstance(pair, (str, bytes))
                or not isinstance(pair, (tuple, list))
                or len(pair) != 2
            ):
                raise PlatformCapabilityError(
                    PlatformCapabilityReasonCode.INVALID_INPUT,
                    "evaluation mechanism_states entries must be "
                    "(mechanism, state) pairs",
                )
            mechanism, pair_state = pair
            if not isinstance(mechanism, str) or mechanism not in required:
                raise PlatformCapabilityError(
                    PlatformCapabilityReasonCode.INVALID_INPUT,
                    "evaluation mechanism_states mechanism %r is not in "
                    "the evaluated required-mechanism set %s (the audit "
                    "trail is aligned with the evaluated set)"
                    % (mechanism, list(required)),
                )
            pairs.append(
                (mechanism, _require_state(pair_state, "mechanism state"))
            )
        mechanisms = tuple(mechanism for mechanism, _ in pairs)
        if mechanisms != required:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "evaluation mechanism_states must align exactly with "
                "the canonical required-mechanism order %s (got %s; "
                "deterministic alignment, never best-effort)"
                % (list(required), list(mechanisms)),
            )
        return tuple(pairs)

    def _require_mechanism_properties(
        self,
        value: object,
        required: Tuple[str, ...],
        mechanism_states: Tuple[Tuple[str, str], ...],
    ) -> Tuple[Tuple[str, Tuple[str, ...]], ...]:
        """The per-required-mechanism declared minimum security
        properties: aligned with the canonical order, canonical
        token sets, and carrying the model's property discipline
        (properties exist exactly for SUPPORTED/RESTRICTED
        primitives — there is no property envelope for an absent
        or unproven primitive)."""
        if isinstance(value, (str, bytes)) or not isinstance(
            value, (tuple, list)
        ):
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "evaluation mechanism_minimum_properties must be a "
                "sequence of (mechanism, properties) pairs",
            )
        states_by_mechanism: Dict[str, str] = dict(mechanism_states)
        entries: List[Tuple[str, Tuple[str, ...]]] = []
        for entry in value:
            if (
                isinstance(entry, (str, bytes))
                or not isinstance(entry, (tuple, list))
                or len(entry) != 2
            ):
                raise PlatformCapabilityError(
                    PlatformCapabilityReasonCode.INVALID_INPUT,
                    "evaluation mechanism_minimum_properties entries "
                    "must be (mechanism, properties) pairs",
                )
            mechanism, properties = entry
            if not isinstance(mechanism, str) or mechanism not in required:
                raise PlatformCapabilityError(
                    PlatformCapabilityReasonCode.INVALID_INPUT,
                    "evaluation mechanism_minimum_properties mechanism "
                    "%r is not in the evaluated required-mechanism set "
                    "%s" % (mechanism, list(required)),
                )
            properties = _token_tuple(
                properties,
                "evaluation mechanism %s minimum security properties"
                % mechanism,
            )
            entry_state = states_by_mechanism[mechanism]
            if entry_state in (
                CapabilityState.SUPPORTED,
                CapabilityState.RESTRICTED,
            ) and not properties:
                raise PlatformCapabilityError(
                    PlatformCapabilityReasonCode.PROPERTY_INVALID,
                    "evaluation mechanism %s is %s and must carry its "
                    "declared non-empty minimum_security_properties (a "
                    "supported/restricted primitive without explicit "
                    "minimum properties is not testable)"
                    % (mechanism, entry_state),
                )
            if entry_state in (
                CapabilityState.UNSUPPORTED,
                CapabilityState.UNKNOWN,
            ) and properties:
                raise PlatformCapabilityError(
                    PlatformCapabilityReasonCode.PROPERTY_INVALID,
                    "evaluation mechanism %s is %s and must carry NO "
                    "minimum properties (there is no property envelope "
                    "for an absent or unproven primitive; no fallback "
                    "exists anywhere in this family)"
                    % (mechanism, entry_state),
                )
            entries.append((mechanism, properties))
        mechanisms = tuple(mechanism for mechanism, _ in entries)
        if mechanisms != required:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "evaluation mechanism_minimum_properties must align "
                "exactly with the canonical required-mechanism order "
                "%s (got %s; deterministic alignment, never "
                "best-effort)" % (list(required), list(mechanisms)),
            )
        return tuple(entries)

    def to_dict(self) -> Dict[str, Any]:
        """The canonical deterministic serialization: the request
        echo, the composed outcome, the merged envelope, the
        typed findings, the component audit trail, and the
        provenance — mechanisms in canonical order, token sets in
        their canonical form, findings in the frozen emission
        order."""
        return {
            "schema_version": SCHEMA_VERSION,
            "registry_version": self.registry_version,
            "registry_digest": self.registry_digest,
            "platform_id": self.platform_id,
            "role": self.role,
            "sharing_mode": self.sharing_mode,
            "state": self.state,
            "restrictions": list(self.restrictions),
            "findings": list(self.findings),
            "role_state": self.role_state,
            "sharing_mode_state": self.sharing_mode_state,
            "required_mechanisms": list(self.required_mechanisms),
            "mechanism_states": [
                {"mechanism": mechanism, "state": state}
                for mechanism, state in self.mechanism_states
            ],
            "mechanism_minimum_properties": [
                {
                    "mechanism": mechanism,
                    "minimum_security_properties": list(properties),
                }
                for mechanism, properties in (
                    self.mechanism_minimum_properties
                )
            ],
            "evidence_references": list(self.evidence_references),
            "evidence_class": self.evidence_class,
        }

    def content_digest(self) -> str:
        """The content address of this exact evaluation result:
        SHA-256 over the canonical JSON bytes of ``to_dict``
        (request + outcome + audit trail + provenance)."""
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.to_dict())
        ).hexdigest()


def _resolve_mode_declaration(
    profile: PlatformProfile, sharing_mode: str
) -> SharingModeDeclaration:
    """The profile's declaration row for one sharing-mode class
    (profiles store unique sorted rows; ``None`` means
    UNDECLARED — absence of a declaration, never a declaration
    of absence)."""
    for declaration in profile.sharing_modes:
        if declaration.sharing_mode == sharing_mode:
            return declaration
    return None  # type: ignore[return-value]


def _resolve_primitive(
    profile: PlatformProfile, mechanism: str
) -> IsolationPrimitive:
    """The profile's isolation-primitive row for one mechanism
    (unique sorted rows; ``None`` means UNDECLARED)."""
    for primitive in profile.isolation_primitives:
        if primitive.mechanism == mechanism:
            return primitive
    return None  # type: ignore[return-value]


def evaluate_sharing_compatibility(
    registry: PlatformCapabilityRegistry,
    platform_id: str,
    role: str,
    sharing_mode: str,
    required_mechanisms: Iterable[str] = (),
) -> CompatibilityEvaluation:
    """Deterministically compose the declared sharing
    compatibility of one platform, role, sharing-mode class, and
    isolation requirement, from ONE registry version's declared
    rows only.

    ``registry`` is the frozen W050.1
    :class:`~platformcaps.registry.PlatformCapabilityRegistry`
    (the evaluation never mutates it and never depends on
    anything but its declared content).  ``role`` is the frozen
    provider/buyer pair; ``sharing_mode`` is one of the frozen
    sharing-mode classes; ``required_mechanisms`` is an optional
    explicit caller isolation requirement (labels from the
    frozen ``ISOLATION_MECHANISMS`` vocabulary — the evaluated
    set is the mode's declared requirements UNION the caller's
    requirement, canonicalized).

    Outcomes (the frozen lattice): unsupported dominates (a
    declared hard negative anywhere is reported, never concealed
    behind an unknown); then unknown (any undeclared or unknown
    component fails the conclusion closed — the DEFAULT for
    unregistered platforms, undeclared modes, and undeclared
    mechanisms alike); then restricted (the merged canonical
    envelope of every restricted component); else supported
    (every component declared supported).  There is no fallback
    and no downgrade anywhere.

    The identity DATA labels (os_family, device_class, network
    configuration, deployment mode) are never inputs: no label,
    however familiar, implies sharing support.

    The returned result is a DECLARATION-LEVEL statement —
    advisory capability input the canonical enforcement owners
    (W048/W049/NetworkPath) MAY consume; never permission, never
    authorization, never proven enforcement, never active
    connectivity, never physical evidence.  Malformed INPUT
    raises a typed
    :class:`~platformcaps.errors.PlatformCapabilityError` (fail
    closed, never coerced); an unregistered platform is NOT an
    input error — it evaluates to ``unknown``, the fail-closed
    default.
    """
    if not isinstance(registry, PlatformCapabilityRegistry):
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.INVALID_INPUT,
            "compatibility evaluation requires a "
            "PlatformCapabilityRegistry instance (got %s)"
            % type(registry).__name__,
        )
    _require_str(platform_id, "evaluation platform_id")
    if role not in ROLES:
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.ROLE_INVALID,
            "evaluation role %r must be one of %s (the frozen "
            "participation roles; never coerced)" % (role, list(ROLES)),
        )
    if sharing_mode not in SharingModeClass.values():
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.SHARING_MODE_INVALID,
            "evaluation sharing mode %r must be one of %s (the frozen "
            "sharing-mode capability classes; never coerced)"
            % (sharing_mode, list(SharingModeClass.values())),
        )
    if isinstance(required_mechanisms, (str, bytes)) or not isinstance(
        required_mechanisms, (tuple, list)
    ):
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.INVALID_INPUT,
            "evaluation required_mechanisms must be a sequence of "
            "frozen mechanism labels",
        )
    caller_required = tuple(required_mechanisms)
    for mechanism in caller_required:
        if not isinstance(mechanism, str) or not mechanism:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "evaluation required_mechanisms tokens must be "
                "non-empty strings",
            )
        if mechanism not in ISOLATION_MECHANISMS:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.MECHANISM_INVALID,
                "evaluation required mechanism %r is outside the "
                "frozen mechanism vocabulary %s (DATA labels; never "
                "coerced)"
                % (mechanism, list(ISOLATION_MECHANISMS)),
            )
    caller_required = tuple(sorted(set(caller_required)))

    registry_version = registry.registry_version
    registry_digest = registry.content_digest()

    if not registry.has_platform(platform_id):
        # The fail-closed DEFAULT: an unregistered platform is not
        # an input error — it evaluates to unknown (never
        # supported), with the platform-level typed finding as the
        # sole finding; the caller's explicit requirement is still
        # audited (each mechanism reads unknown, undeclared).
        return CompatibilityEvaluation(
            platform_id=platform_id,
            role=role,
            sharing_mode=sharing_mode,
            state=CapabilityState.UNKNOWN,
            role_state=CapabilityState.UNKNOWN,
            sharing_mode_state=CapabilityState.UNKNOWN,
            registry_version=registry_version,
            registry_digest=registry_digest,
            restrictions=(),
            findings=(EvaluationFinding.PLATFORM_UNKNOWN,),
            required_mechanisms=caller_required,
            mechanism_states=tuple(
                (mechanism, CapabilityState.UNKNOWN)
                for mechanism in caller_required
            ),
            mechanism_minimum_properties=tuple(
                (mechanism, ()) for mechanism in caller_required
            ),
            evidence_references=(),
            evidence_class=EVIDENCE_CLASS_SOFTWARE,
        )

    profile: PlatformProfile = registry.profile(platform_id)
    role_capability = (
        profile.provider if role == ROLE_PROVIDER else profile.buyer
    )
    role_state = role_capability.state
    role_restrictions = role_capability.restrictions

    mode_declaration = _resolve_mode_declaration(profile, sharing_mode)
    if mode_declaration is None:
        mode_state = CapabilityState.UNKNOWN
        mode_restrictions: Tuple[str, ...] = ()
        mode_required: Tuple[str, ...] = ()
        mode_finding: str = EvaluationFinding.MODE_UNDECLARED
    else:
        mode_state = mode_declaration.state
        mode_restrictions = mode_declaration.restrictions
        mode_required = mode_declaration.required_isolation_mechanisms
        mode_finding = ""

    required = tuple(sorted(set(mode_required) | set(caller_required)))
    mechanism_states: List[Tuple[str, str]] = []
    mechanism_properties: List[Tuple[str, Tuple[str, ...]]] = []
    mechanism_restrictions: Dict[str, Tuple[str, ...]] = {}
    mechanism_findings: List[str] = []
    for mechanism in required:
        primitive = _resolve_primitive(profile, mechanism)
        if primitive is None:
            mechanism_states.append(
                (mechanism, CapabilityState.UNKNOWN)
            )
            mechanism_properties.append((mechanism, ()))
            mechanism_restrictions[mechanism] = ()
            mechanism_findings.append(
                EvaluationFinding.MECHANISM_UNDECLARED
            )
            continue
        mechanism_states.append((mechanism, primitive.state))
        mechanism_properties.append(
            (mechanism, primitive.minimum_security_properties)
        )
        mechanism_restrictions[mechanism] = primitive.restrictions
        if primitive.state != CapabilityState.SUPPORTED:
            mechanism_findings.append(
                _COMPONENT_FINDINGS[("mechanism", primitive.state)]
            )

    component_states = [role_state, mode_state] + [
        state for _, state in mechanism_states
    ]
    if CapabilityState.UNSUPPORTED in component_states:
        composed_state = CapabilityState.UNSUPPORTED
        merged_restrictions: Tuple[str, ...] = ()
    elif CapabilityState.UNKNOWN in component_states:
        composed_state = CapabilityState.UNKNOWN
        merged_restrictions = ()
    elif CapabilityState.RESTRICTED in component_states:
        composed_state = CapabilityState.RESTRICTED
        states_by_mechanism = dict(mechanism_states)
        merged: List[str] = []
        if role_state == CapabilityState.RESTRICTED:
            merged.extend(role_restrictions)
        if mode_state == CapabilityState.RESTRICTED:
            merged.extend(mode_restrictions)
        for mechanism in required:
            if (
                states_by_mechanism[mechanism]
                == CapabilityState.RESTRICTED
            ):
                merged.extend(mechanism_restrictions[mechanism])
        merged_restrictions = tuple(sorted(set(merged)))
    else:
        composed_state = CapabilityState.SUPPORTED
        merged_restrictions = ()

    findings: List[str] = []
    if role_state != CapabilityState.SUPPORTED:
        findings.append(_COMPONENT_FINDINGS[("role", role_state)])
    if mode_finding:
        findings.append(mode_finding)
    elif mode_state != CapabilityState.SUPPORTED:
        findings.append(_COMPONENT_FINDINGS[("mode", mode_state)])
    findings.extend(mechanism_findings)
    if composed_state == CapabilityState.SUPPORTED:
        findings.append(EvaluationFinding.DECLARED_SUPPORTED)

    return CompatibilityEvaluation(
        platform_id=platform_id,
        role=role,
        sharing_mode=sharing_mode,
        state=composed_state,
        role_state=role_state,
        sharing_mode_state=mode_state,
        registry_version=registry_version,
        registry_digest=registry_digest,
        restrictions=merged_restrictions,
        findings=tuple(findings),
        required_mechanisms=required,
        mechanism_states=tuple(mechanism_states),
        mechanism_minimum_properties=tuple(mechanism_properties),
        evidence_references=profile.evidence_references,
        evidence_class=EVIDENCE_CLASS_SOFTWARE,
    )


__all__ = [
    "CompatibilityEvaluation",
    "EvaluationFinding",
    "evaluate_sharing_compatibility",
]
