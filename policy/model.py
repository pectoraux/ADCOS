"""ADCOS Policy engine — domain objects (WORK-010).

Implements the technology-neutral policy layer mandated by
``spec/architecture.md`` (policy authority section) and the frozen
WORK-010 handoff (``spec/prompts/WORK-010.md``). Policy is the authority
that evaluates whether an operation, resource use, session action,
federation action, emergency action, or privacy-sensitive operation is
permitted under explicit policy inputs.

Central boundary (frozen by the WORK-010 prompt):

    POLICY DECISION
      = evaluation of explicit policy rules against explicit facts/claims/context

    POLICY DECISION  !=  identity cryptography
    POLICY DECISION  !=  credential generation/rotation
    POLICY DECISION  !=  topology truth
    POLICY DECISION  !=  resource measurement
    POLICY DECISION  !=  resource mutation unless a separate caller executes an authorized operation
    POLICY DECISION  !=  intent normalization
    POLICY DECISION  !=  path computation / route selection
    POLICY DECISION  !=  adapter selection
    POLICY DECISION  !=  pricing / settlement / billing
    POLICY DECISION  !=  trust score

A policy decision is attributable to a policy evaluation; it MUST NOT be
back-projected into identity/topology/resource state. ``NodeID`` says WHO
the subject is; credential lifecycle says WHETHER the credential is
active; capability statement says WHAT the node claims; discovery/topology
says WHAT was observed and by whom; resource layer says WHAT resources
are offered/measured/accounted; intent says WHAT outcome is desired;
policy says WHETHER an operation is permitted under explicit rules.

The objects in this module are immutable, hashable, and canonicalizable
via ``protocol.canonicalization``. Numeric normative values MUST be
integers (no binary floating point, NaN, or Infinity). Temporal
evaluation uses an INJECTED instant; no policy evaluation function may
call the wall clock directly. Rules are DATA: they MUST NOT contain
executable code, arbitrary Python expressions, imported policy languages,
or dynamic callbacks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Tuple

from protocol.canonicalization import CanonicalizationError, canonical_json_bytes


# --------------------------------------------------------------------------
# Content-digest structural validator (WORK-009 sha256-style fingerprint)
# --------------------------------------------------------------------------

#: A WORK-009 ``NormalizedIntent`` digest is ``sha256(canonical_json_bytes(
#: content_dict()))`` -- exactly 64 lowercase hexadecimal characters. The
#: policy context carries this digest BY REFERENCE (policy MUST NOT
#: rewrite the intent). A non-empty ``normalized_intent_digest`` MUST be
#: structurally valid: a malformed string such as ``"not-an-intent"``
#: MUST NOT satisfy ``INTENT_PRESENT`` and MUST NOT participate in an
#: allow rule (Architect review of PR #10, blocker 2). The check is
#: deliberately the same shape the intent layer produces (64 lowercase
#: hex), so a genuine WORK-009 digest always passes and a garbage value
#: always fails closed.
_CONTENT_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def is_valid_content_digest(value: str) -> bool:
    """Return True if ``value`` is a valid 64-lowercase-hex content digest
    (sha256-style, matching WORK-009 ``NormalizedIntent.digest``).

    This is a STRUCTURAL check only -- it does not verify that the digest
    corresponds to any particular intent content (that is the intent
    layer's authority). Policy consumes the digest by reference and MUST
    NOT re-derive or rewrite it.
    """
    return isinstance(value, str) and bool(_CONTENT_DIGEST_RE.match(value))


class PolicyError(ValueError):
    """Raised when a policy object is malformed, ambiguous, or unsupported.

    Carries a stable machine-readable ``code`` and a deterministic
    human-readable ``detail``. Codes are part of the deterministic
    contract: callers MUST be able to switch on them without parsing
    prose. Diagnostics MUST NOT echo secret material (LOCK-023).
    """

    def __init__(self, code: str, detail: str) -> None:
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------
# Frozen vocabularies (additive evolution is a deliberate schema change)
# --------------------------------------------------------------------------

class Effect:
    """Frozen rule effect vocabulary.

    A closed set of three outcomes:
    - ``ALLOW``: the rule explicitly permits the operation;
    - ``DENY``: the rule explicitly forbids the operation;
    - ``REQUIRE_REVIEW``: the rule neither allows nor denies; the
      operation requires a separate human/process review. This third
      outcome is permitted by the frozen design when an explicit policy
      authority needs to defer a decision. It MUST NEVER silently become
      ALLOW (rule 6 of the conflict-resolution semantics).

    Adding a new effect is a deliberate schema change, never a silent
    extension. Unknown effects MUST fail closed (rule 8 of the prompt).
    """

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_REVIEW = "require-review"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.ALLOW, cls.DENY, cls.REQUIRE_REVIEW)


class DecisionCode:
    """Frozen decision/evaluation outcome codes.

    Stable machine-readable codes that distinguish the deny-by-default
    failure modes required by the prompt (do not collapse them into a
    generic ``false`` result):

    - ``ALLOW``: explicit allow decision (a rule matched and won);
    - ``DENY``: explicit deny decision (a DENY rule matched and won);
    - ``DEFAULT_DENY``: no applicable privileged rule -> deny-by-default;
    - ``FAIL_CLOSED``: ambiguous input, conflicting equal-precedence rules,
      or any other fail-closed condition;
    - ``POLICY_EXPIRED``: the applicable policy set is expired at ``now``;
    - ``POLICY_NOT_YET_VALID``: the applicable policy set is not yet valid;
    - ``MISSING_FACT``: a required authorization fact is absent;
    - ``UNSUPPORTED_PREDICATE``: a rule references an unknown predicate;
    - ``CONFLICT``: unresolved equal-precedence conflict;
    - ``INVALID_SUBJECT``: malformed requester/subject NodeID;
    - ``INVALID_POLICY``: malformed policy rule or policy set.

    Adding a new code is a deliberate schema change. The codes are part
    of the deterministic contract.
    """

    ALLOW = "allow"
    DENY = "deny"
    DEFAULT_DENY = "default-deny"
    FAIL_CLOSED = "fail-closed"
    POLICY_EXPIRED = "policy-expired"
    POLICY_NOT_YET_VALID = "policy-not-yet-valid"
    MISSING_FACT = "missing-fact"
    UNSUPPORTED_PREDICATE = "unsupported-predicate"
    CONFLICT = "conflict"
    INVALID_SUBJECT = "invalid-subject"
    INVALID_POLICY = "invalid-policy"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.ALLOW,
            cls.DENY,
            cls.DEFAULT_DENY,
            cls.FAIL_CLOSED,
            cls.POLICY_EXPIRED,
            cls.POLICY_NOT_YET_VALID,
            cls.MISSING_FACT,
            cls.UNSUPPORTED_PREDICATE,
            cls.CONFLICT,
            cls.INVALID_SUBJECT,
            cls.INVALID_POLICY,
        )


class PolicyDomain:
    """Frozen policy-domain / scope identifier vocabulary.

    Each domain is a structurally distinct policy authority. The frozen
    set covers the WORK-010 prompt's "frozen policy dimensions" without
    turning them into separate authorities:

    - ``IDENTITY``: subject access (who may perform operations);
    - ``RESOURCE``: resource access (which resources may be used and how);
    - ``LOCALITY``: locality policies (explicit labels/sets/references);
    - ``FEDERATION``: federation membership / cross-domain actions;
    - ``PRIVACY``: privacy requirements (end-to-end, relay restrictions);
    - ``EMERGENCY``: emergency priority / preemption;
    - ``SERVICE``: service priority classification;
    - ``ENERGY``: energy reserve policies;
    - ``TRUST``: trust assertions as explicit INPUTS/claims -- NOT a trust
      score engine (the prompt explicitly forbids inventing a reputation
      system in WORK-010).

    These are *policy* domains, not implementations. They never encode
    5G, NR, Wi-Fi, vendor names, cell IDs, route IDs, or any other
    access-technology vocabulary. Adding a new domain is a deliberate
    schema change.
    """

    IDENTITY = "identity"
    RESOURCE = "resource"
    LOCALITY = "locality"
    FEDERATION = "federation"
    PRIVACY = "privacy"
    EMERGENCY = "emergency"
    SERVICE = "service"
    ENERGY = "energy"
    TRUST = "trust"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.IDENTITY,
            cls.RESOURCE,
            cls.LOCALITY,
            cls.FEDERATION,
            cls.PRIVACY,
            cls.EMERGENCY,
            cls.SERVICE,
            cls.ENERGY,
            cls.TRUST,
        )


class Operation:
    """Frozen operation / action identifier vocabulary.

    Stable technology-neutral action identifiers. These are policy-owned
    action identifiers defined in a machine-readable policy registry
    (this class), NOT ad-hoc strings embedded in executable code. They
    never encode ``5g``, ``wifi``, ``satellite``, vendor names, cell IDs,
    APNs, RAN/core implementation details, or route IDs (LOCK-001/002/
    003/004).

    The frozen set covers the examples in the prompt:

    - resource.*: reserve / consume / release
    - session.*: create / modify / terminate
    - federation.*: join / accept-peer / resource-export / resource-import
    - service.invoke
    - privacy.requirement-override
    - emergency.preempt

    Adding a new operation is a deliberate schema change.
    """

    RESOURCE_RESERVE = "resource.reserve"
    RESOURCE_CONSUME = "resource.consume"
    RESOURCE_RELEASE = "resource.release"
    SESSION_CREATE = "session.create"
    SESSION_MODIFY = "session.modify"
    SESSION_TERMINATE = "session.terminate"
    FEDERATION_JOIN = "federation.join"
    FEDERATION_ACCEPT_PEER = "federation.accept-peer"
    FEDERATION_RESOURCE_EXPORT = "federation.resource-export"
    FEDERATION_RESOURCE_IMPORT = "federation.resource-import"
    SERVICE_INVOKE = "service.invoke"
    PRIVACY_REQUIREMENT_OVERRIDE = "privacy.requirement-override"
    EMERGENCY_PREEMPT = "emergency.preempt"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.RESOURCE_RESERVE,
            cls.RESOURCE_CONSUME,
            cls.RESOURCE_RELEASE,
            cls.SESSION_CREATE,
            cls.SESSION_MODIFY,
            cls.SESSION_TERMINATE,
            cls.FEDERATION_JOIN,
            cls.FEDERATION_ACCEPT_PEER,
            cls.FEDERATION_RESOURCE_EXPORT,
            cls.FEDERATION_RESOURCE_IMPORT,
            cls.SERVICE_INVOKE,
            cls.PRIVACY_REQUIREMENT_OVERRIDE,
            cls.EMERGENCY_PREEMPT,
        )


class Privileged:
    """Explicit privileged-operation classification.

    The prompt's deny-by-default rule applies to PRIVILEGED operations.
    The classification is structural (a frozen set), not a naming
    heuristic: the implementation MUST NOT silently classify operations
    as privileged/non-privileged based on arbitrary naming heuristics.

    Read-only or purely local normalization operations MAY have a
    permissive default IF AND ONLY IF the operation class is declared
    non-privileged here. Every operation in :class:`Operation` is
    explicitly listed in exactly one of these two sets.

    All resource/session/federation/emergency/privacy-override operations
    are PRIVILEGED (they mutate state, consume resources, or override
    ordinary rules). ``service.invoke`` is also privileged (it consumes
    capacity and may have side effects). There is currently no
    non-privileged operation in the frozen set; if a future ACR adds one
    (e.g. a read-only status query), it MUST be added to
    :attr:`NON_PRIVILEGED` explicitly here, never inferred.
    """

    PRIVILEGED: Tuple[str, ...] = (
        Operation.RESOURCE_RESERVE,
        Operation.RESOURCE_CONSUME,
        Operation.RESOURCE_RELEASE,
        Operation.SESSION_CREATE,
        Operation.SESSION_MODIFY,
        Operation.SESSION_TERMINATE,
        Operation.FEDERATION_JOIN,
        Operation.FEDERATION_ACCEPT_PEER,
        Operation.FEDERATION_RESOURCE_EXPORT,
        Operation.FEDERATION_RESOURCE_IMPORT,
        Operation.SERVICE_INVOKE,
        Operation.PRIVACY_REQUIREMENT_OVERRIDE,
        Operation.EMERGENCY_PREEMPT,
    )

    NON_PRIVILEGED: Tuple[str, ...] = ()

    @classmethod
    def is_privileged(cls, operation: str) -> bool:
        return operation in cls.PRIVILEGED


# --------------------------------------------------------------------------
# Condition (a declarative predicate + arguments, NOT executable code)
# --------------------------------------------------------------------------

#: Maximum integer magnitude for priority / specificity. They are small
#: deterministic integers used for total ordering. Negative values are
#: rejected; ambiguity in priority/specificity MUST fail closed (rule 4
#: of the conflict-resolution semantics).
MAX_PRIORITY = 1_000_000
MAX_SPECIFICITY = 1_000_000


@dataclass(frozen=True)
class Condition:
    """A single declarative condition: ``(predicate, arguments)``.

    A condition is DATA: it carries a ``predicate`` (one of the frozen
    :class:`PredicateKind` values) and an immutable ``arguments`` mapping
    of named parameters. It MUST NOT carry executable code, Python
    expressions, lambdas, callables, or imported policy languages. The
    engine dispatches on ``predicate`` to a pure matcher function in
    :mod:`policy.predicates`.

    Unknown required predicates MUST fail explicitly (rule 8 of the
    prompt): the engine returns ``UNSUPPORTED_PREDICATE`` and never
    silently ignores a condition.
    """

    predicate: str
    arguments: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        from .predicates import PredicateKind  # local import; avoids cycle
        if not isinstance(self.predicate, str) or not self.predicate:
            raise PolicyError(
                "predicate",
                "predicate must be a non-empty string (got %r)" % (self.predicate,),
            )
        if self.predicate not in PredicateKind.values():
            raise PolicyError(
                "predicate",
                "predicate %r is not a frozen policy predicate (known: %s); "
                "unsupported required predicates fail explicitly (rule 8)"
                % (self.predicate, list(PredicateKind.values())),
            )
        if not isinstance(self.arguments, Mapping):
            raise PolicyError(
                "predicate-args",
                "condition arguments must be a mapping (got %s)"
                % type(self.arguments).__name__,
            )
        for key in self.arguments.keys():
            if not isinstance(key, str):
                raise PolicyError(
                    "predicate-args",
                    "condition argument keys must be strings (got %s)"
                    % type(key).__name__,
                )

    def to_dict(self) -> dict:
        out: dict = {"predicate": self.predicate}
        if self.arguments:
            out["arguments"] = dict(self.arguments)
        return out


# --------------------------------------------------------------------------
# PolicyRule (declarative, immutable)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class PolicyRule:
    """A declarative policy rule.

    Fields:
    - ``rule_id``: stable non-empty string identifier;
    - ``domain``: one of the frozen :class:`PolicyDomain` values;
    - ``effect``: ``ALLOW`` / ``DENY`` / ``REQUIRE_REVIEW``;
    - ``operation``: one of the frozen :class:`Operation` values;
    - ``subjects``: tuple of canonical NodeID text forms (empty tuple =
      "any subject selector");
    - ``conditions``: tuple of :class:`Condition` objects;
    - ``priority``: integer; higher beats lower where explicit (default 0);
    - ``specificity``: integer; higher beats lower where structurally
      represented and explicit (default 0);
    - ``valid_from`` / ``valid_until``: optional RFC 3339 UTC instants;
    - ``provenance``: free-form source metadata string;
    - ``version``: deterministic integer version/sequence for the rule;
    - ``extensions``: opaque WORK-003-style mappings.

    Rules are DATA. They MUST NOT contain executable code, arbitrary
    Python expressions, imported policy languages, or dynamic callbacks.
    Conflict resolution is a property of the policy set + engine, not
    of an individual rule.
    """

    rule_id: str
    domain: str
    effect: str
    operation: str
    subjects: Tuple[str, ...] = ()
    conditions: Tuple[Condition, ...] = ()
    priority: int = 0
    specificity: int = 0
    valid_from: str = ""
    valid_until: str = ""
    provenance: str = ""
    version: int = 0
    extensions: Tuple[Mapping[str, Any], ...] = field(default=())

    def __post_init__(self) -> None:
        if not isinstance(self.rule_id, str) or not self.rule_id:
            raise PolicyError(
                "rule-id",
                "rule_id must be a non-empty string (got %r)" % (self.rule_id,),
            )
        if not isinstance(self.domain, str) or self.domain not in PolicyDomain.values():
            raise PolicyError(
                "domain",
                "domain %r is not a frozen policy domain (known: %s)"
                % (self.domain, list(PolicyDomain.values())),
            )
        if not isinstance(self.effect, str) or self.effect not in Effect.values():
            raise PolicyError(
                "effect",
                "effect %r is not %r, %r, or %r"
                % (self.effect, Effect.ALLOW, Effect.DENY, Effect.REQUIRE_REVIEW),
            )
        if not isinstance(self.operation, str) or self.operation not in Operation.values():
            raise PolicyError(
                "operation",
                "operation %r is not a frozen policy operation (known: %s)"
                % (self.operation, list(Operation.values())),
            )
        if not isinstance(self.subjects, tuple):
            raise PolicyError(
                "subjects",
                "subjects must be a tuple of NodeID strings (got %s)"
                % type(self.subjects).__name__,
            )
        for s in self.subjects:
            if not isinstance(s, str):
                raise PolicyError(
                    "subjects",
                    "subjects entries must be strings (got %s)" % type(s).__name__,
                )
        if not isinstance(self.conditions, tuple):
            raise PolicyError(
                "conditions",
                "conditions must be a tuple of Condition (got %s)"
                % type(self.conditions).__name__,
            )
        for c in self.conditions:
            if not isinstance(c, Condition):
                raise PolicyError(
                    "conditions",
                    "conditions entries must be Condition instances (got %s)"
                    % type(c).__name__,
                )
        if isinstance(self.priority, bool) or not isinstance(self.priority, int):
            raise PolicyError(
                "priority",
                "rule %r priority must be an integer (got %s)"
                % (self.rule_id, type(self.priority).__name__),
            )
        if self.priority < 0 or self.priority > MAX_PRIORITY:
            raise PolicyError(
                "priority",
                "rule %r priority %d is out of range [0, %d]"
                % (self.rule_id, self.priority, MAX_PRIORITY),
            )
        if isinstance(self.specificity, bool) or not isinstance(self.specificity, int):
            raise PolicyError(
                "specificity",
                "rule %r specificity must be an integer (got %s)"
                % (self.rule_id, type(self.specificity).__name__),
            )
        if self.specificity < 0 or self.specificity > MAX_SPECIFICITY:
            raise PolicyError(
                "specificity",
                "rule %r specificity %d is out of range [0, %d]"
                % (self.rule_id, self.specificity, MAX_SPECIFICITY),
            )
        for label, value in (("valid_from", self.valid_from), ("valid_until", self.valid_until)):
            if not isinstance(value, str):
                raise PolicyError(
                    "temporal",
                    "%s must be a string (got %s)" % (label, type(value).__name__),
                )
        if not isinstance(self.provenance, str):
            raise PolicyError(
                "provenance",
                "rule %r provenance must be a string (got %s)"
                % (self.rule_id, type(self.provenance).__name__),
            )
        if isinstance(self.version, bool) or not isinstance(self.version, int):
            raise PolicyError(
                "version",
                "rule %r version must be an integer (got %s)"
                % (self.rule_id, type(self.version).__name__),
            )
        if self.version < 0:
            raise PolicyError(
                "version",
                "rule %r version %d must be non-negative" % (self.rule_id, self.version),
            )
        if not isinstance(self.extensions, tuple):
            raise PolicyError(
                "extensions",
                "extensions must be a tuple of mappings (got %s)"
                % type(self.extensions).__name__,
            )
        for ext in self.extensions:
            if not isinstance(ext, Mapping):
                raise PolicyError(
                    "extensions",
                    "extensions entries must be mappings (got %s)"
                    % type(ext).__name__,
                )

    def to_dict(self) -> dict:
        """Return the canonical dict form (used for serialization).

        Optional empty fields are omitted; absent members are never
        emitted as null. Order is deterministic via ``canonical_json_bytes``.
        """
        out: dict = {
            "rule_id": self.rule_id,
            "domain": self.domain,
            "effect": self.effect,
            "operation": self.operation,
        }
        if self.subjects:
            out["subjects"] = list(self.subjects)
        if self.conditions:
            out["conditions"] = [c.to_dict() for c in self.conditions]
        if self.priority:
            out["priority"] = self.priority
        if self.specificity:
            out["specificity"] = self.specificity
        if self.valid_from:
            out["valid_from"] = self.valid_from
        if self.valid_until:
            out["valid_until"] = self.valid_until
        if self.provenance:
            out["provenance"] = self.provenance
        if self.version:
            out["version"] = self.version
        if self.extensions:
            out["extensions"] = [dict(item) for item in self.extensions]
        return out


# --------------------------------------------------------------------------
# PolicySet / PolicyDocument
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class PolicySet:
    """A deterministic collection of rules belonging to one policy authority.

    Fields:
    - ``set_id``: stable non-empty string identifier;
    - ``version``: integer version/sequence for THIS policy set. This is
      a policy-owned concept: it MUST NOT be conflated with WORK-008
      resource-account versions or WORK-007 topology sequences (rule 9
      of the prompt's policy-store sequencing section).
    - ``issuer_node_id``: MANDATORY canonical WORK-004 NodeID text form
      (provenance of the policy, NOT truth of external facts --
      "issuer != truth"); every PolicySet MUST identify its authority/
      issuer in an access-independent manner (frozen "Policy authority
      and provenance" requirement). An empty/missing issuer is rejected
      at construction and at validation -- an anonymous policy MUST NOT
      be publishable or evaluable;
    - ``valid_from`` / ``valid_until``: optional RFC 3339 UTC instants;
    - ``rules``: tuple of :class:`PolicyRule`;
    - ``default_effect``: ``ALLOW`` or ``DENY`` -- the default when no
      rule matches AND the operation is non-privileged. For privileged
      operations, deny-by-default always wins regardless of
      ``default_effect`` (rule 9 of the prompt's conflict table);
    - ``domain_precedence``: tuple of :class:`PolicyDomain` values in
      explicit precedence order (higher precedence first). When two
      rules conflict and have equal priority/specificity, the one whose
      domain appears earlier in ``domain_precedence`` wins. This is an
      EXPLICIT, deterministic ordering -- never inferred from insertion
      order (rule 5 of the conflict-resolution semantics);
    - ``extensions``: opaque WORK-003-style mappings.

    The policy set does NOT perform evaluation; it carries data. The
    engine in :mod:`policy.evaluation` consumes an immutable snapshot.
    """

    set_id: str
    version: int
    rules: Tuple[PolicyRule, ...]
    issuer_node_id: str = ""
    valid_from: str = ""
    valid_until: str = ""
    default_effect: str = Effect.DENY
    domain_precedence: Tuple[str, ...] = ()
    extensions: Tuple[Mapping[str, Any], ...] = field(default=())

    def __post_init__(self) -> None:
        if not isinstance(self.set_id, str) or not self.set_id:
            raise PolicyError(
                "set-id",
                "set_id must be a non-empty string (got %r)" % (self.set_id,),
            )
        if isinstance(self.version, bool) or not isinstance(self.version, int):
            raise PolicyError(
                "version",
                "set %r version must be an integer (got %s)"
                % (self.set_id, type(self.version).__name__),
            )
        if self.version < 0:
            raise PolicyError(
                "version",
                "set %r version %d must be non-negative" % (self.set_id, self.version),
            )
        if not isinstance(self.rules, tuple):
            raise PolicyError(
                "rules",
                "rules must be a tuple of PolicyRule (got %s)"
                % type(self.rules).__name__,
            )
        for r in self.rules:
            if not isinstance(r, PolicyRule):
                raise PolicyError(
                    "rules",
                    "rules entries must be PolicyRule instances (got %s)"
                    % type(r).__name__,
                )
        # issuer_node_id is MANDATORY: every PolicySet MUST identify its
        # authority/issuer in an access-independent manner (frozen "Policy
        # authority and provenance" requirement; Architect review of PR #10,
        # blocker 1). An empty/missing issuer is rejected here at the
        # dataclass level so that anonymous policies cannot even be
        # constructed, regardless of whether validate_policy_set() is
        # called. The canonical-NodeID parse check happens in
        # validation.validate_policy_set (defense-in-depth).
        if not isinstance(self.issuer_node_id, str) or not self.issuer_node_id:
            raise PolicyError(
                "issuer",
                "issuer_node_id must be a non-empty canonical NodeID string "
                "(got %r); every PolicySet MUST identify its authority/issuer "
                "(frozen 'Policy authority and provenance' requirement)"
                % (self.issuer_node_id,),
            )
        for label, value in (("valid_from", self.valid_from), ("valid_until", self.valid_until)):
            if not isinstance(value, str):
                raise PolicyError(
                    "temporal",
                    "%s must be a string (got %s)" % (label, type(value).__name__),
                )
        # default_effect: only ALLOW or DENY (REQUIRE_REVIEW is a rule
        # effect, not a set-level default -- the default must be a
        # terminal decision).
        if not isinstance(self.default_effect, str) or self.default_effect not in (
            Effect.ALLOW,
            Effect.DENY,
        ):
            raise PolicyError(
                "default-effect",
                "default_effect %r must be %r or %r (REQUIRE_REVIEW is a rule effect, "
                "not a set-level default)" % (self.default_effect, Effect.ALLOW, Effect.DENY),
            )
        if not isinstance(self.domain_precedence, tuple):
            raise PolicyError(
                "domain-precedence",
                "domain_precedence must be a tuple of PolicyDomain strings (got %s)"
                % type(self.domain_precedence).__name__,
            )
        for d in self.domain_precedence:
            if not isinstance(d, str) or d not in PolicyDomain.values():
                raise PolicyError(
                    "domain-precedence",
                    "domain_precedence entry %r is not a frozen policy domain" % (d,),
                )
        # No domain may appear twice in the precedence list (determinism).
        if len(set(self.domain_precedence)) != len(self.domain_precedence):
            raise PolicyError(
                "domain-precedence",
                "domain_precedence contains duplicates (must be a strict ordering)",
            )
        if not isinstance(self.extensions, tuple):
            raise PolicyError(
                "extensions",
                "extensions must be a tuple of mappings (got %s)"
                % type(self.extensions).__name__,
            )
        for ext in self.extensions:
            if not isinstance(ext, Mapping):
                raise PolicyError(
                    "extensions",
                    "extensions entries must be mappings (got %s)"
                    % type(ext).__name__,
                )

    def to_dict(self) -> dict:
        out: dict = {
            "set_id": self.set_id,
            "version": self.version,
        }
        if self.issuer_node_id:
            out["issuer_node_id"] = self.issuer_node_id
        if self.valid_from:
            out["valid_from"] = self.valid_from
        if self.valid_until:
            out["valid_until"] = self.valid_until
        out["default_effect"] = self.default_effect
        if self.domain_precedence:
            out["domain_precedence"] = list(self.domain_precedence)
        out["rules"] = [r.to_dict() for r in self.rules]
        if self.extensions:
            out["extensions"] = [dict(item) for item in self.extensions]
        return out

    def canonical_bytes(self) -> bytes:
        """Return canonical JSON bytes of the policy set (WORK-003 machinery)."""
        try:
            return canonical_json_bytes(self.to_dict())
        except CanonicalizationError as error:  # pragma: no cover - defensive
            raise PolicyError(
                "canonical",
                "policy set is not canonically representable: %s" % error,
            ) from error


# --------------------------------------------------------------------------
# PolicyContext (snapshot of evaluation inputs; treated as facts/claims)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class PolicyContext:
    """A snapshot of evaluation inputs.

    Carries references to facts/claims produced by earlier authorities.
    The context MUST be treated as INPUT, not rewritten into new
    authoritative state. The engine MUST NOT mutate any field of any
    referenced object (WORK-007/008/009/004 authorities).

    Fields:
    - ``requester_node_id``: optional canonical NodeID text form;
    - ``credential_active``: optional bool. If True, the requester's
      credential is ACTIVE (caller asserts this from WORK-004 lifecycle).
      If False, the credential is not active. If None, the credential
      state is unknown -> deny-by-default for credential-active
      predicates (MISSING_FACT);
    - ``operation``: one of the frozen :class:`Operation` values;
    - ``normalized_intent_digest``: optional content digest of a WORK-009
      NormalizedIntent (the intent is consumed by reference; policy MUST
      NOT rewrite the intent or downgrade hard constraints). When non-
      empty, it MUST be structurally a valid 64-lowercase-hex sha256-
      style digest (``is_valid_content_digest``); a malformed value such
      as ``"not-an-intent"`` is rejected at construction and at
      validation so it can never satisfy ``INTENT_PRESENT`` and never
      participate in an allow rule (Architect review of PR #10,
      blocker 2);
    - ``resource_refs``: tuple of resource identifier strings;
    - ``resource_owner_node_id``: optional NodeID text form;
    - ``resource_kind``: optional WORK-008 ResourceKind string;
    - ``topology_evidence_refs``: tuple of evidence identifier strings.
      These are REFERENCES, not authoritative facts: a policy rule may
      say "deny based on reporter X's untrusted claim" but MUST NOT
      promote that claim into topology authority (LOCK-008);
    - ``locality_labels``: tuple of explicit string labels (e.g. "village-A");
    - ``federation_domain``: optional string;
    - ``privacy_requirements``: tuple of explicit requirement strings
      (e.g. "end-to-end", "no-relay-X");
    - ``emergency``: bool, default False;
    - ``service_class``: optional string (e.g. "hospital-critical");
    - ``energy_reserve_current`` / ``energy_reserve_threshold``: optional
      integers (WORK-008 energy facts consumed by reference; policy MUST
      NOT mutate EnergyState);
    - ``capability_evidence_refs``: tuple of capability identifier strings;
    - ``trust_assertions``: tuple of (classification, value) pairs --
      explicit INPUTS, NOT a computed trust score (WORK-010 MUST NOT
      invent a reputation engine);
    - ``evaluation_instant``: RFC 3339 UTC instant -- INJECTED, never
      wall-clock. Rules MUST fail closed when their validity window
      cannot be evaluated safely;
    - ``extensions``: opaque WORK-003-style mappings.
    """

    operation: str
    requester_node_id: str = ""
    credential_active: Optional[bool] = None
    normalized_intent_digest: str = ""
    resource_refs: Tuple[str, ...] = ()
    resource_owner_node_id: str = ""
    resource_kind: str = ""
    topology_evidence_refs: Tuple[str, ...] = ()
    locality_labels: Tuple[str, ...] = ()
    federation_domain: str = ""
    privacy_requirements: Tuple[str, ...] = ()
    emergency: bool = False
    service_class: str = ""
    energy_reserve_current: Optional[int] = None
    energy_reserve_threshold: Optional[int] = None
    capability_evidence_refs: Tuple[str, ...] = ()
    trust_assertions: Tuple[Tuple[str, str], ...] = ()
    evaluation_instant: str = ""
    extensions: Tuple[Mapping[str, Any], ...] = field(default=())

    def __post_init__(self) -> None:
        if not isinstance(self.operation, str) or self.operation not in Operation.values():
            raise PolicyError(
                "operation",
                "context operation %r is not a frozen policy operation (known: %s)"
                % (self.operation, list(Operation.values())),
            )
        if not isinstance(self.requester_node_id, str):
            raise PolicyError(
                "requester",
                "requester_node_id must be a string (got %s)"
                % type(self.requester_node_id).__name__,
            )
        if self.credential_active is not None and not isinstance(self.credential_active, bool):
            raise PolicyError(
                "credential-active",
                "credential_active must be None or bool (got %s)"
                % type(self.credential_active).__name__,
            )
        if not isinstance(self.normalized_intent_digest, str):
            raise PolicyError(
                "intent-digest",
                "normalized_intent_digest must be a string (got %s)"
                % type(self.normalized_intent_digest).__name__,
            )
        # Structural validation: a non-empty intent digest MUST be a valid
        # 64-lowercase-hex content digest. A malformed value (e.g. "not-an-
        # intent") MUST NOT satisfy INTENT_PRESENT and MUST NOT participate
        # in an allow rule (Architect review of PR #10, blocker 2). The
        # check is structural only -- policy does not re-derive the digest
        # (the intent layer owns that authority). Empty string is permitted
        # (means "no intent referenced").
        if self.normalized_intent_digest and not is_valid_content_digest(
            self.normalized_intent_digest
        ):
            raise PolicyError(
                "intent-digest",
                "normalized_intent_digest %r is not a valid content digest "
                "(64 lowercase hex); a malformed intent reference cannot "
                "satisfy intent-present (fail closed)"
                % (self.normalized_intent_digest,),
            )
        for label, value in (
            ("resource_refs", self.resource_refs),
            ("topology_evidence_refs", self.topology_evidence_refs),
            ("locality_labels", self.locality_labels),
            ("privacy_requirements", self.privacy_requirements),
            ("capability_evidence_refs", self.capability_evidence_refs),
        ):
            if not isinstance(value, tuple):
                raise PolicyError(
                    "context",
                    "%s must be a tuple of strings (got %s)" % (label, type(value).__name__),
                )
            for item in value:
                if not isinstance(item, str):
                    raise PolicyError(
                        "context",
                        "%s entries must be strings (got %s)" % (label, type(item).__name__),
                    )
        if not isinstance(self.resource_owner_node_id, str):
            raise PolicyError(
                "resource-owner",
                "resource_owner_node_id must be a string (got %s)"
                % type(self.resource_owner_node_id).__name__,
            )
        if not isinstance(self.resource_kind, str):
            raise PolicyError(
                "resource-kind",
                "resource_kind must be a string (got %s)"
                % type(self.resource_kind).__name__,
            )
        if not isinstance(self.federation_domain, str):
            raise PolicyError(
                "federation-domain",
                "federation_domain must be a string (got %s)"
                % type(self.federation_domain).__name__,
            )
        if not isinstance(self.emergency, bool):
            raise PolicyError(
                "emergency",
                "emergency must be a bool (got %s)" % type(self.emergency).__name__,
            )
        if not isinstance(self.service_class, str):
            raise PolicyError(
                "service-class",
                "service_class must be a string (got %s)"
                % type(self.service_class).__name__,
            )
        for en_label, en_value in (
            ("energy_reserve_current", self.energy_reserve_current),
            ("energy_reserve_threshold", self.energy_reserve_threshold),
        ):
            if en_value is not None:
                if isinstance(en_value, bool) or not isinstance(en_value, int):
                    raise PolicyError(
                        "energy",
                        "%s must be None or int (got %s)" % (en_label, type(en_value).__name__),
                    )
                if en_value < 0:
                    raise PolicyError(
                        "energy",
                        "%s must be non-negative (got %d)" % (en_label, en_value),
                    )
        if not isinstance(self.trust_assertions, tuple):
            raise PolicyError(
                "trust-assertions",
                "trust_assertions must be a tuple of (classification, value) pairs (got %s)"
                % type(self.trust_assertions).__name__,
            )
        for ta in self.trust_assertions:
            if not isinstance(ta, tuple) or len(ta) != 2:
                raise PolicyError(
                    "trust-assertions",
                    "trust_assertions entries must be 2-tuples (got %r)" % (ta,),
                )
            if not isinstance(ta[0], str) or not isinstance(ta[1], str):
                raise PolicyError(
                    "trust-assertions",
                    "trust_assertions entries must be (str, str) (got %r)" % (ta,),
                )
        if not isinstance(self.evaluation_instant, str):
            raise PolicyError(
                "evaluation-instant",
                "evaluation_instant must be a string (got %s)"
                % type(self.evaluation_instant).__name__,
            )
        if not isinstance(self.extensions, tuple):
            raise PolicyError(
                "extensions",
                "extensions must be a tuple of mappings (got %s)"
                % type(self.extensions).__name__,
            )
        for ext in self.extensions:
            if not isinstance(ext, Mapping):
                raise PolicyError(
                    "extensions",
                    "extensions entries must be mappings (got %s)"
                    % type(ext).__name__,
                )

    def to_dict(self) -> dict:
        out: dict = {"operation": self.operation}
        if self.requester_node_id:
            out["requester_node_id"] = self.requester_node_id
        if self.credential_active is not None:
            out["credential_active"] = self.credential_active
        if self.normalized_intent_digest:
            out["normalized_intent_digest"] = self.normalized_intent_digest
        if self.resource_refs:
            out["resource_refs"] = list(self.resource_refs)
        if self.resource_owner_node_id:
            out["resource_owner_node_id"] = self.resource_owner_node_id
        if self.resource_kind:
            out["resource_kind"] = self.resource_kind
        if self.topology_evidence_refs:
            out["topology_evidence_refs"] = list(self.topology_evidence_refs)
        if self.locality_labels:
            out["locality_labels"] = list(self.locality_labels)
        if self.federation_domain:
            out["federation_domain"] = self.federation_domain
        if self.privacy_requirements:
            out["privacy_requirements"] = list(self.privacy_requirements)
        if self.emergency:
            out["emergency"] = True
        if self.service_class:
            out["service_class"] = self.service_class
        if self.energy_reserve_current is not None:
            out["energy_reserve_current"] = self.energy_reserve_current
        if self.energy_reserve_threshold is not None:
            out["energy_reserve_threshold"] = self.energy_reserve_threshold
        if self.capability_evidence_refs:
            out["capability_evidence_refs"] = list(self.capability_evidence_refs)
        if self.trust_assertions:
            out["trust_assertions"] = [[c, v] for c, v in self.trust_assertions]
        if self.evaluation_instant:
            out["evaluation_instant"] = self.evaluation_instant
        if self.extensions:
            out["extensions"] = [dict(item) for item in self.extensions]
        return out


# --------------------------------------------------------------------------
# PolicyDecision (immutable, deterministic, auditable)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class PolicyDecision:
    """Immutable deterministic policy evaluation result.

    Fields:
    - ``decision_id``: content-derived digest
      ``sha256(canonical_json_bytes(content_dict()))`` (64 lowercase hex).
      A fingerprint for cache-keying / duplicate-detection; NOT a NodeID
      and NOT an identity authority;
    - ``effect``: the terminal effect (``ALLOW``, ``DENY``,
      ``DEFAULT_DENY`` -- never ``REQUIRE_REVIEW`` at the decision level;
      REQUIRE_REVIEW rules surface as ``DENY`` + ``FAIL_CLOSED`` if
      unresolved, or as the winning effect's complement otherwise);
    - ``code``: one of the frozen :class:`DecisionCode` values;
    - ``detail``: deterministic human-readable diagnostics (no secrets);
    - ``matched_rule_ids``: tuple of rule_id strings that participated;
    - ``policy_set_id`` / ``policy_set_version``: identity of the
      evaluated policy set;
    - ``evaluation_instant``: the injected instant that was used;
    - ``conflict_trace``: tuple of strings describing how conflicts
      resolved (auditable; deterministic ordering);
    - ``extensions``: opaque WORK-003-style mappings.

    The decision MUST NOT claim that a resource, route, topology fact,
    identity, or capability is intrinsically true merely because policy
    allowed an operation. It carries only the authorization result.
    """

    decision_id: str
    effect: str
    code: str
    detail: str
    matched_rule_ids: Tuple[str, ...]
    policy_set_id: str
    policy_set_version: int
    evaluation_instant: str
    conflict_trace: Tuple[str, ...] = ()
    extensions: Tuple[Mapping[str, Any], ...] = field(default=())

    def __post_init__(self) -> None:
        if not isinstance(self.decision_id, str) or not self.decision_id:
            raise PolicyError(
                "decision-id",
                "decision_id must be a non-empty string (got %r)" % (self.decision_id,),
            )
        if not isinstance(self.effect, str) or self.effect not in (
            Effect.ALLOW,
            Effect.DENY,
        ):
            raise PolicyError(
                "effect",
                "decision effect %r must be %r or %r (REQUIRE_REVIEW is a rule effect; "
                "decisions are terminal ALLOW/DENY)"
                % (self.effect, Effect.ALLOW, Effect.DENY),
            )
        if not isinstance(self.code, str) or self.code not in DecisionCode.values():
            raise PolicyError(
                "code",
                "decision code %r is not a frozen decision code (known: %s)"
                % (self.code, list(DecisionCode.values())),
            )
        if not isinstance(self.detail, str):
            raise PolicyError(
                "detail",
                "detail must be a string (got %s)" % type(self.detail).__name__,
            )
        if not isinstance(self.matched_rule_ids, tuple):
            raise PolicyError(
                "matched-rule-ids",
                "matched_rule_ids must be a tuple of strings (got %s)"
                % type(self.matched_rule_ids).__name__,
            )
        for rid in self.matched_rule_ids:
            if not isinstance(rid, str):
                raise PolicyError(
                    "matched-rule-ids",
                    "matched_rule_ids entries must be strings (got %s)"
                    % type(rid).__name__,
                )
        if not isinstance(self.policy_set_id, str) or not self.policy_set_id:
            raise PolicyError(
                "policy-set-id",
                "policy_set_id must be a non-empty string (got %r)" % (self.policy_set_id,),
            )
        if isinstance(self.policy_set_version, bool) or not isinstance(self.policy_set_version, int):
            raise PolicyError(
                "policy-set-version",
                "policy_set_version must be an integer (got %s)"
                % type(self.policy_set_version).__name__,
            )
        if self.policy_set_version < 0:
            raise PolicyError(
                "policy-set-version",
                "policy_set_version %d must be non-negative" % self.policy_set_version,
            )
        if not isinstance(self.evaluation_instant, str):
            raise PolicyError(
                "evaluation-instant",
                "evaluation_instant must be a string (got %s)"
                % type(self.evaluation_instant).__name__,
            )
        if not isinstance(self.conflict_trace, tuple):
            raise PolicyError(
                "conflict-trace",
                "conflict_trace must be a tuple of strings (got %s)"
                % type(self.conflict_trace).__name__,
            )
        for line in self.conflict_trace:
            if not isinstance(line, str):
                raise PolicyError(
                    "conflict-trace",
                    "conflict_trace entries must be strings (got %s)"
                    % type(line).__name__,
                )
        if not isinstance(self.extensions, tuple):
            raise PolicyError(
                "extensions",
                "extensions must be a tuple of mappings (got %s)"
                % type(self.extensions).__name__,
            )
        for ext in self.extensions:
            if not isinstance(ext, Mapping):
                raise PolicyError(
                    "extensions",
                    "extensions entries must be mappings (got %s)"
                    % type(ext).__name__,
                )

    def content_dict(self) -> dict:
        """Return the canonical *content* dict -- the dict over which the
        ``decision_id`` is computed, deliberately EXCLUDING the
        ``decision_id`` field (a content fingerprint that included itself
        would be circular and unsatisfiable).

        Public invariant (callers MAY rely on this):

            sha256(canonical_bytes()) == self.decision_id
        """
        out: dict = {
            "effect": self.effect,
            "code": self.code,
            "policy_set_id": self.policy_set_id,
            "policy_set_version": self.policy_set_version,
        }
        if self.evaluation_instant:
            out["evaluation_instant"] = self.evaluation_instant
        if self.matched_rule_ids:
            out["matched_rule_ids"] = list(self.matched_rule_ids)
        if self.conflict_trace:
            out["conflict_trace"] = list(self.conflict_trace)
        if self.detail:
            out["detail"] = self.detail
        if self.extensions:
            out["extensions"] = [dict(item) for item in self.extensions]
        return out

    def to_dict(self) -> dict:
        """Return the serialized dict form, INCLUDING the ``decision_id``
        field for storage / transmission convenience.

        This is NOT the representation over which the digest is computed
        -- use :meth:`content_dict` (or :meth:`canonical_bytes`) for
        that. The decision_id field is metadata about the content.
        """
        out: dict = {
            "decision_id": self.decision_id,
            "effect": self.effect,
            "code": self.code,
            "policy_set_id": self.policy_set_id,
            "policy_set_version": self.policy_set_version,
        }
        if self.evaluation_instant:
            out["evaluation_instant"] = self.evaluation_instant
        if self.matched_rule_ids:
            out["matched_rule_ids"] = list(self.matched_rule_ids)
        if self.conflict_trace:
            out["conflict_trace"] = list(self.conflict_trace)
        if self.detail:
            out["detail"] = self.detail
        if self.extensions:
            out["extensions"] = [dict(item) for item in self.extensions]
        return out

    def canonical_bytes(self) -> bytes:
        """Return the canonical JSON bytes (UTF-8) over which the
        ``decision_id`` was computed.

        Public invariant (callers MAY rely on this):

            sha256(canonical_bytes()) == self.decision_id
        """
        try:
            return canonical_json_bytes(self.content_dict())
        except CanonicalizationError as error:  # pragma: no cover - defensive
            raise PolicyError(
                "canonical",
                "decision is not canonically representable: %s" % error,
            ) from error


# --------------------------------------------------------------------------
# PolicyEvaluationResult (explicit success/failure envelope)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class PolicyEvaluationResult:
    """The outcome of :func:`policy.evaluation.evaluate`.

    On success: ``ok`` is True, ``code`` is the decision code, ``detail``
    is deterministic diagnostics, and ``decision`` carries the
    :class:`PolicyDecision`. On failure: ``ok`` is False, ``code`` is a
    stable machine-readable error code, ``detail`` is deterministic
    diagnostics, ``decision`` is None. The result NEVER raises; callers
    switch on ``code``.
    """

    ok: bool
    code: str
    detail: str
    decision: Optional[PolicyDecision] = None


__all__ = [
    "PolicyError",
    "Effect",
    "DecisionCode",
    "PolicyDomain",
    "Operation",
    "Privileged",
    "Condition",
    "PolicyRule",
    "PolicySet",
    "PolicyContext",
    "PolicyDecision",
    "PolicyEvaluationResult",
    "MAX_PRIORITY",
    "MAX_SPECIFICITY",
]
