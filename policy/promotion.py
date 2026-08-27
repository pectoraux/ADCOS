"""WORK-026 telemetry topology-promotion binding vocabulary and
derivation.

Authority statement (the WORK-025 accepted pattern, applied to the
WORK-026 "policy-controlled authority" acceptance criterion):

    WORK-010 policy authority / composition root
            ->
    decision already bound to the exact promotion scope
            ->
    telemetry verification + extraction ONLY
            ->
    authorized topology-promotion export

This module is where the FIRST arrow lives.  The promotion scope a
``telemetry.topology-promote`` policy decision authorizes -- the exact
``(observation_id, subject_kind, subject_ref)`` triple -- is
established HERE, inside the policy authority, from the EVALUATION
CONTEXT the rules actually evaluated.  It is not a post-hoc
decoration any downstream layer can append to an unrelated decision:
the composition root declares the promotion scope as an opaque
descriptor inside ``PolicyContext.extensions`` (the frozen
WORK-003-style surface), the engine derives the binding with strict
mirror checks against the context's first-class ``resource_refs``, and
the resulting :class:`~policy.model.PolicyDecision` is BORN with the
binding among its own ``extensions`` -- covered by the decision's
content-derived ``decision_id`` digest.

What this structurally guarantees:

- a promotion ALLOW can never be replayed onto a different
  observation: rebinding the descriptor breaks the digest, and the
  telemetry layer (WORK-026) re-derives the authorized scope from the
  stored observation and fails closed on any divergence;
- a ``telemetry.topology-promote`` context without a valid descriptor
  FAILS CLOSED at evaluation (``INVALID_POLICY``): the engine never
  emits an unbound promotion decision, so the only decisions that can
  exist for the frozen promotion operation already carry their exact
  promotion scope;
- the ``telemetry`` package possesses NO binding-construction
  capability at all -- it verifies the digest and extracts the scope
  (``telemetry.authorization``), which is the third arrow of the trust
  chain above.  There is deliberately no function anywhere in the
  ``telemetry`` package that can turn an arbitrary ALLOW into a bound
  promotion ALLOW.

The descriptor schema is deliberately minimal and technology-neutral
(LOCK-001/002/003/004): opaque identifiers owned by their respective
authorities, no vendor/platform vocabulary, no executable content.
The policy authority does NOT interpret telemetry identifier FORMATS
(that remains ``telemetry.validation``); it enforces only the
structural schema and the context mirror, and copies the descriptor
verbatim.
"""

from __future__ import annotations

from typing import Any, Mapping

from .model import Operation, PolicyContext, PolicyError

#: Discriminator carried inside the promotion descriptor (context
#: side) and the promotion binding (decision side).  The descriptor
#: rides in the context's opaque WORK-003-style ``extensions``; this
#: marker is what the POLICY authority looks for when deriving the
#: binding, so foreign extensions can never be mistaken for a
#: promotion descriptor.  Owned HERE (the authority), consumed by the
#: engine and re-exported read-only by the telemetry layer.
PROMOTION_BINDING_KIND = "adcos.telemetry-topology-promotion"

#: The exact key set of a promotion descriptor / binding mapping
#: (strict schema: unknown keys fail closed, so nothing can be
#: smuggled alongside the authorized promotion scope).
PROMOTION_BINDING_KEYS = frozenset(
    {
        "kind",
        "operation",
        "observation_id",
        "subject_kind",
        "subject_ref",
    }
)


def promotion_binding_from_context(
    context: PolicyContext,
) -> Mapping[str, Any]:
    """Derive the promotion binding for a
    ``telemetry.topology-promote`` context.

    The descriptor must be present in ``context.extensions`` EXACTLY
    once, carry exactly :data:`PROMOTION_BINDING_KEYS`, have string
    values, declare the frozen ``telemetry.topology-promote``
    operation, carry a non-empty ``observation_id``, ``subject_kind``
    and ``subject_ref``, and MIRROR the context's first-class facts:

    - ``descriptor["subject_ref"]`` must be among
      ``context.resource_refs`` (the rules must have evaluated the
      promoted subject);
    - ``descriptor["observation_id"]`` must be among
      ``context.resource_refs`` (the rules must have evaluated the
      exact observation being promoted).

    A descriptor that disagrees with the context it rides in is a
    self-inconsistent authorization input: the rules evaluated the
    first-class fields, so the binding must restate exactly those
    facts.

    Returns the validated descriptor as a plain mapping (verbatim
    content).  Raises :class:`~policy.model.PolicyError` with code
    ``promotion-binding`` on ANY violation -- the engine turns that
    into a fail-closed ``INVALID_POLICY`` evaluation outcome, so a
    malformed or missing descriptor can never produce an unbound
    promotion decision.
    """
    if not isinstance(context, PolicyContext):
        raise PolicyError(
            "promotion-binding",
            "promotion binding derivation requires a genuine "
            "policy.model.PolicyContext (got %s)"
            % type(context).__name__,
        )
    if context.operation != Operation.TELEMETRY_TOPOLOGY_PROMOTE:
        raise PolicyError(
            "promotion-binding",
            "promotion binding derivation requires the frozen %r "
            "operation (context operation is %r)"
            % (Operation.TELEMETRY_TOPOLOGY_PROMOTE, context.operation),
        )
    descriptors = []
    for extension in context.extensions:
        kind = extension.get("kind") if hasattr(extension, "get") else None
        if kind == PROMOTION_BINDING_KIND:
            descriptors.append(extension)
    if not descriptors:
        raise PolicyError(
            "promotion-binding",
            "telemetry.topology-promote context carries no %r promotion "
            "descriptor in extensions -- the exact promotion scope "
            "(observation, subject kind, subject ref) must be declared "
            "up front; the engine never emits an unbound promotion "
            "decision (fail closed)" % (PROMOTION_BINDING_KIND,),
        )
    if len(descriptors) > 1:
        raise PolicyError(
            "promotion-binding",
            "telemetry.topology-promote context carries %d %r promotion "
            "descriptors (exactly one is required; ambiguity fails "
            "closed)" % (len(descriptors), PROMOTION_BINDING_KIND),
        )
    descriptor = descriptors[0]
    keys = set(descriptor.keys())
    unknown = keys - PROMOTION_BINDING_KEYS
    if unknown:
        raise PolicyError(
            "promotion-binding",
            "promotion descriptor carries unknown keys %s (strict "
            "schema; nothing rides alongside the authorized promotion "
            "scope)" % (sorted(unknown),),
        )
    missing = PROMOTION_BINDING_KEYS - keys
    if missing:
        raise PolicyError(
            "promotion-binding",
            "promotion descriptor is missing keys %s"
            % (sorted(missing),),
        )
    for key in sorted(PROMOTION_BINDING_KEYS):
        if not isinstance(descriptor[key], str):
            raise PolicyError(
                "promotion-binding",
                "promotion descriptor key %r must be a string (got %s)"
                % (key, type(descriptor[key]).__name__),
            )
    if descriptor["operation"] != Operation.TELEMETRY_TOPOLOGY_PROMOTE:
        raise PolicyError(
            "promotion-binding",
            "promotion descriptor declares operation %r, not the frozen "
            "%r operation"
            % (descriptor["operation"], Operation.TELEMETRY_TOPOLOGY_PROMOTE),
        )
    for required in ("observation_id", "subject_kind", "subject_ref"):
        if not descriptor[required]:
            raise PolicyError(
                "promotion-binding",
                "promotion descriptor carries an empty %s (the authorized "
                "promotion scope is never optional)" % (required,),
            )
    # Mirror checks: the binding must restate exactly the first-class
    # facts the rules evaluated.  A descriptor that disagrees with its
    # own context is a self-inconsistent authorization input -- the
    # authorized promotion scope would not be the evaluated scope.
    resource_refs = tuple(context.resource_refs)
    if descriptor["subject_ref"] not in resource_refs:
        raise PolicyError(
            "promotion-binding",
            "promotion descriptor subject_ref is not among the "
            "context resource_refs the rules evaluated (the promoted "
            "subject must be exactly what the rules saw; fail closed)",
        )
    if descriptor["observation_id"] not in resource_refs:
        raise PolicyError(
            "promotion-binding",
            "promotion descriptor observation_id is not among the "
            "context resource_refs the rules evaluated (the promoted "
            "observation must be exactly what the rules saw; fail "
            "closed)",
        )
    return dict(descriptor)


__all__ = [
    "PROMOTION_BINDING_KIND",
    "PROMOTION_BINDING_KEYS",
    "promotion_binding_from_context",
]
