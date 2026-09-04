"""WORK-050 versioned auditable history (W050.3).

The HISTORY layer of the versioned platform capability registry:
:class:`CompatibilityHistory` preserves ALREADY-PRODUCED W050.2
compatibility-evaluation results
(:class:`~platformcaps.evaluation.CompatibilityEvaluation`) as
immutable, versioned, append-only, content-addressed historical
decision records, and reconstructs them deterministically from
their canonical serialization:

    CompatibilityEvaluation
        |
        v
    immutable historical decision record
        |
        +-- versioned        (its own frozen history schema dimension)
        +-- append-only      (functional append; no update/delete/upsert)
        +-- content-addressed (SHA-256 over the canonical record content)
        +-- deterministic identity (no clock, no randomness, no counters)
        +-- deterministic replay / restoration (byte-identical)

What this layer is NOT (the frozen W050.3 boundary — history owns
exactly ONE concern, the preservation and deterministic
reconstruction of prior W050 compatibility-evaluation outcomes):

    history  !=  a second evaluator (it NEVER recomputes
                 compatibility: it consumes the W050.2 result
                 object as DATA, imports no registry, consults
                 none, and never refreshes a preserved record
                 against current declarations)
              !=  policy
              !=  permission / authorization
              !=  proven enforcement
              !=  active connectivity
              !=  physical evidence

History invariants (frozen, all enforced at construction):

1. IMMUTABLE — a preserved record never changes: records are
   frozen dataclasses carrying an already-frozen W050.2 result,
   and the history CONTAINER itself is frozen exactly like the
   W050.1-corrected registry (construction is the only writer,
   through the base-object setter ONLY; public
   ``__setattr__``/``__delattr__`` raise unconditionally —
   private slots, new attributes, ``__class__`` reassignment,
   and re-initialization are all rejected; the deliberate
   ``object.__setattr__`` escape hatch is outside the contract).
2. APPEND-ONLY — there is no in-place update, no delete, and no
   upsert anywhere: ``append`` is FUNCTIONAL (it returns a NEW
   frozen history; the history it was called on is unchanged),
   so a lineage only ever ACCUMULATES records, and an existing
   record's content and identity can never be replaced.
3. CONTENT-ADDRESSED decision identity — every record's
   ``decision_id`` is SHA-256 over the canonical JSON bytes of
   the exact record content (the history schema dimension plus
   the exact canonical W050.2 result), reproducible from
   identical content and derived from NOTHING else: no
   wall-clock time, no process id, no memory address, no
   randomness, no insertion counter, no hash-iteration order,
   no environment state.  A supplied id that does not digest
   the content it labels is rejected at construction (forged
   or tampered; fail closed) — the W049 content-derived-id
   discipline, enforced at record construction, again at store
   assembly, and again at replay.
4. VERSIONED as its own dimension — the history schema version
   (:data:`HISTORY_SCHEMA_VERSION`) is the shape of the
   historical record/container.  It is NOT the registry version
   (the version of capability declarations) and NOT the
   evaluation ``schema_version`` (the shape of the evaluation
   result): the three dimensions are deliberately distinct, and
   a history schema mismatch fails closed (SCHEMA_INVALID — no
   best-effort interpretation, no silent migration, no
   coercion).
5. PROVENANCE-PRESERVING — a stored decision preserves the
   exact W050.2 provenance (registry_version, registry_digest,
   platform_id, role, sharing_mode, composed state, findings,
   component states, required mechanisms, minimum security
   properties, restrictions, evidence references, evidence
   class).  History NEVER reconstructs provenance from a
   current registry and NEVER refreshes a historical record
   against the latest declarations: REGISTRY EVOLUTION NEVER
   REWRITES HISTORY — a record produced from registry V1 stays
   byte-identical and semantically identical after V2 exists.
6. DETERMINISTIC — canonical serialization emits the records in
   canonical decision-id order (never insertion order, never
   set/dict iteration order), so identical history content
   yields byte-identical serialization and ``content_digest``
   regardless of append order, repeat count, or hash-seed
   configuration.
7. IDEMPOTENT identical-append discipline — appending the exact
   same evaluation content twice preserves ONE record under the
   SAME decision_id and leaves the history digest unchanged;
   conflicting content under the same derived identity is
   impossible under correct hashing and nonetheless fails
   closed (DUPLICATE_CONFLICT — never first-wins, never
   last-wins, never overwrite, never merge).
8. RESTORATION fail-closed — :meth:`restore \
   <CompatibilityHistory.restore>` accepts exactly the canonical
   serialized history (the parsed mapping or the canonical JSON
   bytes; duplicate JSON object keys are rejected): history
   schema (container and record levels), record structure,
   decision identity, the contained evaluation structure,
   registry provenance, evidence class, finding vocabulary,
   state vocabulary, deterministic ordering, and duplicate
   discipline are all validated, and the contained evaluation
   payload is reconstructed THROUGH the accepted W050.2
   constructor (its frozen invariants and typed reasons apply;
   no unchecked object creation).  No invalid historical object
   can enter the store through restoration.

Typed errors (frozen — this stage adds NO reason code and no
stringly-typed reason anywhere): history failures REUSE the
accepted W050 reason vocabulary.  INVALID_INPUT covers malformed
input at every history boundary (including a forged or tampered
record id and a non-canonical serialization); SCHEMA_INVALID
covers a history-schema mismatch at either level (and an
evaluation-payload schema mismatch); DUPLICATE_CONFLICT covers
content conflicting under one derived identity; UNKNOWN_PLATFORM
is the store's unresolved-content-address reason, reused for a
decision id that does not resolve in the history (the same
fail-closed never-implicitly-absent rule the registry applies to
a platform id that does not resolve in the registry — one
vocabulary, no second taxonomy); every evaluation-vocabulary
violation (CAPABILITY_INVALID, ROLE_INVALID,
SHARING_MODE_INVALID, MECHANISM_INVALID, RESTRICTION_INVALID,
PROPERTY_INVALID, VERSION_INVALID, EVIDENCE_INVALID) propagates
from the W050.2 constructor during payload reconstruction —
history never re-implements the evaluation vocabulary (it is a
persistence/audit boundary, not a semantic boundary).

No temporal semantics (frozen): "historical" NEVER means
wall-clock timestamps here — records carry NO
created_at/appended_at/timestamp/nonce/sequence-number fields,
and the canonical order derives ONLY from stable record data
(the content-derived decision ids), never from insertion
timing.

No external authority (frozen): this module consults NOTHING
but its inputs — no OS APIs, no platform adapters, no W048, no
W049, no NetworkPath, no transport, no identity/session state,
no payment, no usage, no marketplace, no physical evidence.  It
imports no registry; it records results, it does not evaluate.

What this module deliberately does NOT contain (the W050.3 stop
boundary): the deterministic permanent battery and CI wiring
(tools/platformcaps_selftest.py does not exist at this stage —
that is W050.4), W048/W049 integration, platform enforcement,
and any OS firewall/tether/VPN/proxy behavior.  The W050
sequence remains: declaration registry -> deterministic
evaluation -> THIS stage (versioned auditable history) ->
deterministic verification + CI.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Dict, Iterable, List, Mapping, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import PlatformCapabilityError, PlatformCapabilityReasonCode
from .evaluation import CompatibilityEvaluation
from .model import SCHEMA_VERSION

#: The frozen history schema version — the shape dimension of the
#: historical record/container.  Deliberately its OWN dimension: it
#: is not the registry version (the version of capability
#: declarations) and not the evaluation ``schema_version`` (the
#: shape of the evaluation result).  A serialized history whose
#: schema is not exactly this value fails closed (SCHEMA_INVALID).
HISTORY_SCHEMA_VERSION = "1"

_SHA256_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")

#: the exact key set of a serialized historical decision record
#: (the canonical form this schema defines — a record carrying
#: unknown or missing members is not a record this schema defines)
_RECORD_KEYS = frozenset(("history_schema_version", "decision_id", "evaluation"))

#: the exact key set of a serialized history container
_CONTAINER_KEYS = frozenset(("history_schema_version", "records"))

#: the exact key set of the canonical W050.2 evaluation payload
#: (the frozen ``CompatibilityEvaluation.to_dict`` form history
#: persists and reconstructs)
_EVALUATION_KEYS = frozenset(
    (
        "schema_version",
        "registry_version",
        "registry_digest",
        "platform_id",
        "role",
        "sharing_mode",
        "state",
        "restrictions",
        "findings",
        "role_state",
        "sharing_mode_state",
        "required_mechanisms",
        "mechanism_states",
        "mechanism_minimum_properties",
        "evidence_references",
        "evidence_class",
    )
)

#: the exact key set of one serialized (mechanism, state) entry
_MECHANISM_STATE_KEYS = frozenset(("mechanism", "state"))

#: the exact key set of one serialized (mechanism, properties)
#: entry
_MECHANISM_PROPERTY_KEYS = frozenset(
    ("mechanism", "minimum_security_properties")
)


def _require_str(value: object, label: str) -> str:
    """A non-empty string field (fail closed; never coerced)."""
    if not isinstance(value, str) or not value:
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


def _require_mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.INVALID_INPUT,
            "%s must be a mapping" % label,
        )
    return value


def _require_exact_keys(
    mapping: Mapping[str, Any], keys: Any, label: str
) -> None:
    """The canonical form defines each structure EXACTLY (no
    unknown members, no missing members — the audit boundary does
    not best-effort-interpret shapes it does not define)."""
    present = frozenset(mapping)
    if present != frozenset(keys):
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.INVALID_INPUT,
            "%s members are not exactly %s (missing %s; unknown %s) — "
            "the canonical form defines the structure exactly; fail "
            "closed" % (label, sorted(keys), sorted(frozenset(keys) - present), sorted(present - frozenset(keys))),
        )


def _derive_decision_id(evaluation: CompatibilityEvaluation) -> str:
    """The content-derived decision id: SHA-256 over the canonical
    JSON bytes of the exact record content (the history schema
    dimension plus the exact canonical W050.2 result) — an address
    of the exact decision record, reproducible from identical
    content and derived from nothing else."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(
            {
                "history_schema_version": HISTORY_SCHEMA_VERSION,
                "evaluation": evaluation.to_dict(),
            }
        )
    ).hexdigest()


def decision_identity(evaluation: CompatibilityEvaluation) -> str:
    """The public content-derived identity of one W050.2
    compatibility-evaluation result: the decision id under which
    the history layer would preserve it (SHA-256 over the
    canonical record content; deterministic, no temporal or
    environmental inputs).

    This is a pure function of the result content — computing it
    preserves nothing and consults nothing; it is the address, not
    the storage."""
    if not isinstance(evaluation, CompatibilityEvaluation):
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.INVALID_INPUT,
            "decision identity requires a CompatibilityEvaluation "
            "instance (got %s)" % type(evaluation).__name__,
        )
    return _derive_decision_id(evaluation)


@dataclass(frozen=True)
class HistoricalDecisionRecord:
    """One immutable, content-addressed historical decision record
    (W050.3).

    A thin persistence/audit wrapper around the accepted W050.2
    result: its ONLY additional semantics are the historical
    identity (``decision_id``, content-derived) and the history
    schema dimension — it does not fork the evaluation vocabulary,
    the state vocabulary, the findings vocabulary, or the
    mechanism vocabulary, and it carries no temporal fields (no
    timestamp, nonce, or sequence number: the identity and the
    canonical order derive from content alone).

    ``evaluation`` is the EXACT accepted W050.2 result object
    (preserved as data — with its full registry provenance, never
    recomputed, never refreshed).  ``decision_id`` is DERIVED from
    the canonical record content: an empty id is derived at
    construction; a SUPPLIED id must equal that same SHA-256
    digest — an attacker-chosen id can never vouch for arbitrary
    content (a forged restored record fails closed here, at
    construction, before the history can accept it)."""

    evaluation: CompatibilityEvaluation
    decision_id: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.evaluation, CompatibilityEvaluation):
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "historical record evaluation must be a "
                "CompatibilityEvaluation instance (got %s)"
                % type(self.evaluation).__name__,
            )
        if self.decision_id != "":
            if (
                not isinstance(self.decision_id, str)
                or not _SHA256_DIGEST_PATTERN.match(self.decision_id)
            ):
                raise PlatformCapabilityError(
                    PlatformCapabilityReasonCode.INVALID_INPUT,
                    "supplied decision_id %r must be a canonical "
                    "sha256 content digest (the id is the address of "
                    "the exact decision record; fail closed)" % (self.decision_id,),
                )
        derived = _derive_decision_id(self.evaluation)
        if self.decision_id == "":
            object.__setattr__(self, "decision_id", derived)
        elif self.decision_id != derived:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "historical record is unverifiable: its decision_id "
                "%r is not the deterministic content-derived id %r — "
                "the id does not digest the content it labels, so "
                "the record is forged or tampered and is rejected "
                "(fail closed; the history is append-only evidence "
                "and never accepts attacker-chosen ids)"
                % (self.decision_id, derived),
            )

    def content(self) -> Dict[str, Any]:
        """The canonical record content the decision id addresses
        (the id itself excluded — it is the address, not the
        content)."""
        return {
            "history_schema_version": HISTORY_SCHEMA_VERSION,
            "evaluation": self.evaluation.to_dict(),
        }

    def to_dict(self) -> Dict[str, Any]:
        """The canonical deterministic serialization of the record
        (the id-addressed content plus the id)."""
        content = self.content()
        content["decision_id"] = self.decision_id
        return content


def _mechanism_state_pairs(value: object) -> Tuple[Tuple[str, str], ...]:
    """Convert the serialized ``mechanism_states`` entries (the
    canonical ``{"mechanism", "state"}`` mappings) into the
    ``(mechanism, state)`` pair tuple the W050.2 constructor
    consumes (shape-checked here; values re-validated by the
    constructor's own invariants)."""
    if isinstance(value, (str, bytes)) or not isinstance(value, (tuple, list)):
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.INVALID_INPUT,
            "serialized evaluation mechanism_states must be a "
            "sequence of {mechanism, state} entries",
        )
    pairs: List[Tuple[str, str]] = []
    for entry in value:
        mapping = _require_mapping(
            entry, "serialized evaluation mechanism_states entry"
        )
        _require_exact_keys(
            mapping, _MECHANISM_STATE_KEYS, "serialized mechanism_states entry"
        )
        pairs.append((mapping["mechanism"], mapping["state"]))
    return tuple(pairs)


def _mechanism_property_entries(
    value: object,
) -> Tuple[Tuple[str, Tuple[str, ...]], ...]:
    """Convert the serialized ``mechanism_minimum_properties``
    entries (the canonical ``{"mechanism",
    "minimum_security_properties"}`` mappings) into the
    ``(mechanism, properties)`` pair tuple the W050.2 constructor
    consumes."""
    if isinstance(value, (str, bytes)) or not isinstance(value, (tuple, list)):
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.INVALID_INPUT,
            "serialized evaluation mechanism_minimum_properties must "
            "be a sequence of {mechanism, minimum_security_properties} "
            "entries",
        )
    entries: List[Tuple[str, Tuple[str, ...]]] = []
    for entry in value:
        mapping = _require_mapping(
            entry,
            "serialized evaluation mechanism_minimum_properties entry",
        )
        _require_exact_keys(
            mapping,
            _MECHANISM_PROPERTY_KEYS,
            "serialized mechanism_minimum_properties entry",
        )
        properties = mapping["minimum_security_properties"]
        if isinstance(properties, (str, bytes)) or not isinstance(
            properties, (tuple, list)
        ):
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "serialized mechanism minimum_security_properties must "
                "be a sequence of non-empty string tokens",
            )
        entries.append((mapping["mechanism"], tuple(properties)))
    return tuple(entries)


def _evaluation_from_payload(payload: object) -> CompatibilityEvaluation:
    """Reconstruct the W050.2 result from its canonical serialized
    payload — THROUGH the accepted constructor, so its frozen
    invariants and typed reasons apply verbatim (the history layer
    never re-implements the evaluation vocabulary: it is a
    persistence/audit boundary, not a semantic boundary; no
    unchecked object creation, no bypasses)."""
    mapping = _require_mapping(
        payload, "serialized evaluation payload"
    )
    _require_exact_keys(
        mapping, _EVALUATION_KEYS, "serialized evaluation payload"
    )
    if mapping["schema_version"] != SCHEMA_VERSION:
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.SCHEMA_INVALID,
            "evaluation payload schema_version %r is not %r (the "
            "historical payload is the accepted W050.2 result form; "
            "fail closed, never best-effort)"
            % (mapping["schema_version"], SCHEMA_VERSION),
        )
    return CompatibilityEvaluation(
        platform_id=mapping["platform_id"],
        role=mapping["role"],
        sharing_mode=mapping["sharing_mode"],
        state=mapping["state"],
        role_state=mapping["role_state"],
        sharing_mode_state=mapping["sharing_mode_state"],
        registry_version=mapping["registry_version"],
        registry_digest=mapping["registry_digest"],
        restrictions=mapping["restrictions"],
        findings=mapping["findings"],
        required_mechanisms=mapping["required_mechanisms"],
        mechanism_states=_mechanism_state_pairs(mapping["mechanism_states"]),
        mechanism_minimum_properties=_mechanism_property_entries(
            mapping["mechanism_minimum_properties"]
        ),
        evidence_references=mapping["evidence_references"],
        evidence_class=mapping["evidence_class"],
    )


def _reject_duplicate_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    """The JSON object-hook that rejects duplicate object keys: a
    doctored serialization whose effective content differs from its
    surface can never enter the audit boundary (fail closed)."""
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "duplicate object key %r in serialized history (a "
                "serialization whose effective content differs from "
                "its surface never enters the audit boundary; fail "
                "closed)" % (key,),
            )
        result[key] = value
    return result


def _parse_serialized_history(data: object) -> Mapping[str, Any]:
    """Accept the canonical serialized history as the parsed
    mapping or as canonical JSON bytes (UTF-8; duplicate object
    keys rejected).  Anything else is malformed input (fail
    closed; never best-effort)."""
    if isinstance(data, Mapping):
        return data
    if isinstance(data, (bytes, bytearray)):
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeDecodeError as error:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "serialized history bytes must be UTF-8 canonical "
                "JSON (invalid UTF-8; fail closed)",
            ) from error
        try:
            value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
        except json.JSONDecodeError as error:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "serialized history bytes must be canonical JSON "
                "(invalid JSON: %s; fail closed)" % (error,),
            ) from error
        if not isinstance(value, Mapping):
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "serialized history must be a JSON object (the "
                "canonical container form; got %s)"
                % type(value).__name__,
            )
        return value
    raise PlatformCapabilityError(
        PlatformCapabilityReasonCode.INVALID_INPUT,
        "serialized history must be the parsed canonical mapping or "
        "canonical JSON bytes (got %s)" % type(data).__name__,
    )


def _records_from_payload(
    payload: Mapping[str, Any],
) -> Tuple[HistoricalDecisionRecord, ...]:
    """Validate the serialized history record-by-record (schema at
    both levels, exact structure, identity, the contained
    evaluation through its constructor, canonical strictly
    ascending order — hence no duplicates) and return the record
    tuple for container construction."""
    if payload.get("history_schema_version") != HISTORY_SCHEMA_VERSION:
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.SCHEMA_INVALID,
            "history schema_version %r is not %r (this implementation "
            "reads exactly one history schema; fail closed — no "
            "best-effort interpretation, no silent migration, no "
            "coercion)" % (payload.get("history_schema_version"), HISTORY_SCHEMA_VERSION),
        )
    _require_exact_keys(payload, _CONTAINER_KEYS, "serialized history")
    records_value = payload["records"]
    if isinstance(records_value, (str, bytes)) or not isinstance(
        records_value, (tuple, list)
    ):
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.INVALID_INPUT,
            "serialized history records must be a sequence of "
            "record mappings",
        )
    records: List[HistoricalDecisionRecord] = []
    previous_id = ""
    for entry in records_value:
        mapping = _require_mapping(entry, "serialized history record")
        if mapping.get("history_schema_version") != HISTORY_SCHEMA_VERSION:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.SCHEMA_INVALID,
                "record history_schema_version %r is not %r (a "
                "record of another history schema never enters this "
                "store; fail closed)"
                % (mapping.get("history_schema_version"), HISTORY_SCHEMA_VERSION),
            )
        _require_exact_keys(
            mapping, _RECORD_KEYS, "serialized history record"
        )
        decision_id = mapping["decision_id"]
        if (
            not isinstance(decision_id, str)
            or not _SHA256_DIGEST_PATTERN.match(decision_id)
        ):
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "record decision_id %r must be a canonical sha256 "
                "content digest (the id is the address of the exact "
                "decision record; fail closed)" % (decision_id,),
            )
        evaluation = _evaluation_from_payload(mapping["evaluation"])
        records.append(
            HistoricalDecisionRecord(
                decision_id=decision_id, evaluation=evaluation
            )
        )
        # Deterministic ordering + duplicate discipline: the
        # canonical form carries the records in strictly ascending
        # decision-id order (unique ids, content-derived order —
        # never insertion order); anything else is not the
        # canonical form and fails closed.
        if not previous_id < decision_id:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "serialized history records must be in strictly "
                "ascending decision-id order (canonical unique order; "
                "out-of-order or duplicate records are rejected — "
                "fail closed, never best-effort reordering)",
            )
        previous_id = decision_id
    return tuple(records)


def _require_record_sequence(
    value: object,
) -> Tuple[HistoricalDecisionRecord, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, (tuple, list)):
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.INVALID_INPUT,
            "history records must be a sequence of "
            "HistoricalDecisionRecord instances",
        )
    records = tuple(value)
    for record in records:
        if not isinstance(record, HistoricalDecisionRecord):
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "history records entries must be "
                "HistoricalDecisionRecord instances (got %s)"
                % type(record).__name__,
            )
    return records


class CompatibilityHistory:
    """The versioned, append-only, content-addressed compatibility
    decision history (W050.3).

    Construct from an iterable of records (the empty history is
    ``CompatibilityHistory()``), extend FUNCTIONALLY with
    :meth:`append` (which returns a NEW frozen history — the one
    it was called on is unchanged; there is no in-place mutation
    anywhere), query with :meth:`get` / :meth:`contains` /
    :meth:`records` / :meth:`decision_ids` / :meth:`replay`,
    serialize with :meth:`to_dict` / :meth:`content_digest`, and
    reconstruct deterministically with :meth:`restore`.

    The container is frozen exactly like the W050.1-corrected
    registry: construction is the only writer (it writes through
    the base-object setter exclusively; the public
    ``__setattr__``/``__delattr__`` raise unconditionally), the
    internal record mapping is a read-only proxy, and
    re-initialization of a constructed history is rejected.  A new
    record enters a lineage ONLY through ``append`` or
    ``restore`` — there is no update, no delete, and no upsert.

    The history consumes W050.2 results as DATA: it never
    recomputes compatibility, never consults a registry (current
    or otherwise), never consults any external authority, and
    never rewrites the provenance of a preserved decision
    (registry evolution never rewrites history)."""

    __slots__ = ("_frozen", "_records_by_id")

    def __init__(
        self, records: Iterable[HistoricalDecisionRecord] = ()
    ) -> None:
        if getattr(self, "_frozen", False):
            # re-initialization of a constructed history is a
            # mutation of frozen state — rejected like every other
            # post-construction write
            raise AttributeError(
                "CompatibilityHistory is frozen after construction: "
                "re-initialization is rejected (a new history is a "
                "new instance; append is functional)"
            )
        rows = _require_record_sequence(records)
        by_id: Dict[str, HistoricalDecisionRecord] = {}
        for record in rows:
            # Store-boundary identity re-verification (the W049
            # journal append-guard discipline): even a record that
            # bypassed the record constructor's enforcement (a
            # deserialization bypass, contract-external surgery)
            # can never enter the store with an id that does not
            # digest its content.
            if record.decision_id != _derive_decision_id(record.evaluation):
                raise PlatformCapabilityError(
                    PlatformCapabilityReasonCode.INVALID_INPUT,
                    "the history refuses the record for platform %r: "
                    "its decision_id %r is not the deterministic "
                    "content-derived id (fail closed — the "
                    "evidentiary record cannot carry a record whose "
                    "id does not digest its content)"
                    % (record.evaluation.platform_id, record.decision_id),
                )
            known = by_id.get(record.decision_id)
            if known is not None:
                if known.evaluation.to_dict() != record.evaluation.to_dict():
                    raise PlatformCapabilityError(
                        PlatformCapabilityReasonCode.DUPLICATE_CONFLICT,
                        "conflicting historical records under decision "
                        "id %r (same derived identity, different "
                        "content; fail closed — never first-wins, never "
                        "last-wins, never a silent merge; impossible "
                        "under correct hashing and rejected regardless)"
                        % (record.decision_id,),
                    )
                # identical duplicate: idempotent (collapsed; the
                # canonical content and digest are unchanged)
                continue
            by_id[record.decision_id] = record
        # The freeze itself (the W050.1-corrected discipline):
        # construction is the ONLY writer, through the base-object
        # setter exclusively; the frozen flag is written LAST (it
        # is what makes __init__ re-invocation fail closed too).
        object.__setattr__(self, "_records_by_id", MappingProxyType(by_id))
        object.__setattr__(self, "_frozen", True)

    def __setattr__(self, name: str, value: object) -> None:
        # Unconditional: there is no post-construction mutation
        # surface on the history object itself (append is
        # functional; the invariant is enforced, not merely
        # documented).
        raise AttributeError(
            "CompatibilityHistory is frozen after construction: "
            "attribute assignment %r is rejected (immutable "
            "append-only history; append is functional and returns "
            "a new history)" % (name,)
        )

    def __delattr__(self, name: str) -> None:
        raise AttributeError(
            "CompatibilityHistory is frozen after construction: "
            "attribute deletion %r is rejected (immutable "
            "append-only history)" % (name,)
        )

    def records(self) -> Tuple[HistoricalDecisionRecord, ...]:
        """All preserved records, in canonical decision-id order
        (the deterministic order — content-derived, never
        insertion order, never hash-iteration order)."""
        return tuple(
            self._records_by_id[decision_id]
            for decision_id in sorted(self._records_by_id)
        )

    def decision_ids(self) -> Tuple[str, ...]:
        """All preserved decision ids, in canonical sorted order."""
        return tuple(sorted(self._records_by_id))

    def replay(self) -> Tuple[CompatibilityEvaluation, ...]:
        """Deterministically replay the preserved decisions: the
        W050.2 results in canonical decision-id order, each
        re-verified against its content-derived identity before it
        is yielded (a replayed decision is provably the decision
        its id addresses; any inconsistency fails closed).

        Replay re-yields PRESERVED results as data — it never
        re-evaluates anything (there is no registry here to
        consult)."""
        evaluations: List[CompatibilityEvaluation] = []
        for record in self.records():
            if record.decision_id != _derive_decision_id(record.evaluation):
                raise PlatformCapabilityError(
                    PlatformCapabilityReasonCode.INVALID_INPUT,
                    "historical decision %r is unverifiable at replay: "
                    "its decision_id does not digest its content — "
                    "the preserved record is corrupted (fail closed)"
                    % (record.decision_id,),
                )
            evaluations.append(record.evaluation)
        return tuple(evaluations)

    def get(self, decision_id: str) -> HistoricalDecisionRecord:
        """The preserved record for one decision id.

        Fail closed: a malformed id raises INVALID_INPUT; a
        well-formed id that does not resolve in this history
        raises UNKNOWN_PLATFORM (the store's unresolved
        content-address reason — the registry's fail-closed
        default for a platform id that does not resolve, reused
        verbatim for a decision id: an unpreserved decision never
        reads as an implicit absence)."""
        _require_str(decision_id, "decision_id")
        record = self._records_by_id.get(decision_id)
        if record is None:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.UNKNOWN_PLATFORM,
                "decision %r is not preserved in this history (an "
                "unresolved decision id fails closed — never an "
                "implicit absence)" % (decision_id,),
            )
        return record

    def contains(self, decision_id: str) -> bool:
        """Whether one decision id resolves (membership only; it
        never implies anything about the decision's content)."""
        _require_str(decision_id, "decision_id")
        return decision_id in self._records_by_id

    def append(
        self, evaluation: CompatibilityEvaluation
    ) -> "CompatibilityHistory":
        """Preserve one W050.2 evaluation result and return the
        NEW history that contains it.

        Append is FUNCTIONAL: the history this is called on is
        unchanged (there is no in-place mutation anywhere —
        construction is the only writer), and the returned lineage
        only ever accumulates records.  Appending the exact same
        evaluation content is IDEMPOTENT: one record under the
        same decision_id, and the history digest is unchanged (the
        identical-append discipline — the call returns this
        history itself).  Conflicting content under the same
        derived identity is impossible under correct hashing and
        fails closed regardless (DUPLICATE_CONFLICT)."""
        if not isinstance(evaluation, CompatibilityEvaluation):
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "history appends CompatibilityEvaluation results only "
                "(got %s)" % type(evaluation).__name__,
            )
        record = HistoricalDecisionRecord(evaluation=evaluation)
        existing = self._records_by_id.get(record.decision_id)
        if existing is not None:
            if existing.evaluation.to_dict() != evaluation.to_dict():
                raise PlatformCapabilityError(
                    PlatformCapabilityReasonCode.DUPLICATE_CONFLICT,
                    "conflicting historical content under decision id "
                    "%r (same derived identity, different content; "
                    "fail closed — never first-wins, never last-wins, "
                    "never overwrite, never merge; impossible under "
                    "correct hashing and rejected regardless)"
                    % (record.decision_id,),
                )
            return self  # idempotent: identical decision content
        return CompatibilityHistory(self.records() + (record,))

    def to_dict(self) -> Dict[str, Any]:
        """The canonical deterministic serialization: the history
        schema dimension and the records in canonical decision-id
        order (each record in its canonical form).  Identical
        history content yields byte-identical serialization
        regardless of append order, repeat count, or hash-seed
        configuration."""
        return {
            "history_schema_version": HISTORY_SCHEMA_VERSION,
            "records": [record.to_dict() for record in self.records()],
        }

    def content_digest(self) -> str:
        """The content address of this exact history content:
        SHA-256 over the canonical JSON bytes of ``to_dict``."""
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.to_dict())
        ).hexdigest()

    @classmethod
    def restore(cls, data: object) -> "CompatibilityHistory":
        """Reconstruct a history from its canonical serialized form
        — the parsed mapping or the canonical JSON bytes
        themselves (UTF-8; duplicate object keys are rejected).

        Fail closed on every dimension: the history schema version
        (container and record levels — SCHEMA_INVALID on mismatch),
        the exact record structure, the declared decision
        identities (each must digest the content it labels), the
        contained evaluation payloads (reconstructed THROUGH the
        accepted W050.2 constructor, whose frozen vocabularies and
        typed reasons apply verbatim), the registry provenance
        shapes, the evidence class, the deterministic strictly
        ascending record order, and the duplicate discipline.  A
        serialization that is not the canonical form of its own
        records is rejected outright — no best-effort
        interpretation, no silent migration, no coercion, and no
        invalid historical object enters the store.

        The restoration contract: canonical history bytes ->
        restore -> the same logical records under the same record
        ids -> the same canonical serialization (repeated
        restore/serialize cycles remain byte-identical)."""
        payload = _parse_serialized_history(data)
        history = cls(_records_from_payload(payload))
        if history.to_dict() != payload:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "the serialized history is not the canonical form of "
                "its own records (schema, structure, identity, "
                "ordering, and duplicate discipline are all verified, "
                "and the restored form must be exactly the input "
                "form — non-canonical serializations are rejected; "
                "fail closed, never best-effort normalization at the "
                "audit boundary)",
            )
        return history

    def __len__(self) -> int:
        return len(self._records_by_id)

    def __contains__(self, decision_id: object) -> bool:
        if not isinstance(decision_id, str):
            return False
        return decision_id in self._records_by_id

    def __repr__(self) -> str:
        return (
            "CompatibilityHistory(records=%d, digest=%s)"
            % (len(self._records_by_id), self.content_digest()[:23])
        )


__all__ = [
    "CompatibilityHistory",
    "HISTORY_SCHEMA_VERSION",
    "HistoricalDecisionRecord",
    "decision_identity",
]
