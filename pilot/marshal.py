"""WORK-040 deployment-plane marshalling of the WORK-033 session
artifacts.

The accepted runtime hands session artifacts between compositions as
IN-PROCESS values.  A real multi-process deployment must move the
same DATA between OS processes; this module does exactly that, and
ONLY that:

- serialization uses each production object's OWN ``to_dict`` /
  ``from_mapping`` / validating-constructor surface;
- reconstruction re-runs every production constructor validation
  (a tampered payload fails closed at reconstruction, before any
  authority is touched);
- no field is added, dropped, re-typed, or re-interpreted here.

This is marshalling, not protocol semantics: the receiving runtime
still runs its full chain (policy gate, mirrored session identity
derivation, transport transcript verification) over the reconstructed
values -- exactly as it does for in-process callers.
"""

from __future__ import annotations

from typing import Any, Mapping

from agent import DatagramArtifact, SessionAcceptArtifact, SessionConfirmArtifact, SessionRequestArtifact
from identity import (
    CredentialRecord,
    CredentialReference,
    LifecycleState,
    NodeID,
    RevocationInfo,
)
from identity.node_id import parse_node_id
from policy import PolicyDecision
from routing import RouteDecision
from routing import route_decision_from_mapping as _route_decision_from_mapping
from transport import (
    TransportAcceptance,
    TransportConfirmation,
    TransportOffer,
    TransportSecurityPolicy,
)

from .errors import PilotError, PilotReasonCode

__all__ = [
    "policy_decision_to_mapping",
    "policy_decision_from_mapping",
    "route_decision_to_mapping",
    "route_decision_from_mapping",
    "transport_offer_to_mapping",
    "transport_offer_from_mapping",
    "transport_acceptance_to_mapping",
    "transport_acceptance_from_mapping",
    "transport_confirmation_to_mapping",
    "transport_confirmation_from_mapping",
    "session_request_to_mapping",
    "session_request_from_mapping",
    "session_accept_to_mapping",
    "session_accept_from_mapping",
    "session_confirm_to_mapping",
    "session_confirm_from_mapping",
    "datagram_to_mapping",
    "datagram_from_mapping",
    "credential_record_to_mapping",
    "credential_record_from_mapping",
]


def _require_mapping(data: object, label: str) -> Mapping[str, Any]:
    if not isinstance(data, Mapping):
        raise PilotError(
            PilotReasonCode.MARSHAL_INVALID,
            "%s must be a mapping (got %s)" % (label, type(data).__name__),
        )
    return data


def _required_str(data: Mapping[str, Any], key: str, label: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise PilotError(
            PilotReasonCode.MARSHAL_INVALID,
            "%s.%s must be a non-empty string" % (label, key),
        )
    return value


def _str_tuple(value: object, label: str) -> tuple:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        raise PilotError(
            PilotReasonCode.MARSHAL_INVALID,
            "%s must be a list of strings" % (label,),
        )
    out = []
    for item in value:
        if not isinstance(item, str):
            raise PilotError(
                PilotReasonCode.MARSHAL_INVALID,
                "%s entries must be strings" % (label,),
            )
        out.append(item)
    return tuple(out)


def _mapping_tuple(value: object, label: str) -> tuple:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        raise PilotError(
            PilotReasonCode.MARSHAL_INVALID,
            "%s must be a list of mappings" % (label,),
        )
    out = []
    for item in value:
        if not isinstance(item, Mapping):
            raise PilotError(
                PilotReasonCode.MARSHAL_INVALID,
                "%s entries must be mappings" % (label,),
            )
        out.append(dict(item))
    return tuple(out)


# -- WORK-010 policy decision -------------------------------------------


def policy_decision_to_mapping(decision: PolicyDecision) -> dict:
    """Serialize through the production ``to_dict`` surface."""
    return decision.to_dict()


def policy_decision_from_mapping(data: object) -> PolicyDecision:
    mapping = _require_mapping(data, "policy-decision")
    version_value = mapping.get("policy_set_version")
    if isinstance(version_value, bool) or not isinstance(version_value, int):
        if isinstance(version_value, str) and version_value.isdigit():
            version_value = int(version_value)
        else:
            raise PilotError(
                PilotReasonCode.MARSHAL_INVALID,
                "policy-decision.policy_set_version must be an integer",
            )
    try:
        return PolicyDecision(
            decision_id=_required_str(mapping, "decision_id", "policy-decision"),
            effect=_required_str(mapping, "effect", "policy-decision"),
            code=_required_str(mapping, "code", "policy-decision"),
            detail=mapping.get("detail", ""),
            matched_rule_ids=_str_tuple(
                mapping.get("matched_rule_ids"), "policy-decision.matched_rule_ids"
            ),
            policy_set_id=_required_str(mapping, "policy_set_id", "policy-decision"),
            policy_set_version=version_value,
            evaluation_instant=mapping.get("evaluation_instant", ""),
            conflict_trace=_str_tuple(
                mapping.get("conflict_trace"), "policy-decision.conflict_trace"
            ),
            extensions=_mapping_tuple(
                mapping.get("extensions"), "policy-decision.extensions"
            ),
        )
    except PilotError:
        raise
    except Exception as error:  # production constructor validation
        raise PilotError(
            PilotReasonCode.MARSHAL_INVALID,
            "policy decision reconstruction rejected: %s"
            % (type(error).__name__,),
        ) from error


# -- WORK-011 route decision --------------------------------------------


def route_decision_to_mapping(decision: RouteDecision) -> dict:
    """Serialize through the production ``to_dict`` surface."""
    return decision.to_dict()


def route_decision_from_mapping(data: object) -> RouteDecision:
    """Reconstruct through the production ``from_mapping`` pair."""
    try:
        return _route_decision_from_mapping(data)
    except Exception as error:
        raise PilotError(
            PilotReasonCode.MARSHAL_INVALID,
            "route decision reconstruction rejected: %s"
            % (type(error).__name__,),
        ) from error


# -- WORK-017 transport handshake records --------------------------------


def transport_offer_to_mapping(offer: TransportOffer) -> dict:
    return offer.to_dict()


def _security_policy_from_view(view: object) -> TransportSecurityPolicy:
    mapping = _require_mapping(view, "offer.policy")
    families = mapping.get("allowed_families")
    return TransportSecurityPolicy(
        require_integrity=bool(mapping.get("require_integrity", True)),
        require_confidentiality=bool(
            mapping.get("require_confidentiality", False)
        ),
        require_forward_secrecy=bool(
            mapping.get("require_forward_secrecy", False)
        ),
        require_multipath=bool(mapping.get("require_multipath", False)),
        minimum_rank=int(mapping.get("minimum_rank", 0)),
        allowed_families=(
            None if families is None else _str_tuple(families, "offer.policy.allowed_families")
        ),
        policy_id=str(mapping.get("policy_id", "transport.policy.default")),
    )


def transport_offer_from_mapping(data: object) -> TransportOffer:
    mapping = _require_mapping(data, "transport-offer")
    try:
        return TransportOffer(
            session_id=_required_str(mapping, "session_id", "transport-offer"),
            initiator_node_id=_required_str(
                mapping, "initiator_node_id", "transport-offer"
            ),
            responder_node_id=_required_str(
                mapping, "responder_node_id", "transport-offer"
            ),
            offered_profiles=_str_tuple(
                mapping.get("offered_profiles"), "transport-offer.offered_profiles"
            ),
            policy=_security_policy_from_view(mapping.get("policy")),
            offer_nonce=_required_str(mapping, "offer_nonce", "transport-offer"),
            issued_at=_required_str(mapping, "issued_at", "transport-offer"),
            expires_at=_required_str(mapping, "expires_at", "transport-offer"),
            extensions=dict(mapping.get("extensions") or {}),
        )
    except PilotError:
        raise
    except Exception as error:
        raise PilotError(
            PilotReasonCode.MARSHAL_INVALID,
            "transport offer reconstruction rejected: %s"
            % (type(error).__name__,),
        ) from error


def transport_acceptance_to_mapping(acceptance: TransportAcceptance) -> dict:
    return acceptance.to_dict()


def transport_acceptance_from_mapping(data: object) -> TransportAcceptance:
    mapping = _require_mapping(data, "transport-acceptance")
    try:
        return TransportAcceptance(
            transport_id=_required_str(
                mapping, "transport_id", "transport-acceptance"
            ),
            offer_digest=_required_str(
                mapping, "offer_digest", "transport-acceptance"
            ),
            selected_profile=_required_str(
                mapping, "selected_profile", "transport-acceptance"
            ),
            responder_nonce=_required_str(
                mapping, "responder_nonce", "transport-acceptance"
            ),
            responder_confirmation=_required_str(
                mapping, "responder_confirmation", "transport-acceptance"
            ),
            responder_attestation=_required_str(
                mapping, "responder_attestation", "transport-acceptance"
            ),
            key_lineage=_required_str(
                mapping, "key_lineage", "transport-acceptance"
            ),
            issued_at=_required_str(mapping, "issued_at", "transport-acceptance"),
            extensions=dict(mapping.get("extensions") or {}),
        )
    except PilotError:
        raise
    except Exception as error:
        raise PilotError(
            PilotReasonCode.MARSHAL_INVALID,
            "transport acceptance reconstruction rejected: %s"
            % (type(error).__name__,),
        ) from error


def transport_confirmation_to_mapping(
    confirmation: TransportConfirmation,
) -> dict:
    return confirmation.to_dict()


def transport_confirmation_from_mapping(data: object) -> TransportConfirmation:
    mapping = _require_mapping(data, "transport-confirmation")
    try:
        return TransportConfirmation(
            transport_id=_required_str(
                mapping, "transport_id", "transport-confirmation"
            ),
            offer_digest=_required_str(
                mapping, "offer_digest", "transport-confirmation"
            ),
            initiator_confirmation=_required_str(
                mapping, "initiator_confirmation", "transport-confirmation"
            ),
            initiator_attestation=_required_str(
                mapping, "initiator_attestation", "transport-confirmation"
            ),
            issued_at=_required_str(
                mapping, "issued_at", "transport-confirmation"
            ),
        )
    except PilotError:
        raise
    except Exception as error:
        raise PilotError(
            PilotReasonCode.MARSHAL_INVALID,
            "transport confirmation reconstruction rejected: %s"
            % (type(error).__name__,),
        ) from error


# -- WORK-033 session artifacts ------------------------------------------


def session_request_to_mapping(request: SessionRequestArtifact) -> dict:
    return {
        "session_id": request.session_id,
        "source_node_id": request.source_node_id,
        "destination_node_id": request.destination_node_id,
        "creation_instant": request.creation_instant,
        "intent_digest": request.intent_digest,
        "route_decision": route_decision_to_mapping(request.route_decision),
        "policy_decision": policy_decision_to_mapping(request.policy_decision),
        "offer": transport_offer_to_mapping(request.offer),
    }


def session_request_from_mapping(data: object) -> SessionRequestArtifact:
    mapping = _require_mapping(data, "session-request")
    return SessionRequestArtifact(
        session_id=_required_str(mapping, "session_id", "session-request"),
        source_node_id=_required_str(
            mapping, "source_node_id", "session-request"
        ),
        destination_node_id=_required_str(
            mapping, "destination_node_id", "session-request"
        ),
        creation_instant=_required_str(
            mapping, "creation_instant", "session-request"
        ),
        intent_digest=str(mapping.get("intent_digest", "")),
        route_decision=route_decision_from_mapping(
            mapping.get("route_decision")
        ),
        policy_decision=policy_decision_from_mapping(
            mapping.get("policy_decision")
        ),
        offer=transport_offer_from_mapping(mapping.get("offer")),
    )


def session_accept_to_mapping(accept: SessionAcceptArtifact) -> dict:
    return {
        "session_id": accept.session_id,
        "acceptance": transport_acceptance_to_mapping(accept.acceptance),
    }


def session_accept_from_mapping(data: object) -> SessionAcceptArtifact:
    mapping = _require_mapping(data, "session-accept")
    return SessionAcceptArtifact(
        session_id=_required_str(mapping, "session_id", "session-accept"),
        acceptance=transport_acceptance_from_mapping(
            mapping.get("acceptance")
        ),
    )


def session_confirm_to_mapping(confirm: SessionConfirmArtifact) -> dict:
    return {
        "session_id": confirm.session_id,
        "transport_id": confirm.transport_id,
        "confirmation": transport_confirmation_to_mapping(confirm.confirmation),
    }


def session_confirm_from_mapping(data: object) -> SessionConfirmArtifact:
    mapping = _require_mapping(data, "session-confirm")
    return SessionConfirmArtifact(
        session_id=_required_str(mapping, "session_id", "session-confirm"),
        transport_id=_required_str(mapping, "transport_id", "session-confirm"),
        confirmation=transport_confirmation_from_mapping(
            mapping.get("confirmation")
        ),
    )


def datagram_to_mapping(artifact: DatagramArtifact) -> dict:
    return {
        "session_id": artifact.session_id,
        "transport_id": artifact.transport_id,
        "frame": dict(artifact.frame),
    }


def datagram_from_mapping(data: object) -> DatagramArtifact:
    mapping = _require_mapping(data, "datagram")
    frame = mapping.get("frame")
    if not isinstance(frame, Mapping):
        raise PilotError(
            PilotReasonCode.MARSHAL_INVALID,
            "datagram.frame must be a mapping",
        )
    return DatagramArtifact(
        session_id=_required_str(mapping, "session_id", "datagram"),
        transport_id=_required_str(mapping, "transport_id", "datagram"),
        frame=dict(frame),
    )


# -- WORK-004 credential record (deployment announce carriage) ------------


def credential_record_to_mapping(record: CredentialRecord) -> dict:
    """Serialize the PUBLIC credential record (no secret material)."""
    revoked = None
    if record.revoked is not None:
        revoked = {
            "revoked_at": record.revoked.revoked_at,
            "reason": record.revoked.reason,
        }
    return {
        "reference_id": record.reference.reference_id,
        "node_id": record.node_id.text,
        "profile_id": record.profile_id,
        "role": record.role,
        "algorithm": record.algorithm,
        "key_version": record.key_version,
        "public_material_hex": record.public_material_hex,
        "status": record.status.value,
        "provisioned_at": record.provisioned_at,
        "activated_at": record.activated_at,
        "expires_at": record.expires_at,
        "superseded_at": record.superseded_at,
        "revoked": revoked,
    }


def credential_record_from_mapping(data: object) -> CredentialRecord:
    """Reconstruct through the production validating constructors."""
    mapping = _require_mapping(data, "credential-record")
    try:
        node_id: NodeID = parse_node_id(
            _required_str(mapping, "node_id", "credential-record")
        )
        status = LifecycleState(
            _required_str(mapping, "status", "credential-record")
        )
        revoked_data = mapping.get("revoked")
        revoked = None
        if revoked_data is not None:
            if not isinstance(revoked_data, Mapping):
                raise ValueError("revoked must be a mapping")
            revoked = RevocationInfo(
                revoked_at=_required_str(
                    revoked_data, "revoked_at", "credential-record.revoked"
                ),
                reason=str(revoked_data.get("reason", "")),
            )
        return CredentialRecord(
            reference=CredentialReference(
                _required_str(
                    mapping, "reference_id", "credential-record"
                )
            ),
            node_id=node_id,
            profile_id=_required_str(
                mapping, "profile_id", "credential-record"
            ),
            role=_required_str(mapping, "role", "credential-record"),
            algorithm=_required_str(
                mapping, "algorithm", "credential-record"
            ),
            key_version=int(mapping.get("key_version", 0)),
            public_material_hex=_required_str(
                mapping, "public_material_hex", "credential-record"
            ),
            status=status,
            provisioned_at=_required_str(
                mapping, "provisioned_at", "credential-record"
            ),
            activated_at=mapping.get("activated_at"),
            expires_at=mapping.get("expires_at"),
            superseded_at=mapping.get("superseded_at"),
            revoked=revoked,
        )
    except PilotError:
        raise
    except Exception as error:
        raise PilotError(
            PilotReasonCode.MARSHAL_INVALID,
            "credential record reconstruction rejected: %s"
            % (type(error).__name__,),
        ) from error
