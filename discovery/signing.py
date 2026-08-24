"""Discovery observation signing and verification (WORK-006).

Signature = attributable observation, NOT truth. Verification proves the
observation was produced by the holder of the referenced credential at
signing time, and that the credential was USABLE at the evaluation
instant; it does not establish identity, trust, topology authority,
routing, reachability truth, or authorization.

The verifier is **provenance-bound and time-aware** — the same accepted
pattern as WORK-005 ``verify_statement``:

1. ``sender_node_id`` is parsed through the WORK-004 ``parse_node_id``
   (no duplicated grammar);
2. the WORK-004 credential record is retrieved; the credential MUST
   belong to the SAME NodeID the observation names as
   ``sender_node_id`` (cross-node forgery rejected);
3. the credential's lifecycle is evaluated AT the injected instant —
   ACTIVE status, not revoked, not expired (``expires_at <= now``,
   mirroring ``IdentityService._require_active``); and
4. the signature is byte-exact over the canonical security-critical
   content.

Trust/authorization semantics stay OUT of the verifier — this is
PROVENANCE only (the observation came from the node it claims to be from,
using a credential usable at the claimed instant).
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from identity.credentials import CredentialReference
from identity.lifecycle import LifecycleState
from identity.node_id import NodeIdError, parse_node_id
from identity.provider import SignatureProvider
from identity.store import CredentialStore
from protocol.temporal import TemporalError, parse_instant

from .model import DiscoveryError, DiscoveryObservation, observation_signature_input


def sign_observation(
    observation: DiscoveryObservation,
    *,
    store: CredentialStore,
    provider: SignatureProvider,
    credential: CredentialReference,
) -> DiscoveryObservation:
    """Return a signed copy of the observation (signature material
    opaque). Signing flows exclusively through the WORK-004 provider
    seam — no key material enters the discovery layer."""
    signature_input = observation_signature_input(observation)
    try:
        signature_bytes = provider.sign(store, credential, signature_input)
    except Exception as error:
        raise DiscoveryError(
            "signing",
            "provider signing failed: %s: %s" % (type(error).__name__, error),
        ) from error
    from dataclasses import replace

    return replace(observation, signature=signature_bytes.hex())


def verify_observation(
    observation: DiscoveryObservation,
    *,
    store: CredentialStore,
    provider: SignatureProvider,
    credential: CredentialReference,
    now: datetime,
) -> bool:
    """Verify an observation's signature through the provider seam at the
    injected evaluation instant.

    ``now`` is a timezone-aware UTC datetime INJECTED by the caller — no
    wall-clock access anywhere in this layer (fully deterministic and
    reproducible).

    Returns True ONLY when:
    1. the credential's WORK-004 record belongs to the SAME NodeID as
       the observation's ``sender_node_id`` (cross-node forgery rejected);
    2. the credential's lifecycle is usable AT the evaluation instant —
       ACTIVE status, not revoked, not expired (``expires_at <= now``,
       mirroring ``IdentityService._require_active``); and
    3. the signature is byte-exact over the canonical security-critical
       content.

    This does NOT introduce trust or authorization policy — it verifies
    PROVENANCE. An ACTIVE-but-expired credential has a byte-correct
    signature but is rejected because the key was no longer usable at the
    evaluation instant.
    """
    if not observation.signature:
        return False
    if now.tzinfo is None:
        # Fail closed: a naive evaluation instant is a caller bug.
        return False
    # BIND: the credential used for verification must belong to the same
    # NodeID the observation names as its sender_node_id. A valid
    # signature from Node B on an observation naming Node A as sender is
    # rejected (cross-node forgery).
    try:
        record = store.get_record(credential)
    except Exception:
        return False
    try:
        declared_sender = parse_node_id(observation.sender_node_id)
    except (NodeIdError, Exception):
        return False
    if record.node_id != declared_sender:
        return False
    # LIFECYCLE at the evaluation instant. ``status`` is the primary
    # lifecycle signal (REVOKED / SUPERSEDED / EXPIRED / PROVISIONED /
    # ROTATING are all provenance-breaks). Expiry is additionally checked
    # against the injected instant — an ACTIVE credential whose
    # ``expires_at`` has passed is no longer usable. Revocation metadata
    # is checked defensively (an invariant violation would mean a record
    # carries revocation info without the status having flipped — fail
    # closed).
    if record.status is not LifecycleState.ACTIVE:
        return False
    if record.revoked is not None:
        return False
    if record.expires_at is not None:
        try:
            expires_instant = parse_instant(record.expires_at)
        except TemporalError:
            return False
        if expires_instant <= now:
            return False
    # Only then check the byte-exact signature.
    try:
        expected = provider.sign(store, credential, observation_signature_input(observation))
    except Exception:
        return False
    import hmac as _hmac

    try:
        provided = bytes.fromhex(observation.signature)
    except ValueError:
        return False
    return _hmac.compare_digest(expected, provided)
