"""ADCOS gateway resolver (WORK-018): evidence-backed gateway role.

Architecture §"a reported gateway claim cannot be silently converted
into an authoritative gateway fact" and §"remote summaries are claims;
a gateway or high-value capability becomes authoritative only with
acceptable evidence under local policy" make the rule explicit:

A node CLAIMS to be a gateway for a destination prefix.  The claim
is AUTHORITATIVE only with acceptable evidence (an evidence_digest
acceptable to the caller's local policy).  The IP integration
boundary NEVER mints authority from an unevidenced claim -- it
returns the role claim with its evidence binding and lets the caller
decide whether to fail closed for privileged egress.

The resolver is read-only: it never writes to topology, never
mutates claims, and never re-classifies an unevidenced claim as
authoritative.  A gateway is a ROLE, never an identity -- the node's
identity lives in WORK-004; the IP integration boundary merely
records the role claim and its evidence binding.
"""

from __future__ import annotations

from typing import Optional

from .contract import GatewayClaim, IPIntegrationContext, TopologyReader
from .errors import IPIntegrationError, IPIntegrationReasonCode
from .model import GatewayRole, IPv6Address, IPv6Prefix


class GatewayResolver:
    """Evidence-backed gateway role resolver.

    Looks up a gateway claim through the read-only
    :class:`TopologyReader` facade.  Returns a :class:`GatewayRole`
    with ``authoritative=True`` if and only if the topology layer
    produced a claim with acceptable evidence.  Raises
    ``GATEWAY_UNEVIDENCED`` for privileged egress when no evidenced
    claim exists.

    The resolver never mints authority from an unevidenced claim.
    Two nodes can BOTH be gateways for the same destination prefix --
    gateway-ness is a role, not an identity.
    """

    label = "gateway-resolver"

    def resolve(
        self,
        context: IPIntegrationContext,
        destination: IPv6Address,
    ) -> GatewayRole:
        if not isinstance(destination, IPv6Address):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "destination must be an IPv6Address",
            )
        claim: Optional[GatewayClaim] = context.topology_reader().gateway_for(destination)
        if claim is None:
            raise IPIntegrationError(
                IPIntegrationReasonCode.GATEWAY_UNEVIDENCED,
                "no gateway claim for destination %s" % destination.canonical,
            )
        if not claim.evidence_digest:
            # An unevidenced claim is NOT authoritative.  The resolver
            # returns the role with authoritative=False for read-only
            # inspection; the caller (the manager's egress path) will
            # fail closed for privileged egress.  The R3 red test
            # exercises the privileged egress fail-closed path.
            raise IPIntegrationError(
                IPIntegrationReasonCode.GATEWAY_UNEVIDENCED,
                "gateway claim for destination %s carries no evidence "
                "(architecture §gateway evidence)" % destination.canonical,
            )
        return GatewayRole(
            node_id=claim.node_id,
            destination_prefix=claim.destination_prefix,
            evidence_digest=claim.evidence_digest,
            role_instant=claim.claim_instant,
            authoritative=True,
        )


__all__ = ["GatewayResolver"]
