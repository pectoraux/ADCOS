"""WORK-046 deterministic resource identifiers and request
correlation.

Identity discipline (the W041/W042/W051 precedent): every
developer-visible resource id and every request correlation id
is a CONTENT-DERIVED fingerprint --

    "sha256:" + sha256(canonical_json_bytes(content))

over the WORK-003 canonical JSON profile.  Identifiers are
fingerprints ONLY: not NodeIDs, not trust, never an
authorization, and never a session, path, routing, or transport
identity.  ADAPTED resources (commercial intents/reservations,
usage accounts, allocations, policies) do NOT re-derive their
ids at all -- they CITE the canonical subsystem's own
content-derived ids unchanged (no parallel ID algorithm for
resources whose truth lives in an accepted authority).

Determinism and collision safety: the derivation content binds
the ENVIRONMENT namespace, the resource kind, the owning
developer, and the mutation's durable uniqueness material (the
developer-supplied idempotency key, which the durable
idempotency ledger keeps unique per developer).  Therefore:

- identical logical mutations derive identical ids (stable
  across retries, reads, webhook delivery, pagination, and
  restart/recovery -- the W046 contract's stability demands);
- sandbox and production namespaces derive DIFFERENT ids by
  construction (the environment member differs), so a sandbox
  resource id can never collide with a production resource id;
- the ids are deterministic across hash seeds and processes
  (canonical bytes, sorted content, no randomness, no UUIDs).

Request correlation: ``derive_request_id`` fingerprints the
full request attribution (environment, api version, method,
route, canonical body).  A retried identical request therefore
carries the SAME correlation id across attempts (traceable
retry chains); a materially different request derives a
different one.  Correlation ids are observability DATA: they
never authorize, never order state, and never become resource
identity.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

from protocol.canonicalization import canonical_json_bytes

#: The id namespace discriminator for developer-API resources.
ID_NAMESPACE = "adc-os-developerapi"


def _fingerprint(content: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(dict(content))
    ).hexdigest()


def derive_resource_id(
    environment: str,
    kind: str,
    developer_id: str,
    key_material: str,
) -> str:
    """A deterministic, collision-safe, environment-namespaced
    developer-visible resource id.

    ``key_material`` is the mutation's durable uniqueness
    material (the developer-supplied idempotency key): the
    durable idempotency ledger guarantees one admitted mutation
    per (developer, key), so derived ids are collision-safe by
    the ledger, not by chance."""
    if not environment or not kind or not developer_id or not key_material:
        raise ValueError(
            "invalid-input: resource id derivation requires environment, "
            "kind, developer, and key material (all non-empty)"
        )
    return _fingerprint(
        {
            "namespace": ID_NAMESPACE,
            "environment": environment,
            "kind": kind,
            "developer": developer_id,
            "key": key_material,
        }
    )


def derive_request_id(
    environment: str,
    api_version: str,
    method: str,
    route: str,
    body: Mapping[str, Any],
) -> str:
    """A deterministic, request-scoped correlation identifier.

    Pure function of the full request attribution: identical
    retried requests correlate, materially different requests do
    not.  Observability DATA only."""
    if not environment or not api_version or not method or not route:
        raise ValueError(
            "invalid-input: request correlation requires environment, api "
            "version, method, and route (all non-empty)"
        )
    return _fingerprint(
        {
            "namespace": ID_NAMESPACE,
            "correlation": True,
            "environment": environment,
            "api_version": api_version,
            "method": method,
            "route": route,
            "body": dict(body),
        }
    )


def derive_api_command_id(
    environment: str, developer_id: str, idempotency_key: str
) -> str:
    """The deterministic command id the boundary submits to an
    adapted canonical subsystem for one API mutation.

    Derived from the (environment, developer, idempotency key)
    triple -- NOT from the request body -- so the crash-window
    redelivery of the SAME key with DIFFERENT content fails
    closed inside the canonical subsystem's own durable
    idempotency (command-conflict) and is classified at the
    boundary as ``idempotency-conflict``; the same key with the
    same content replays idempotently through the subsystem's
    own duplicate semantics."""
    if not environment or not developer_id or not idempotency_key:
        raise ValueError(
            "invalid-input: api command derivation requires environment, "
            "developer, and idempotency key (all non-empty)"
        )
    return "developerapi:" + _fingerprint(
        {
            "namespace": ID_NAMESPACE,
            "command": True,
            "environment": environment,
            "developer": developer_id,
            "key": idempotency_key,
        }
    )
