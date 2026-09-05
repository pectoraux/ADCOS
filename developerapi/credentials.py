"""WORK-046 developer/application credentials and capabilities.

The scoped-credential model of the developer boundary (the
W046 contract's criterion 2):

- **Capability vocabulary**: one frozen, explicit scope
  vocabulary (``offers:read`` .. ``webhooks:write``).  There is
  deliberately NO universal application permission: every API
  operation requires a specific capability, and authorization
  is checked at the boundary BEFORE any adapted subsystem is
  touched.

- **ApplicationCredential**: one frozen application identity
  record: the application id (content-derived over the
  environment/developer/name/uniqueness material), the owning
  developer, the ENVIRONMENT the credential is valid in, the
  declared capability set, the validity window, and the status
  (``active`` / ``revoked``; expiry is evaluated against the
  injected clock at verification time).

- **Credential verification**: authentication is a CONSTANT-TIME
  comparison of the presented secret's digest against the
  stored digest -- the secret itself is never stored, never
  journaled, never logged (the issuance result is the ONLY
  place the secret appears, exactly once, and the battery's
  secret-hygiene case audits every other surface for it).
  Unknown application, revoked credential, or wrong secret all
  fail closed ``authentication-invalid`` (no enumeration
  oracle); an expired credential fails closed
  ``authentication-expired``.

- **Environment binding**: a credential is valid in exactly ONE
  environment.  A sandbox credential presented to the
  production service fails closed ``environment-mismatch`` (and
  vice versa) -- one of the sandbox/production isolation
  guarantees the contract requires.

- **Capability enforcement invariant**: an application can
  perform ONLY the operations granted by its declared capability
  set.  Authentication NEVER grants authority by itself: a
  fully authenticated application without the required
  capability is rejected ``capability-denied`` before any
  business surface is reached (the battery's negative
  authorization cases).

Credentials are the developer platform's APPLICATION-level
commercial access identity ONLY.  They are not NodeIDs, not
network identity (WORK-004 owns that), not trust, and never a
connectivity authorization of any kind.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Iterable, Tuple

from agent.clock import AgentClock

from .errors import DeveloperApiError, DeveloperApiReasonCode
from .identifiers import ID_NAMESPACE

from protocol.canonicalization import canonical_json_bytes


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


#: The synthetic credential-secret prefix (test/issuance
#: convention; never a live provider token).
SECRET_PREFIX = "dasec_"


class Capability:
    """The frozen developer-platform capability vocabulary."""

    OFFERS_READ = "offers:read"
    OFFERS_WRITE = "offers:write"
    INTENTS_READ = "intents:read"
    INTENTS_WRITE = "intents:write"
    LEASES_READ = "leases:read"
    LEASES_WRITE = "leases:write"
    USAGE_READ = "usage:read"
    BILLING_READ = "billing:read"
    ECONOMIC_POLICY_READ = "economic_policy:read"
    ECONOMIC_POLICY_WRITE = "economic_policy:write"
    WEBHOOKS_READ = "webhooks:read"
    WEBHOOKS_WRITE = "webhooks:write"

    @classmethod
    def values(cls) -> tuple:
        return (
            cls.OFFERS_READ,
            cls.OFFERS_WRITE,
            cls.INTENTS_READ,
            cls.INTENTS_WRITE,
            cls.LEASES_READ,
            cls.LEASES_WRITE,
            cls.USAGE_READ,
            cls.BILLING_READ,
            cls.ECONOMIC_POLICY_READ,
            cls.ECONOMIC_POLICY_WRITE,
            cls.WEBHOOKS_READ,
            cls.WEBHOOKS_WRITE,
        )


def _require_capabilities(
    capabilities: Iterable[str],
) -> Tuple[str, ...]:
    if isinstance(capabilities, str) or not isinstance(capabilities, Iterable):
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "capabilities must be an iterable of scope strings",
        )
    out = []
    for capability in capabilities:
        _require_text(capability, "capability")
        if capability not in Capability.values():
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "capability %r is not in the frozen vocabulary %s"
                % (capability, list(Capability.values())),
            )
        if capability not in out:
            out.append(capability)
    if not out:
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "an application credential must declare at least one capability",
        )
    return tuple(sorted(out))


def derive_application_id(
    environment: str,
    developer_id: str,
    application_name: str,
    key_material: str,
) -> str:
    """The content-derived application id (deterministic,
    environment-namespaced, collision-safe by the issuance
    uniqueness material)."""
    for label, value in (
        ("environment", environment),
        ("developer_id", developer_id),
        ("application_name", application_name),
        ("key_material", key_material),
    ):
        _require_text(value, label)
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(
            {
                "namespace": ID_NAMESPACE,
                "application": True,
                "environment": environment,
                "developer": developer_id,
                "name": application_name,
                "key": key_material,
            }
        )
    ).hexdigest()


def derive_credential_secret(
    issuance_key: bytes, application_id: str
) -> str:
    """The deterministic issuance-time application secret.

    Derived (never stored): the platform's injected issuance key
    is the ONLY holder of the derivation material; the journal
    stores the secret's DIGEST, so journal bytes never carry
    credential secrets.  The secret is returned to the platform
    caller exactly once at issuance."""
    if not isinstance(issuance_key, (bytes, bytearray)) or not issuance_key:
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "issuance_key must be non-empty bytes",
        )
    _require_text(application_id, "application_id")
    digest = hmac.new(
        bytes(issuance_key),
        b"%s:application-secret:v1" % application_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return SECRET_PREFIX + digest


def secret_digest(secret: str) -> str:
    """The stored verification form of a credential secret."""
    _require_text(secret, "credential secret")
    return "sha256:" + hashlib.sha256(
        secret.encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class ApplicationCredential:
    """One frozen application credential record (the public,
    journal-safe form: the secret digest, never the secret)."""

    application_id: str
    developer_id: str
    application_name: str
    environment: str
    capabilities: Tuple[str, ...]
    status: str
    valid_until: str
    issued_at: str
    secret_digest: str

    def __post_init__(self) -> None:
        for label, value in (
            ("application_id", self.application_id),
            ("developer_id", self.developer_id),
            ("application_name", self.application_name),
            ("environment", self.environment),
            ("status", self.status),
            ("valid_until", self.valid_until),
            ("issued_at", self.issued_at),
            ("secret_digest", self.secret_digest),
        ):
            _require_text(value, label)
        if self.status not in ("active", "revoked"):
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "credential status %r must be active or revoked"
                % self.status,
            )
        object.__setattr__(
            self, "capabilities", _require_capabilities(self.capabilities)
        )

    def to_dict(self) -> Dict[str, Any]:
        """The developer-facing public form (no secret material)."""
        return {
            "application_id": self.application_id,
            "developer_id": self.developer_id,
            "application_name": self.application_name,
            "environment": self.environment,
            "capabilities": list(self.capabilities),
            "status": self.status,
            "valid_until": self.valid_until,
            "issued_at": self.issued_at,
        }


@dataclass(frozen=True)
class IssuedCredential:
    """The one-time issuance result: the public record plus the
    secret, shown to the platform caller exactly ONCE (never
    journaled, never logged, never re-derivable by read)."""

    record: ApplicationCredential
    secret: str

    def to_dict(self) -> Dict[str, Any]:
        out = dict(self.record.to_dict())
        out["credential_secret"] = self.secret
        return out


def verify_credential(
    application: ApplicationCredential,
    environment: str,
    presented_secret: object,
    clock: AgentClock,
) -> None:
    """Verify one presented credential against its record.

    Fail-closed order: environment binding first (a sandbox
    credential never authenticates against the production
    service), then status, then constant-time secret comparison,
    then expiry evaluated against the injected clock.

    Raises the typed authentication failures; returns None on
    success."""
    if not isinstance(clock, AgentClock):
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "credential verification requires an AgentClock",
        )
    _require_text(environment, "environment")
    if application.environment != environment:
        raise DeveloperApiError(
            DeveloperApiReasonCode.ENVIRONMENT_MISMATCH,
            "credential %r is bound to environment %r and cannot "
            "authenticate in environment %r"
            % (application.application_id, application.environment, environment),
        )
    if application.status == "revoked":
        raise DeveloperApiError(
            DeveloperApiReasonCode.AUTHENTICATION_INVALID,
            "credential %r is revoked" % application.application_id,
        )
    if not isinstance(presented_secret, str) or not presented_secret:
        raise DeveloperApiError(
            DeveloperApiReasonCode.AUTHENTICATION_INVALID,
            "a credential secret is required",
        )
    if not hmac.compare_digest(
        secret_digest(presented_secret).encode("utf-8"),
        application.secret_digest.encode("utf-8"),
    ):
        raise DeveloperApiError(
            DeveloperApiReasonCode.AUTHENTICATION_INVALID,
            "credential %r failed verification" % application.application_id,
        )
    now = clock.now()
    if application.valid_until and application.valid_until <= now:
        raise DeveloperApiError(
            DeveloperApiReasonCode.AUTHENTICATION_EXPIRED,
            "credential %r expired at %s (now %s)"
            % (application.application_id, application.valid_until, now),
        )


def require_capability(
    application: ApplicationCredential,
    capability: str,
) -> None:
    """The scoped-authorization gate: the operation's required
    capability must be in the application's declared set.

    Authentication alone NEVER grants authority (the negative
    authorization battery pins this)."""
    if capability not in Capability.values():
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "capability %r is not in the frozen vocabulary" % capability,
        )
    if capability not in application.capabilities:
        raise DeveloperApiError(
            DeveloperApiReasonCode.CAPABILITY_DENIED,
            "application %r lacks the required capability %r (declared: %s)"
            % (
                application.application_id,
                capability,
                list(application.capabilities),
            ),
        )
