"""WORK-046 environment model (sandbox / production isolation).

The W046 contract's environment discipline:

- Sandbox and production are EXPLICIT, NON-INTERCHANGEABLE
  namespaces.  A service instance is constructed bound to
  exactly ONE environment, with its OWN store (journal), its
  OWN credentials, and its OWN adapted authority instances --
  isolation by construction, not by convention.

- A sandbox operation MUST NOT silently create production
  commercial state: the sandbox service physically holds
  different authority instances and a different journal, so no
  code path can reach production state from a sandbox request
  (the battery proves this side by side).

- A sandbox artifact MUST NOT be presented as physical
  connectivity evidence, production usage evidence, production
  settlement, or live service proof: every response carries the
  environment identity, and :func:`evidence_class` classifies
  sandbox results as ``sandbox-simulation`` (explicitly NOT
  production evidence).  Resource ids are environment-namespaced
  by derivation (:mod:`developerapi.identifiers`), so a sandbox
  resource id can never collide with (or be presented as) a
  production resource id.

- Environment identity is visible in every API resource,
  response envelope, and webhook payload (the ``environment``
  member), and a credential bound to one environment fails
  closed ``environment-mismatch`` against the other.
"""

from __future__ import annotations

from .errors import DeveloperApiError, DeveloperApiReasonCode


class Environment:
    """The frozen environment vocabulary."""

    SANDBOX = "sandbox"
    PRODUCTION = "production"

    @classmethod
    def values(cls) -> tuple:
        return (cls.SANDBOX, cls.PRODUCTION)


def require_environment(value: object) -> str:
    """Validate one environment name (fail closed)."""
    if value not in Environment.values():
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "environment %r must be one of %s"
            % (value, list(Environment.values())),
        )
    return value  # type: ignore[return-value]


def evidence_class(environment: str) -> str:
    """The honest evidence classification of results produced
    in one environment.

    ``sandbox-simulation`` results are NEVER production
    evidence: the battery's evidence-classification case pins
    that a production evidence requirement rejects them."""
    environment = require_environment(environment)
    if environment == Environment.SANDBOX:
        return "sandbox-simulation"
    return "production-commercial"


def is_production_evidence(environment: str) -> bool:
    """Whether results from this environment may satisfy a
    PRODUCTION evidence requirement (sandbox: never)."""
    return require_environment(environment) == Environment.PRODUCTION
