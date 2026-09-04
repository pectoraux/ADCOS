"""ADCOS platform capability package — WORK-050: the versioned
platform connectivity sharing capability registry and its
deterministic compatibility evaluation.

Implements the frozen WORK-050 stages under the active
authorization WORK-050-CORE-001 (DEC-0078; baseline advanced to
deae346 by DEC-0079 / LEDGER-RECON-023): W050.1 — the
declaration model and the immutable versioned content-addressed
registry (accepted); W050.2 — the deterministic compatibility
evaluation ((profile x role x sharing mode x isolation
requirement) -> supported/restricted/unsupported/unknown + typed
findings; unregistered is the fail-closed unknown default; no
label ever implies support).  The central boundary:

    W050 "supported"  !=  permission
                      !=  authorization
                      !=  proven enforcement
                      !=  active connectivity
                      !=  physical evidence

This package is a CAPABILITY/ISOLATION DECLARATION boundary, not
a new enforcement authority: it declares, as versioned advisory
capability input consumed by WORK-048/W049, which platforms (by
opaque identity: OS family, device class, network configuration,
deployment mode — DATA labels, never authoritative) DECLARE which
connectivity-sharing capability, per participation role and per
sharing-mode class, with which isolation primitives carrying
explicit minimum security/isolation properties, plus metering /
byte-counting authority and lease-enforcement capability
DECLARATIONS.  It is NOT routing, NetworkPath, session, identity,
transport, commercial, usage, payment, marketplace, or enforcement
authority, and it does not implement WORK-048/W049 enforcement.

Vocabulary reuse (frozen — no second vocabulary exists in this
family): the capability-state vocabulary is IMPORTED from the
accepted containment authority's frozen definition
(``containment.state.CapabilityState``, ACR-012 §4:
``unsupported | unknown | supported | restricted``), exactly as
``client/capability.py`` (W049) established the reuse pattern;
isolation mechanism labels are the frozen ``ISOLATION_MECHANISMS``
DATA handles.  Nothing in this package redeclares a capability
state.

Fail-closed rules (frozen):

1. A capability state outside the frozen vocabulary is rejected
   (CAPABILITY_INVALID) — never coerced.
2. The DEFAULT for an unregistered platform is UNKNOWN (fail
   closed), never supported: no platform label, OS name, socket
   capability, or tethering-API presence is ever implicitly
   converted into a capability state — the only capability
   source is an explicit registry declaration.
3. RESTRICTED is usable only within its explicit, documented
   restriction set (sorted, deduplicated, frozen at declaration).
4. Conflicting duplicate rows fail closed (DUPLICATE_CONFLICT);
   identical duplicates are idempotent.
5. The registry is immutable, versioned, content-addressed, and
   deterministic (byte-identical repeat serialization; canonical
   order independent of input order and hash-seed).
6. Every row is SOFTWARE evidence class only: a capability
   declaration is never a PHYSICAL platform claim and never
   proof that a particular physical deployment currently works.

W050.2 stop boundary (frozen): this package contains the
declaration model, the registry, and the deterministic
compatibility evaluation ONLY.  Versioned auditable HISTORY,
the deterministic battery, and CI wiring are later stages
(history.py / selftest are NOT implemented here); W048/W049
integration, OS/platform adapters, packet forwarding, and
firewall/tether/VPN/proxy implementation are forbidden
territory.  This package composes with the authorities — it
replaces none of them.
"""

from __future__ import annotations

from .errors import PlatformCapabilityError, PlatformCapabilityReasonCode
from .evaluation import (
    CompatibilityEvaluation,
    EvaluationFinding,
    evaluate_sharing_compatibility,
)
from .model import (
    EVIDENCE_CLASS_SOFTWARE,
    ROLE_BUYER,
    ROLE_PROVIDER,
    ROLES,
    SCHEMA_VERSION,
    CapabilityState,
    IsolationPrimitive,
    LeaseEnforcementCapability,
    MeteringCapability,
    PlatformIdentity,
    PlatformProfile,
    RoleCapability,
    SharingModeClass,
    SharingModeDeclaration,
)
from .registry import PlatformCapabilityRegistry

__all__ = [
    "EVIDENCE_CLASS_SOFTWARE",
    "ROLE_BUYER",
    "ROLE_PROVIDER",
    "ROLES",
    "SCHEMA_VERSION",
    "CapabilityState",
    "CompatibilityEvaluation",
    "EvaluationFinding",
    "IsolationPrimitive",
    "LeaseEnforcementCapability",
    "MeteringCapability",
    "PlatformCapabilityError",
    "PlatformCapabilityReasonCode",
    "PlatformCapabilityRegistry",
    "PlatformIdentity",
    "PlatformProfile",
    "RoleCapability",
    "SharingModeClass",
    "SharingModeDeclaration",
    "evaluate_sharing_compatibility",
]
