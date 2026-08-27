# WORK-028 Threat Model and Security Hardening

## Status

This document is the WORK-028 security artifact reconstructed and implemented against the frozen ADCOS architecture and the accepted dependency graph. It introduces no new protocol authority and no `/security` domain authority.

## Security objective

ADCOS security is treated as an executable property across the existing authority boundaries. The security posture is zero-trust: compromise of a node, adapter, provider, service, telemetry producer, or federation peer must not silently grant authority over another subsystem.

## Assets

- Node identity and credential references;
- policy decisions and privileged operations;
- topology state and evidence provenance;
- resource offers and measurements;
- route/path bindings;
- logical session identity and lifecycle;
- multipath and mobility state;
- federation relationships, scopes, grants and revocations;
- secure transport state and replay windows;
- service invocation authorization;
- telemetry provenance/privacy;
- energy/offline authorization state;
- protocol envelopes and version negotiation.

## Adversary model

The baseline assumes an attacker may control a previously valid node, adapter/provider implementation, federation peer, service caller, telemetry source, or captured protocol message. The attacker may replay valid objects, mutate fields, substitute identities, exploit lifecycle/recovery races, attempt cross-authority calls, or exploit Python object-level access to callable/attribute surfaces.

The model does **not** assume that Python privacy naming (`_name`) is a security boundary. Where authority issuance or mutation is security-critical, the existing accepted designs use structural ownership, content binding, validation ordering, and capability/frame boundaries.

## Abuse-case matrix

| Threat | Required control | Executable evidence |
|---|---|---|
| Compromised node / credential misuse | explicit identity/credential state, revocation, zero-trust checks | `identity_selftest.py`, `transport_selftest.py`, `federation_selftest.py` |
| Replay / stale message | envelope expiry, sequence/replay windows, transactional admission | `envelope_selftest.py`, `session_selftest.py`, `transport_selftest.py` |
| Identity spoofing / cross-domain confusion | access-independent NodeID plus explicit domain/peer binding | `identity_selftest.py`, `federation_selftest.py` |
| Topology/evidence poisoning | independent topology dimensions and provenance-preserving claims | `topology_selftest.py`, `federation_selftest.py` |
| Downgrade / profile confusion | negotiated profiles, compatibility rules, secure transport downgrade tests | `capability_selftest.py`, `transport_selftest.py` |
| Privilege escalation | deny-by-default policy and born-bound privileged decisions | `policy_selftest.py`, `service_selftest.py`, `telemetry_selftest.py` |
| Route/path hijacking | content-bound path/decision identifiers and policy/session binding | `routing_selftest.py`, `session_selftest.py`, `multipath_selftest.py` |
| Capability inflation / provider leakage | adapter sandboxing and declaration floors; provider isolation; vendor specifics structurally confined to the adapters boundary | `capability_selftest.py`, `adapter_selftest.py`, `security_selftest.py` (BOUND-01/NT-*) |
| Federation scope escalation | explicit scope evaluation, revocation, peer-domain isolation | `federation_selftest.py` |
| Secret leakage | LOCK-023 structural scans and serialization/diagnostic negative tests | `security_selftest.py`, `identity_selftest.py`, `adapter_selftest.py`, `transport_selftest.py` |
| Authority bypass | downstream layers verify/extract rather than mint upstream authority | `security_selftest.py` plus policy/service/telemetry/routing/session suites |
| Recovery resurrection / rollback abuse | explicit lifecycle transitions, revocation lineage, cleanup proofs | `mobility_selftest.py`, `service_selftest.py`, `energy_selftest.py`, `session_selftest.py` |

## Security controls by authority

### Identity authority
`identity/` remains authoritative for NodeID and credential state. Security tests must reject technology-derived identity and credential-like leakage into ordinary domain serialization.

### Policy authority
`policy/` remains authoritative for authorization. Downstream families may consume verified decisions but must not mint privileged decisions themselves. Privileged operations remain deny-by-default.

### Topology authority
`topology/` owns topology state. Remote statements remain claims with provenance and cannot silently become authoritative topology facts.

### Routing/session authority
`routing/` owns path selection; `sessions/` owns logical session state. Security controls must prevent path/content tampering from changing session identity or bypassing policy.

### Adapter/transport boundaries
Provider-specific state remains outside the core. Vendor specifics are structurally confined behind the provider seam (LOCK-016): external vendor/mobile SDK imports are rejected in every authority package, and vendor-named in-repo modules exist only inside `adapters/` — never imported by non-adapter authority packages. Transport security uses established standard primitives and explicit record-protection seams; anti-replay admission is transactional.

### Federation authority
`federation/` owns inter-domain scopes and revocation. Membership in another domain is never equivalent to node-level trust.

### Services/telemetry/energy
These layers consume upstream authority. Their tests must prove that local convenience state, telemetry observations, or resilience caches cannot manufacture upstream authorization.

## Secure defaults

The expected default is fail-closed for security-critical ambiguity:

- absent/invalid credentials → reject;
- unknown privileged operation → reject;
- unknown or stale authorization → reject;
- invalid replay/sequence state → reject;
- invalid policy/resource/topology binding → reject;
- unverified provider capability → reject or remain non-authoritative;
- secret-like content in ordinary metadata → reject;
- recovery without fresh authority where required → reject;
- cleanup that cannot be proven → explicit degraded/pending state, never silent success.

Optional functionality may fail soft only when doing so cannot grant authority.

## Required security battery

`tools/security_selftest.py` combines the security-critical existing family batteries with cross-cutting structural checks. Existing family tests remain the authoritative semantic tests for their individual domains; this Work Item supplies the cross-domain security gate and threat-model evidence rather than duplicating each family's full semantics.

Every acceptance-critical finding must be represented by either a structural check or a discriminating negative regression.

## Residual assumptions

This threat model does not claim resistance to arbitrary runtime replacement of Python code objects, the interpreter, operating-system compromise, hardware-key exfiltration, or a malicious maintainer. Those are outside the application-level authority model. Cryptographic and hardware trust roots remain implementation/deployment concerns under the frozen provider boundaries.

## Definition of done

Security is considered executable when the threat-model matrix is mapped to automated negative evidence, the cross-cutting structural checks pass, and all existing security-relevant authority suites pass in the same CI gate. No separate security authority is introduced.
