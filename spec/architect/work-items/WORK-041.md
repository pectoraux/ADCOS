# WORK-041 — First-Class Network Path and Platform Integration

Status: READY-CANDIDATE — not execution-authorized.
Tracking issue: #68
Architecture basis: ACR-005 (accepted by DEC-0047)

## Objective
Implement the accepted ACR-005 network-path/platform boundary without creating a second identity, session, routing, transport, federation, or policy authority.

## Required outcomes
- Introduce a technology-neutral `NetworkPath` representation over existing authority-owned state.
- Separate platform observation from ADCOS protocol state.
- Separate path detection, validation, binding, activation, and retirement.
- Make handover transactional: validate/bind/probe candidate before activating it; preserve the prior active path on failure where possible.
- Preserve stable logical `session_id` across physical path changes.
- Provide an evidence chain from physical/platform observation through path validation and ADCOS binding to traffic proof.

## Required dependencies
- ACR-005 accepted.
- WORK-016 Adapter SDK/runtime.
- WORK-018 IP integration.
- WORK-033 AgentRuntime.
- WORK-034 EdgeGateway.

## Allowed authority inputs
Use existing public contracts only. Technology-specific observations must enter through adapter/platform boundaries.

## Forbidden
- New identity/session/routing/transport/federation/policy authority.
- Wire-schema changes unless separately authorized.
- Private authority access.
- Synthetic physical evidence presented as physical PASS.
- W040 continuation or WORK-042+ implementation.

## Acceptance criteria
1. The same logical session can move between distinct validated physical paths without changing `session_id`.
2. Candidate paths are detected without automatically becoming active.
3. Failed validation/bind/probe leaves the existing active path intact where possible.
4. The path/platform evidence chain is explicit, deterministic, replay-safe, and independently verifiable.
5. Existing accepted batteries remain green; no frozen authority ownership changes.

## Evidence classes
- Software/architecture conformance: required.
- Deterministic automated verification: required.
- Physical deployment evidence: not required to implement W041; physical claims remain subject to existing evidence governance.

## Execution gate
This contract does not authorize implementation. An ACTIVE repository-local authorization must exist on `main` with the exact baseline and scope before a W041 implementation branch may proceed.
