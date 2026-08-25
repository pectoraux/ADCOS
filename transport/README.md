# ADCOS Transport — Secure transport profiles (WORK-017)

## Status

**ACTIVE — Module Authority: secure transport mappings**

Implements the WORK-017 Work Item (`spec/work-items.md`) behind the
frozen `/transport` module boundary (`spec/architecture.md` §29;
`spec/architecture-lock.md` module ownership): transport mappings for
secure control/user paths, with session security independent of access
technology, keys bound to session/identity policy, replaceable
transports behind the transport interface, and tested
replay/downgrade resistance.

## The standards boundary (LOCK-018)

This module draws a precise line between **ADCOS transport semantics**
and **profile-specific cryptography**.  Nothing below is negotiable by
tests — it is the architectural boundary the WORK-017 review required:

```text
ADCOS TRANSPORT CONTRACT (core semantics — this module, frozen, testable)
    negotiation, replay windows, downgrade detection, key lifecycle,
    identity binding, session binding, lifecycle, failure isolation
                        |
                        |  behind TransportContract -> SandboxedTransport
                        |  -> TransportManager; INSIDE implementations
                        v
    RECORD PROTECTION (transport/recordprotection.py — the crypto seam)
        built-in:   ReferenceRecordProtection — integrity-only,
                    NON-confidential (HMAC-SHA256 RFC 2104 in its
                    standard MAC role; payload visible in wire_payload;
                    every frame self-declares
                    protection_model="reference-mac-only")
        production: the profile's STANDARD record protection —
                    TLS 1.3 record protection (RFC 8446 §5.2),
                    QUIC packet protection (RFC 9001 §5.4),
                    IPsec ESP (RFC 4303 §3.3.3), or WireGuard-class —
                    supplied by a concrete RecordProtection
                    implementation composed into the engine
```

Three consequences, stated plainly:

1. **`ModeledTransportEngine` is a REFERENCE MODEL, not a protocol
   implementation.**  It does NOT implement TLS 1.3, QUIC, IPsec, or
   WireGuard; its frames are not wire-compatible with any of them; it
   makes no confidentiality claim.  It proves the ADCOS transport
   CONTRACT (negotiation, transcript-bound key derivation over
   HKDF-SHA256 RFC 5869, key confirmation, replay windows, generation
   lifecycle, isolation) for any profile.  A TLS/QUIC implementation
   is an actual TLS/QUIC profile implementation plugged in behind the
   seam; an IPsec implementation is an actual IPsec profile
   implementation; a WireGuard implementation is an actual
   WireGuard-class implementation.  None of them is this engine.
2. **The reference record model is honestly non-confidential.**  The
   frame carries the payload visibly (`wire_payload`) and declares
   `protection_model="reference-mac-only"` on every frame.
   Confidentiality is a PROFILE property (declared as data by the
   profile catalog) delivered in production by the profile's standard
   record protection behind the `RecordProtection` seam — ADCOS
   defines no record-protection construction of its own (LOCK-018:
   standard leverage over reinvention).
3. **The frame contract is structural and crypto-neutral.**  Core
   validation (`transport.validation.validate_frame_view`) checks the
   member set — `transport_id`, `generation`, `sequence`,
   `protection_model`, `wire_payload`, `integrity_tag` — shapes and
   hex encoding only.  `protection_model` is an OPEN vocabulary: core
   never branches on it; each implementation enforces exactly its own
   model and fails closed on foreign models.

Profile catalog entries (`transport.profiles`) are negotiation DATA
describing standard technologies (structural properties: integrity,
confidentiality, forward secrecy, replay mode, multipath capability,
security rank).  Selecting `transport.tls.v1-3` binds SEMANTICS
(key-schedule transcript inputs, family, rank); it does not make the
engine a TLS 1.3 implementation.

## Authority boundary

```text
SECURE TRANSPORT
    ≠ SESSION AUTHORITY     (read-only WORK-012 lookup via SessionReader)
    ≠ IDENTITY AUTHORITY    (WORK-004 facade; secrets stay in the store)
    ≠ POLICY AUTHORITY      (caller-supplied policy floor DATA)
    ≠ TOPOLOGY AUTHORITY
    ≠ ACCESS AUTHORITY      (siblings with /adapters beneath session
                             semantics — architecture §25 rule 9)
    ≠ VENDOR AUTHORITY      (LOCK-017: engine health is data, never authority)
```

The transport layer is authoritative **only** for the secure-channel
state of the transports it manages — never for ADCOS-wide state.

## The replaceable interface

| Operation | Mediated behavior |
|---|---|
| `supported_profiles()` | profile ids the implementation serves (data) |
| `initialize(context)` | bring up per-transport engine state |
| `handshake_initiator(context, offer)` | start the initiator side (pending handle) |
| `handshake_responder(context, offer, …)` | negotiate, mint the final id, derive keys, produce the acceptance |
| `complete_initiator(context, offer, acceptance, …)` | verify echo/selection/id/confirmation, produce the initiator confirmation |
| `accept_confirmation(context, …)` | verify the initiator key confirmation |
| `protect(context, payload)` | frame one payload under the engine's record-protection model |
| `unprotect(context, frame)` | verify model/integrity/generation/replay, return payload |
| `rekey(context, cause)` | chained generation advance (rotation bound: 8) |
| `health()` | implementation-local health (never authoritative alone) |
| `close(context)` | destroy working key material |

Implementations depend on `TransportContract` + the least-authority
`TransportContext` facade (ids, injected instant, deterministic step
budget) and on nothing else.  `ModeledTransportEngine` — the built-in
deterministic REFERENCE MODEL — composes a `RecordProtection` object
(default: `ReferenceRecordProtection`, the integrity-only
non-confidential record model described above).  Concrete production
transports (real TLS 1.3/QUIC libraries, IPsec/WireGuard daemons,
each with its own standard record protection) plug in behind the same
ABC; `TransportManager.register_implementation` swaps them at runtime,
and `ModeledTransportEngine(record_protection=...)` composes any
record model without touching core semantics.  A swap reassigns only
the manager's DEFAULT sandbox (the one NEW establishments are routed
to); every established transport record and pending handshake owns
the sandbox it was established with, so a live transport is never
re-routed into a new implementation that holds no state for it
(per-transport sandbox ownership).

## Security model (§19; LOCK-022/LOCK-023)

- **Zero trust**: establishments require usable WORK-004 operational
  credentials on both sides; attestations are verified against the
  signer's active credential; revoked/expired credentials fail closed
  (establish, rekey, and `recheck` suspend live transports).
- **Pre-authorization lifecycle (WORK-017 correction)**: the responder
  holds a completed handshake in `AWAITING_CONFIRM` — the channel is
  cryptographically usable, the peer is NOT yet
  authenticated/authorized.  Every privileged operation
  (send/receive/protect_envelope/receive_envelope/rekey) fails closed
  with `peer-unconfirmed` until `confirm()` verifies the initiator key
  confirmation AND identity attestation AND the responder's own
  credential is still live.  "Channel cryptographically usable" is
  never conflated with "peer authenticated and authorized"; the
  initiator side is symmetric (no transport record exists before
  `complete_initiator` verifies the responder attestation).  An
  unconfirmed channel cannot suspend into the logical-session
  continuity model — it can only be confirmed or closed.
- **Key binding**: traffic secrets derive over a transcript covering
  (session, both NodeIDs, full offered set, selected profile, policy
  floor, responder attestation) — changing any input changes the keys;
  the freshness contributions are the content-derived nonces.
- **Downgrade resistance** (layered): offer-digest echo; selection
  eligibility (offered ∩ known ∩ policy floor); cryptographic key
  confirmation over the transcript-derived secret.
- **Replay protection**: offer-nonce ledger (handshake replay),
  sliding per-transport anti-replay windows (frame replay),
  WORK-003 temporal validation (message expiration).  Window
  admission is TRANSACTIONAL: the receive window is pre-checked
  read-only, the record is authenticated (model + integrity tag),
  and the sequence is committed ONLY on success — a forged frame
  with a huge sequence and an invalid tag cannot advance the
  window and starve legitimate lower-sequence frames (unauthenticated
  network input never mutates security state).
- **No secret leakage**: working key material lives only inside
  engine instances; every offer/acceptance/confirmation/state/event/
  view is structurally secret-free (deep secret rejection).
- **Failure isolation**: implementation exceptions (including
  `BaseException`) become typed `TransportFailure` **values**; return
  values are contract-validated before entering manager state; the
  deterministic step budget is the hang model.

## Determinism

All instants are injected; ids (`transport_id`, `offer_nonce`,
`event_id`) are content-derived over WORK-003 canonical JSON; profile
negotiation is maximal-rank with lexicographic tie-break (attacker
order-independent); the whole-manager `snapshot()`/
`to_canonical_bytes()` form is byte-stable for a given operation
history — and byte-identical across different record-protection
implementations (the public contract is independent of the crypto
behind it).  No wall clock, no randomness, no network.

## Out of scope

Application protocols (WORK-017 out-of-scope statement), concrete
production TLS/QUIC/IPsec network stacks and their standard record
protections (behind the seam, not in this module), IP integration
(WORK-018), concrete access technologies (WORK-019..WORK-022,
WORK-038), the WORK-010 policy engine, multipath scheduling
(WORK-013), and any second identity/session/topology authority.

## Verification

`python3 tools/transport_selftest.py` — 67 cases: contract tests,
downgrade and replay attack tests, interoperability tests,
key-binding proofs, authority-boundary audits, determinism proofs,
and the standards-boundary battery (61–67): static primitive audit
(HKDF/HMAC only, no cipher tokens anywhere in the package), honest
non-confidential self-describing frames, the pre-confirmation
zero-trust gate, record-protection replaceability, public-contract
independence from the crypto implementation, initiator-side
impersonation rejection, and this boundary documentation (runs in CI
after the adapter suite).
