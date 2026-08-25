"""Standard-primitive key schedule (WORK-017).

HKDF-SHA256 (IETF RFC 5869) and HMAC-SHA256 (IETF RFC 2104) — standard
IETF primitives implemented over the Python standard library so the
reference transport engine runs deterministically and offline with
zero third-party dependencies (LOCK-018: standards-based primitives
over reinvention).

SCOPE (WORK-017 correction): this module is the KEY SCHEDULE ONLY —
transcript-bound master-secret derivation, directional traffic-key
separation, key confirmation, chained rekey, and public lineage
digests.  It deliberately contains NO record protection: frame-level
protection lives behind the record-protection seam
(:mod:`transport.recordprotection`) inside transport implementations,
where production engines supply their profile's STANDARD record
protection (TLS 1.3 / QUIC / IPsec ESP / WireGuard-class).  The exact
extraction/expansion labels below are the frozen reference schedule;
production transport implementations plug their profile-native
schedules in behind the same
:class:`transport.contract.TransportContract` interface, and the
transcript inputs make every derived secret bound to (session,
identities, negotiated profile, policy floor) — the WORK-017 key
binding criterion.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Tuple

#: Domain-separation prefix for every label in the reference schedule.
SCHEDULE_DOMAIN = "adcos-transport"

#: Derived-secret length (bytes).
SECRET_LEN = 32


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract (RFC 5869 section 2.2) with SHA-256."""
    return _hmac(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand (RFC 5869 section 2.3) with SHA-256."""
    if isinstance(length, bool) or not isinstance(length, int) or length < 1:
        raise ValueError("hkdf_expand length must be a positive integer")
    if length > 255 * 32:
        raise ValueError("hkdf_expand length exceeds RFC 5869 limit")
    blocks = bytearray()
    previous = b""
    counter = 1
    while len(blocks) < length:
        previous = _hmac(prk, previous + info + bytes([counter]))
        blocks.extend(previous)
        counter += 1
    return bytes(blocks[:length])


def _label(name: str) -> bytes:
    return ("%s/%s" % (SCHEDULE_DOMAIN, name)).encode("utf-8")


def master_secret(transcript_digest_hex: str, freshness: bytes) -> bytes:
    """The generation-0 master secret.

    ``salt`` = the handshake transcript digest bytes (binds the secret
    to session, endpoints, full offered set, selected profile, policy
    floor, and both identity attestations); ``ikm`` = the concatenated
    freshness contributions (the two handshake nonces — the modeled
    ephemeral contributions).  Changing ANY transcript input changes
    the secret; changing the freshness changes the secret.
    """
    salt = bytes.fromhex(transcript_digest_hex)
    return hkdf_extract(salt, freshness)


def direction_keys(master: bytes, role: str) -> Tuple[bytes, bytes]:
    """Derive the (send_key, recv_key) pair for one side.

    ``role`` is ``"initiator"`` or ``"responder"``: the initiator's
    send key EQUALS the responder's receive key (the i2r key) and vice
    versa (the r2i key) — directional derivation with role binding, so
    the two ends derive matching directional keys without ever
    transmitting them.  Each direction key is the HMAC key handed to
    the record-protection seam for that direction (it is a key-derivation
    output, never a record-protection construction).
    """
    if role not in ("initiator", "responder"):
        raise ValueError("role must be 'initiator' or 'responder'")
    i2r = hkdf_expand(master, _label("keys/i2r"), SECRET_LEN)
    r2i = hkdf_expand(master, _label("keys/r2i"), SECRET_LEN)
    if role == "initiator":
        return (i2r, r2i)
    return (r2i, i2r)


def confirmation_tag(master: bytes, role: str) -> str:
    """Key-confirmation MAC proving possession of the master secret."""
    if role not in ("initiator", "responder"):
        raise ValueError("role must be 'initiator' or 'responder'")
    tag = _hmac(master, _label("confirm/%s" % role))
    return tag.hex()


def rekey_secret(current: bytes, cause: str, generation: int) -> bytes:
    """Chained generation advance (key rotation).

    The next generation's master secret is derived from the current
    one plus the rekey cause and generation number; the previous
    secret is then logically destroyed by the engine (only its PUBLIC
    lineage digest is retained).  Reuse of an old-generation frame
    fails closed at unprotect time.
    """
    info = _label("rekey/%s/%d" % (cause, generation))
    return hkdf_expand(current, info, SECRET_LEN)


def public_generation_digest(master: bytes) -> str:
    """The PUBLIC lineage digest of a generation's master secret.

    A truncated SHA-256 fingerprint for audit/state exposure — safe to
    publish (it is a digest of key material, never the material
    itself; compare the WORK-004 dev-provider public-material
    convention).
    """
    return hashlib.sha256(_label("lineage") + master).hexdigest()[:16]
