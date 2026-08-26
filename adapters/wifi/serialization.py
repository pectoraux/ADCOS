"""ADCOS Wi-Fi/non-3GPP access adapter serialization (WORK-021).

Canonical-JSON serialization for the Wi-Fi/non-3GPP access boundary's
outward-facing state.  Uses the WORK-003 ``protocol.canonicalization``
module (canonical JSON bytes) so the boundary's public state is
byte-identical across implementations (B2: ``implementation_label``
excluded from canonical state; mirrors the WORK-018/019 discipline).
No vendor SDK, no crypto, no randomness.
"""

from __future__ import annotations

from typing import Any

from protocol.canonicalization import canonical_json_bytes

__all__ = ["canonical_json_bytes", "to_canonical_bytes", "to_canonical_dict"]


def to_canonical_dict(obj: Any) -> Any:
    """Recursively reduce a model object to a canonical-JSON-able
    structure (dicts/lists/primitives)."""
    if hasattr(obj, "to_dict") and callable(obj.to_dict):
        return to_canonical_dict(obj.to_dict())
    if isinstance(obj, dict):
        return {str(k): to_canonical_dict(v) for k, v in sorted(obj.items())}
    if isinstance(obj, (list, tuple)):
        return [to_canonical_dict(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


def to_canonical_bytes(obj: Any) -> bytes:
    """Canonical-JSON bytes of the boundary's outward-facing state."""
    return canonical_json_bytes(to_canonical_dict(obj))
