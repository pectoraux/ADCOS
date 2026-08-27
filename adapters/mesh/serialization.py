"""ADCOS mesh serialization helpers (WORK-023).

Canonical-JSON reduction of the mesh value types (recursive
``to_dict()``), mirroring the WORK-018/019/021/022 family
serialization modules.  Every value type carries a ``to_dict()``
producing canonical-JSON-representable content (strings, ints,
bools, lists); the helpers below reduce any value-tree of such
types into the frozen canonical bytes.
"""

from __future__ import annotations

from typing import Any

from protocol.canonicalization import canonical_json_bytes

__all__ = [
    "to_canonical_dict",
    "to_canonical_bytes",
    "canonical_json_bytes",
]


def to_canonical_dict(value: Any) -> Any:
    """Recursively reduce a value-tree of mesh value types into plain
    canonical-JSON content (dicts/lists/strings/ints/bools)."""
    if hasattr(value, "to_dict"):
        return to_canonical_dict(value.to_dict())
    if isinstance(value, dict):
        return {key: to_canonical_dict(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_canonical_dict(item) for item in value]
    return value


def to_canonical_bytes(value: Any) -> bytes:
    """The deterministic canonical bytes of a mesh value-tree."""
    return canonical_json_bytes(to_canonical_dict(value))
