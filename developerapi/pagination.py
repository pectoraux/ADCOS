"""WORK-046 deterministic pagination and filtering.

The W046 contract's list-operation discipline:

- **deterministic ordering**: every list operation iterates a
  canonical, sorted order (resource id ascending).  A repeated
  read against unchanged state produces byte-identical
  ordering; there is NO dependence on incidental dictionary,
  database, or process ordering.

- **stable cursor semantics**: the cursor is an opaque,
  content-derived fingerprint of (environment, resource kind,
  developer, the request's filter digest, and the last item's
  id).  A cursor is only valid for the SAME list context: a
  cursor from another kind, another developer, another
  environment, or a different filter set is rejected
  deterministically (``pagination-invalid``) -- no silent
  cross-context reuse, no leaking hidden data.

- **limits**: the page-size bounds are frozen (default 20, max
  100); out-of-bounds limits are rejected deterministically.

- **filtering**: equality filters over declared, indexable
  members with sorted iteration (deterministic); unknown filter
  keys are rejected (``filter-invalid``) rather than ignored.

- **tenant isolation**: the gateway only ever hands this module
  the authenticated developer's own resources, so pagination
  cannot leak cross-tenant data (battery-pinned with two
  developers side by side).

Cursors are DATA: they never order or mutate canonical state,
and they never become resource identity.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import DeveloperApiReasonCode, DeveloperApiError

#: The frozen page-size bounds (single site).
DEFAULT_PAGE_LIMIT = 20
MAX_PAGE_LIMIT = 100


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


def normalize_limit(limit: object) -> int:
    """The validated page size (default 20, bounds 1..100;
    deterministic rejection outside)."""
    if limit is None:
        return DEFAULT_PAGE_LIMIT
    if not isinstance(limit, int) or isinstance(limit, bool):
        raise DeveloperApiError(
            DeveloperApiReasonCode.PAGINATION_INVALID,
            "limit must be an integer between 1 and %d" % MAX_PAGE_LIMIT,
        )
    if limit < 1 or limit > MAX_PAGE_LIMIT:
        raise DeveloperApiError(
            DeveloperApiReasonCode.PAGINATION_INVALID,
            "limit %d is outside 1..%d" % (limit, MAX_PAGE_LIMIT),
        )
    return limit


def normalize_filters(
    filters: object, allowed: Tuple[str, ...]
) -> Dict[str, str]:
    """The validated equality-filter set (unknown keys rejected
    ``filter-invalid``; values must be non-empty scalars)."""
    if filters is None:
        return {}
    if isinstance(filters, str) or not isinstance(filters, Mapping):
        raise DeveloperApiError(
            DeveloperApiReasonCode.FILTER_INVALID,
            "filters must be a mapping of member name -> value",
        )
    out: Dict[str, str] = {}
    for key in sorted(filters):
        if key not in allowed:
            raise DeveloperApiError(
                DeveloperApiReasonCode.FILTER_INVALID,
                "filter %r is not one of the filterable members %s"
                % (key, list(allowed)),
            )
        value = filters[key]
        if isinstance(value, bool) or not isinstance(
            value, (str, int)
        ):
            raise DeveloperApiError(
                DeveloperApiReasonCode.FILTER_INVALID,
                "filter %r must carry a string or integer value" % key,
            )
        out[key] = str(value)
    return out


def _cursor_digest(
    environment: str,
    kind: str,
    developer_id: str,
    filter_digest: str,
) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(
            {
                "cursor": True,
                "environment": environment,
                "kind": kind,
                "developer": developer_id,
                "filters": filter_digest,
            }
        )
    ).hexdigest()


def encode_cursor(
    environment: str,
    kind: str,
    developer_id: str,
    filters: Mapping[str, str],
    last_id: str,
) -> str:
    """The opaque cursor: a content-derived fingerprint binding
    the list context and the resume position."""
    _require_text(environment, "environment")
    _require_text(kind, "resource kind")
    _require_text(developer_id, "developer")
    _require_text(last_id, "last id")
    filter_digest = "sha256:" + hashlib.sha256(
        canonical_json_bytes(dict(filters))
    ).hexdigest()
    payload = "%s:%s" % (
        _cursor_digest(environment, kind, developer_id, filter_digest),
        last_id,
    )
    return "cur_" + payload.encode("utf-8").hex()


def decode_cursor(
    cursor: object,
    environment: str,
    kind: str,
    developer_id: str,
    filters: Mapping[str, str],
) -> str:
    """Validate a cursor against the current list context and
    return the resume-after resource id.

    Fail closed ``pagination-invalid`` on: malformed cursor,
    wrong context (environment/kind/developer/filters), or a
    tampered fingerprint -- deterministic rejection, never a
    silent reset."""
    if not isinstance(cursor, str) or not cursor.startswith("cur_"):
        raise DeveloperApiError(
            DeveloperApiReasonCode.PAGINATION_INVALID,
            "cursor is malformed (expected the opaque cur_ form)",
        )
    filter_digest = "sha256:" + hashlib.sha256(
        canonical_json_bytes(dict(filters))
    ).hexdigest()
    expected_prefix = _cursor_digest(
        environment, kind, developer_id, filter_digest
    )
    payload = "%s:" % expected_prefix
    # cursor = cur_ + hex(digest + ":" + last_id)
    try:
        hex_body = cursor[len("cur_"):]
        decoded = bytes.fromhex(hex_body).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as error:
        raise DeveloperApiError(
            DeveloperApiReasonCode.PAGINATION_INVALID,
            "cursor is not a decodable opaque token: %s" % error,
        ) from error
    if not decoded.startswith(payload):
        raise DeveloperApiError(
            DeveloperApiReasonCode.PAGINATION_INVALID,
            "cursor belongs to a different list context (environment/"
            "kind/developer/filters must match the request)",
        )
    last_id = decoded[len(payload):]
    if not last_id:
        raise DeveloperApiError(
            DeveloperApiReasonCode.PAGINATION_INVALID,
            "cursor carries no resume position",
        )
    return last_id


def apply_filters(
    items: Sequence[Mapping[str, Any]],
    filters: Mapping[str, str],
) -> List[Mapping[str, Any]]:
    """Deterministic equality filtering over the declared
    members (sorted output order preserved: id ascending)."""

    def matches(item: Mapping[str, Any]) -> bool:
        for key in sorted(filters):
            member = item.get(key)
            if member is None:
                return False
            if str(member) != filters[key]:
                return False
        return True

    return [item for item in items if matches(item)]


def paginate(
    items: Sequence[Mapping[str, Any]],
    *,
    environment: str,
    kind: str,
    developer_id: str,
    filters: Mapping[str, str],
    cursor: object,
    limit: object,
) -> Tuple[List[Mapping[str, Any]], str, bool]:
    """Deterministic cursor pagination over the (already
    tenant-scoped, canonically sorted) item sequence.

    Returns (page, next_cursor, has_more).  A repeated call
    with unchanged state and the same inputs produces the
    byte-identical page."""
    limit = normalize_limit(limit)
    ordered = sorted(items, key=lambda item: str(item.get("id", "")))
    if cursor:
        last_id = decode_cursor(
            cursor, environment, kind, developer_id, filters
        )
        ordered = [
            item
            for item in ordered
            if str(item.get("id", "")) > last_id
        ]
    page = ordered[:limit]
    rest = ordered[limit:]
    has_more = bool(rest)
    next_cursor = ""
    if has_more:
        next_cursor = encode_cursor(
            environment,
            kind,
            developer_id,
            filters,
            str(page[-1].get("id", "")),
        )
    return page, next_cursor, has_more
