"""WORK-047 privacy-preserving proximity abstraction.

The geospatial representation of the marketplace discovery family.

Frozen boundary (the W047 contract):

- The consumer's location is NEVER represented more precisely than
  the product decision requires.  Precision is an explicit,
  configurable, FROZEN vocabulary of bounded cell sizes; there is
  no "exact" level and no API surface that returns exact consumer
  coordinates.
- Exact consumer location is not stored by default -- and in this
  family it is never stored at all: the ONLY persisted location
  representation is :class:`LocationBound` (a quantized cell id +
  the precision level + provenance).  The binding function
  consumes exact coordinates transiently and returns a bound; the
  coordinates are not retained anywhere in the family.
- Proximity is EVIDENCE, never invented truth: cell quantization
  and the equatorial meter approximation make the distance between
  two bounds a conservative BOUNDED interval, never an exact
  distance, and never a reachability claim.

Determinism: pure integer arithmetic over micro-degree integers
(no floating point, no wall clock, no randomness).  Two exact
coordinates inside one cell bind to the byte-identical bound
(deterministic many-to-one quantization), and identical inputs
produce byte-identical canonical content.

Privacy honesty: quantization bounds the spatial RESOLUTION of the
persisted representation (a cell id at an explicit precision level,
never exact coordinates).  It is deliberately NOT a population-count
guarantee -- there is no minimum-k threshold, no population census,
and no suppression rule in this family, and none is claimed.  A
population-count privacy design would require a separately
authorized privacy authority; this family does not invent one.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import MarketplaceError, MarketplaceReasonCode

# ---------------------------------------------------------------------------
# The frozen precision vocabulary (configurable accuracy/privacy)
# ---------------------------------------------------------------------------

#: Approximate meters per degree of latitude (WGS-84 mean value).
#: Integer constant: the deterministic meter basis of this family.
_METERS_PER_DEGREE_LAT = 110_574

#: Approximate meters per degree of longitude at the equator.
#: Integer constant.  The equatorial basis is a conservative
#: OVERESTIMATE of the true east-west distance at any latitude,
#: which keeps every derived distance interval conservative for
#: inclusion decisions (fail closed: a candidate is only proposed
#: within a distance limit when the whole bound is within it).
_METERS_PER_DEGREE_LON = 111_320

#: The frozen precision vocabulary: level name -> bounded cell size
#: in meters.  The level names embed the bound so a serialized
#: record is self-describing about its own precision.  The finest
#: level (50 m) is still a BOUND -- there is deliberately no exact
#: level.
PRECISION_LEVELS: Dict[str, int] = {
    "coarse-50000m": 50_000,
    "regional-10000m": 10_000,
    "district-2500m": 2_500,
    "local-1000m": 1_000,
    "neighborhood-250m": 250,
    "near-50m": 50,
}

#: The default discovery precision (the product rule: marketplace
#: offer discovery needs no finer precision than a district).
DEFAULT_PRECISION_LEVEL = "district-2500m"

#: The frozen provenance vocabulary for location bounds.
BOUND_PROVENANCE_VALUES: Tuple[str, ...] = (
    "consumer-query-bounded",
    "provider-coverage-declared",
)


def precision_levels() -> Tuple[str, ...]:
    """The precision vocabulary, sorted (frozen order)."""
    return tuple(sorted(PRECISION_LEVELS))


def cell_size_m(precision_level: str) -> int:
    """The bounded cell size (meters) of one precision level."""
    if precision_level not in PRECISION_LEVELS:
        raise MarketplaceError(
            MarketplaceReasonCode.PRECISION_UNKNOWN,
            "precision level %r is not one of the frozen vocabulary %s"
            % (precision_level, [precision_levels()]),
        )
    return PRECISION_LEVELS[precision_level]


def _grid_steps(precision_level: str) -> Tuple[int, int]:
    """The integer micro-degree grid steps of one precision level.

    Latitudinal and longitudinal steps are derived from the frozen
    meter constants with pure integer arithmetic (floor division),
    so the grid is byte-stable across platforms and runs.
    """
    size = cell_size_m(precision_level)
    lat_step = (size * 1_000_000) // _METERS_PER_DEGREE_LAT
    lon_step = (size * 1_000_000) // _METERS_PER_DEGREE_LON
    if lat_step <= 0 or lon_step <= 0:
        raise MarketplaceError(
            MarketplaceReasonCode.PRECISION_UNKNOWN,
            "precision level %r degenerates to a zero grid step"
            % precision_level,
        )
    return lat_step, lon_step


# ---------------------------------------------------------------------------
# The persisted representation: a bounded cell (never exact)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LocationBound:
    """One privacy-bounded location representation.

    Members (deliberately minimal -- and deliberately WITHOUT any
    latitude/longitude member):

    - ``cell_id``: the quantized grid cell
      (``"mpcell:v1:<level>:<lat-index>:<lon-index>"``);
    - ``precision_level``: the frozen precision level that produced
      the cell (the bound's explicit precision statement);
    - ``provenance``: where the bound came from (the frozen
      vocabulary: a consumer query bound or a provider-declared
      coverage bound).

    A LocationBound never carries, and can never be converted back
    to, an exact position: the quantization is many-to-one by
    construction.
    """

    cell_id: str
    precision_level: str
    provenance: str

    def __post_init__(self) -> None:
        if not isinstance(self.cell_id, str) or not self.cell_id:
            raise MarketplaceError(
                MarketplaceReasonCode.INVALID_INPUT,
                "cell_id must be a non-empty string",
            )
        if self.cell_id.split(":")[:2] != ["mpcell", "v1"]:
            raise MarketplaceError(
                MarketplaceReasonCode.INVALID_INPUT,
                "cell_id must be an mpcell:v1 grid cell id",
            )
        cell_size_m(self.precision_level)  # frozen-vocabulary check
        if self.provenance not in BOUND_PROVENANCE_VALUES:
            raise MarketplaceError(
                MarketplaceReasonCode.EVIDENCE_INVALID,
                "bound provenance %r is not one of the frozen vocabulary %s"
                % (self.provenance, list(BOUND_PROVENANCE_VALUES)),
            )

    @property
    def bound_size_m(self) -> int:
        """The bounded cell size in meters (the precision bound)."""
        return cell_size_m(self.precision_level)

    def content(self) -> Dict[str, Any]:
        """The canonical content basis (the digest basis)."""
        return {
            "cell_id": self.cell_id,
            "precision_level": self.precision_level,
            "provenance": self.provenance,
        }

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.content())

    @classmethod
    def from_dict(cls, data: object) -> "LocationBound":
        if not isinstance(data, dict):
            raise MarketplaceError(
                MarketplaceReasonCode.INVALID_INPUT,
                "location bound must be a mapping",
            )
        try:
            return cls(
                cell_id=data["cell_id"],
                precision_level=data["precision_level"],
                provenance=data["provenance"],
            )
        except KeyError as error:
            raise MarketplaceError(
                MarketplaceReasonCode.INVALID_INPUT,
                "location bound is missing %s" % error,
            ) from error


# ---------------------------------------------------------------------------
# Binding: exact coordinates -> bounded representation (one way)
# ---------------------------------------------------------------------------

# geodetic domain in integer micro-degrees
_LAT_MIN, _LAT_MAX = -90_000_000, 90_000_000
_LON_MIN, _LON_MAX = -180_000_000, 180_000_000


def _cell_indices(
    latitude_micro_deg: int,
    longitude_micro_deg: int,
    precision_level: str,
) -> Tuple[int, int]:
    """The deterministic grid indices of exact coordinates.

    Floor division handles negative latitudes/longitudes the same
    way on every platform (Python ``//`` is mathematical floor).
    """
    lat_step, lon_step = _grid_steps(precision_level)
    lat_index = latitude_micro_deg // lat_step
    lon_index = longitude_micro_deg // lon_step
    return lat_index, lon_index


def bind_query_location(
    latitude_micro_deg: int,
    longitude_micro_deg: int,
    precision_level: str,
) -> LocationBound:
    """Bind one exact consumer position to its bounded cell.

    THE privacy boundary of the family:

    - the exact coordinates are consumed transiently and NEVER
      returned, stored, or logged by this family (the return value
      is a :class:`LocationBound` -- cell id, precision,
      provenance, nothing else);
    - the precision is bounded by the frozen vocabulary (there is
      no exact level);
    - coordinates are validated against the geodetic domain and
      rejected (fail closed) outside it.

    Two exact positions inside one cell bind to the byte-identical
    bound: the binding is many-to-one by construction, which bounds
    the spatial resolution of everything downstream.  This is a
    resolution bound only -- no population-count guarantee is
    claimed or implied.
    """
    for label, value, low, high in (
        ("latitude_micro_deg", latitude_micro_deg, _LAT_MIN, _LAT_MAX),
        ("longitude_micro_deg", longitude_micro_deg, _LON_MIN, _LON_MAX),
    ):
        if not isinstance(value, int) or isinstance(value, bool):
            raise MarketplaceError(
                MarketplaceReasonCode.QUERY_LOCATION_INVALID,
                "%s must be an integer micro-degree value" % label,
            )
        if value < low or value > high:
            raise MarketplaceError(
                MarketplaceReasonCode.QUERY_LOCATION_INVALID,
                "%s=%d is outside the geodetic domain [%d, %d]"
                % (label, value, low, high),
            )
    lat_index, lon_index = _cell_indices(
        latitude_micro_deg, longitude_micro_deg, precision_level
    )
    cell_id = "mpcell:v1:%s:%d:%d" % (
        precision_level, lat_index, lon_index,
    )
    return LocationBound(
        cell_id=cell_id,
        precision_level=precision_level,
        provenance="consumer-query-bounded",
    )


def declare_coverage_cell(
    latitude_micro_deg: int,
    longitude_micro_deg: int,
    precision_level: str,
) -> LocationBound:
    """Declare one provider coverage cell (provider evidence).

    The same quantization as the consumer binding, provenance
    ``provider-coverage-declared``: provider-advertised coverage is
    EVIDENCE about where an offer is delivered, never proof of
    current reachability.
    """
    bound = bind_query_location(
        latitude_micro_deg, longitude_micro_deg, precision_level
    )
    return LocationBound(
        cell_id=bound.cell_id,
        precision_level=precision_level,
        provenance="provider-coverage-declared",
    )


def _harmonize(bound: LocationBound, precision_level: str) -> Tuple[int, int]:
    """Re-index a bound's cell onto a (possibly coarser) grid.

    Harmonization only ever COARSENS (the coarser level of the two
    bounds is chosen by the caller): re-quantizing a cell center to
    a coarser grid loses precision and never gains it, so the
    derived distance can never become more precise than the
    coarser bound allows.
    """
    parts = bound.cell_id.split(":")
    lat_index = int(parts[3])
    lon_index = int(parts[4])
    own_level = parts[2]
    lat_step, lon_step = _grid_steps(precision_level)
    if own_level == precision_level:
        return lat_index, lon_index
    # the cell center in micro-degrees (of the OWN grid)
    own_lat_step, own_lon_step = _grid_steps(own_level)
    center_lat = lat_index * own_lat_step + own_lat_step // 2
    center_lon = lon_index * own_lon_step + own_lon_step // 2
    # re-quantize to the target (coarser) grid
    return center_lat // lat_step, center_lon // lon_step


def distance_bound_m(first: LocationBound, second: LocationBound) -> Tuple[int, int]:
    """The conservative bounded distance (meters) between two bounds.

    Returns ``(minimum_m, maximum_m)``:

    - both cells are harmonized onto the COARSER precision of the
      two bounds (information only coarsens);
    - the center distance uses the fixed integer meter constants
      (the equatorial longitude basis overestimates east-west
      distance away from the equator, keeping the bound
      conservative);
    - each harmonized cell contributes a conservative in-cell
      radius (its own bound size), so the interval always covers
      the true distance between the two original cells.

    The result is a BOUND -- never an exact distance, never a
    reachability claim.
    """
    coarser = (
        first.precision_level
        if cell_size_m(first.precision_level)
        >= cell_size_m(second.precision_level)
        else second.precision_level
    )
    a_lat, a_lon = _harmonize(first, coarser)
    b_lat, b_lon = _harmonize(second, coarser)
    lat_step, lon_step = _grid_steps(coarser)
    center_a_lat = a_lat * lat_step + lat_step // 2
    center_a_lon = a_lon * lon_step + lon_step // 2
    center_b_lat = b_lat * lat_step + lat_step // 2
    center_b_lon = b_lon * lon_step + lon_step // 2
    lat_delta_micro = abs(center_a_lat - center_b_lat)
    lon_delta_micro = abs(center_a_lon - center_b_lon)
    lat_meters = (lat_delta_micro * _METERS_PER_DEGREE_LAT) // 1_000_000
    lon_meters = (lon_delta_micro * _METERS_PER_DEGREE_LON) // 1_000_000
    center_distance = lat_meters + lon_meters  # conservative (L1-style overestimate)
    radius = cell_size_m(coarser)  # conservative in-cell radius
    minimum = center_distance - 2 * radius
    if minimum < 0:
        minimum = 0
    maximum = center_distance + 2 * radius
    return minimum, maximum
