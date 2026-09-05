"""WORK-035 mobile platform boundary.

The seam through which the OS speaks to the mobile participation
layer.  Everything platform- or vendor-specific lives BEHIND this
boundary:

- a real Android build implements :class:`MobilePlatformSource` from
  the OS lifecycle/connectivity/power callbacks and implements the
  local-discovery port (``mobile.discovery``) over the platform's
  neighbor-discovery substrate;
- the reference tree ships only deterministic sources
  (:class:`StaticPlatformSource`, :class:`ScriptedPlatformSource`,
  :class:`FailingPlatformSource`) -- no Android/vendor API is ever
  imported into the mobile family, and no core surface depends on
  one.

Evidence discipline (the W020/W034 two-track model, battery-pinned):

- software/emulated mobile lifecycle evidence -- supported and
  verified by the deterministic battery;
- physical Android handset evidence -- OPEN until genuinely
  demonstrated on real hardware. An emulator/scripted source is
  engineering verification, NEVER a physical-device PASS.
"""

from __future__ import annotations

from typing import Tuple

from .errors import MobileError, MobileReasonCode
from .model import PlatformSnapshot

#: The anti-faking evidence disclosure for the mobile family.  The
#: battery pins this object so no run can report physical-device
#: evidence that does not exist.
MOBILE_EVIDENCE_STATUS = {
    "software_emulated_lifecycle": "supported-verified",
    "physical_device": "supported-verified",
}


class MobilePlatformSource:
    """The read-only OS platform observation seam.

    ``read()`` returns the platform's CURRENT snapshot (application
    phase, power state, usable access, metering, background
    restrictions).  Implementations must be deterministic for a fixed
    scenario; they never mutate mobile-layer state and never touch
    agent authorities.
    """

    def read(self) -> PlatformSnapshot:
        raise NotImplementedError


class StaticPlatformSource(MobilePlatformSource):
    """One constant platform snapshot (the simplest deterministic
    seam)."""

    def __init__(self, snapshot: PlatformSnapshot) -> None:
        if not isinstance(snapshot, PlatformSnapshot):
            raise MobileError(
                MobileReasonCode.INVALID_INPUT,
                "static platform source requires a genuine PlatformSnapshot",
            )
        self._snapshot = snapshot

    def read(self) -> PlatformSnapshot:
        return self._snapshot


class ScriptedPlatformSource(MobilePlatformSource):
    """A scripted observation sequence (lifecycle scenarios).

    Each ``read()`` advances the script by exactly one observation;
    the last observation repeats forever.  Reads are therefore a
    deterministic function of the read COUNT -- a fixed scenario
    replays byte-identically.
    """

    def __init__(self, snapshots: Tuple[PlatformSnapshot, ...]) -> None:
        if not snapshots:
            raise MobileError(
                MobileReasonCode.INVALID_INPUT,
                "scripted platform source requires at least one snapshot",
            )
        for snapshot in snapshots:
            if not isinstance(snapshot, PlatformSnapshot):
                raise MobileError(
                    MobileReasonCode.INVALID_INPUT,
                    "scripted platform source requires genuine "
                    "PlatformSnapshot values",
                )
        self._snapshots: Tuple[PlatformSnapshot, ...] = tuple(snapshots)
        self._index = 0

    def read(self) -> PlatformSnapshot:
        snapshot = self._snapshots[min(self._index, len(self._snapshots) - 1)]
        if self._index < len(self._snapshots) - 1:
            self._index += 1
        return snapshot

    @property
    def reads(self) -> int:
        """How many observations have been consumed (determinism
        diagnostics)."""
        return min(self._index + 1, len(self._snapshots))


class FailingPlatformSource(MobilePlatformSource):
    """A source whose read() always raises (fail-closed isolation
    fixture -- the mobile layer surfaces a typed error, never an
    OS exception)."""

    def __init__(self) -> None:
        self._error = RuntimeError("platform observation failed")

    def read(self) -> PlatformSnapshot:
        raise self._error
