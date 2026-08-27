"""ADCOS deterministic power simulation (WORK-027).

The verification vehicle for the WORK-027 "power simulation"
requirement: a discrete-event, integer-only simulator of a node's
energy budget driven by a :class:`~energy.model.PowerProfile`
(power source, battery capacity, piecewise-constant load and
generation schedules in milliwatts).

Determinism discipline: the simulator steps INTEGER seconds; per
step the level changes by ``(generation_mW - load_mW) * 1 s = mJ``
(exact integer arithmetic; no floats anywhere); the level is clamped
to ``[0, capacity]``.  Reaching the zero clamp with a still-positive
net draw is a BROWNOUT -- the honest signal that the load could not
be fully served (exactly the condition the survival gate exists to
prevent).  The same profile + step sequence always produces a
byte-identical trajectory (pinned across hash seeds by the selftest).

The simulator exposes each step's energy state as a REAL WORK-008
:class:`~resources.model.EnergyState`, so the whole downstream
control chain (posture -> stage -> gates/adaptation) consumes the
simulation exactly as it consumes real measurements -- the
simulation never alters core semantics (the WORK-031 discipline,
applied from birth).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from resources.model import EnergyState, Quantity, ResourceKind

from .errors import EnergyError, EnergyReasonCode
from .model import PowerProfile


@dataclass(frozen=True)
class PowerStepResult:
    """One simulated second's outcome (pure DATA):

    - ``second`` -- the simulated second index;
    - ``level_millijoules`` -- the level at the END of the second
      (after applying the net rate and clamping);
    - ``load_milliwatts`` / ``generation_milliwatts`` -- the rates
      that applied during the second;
    - ``brownout`` -- the net draw exceeded the available level: the
      load was NOT fully served during this second.
    """

    second: int
    level_millijoules: int
    load_milliwatts: int
    generation_milliwatts: int
    brownout: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "second": self.second,
            "level_millijoules": self.level_millijoules,
            "load_milliwatts": self.load_milliwatts,
            "generation_milliwatts": self.generation_milliwatts,
            "brownout": self.brownout,
        }


class PowerSimulator:
    """The deterministic integer power simulator for one node.

    Usage:

        sim = PowerSimulator(profile)
        for _ in range(3600):
            result = sim.step()          # advance exactly one second
        state = sim.energy_state()       # REAL WORK-008 EnergyState
        digest = sim.trajectory_digest() # deterministic fingerprint

    The trajectory digest is ``sha256`` over every step result in
    order -- identical histories produce identical digests (the
    determinism proof), and any divergence in load, generation,
    capacity, or initial level changes it.
    """

    def __init__(self, profile: PowerProfile) -> None:
        if not isinstance(profile, PowerProfile):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "profile must be a PowerProfile instance",
            )
        self._profile = profile
        self._second: int = 0
        self._level: int = profile.initial_level_millijoules
        self._history: List[PowerStepResult] = []

    # -- the discrete-event core --------------------------------------------

    def step(self, seconds: int = 1) -> Tuple[PowerStepResult, ...]:
        """Advance the simulation by ``seconds`` integer seconds (one
        :class:`PowerStepResult` per second, returned in order)."""
        if not isinstance(seconds, int) or isinstance(seconds, bool) or seconds < 1:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "seconds must be a positive int (integer-second discrete event)",
            )
        results: List[PowerStepResult] = []
        for _ in range(seconds):
            load = self._profile.load_at(self._second)
            generation = self._profile.generation_at(self._second)
            net = generation - load
            brownout = False
            if net >= 0:
                self._level = min(
                    self._profile.capacity_millijoules, self._level + net
                )
            else:
                # net < 0: the battery drains; if it cannot cover the
                # whole second's net draw, the level hits the zero
                # clamp and the load was not fully served (brownout).
                if self._level + net < 0:
                    brownout = True
                self._level = max(0, self._level + net)
            result = PowerStepResult(
                second=self._second,
                level_millijoules=self._level,
                load_milliwatts=load,
                generation_milliwatts=generation,
                brownout=brownout,
            )
            self._history.append(result)
            self._second += 1
            results.append(result)
        return tuple(results)

    # -- state accessors --------------------------------------------------------

    def elapsed_seconds(self) -> int:
        return self._second

    def level_millijoules(self) -> int:
        return self._level

    def brownout_count(self) -> int:
        """How many simulated seconds were brownouts (the honest
        degradation signal)."""
        return sum(1 for result in self._history if result.brownout)

    def energy_state(self) -> EnergyState:
        """The current energy budget as a REAL WORK-008
        :class:`~resources.model.EnergyState` (base units), so the
        downstream control chain consumes the simulation exactly as
        it consumes real measurements."""
        load = self._profile.load_at(max(0, self._second - 1))
        return EnergyState(
            energy_level=Quantity(
                value=self._level, unit="millijoules", dimension="remaining"
            ),
            energy_capacity=Quantity(
                value=self._profile.capacity_millijoules,
                unit="millijoules",
                dimension="capacity",
            ),
            power_draw=Quantity(
                value=load, unit="milliwatts", dimension="draw"
            ),
        )

    def reserve_basis_points(self) -> int:
        """The current reserve ratio (basis points of capacity)."""
        capacity = self._profile.capacity_millijoules
        return 10000 * self._level // capacity if capacity > 0 else 0

    def history(self) -> Tuple[PowerStepResult, ...]:
        """Every step result so far, in order."""
        return tuple(self._history)

    def trajectory_digest(self) -> str:
        """The deterministic trajectory fingerprint: ``sha256`` over
        the canonical step-result sequence (same history -> same
        digest; any divergence -> a different digest)."""
        import hashlib

        material = b"".join(
            repr(result.to_dict()).encode("utf-8") for result in self._history
        )
        return hashlib.sha256(material).hexdigest()


__all__ = ["PowerSimulator", "PowerStepResult"]
