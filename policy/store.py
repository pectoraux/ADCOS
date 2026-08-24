"""Atomic policy store with version sequencing (WORK-010).

The policy store separates MUTATION (publish / withdraw) from
EVALUATION (read-only, consumes an immutable snapshot). Per the prompt's
"Policy mutation vs evaluation" section:

    PolicyStore.publish(policy)
    PolicyStore.withdraw(policy)
    PolicyEngine.evaluate(policy_snapshot, context, now)

Evaluation consumes an immutable policy snapshot. Publishing/replacing
policy has explicit version/sequence semantics and does not race
implicitly with an in-flight evaluation.

Policy-set version sequencing is a policy-owned concept, distinct from
WORK-008 resource-account versions and WORK-007 topology sequences (rule
9 of the prompt's "Policy store sequencing" section). The store enforces:

- older versions cannot replace newer versions (monotonic);
- equal-version/different-content conflicts fail closed (the caller must
  bump the version explicitly);
- replacing a live policy is atomic (copy-on-write snapshot);
- an evaluation operates on one immutable snapshot;
- withdrawing a policy is distinct from expiration (a withdrawn policy
  remains queryable but is not applicable);
- policy history remains queryable without making withdrawn policies
  applicable.

The store is in-process and uses local-memory caching only (no MySQL,
Redis, or external middleware -- per the project's standard technology
stack). It is thread-safe via a coarse lock around mutation; evaluation
reads an immutable snapshot without locking.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .model import PolicyError, PolicySet
from .validation import validate_policy_set


@dataclass(frozen=True)
class _StoredEntry:
    """Internal record of a stored policy set version.

    - ``policy_set``: the immutable :class:`PolicySet`;
    - ``withdrawn``: True once :meth:`PolicyStore.withdraw` has been
      called for this (set_id, version). Withdrawn entries remain
      queryable (history) but are NOT returned by
      :meth:`PolicyStore.snapshot` / :meth:`PolicyStore.list_applicable`.
    """

    policy_set: PolicySet
    withdrawn: bool = False


class PolicyStore:
    """An in-memory, thread-safe policy store with atomic sequencing.

    The store keeps a per-``set_id`` history of stored versions. The
    highest non-withdrawn version for each ``set_id`` is the "live"
    version returned by :meth:`snapshot`.

    Mutation methods (:meth:`publish`, :meth:`withdraw`) acquire a
    coarse lock; read methods (:meth:`snapshot`, :meth:`list_applicable`,
    :meth:`get`) are lock-free after the snapshot tuple is constructed
    (the underlying dict is replaced atomically under the lock, and
    readers receive a tuple they can iterate without the lock).
    """

    def __init__(self) -> None:
        # set_id -> list of _StoredEntry, ordered by version ascending.
        self._history: Dict[str, List[_StoredEntry]] = {}
        # Coarse lock around mutation. Reads construct an immutable
        # snapshot tuple under the lock and then return it; subsequent
        # iteration is lock-free.
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Mutation: publish / withdraw
    # ------------------------------------------------------------------

    def publish(self, policy_set: PolicySet) -> None:
        """Publish a new policy-set version atomically.

        Rules (prompt's "Policy store sequencing"):
        - validate the policy set (deep validation; raises PolicyError
          on any malformed rule / temporal / NodeID / forbidden-token /
          secret-material issue);
        - older versions cannot replace newer versions: if a stored
          version > the new version exists, raise (version-regression);
        - equal-version/different-content conflicts fail closed: if a
          stored version == the new version exists with different
          canonical bytes, raise (the caller must bump the version
          explicitly);
        - equal-version/same-content is idempotent (no-op);
        - replacing a live policy is atomic (copy-on-write: a new list
          is constructed under the lock and replaces the old one in one
          assignment).
        """
        validate_policy_set(policy_set)
        new_bytes = policy_set.canonical_bytes()
        with self._lock:
            history = self._history.get(policy_set.set_id)
            if history:
                # Check for version-regression and equal-version
                # different-content.
                for entry in history:
                    if entry.policy_set.version > policy_set.version:
                        raise PolicyError(
                            "version-regression",
                            "cannot publish set %r version %d: a newer "
                            "version %d is already stored (older versions "
                            "cannot replace newer versions)"
                            % (
                                policy_set.set_id,
                                policy_set.version,
                                entry.policy_set.version,
                            ),
                        )
                    if entry.policy_set.version == policy_set.version:
                        if entry.policy_set.canonical_bytes() == new_bytes:
                            # Idempotent: same version, same content. No-op.
                            return
                        raise PolicyError(
                            "version-conflict",
                            "cannot publish set %r version %d: a stored "
                            "version with the same number but different "
                            "content exists (bump the version explicitly)"
                            % (policy_set.set_id, policy_set.version),
                        )
            # Append a new entry (copy-on-write: rebuild the list).
            new_history = list(history) if history else []
            new_history.append(_StoredEntry(policy_set=policy_set, withdrawn=False))
            # Keep history sorted by version ascending for deterministic
            # snapshot construction.
            new_history.sort(key=lambda e: e.policy_set.version)
            self._history[policy_set.set_id] = new_history

    def withdraw(self, set_id: str, version: int) -> None:
        """Withdraw a specific (set_id, version) policy set.

        Withdrawal is DISTINCT from expiration:
        - a withdrawn policy remains queryable via :meth:`get` (history)
          but is NOT returned by :meth:`snapshot` / :meth:`list_applicable`;
        - an expired policy (valid_until < now) is filtered out by
          :meth:`list_applicable` independently of withdrawal status.

        Withdrawing an already-withdrawn entry is idempotent. Withdrawing
        an unknown (set_id, version) raises PolicyError.
        """
        if not isinstance(set_id, str) or not set_id:
            raise PolicyError(
                "set-id",
                "set_id must be a non-empty string (got %r)" % (set_id,),
            )
        if isinstance(version, bool) or not isinstance(version, int):
            raise PolicyError(
                "version",
                "version must be an integer (got %s)" % type(version).__name__,
            )
        with self._lock:
            history = self._history.get(set_id)
            if not history:
                raise PolicyError(
                    "not-found",
                    "no policy set with set_id=%r is stored" % set_id,
                )
            target: Optional[_StoredEntry] = None
            for entry in history:
                if entry.policy_set.version == version:
                    target = entry
                    break
            if target is None:
                raise PolicyError(
                    "not-found",
                    "no policy set with set_id=%r version=%d is stored"
                    % (set_id, version),
                )
            if target.withdrawn:
                # Idempotent.
                return
            # Copy-on-write: rebuild the list with the withdrawn flag set.
            new_history = []
            for entry in history:
                if entry.policy_set.version == version:
                    new_history.append(
                        _StoredEntry(
                            policy_set=entry.policy_set,
                            withdrawn=True,
                        )
                    )
                else:
                    new_history.append(entry)
            self._history[set_id] = new_history

    # ------------------------------------------------------------------
    # Read: snapshot / list_applicable / get
    # ------------------------------------------------------------------

    def snapshot(self) -> Tuple[PolicySet, ...]:
        """Return an immutable tuple of the currently-applicable policy
        sets (highest non-withdrawn version per set_id).

        The returned tuple is constructed under the lock and is safe to
        iterate without the lock. The engine consumes this snapshot
        read-only.
        """
        with self._lock:
            out: List[PolicySet] = []
            for set_id in sorted(self._history.keys()):
                history = self._history[set_id]
                # The live entry is the highest non-withdrawn version.
                live: Optional[PolicySet] = None
                for entry in history:
                    if not entry.withdrawn:
                        live = entry.policy_set
                if live is not None:
                    out.append(live)
            return tuple(out)

    def list_applicable(self, now: str) -> Tuple[PolicySet, ...]:
        """Return the subset of :meth:`snapshot` whose validity window
        contains ``now``. Expired or not-yet-valid sets are filtered out.

        ``now`` is an INJECTED RFC 3339 UTC instant string; the store
        does NOT read the wall clock.
        """
        from protocol.temporal import TemporalError, parse_instant  # local
        try:
            now_dt = parse_instant(now)
        except TemporalError as error:
            raise PolicyError(
                "evaluation-instant",
                "now %r is not RFC 3339 UTC: %s" % (now, error),
            ) from error
        out: List[PolicySet] = []
        for ps in self.snapshot():
            if ps.valid_from:
                try:
                    vf = parse_instant(ps.valid_from)
                except TemporalError:
                    continue  # malformed -> skip
                if now_dt < vf:
                    continue
            if ps.valid_until:
                try:
                    vu = parse_instant(ps.valid_until)
                except TemporalError:
                    continue
                if now_dt > vu:
                    continue
            out.append(ps)
        return tuple(out)

    def get(self, set_id: str, version: int) -> PolicySet:
        """Return a stored policy set by (set_id, version), including
        withdrawn entries (history query). Raises PolicyError if not
        found.

        Withdrawn policies remain queryable via this method -- they are
        NOT applicable (filtered out by :meth:`snapshot`) but the
        history is preserved for audit.
        """
        if not isinstance(set_id, str) or not set_id:
            raise PolicyError(
                "set-id",
                "set_id must be a non-empty string (got %r)" % (set_id,),
            )
        if isinstance(version, bool) or not isinstance(version, int):
            raise PolicyError(
                "version",
                "version must be an integer (got %s)" % type(version).__name__,
            )
        with self._lock:
            history = self._history.get(set_id)
            if not history:
                raise PolicyError(
                    "not-found",
                    "no policy set with set_id=%r is stored" % set_id,
                )
            for entry in history:
                if entry.policy_set.version == version:
                    return entry.policy_set
            raise PolicyError(
                "not-found",
                "no policy set with set_id=%r version=%d is stored"
                % (set_id, version),
            )

    def is_withdrawn(self, set_id: str, version: int) -> bool:
        """Return True if the (set_id, version) entry is withdrawn.

        Returns False if the entry exists and is live. Raises PolicyError
        if the entry does not exist.
        """
        if not isinstance(set_id, str) or not set_id:
            raise PolicyError(
                "set-id",
                "set_id must be a non-empty string (got %r)" % (set_id,),
            )
        if isinstance(version, bool) or not isinstance(version, int):
            raise PolicyError(
                "version",
                "version must be an integer (got %s)" % type(version).__name__,
            )
        with self._lock:
            history = self._history.get(set_id)
            if not history:
                raise PolicyError(
                    "not-found",
                    "no policy set with set_id=%r is stored" % set_id,
                )
            for entry in history:
                if entry.policy_set.version == version:
                    return entry.withdrawn
            raise PolicyError(
                "not-found",
                "no policy set with set_id=%r version=%d is stored"
                % (set_id, version),
            )


__all__ = [
    "PolicyStore",
]
