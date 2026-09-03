"""WORK-048 sharing pure-integer instant arithmetic.

Pure-integer RFC 3339 UTC arithmetic (the marketplace/handoff
discipline, mirrored verbatim): no ``datetime`` import anywhere in
the sharing family, deterministic on every platform, no wall-clock
reads, no environment dependence.  Every instant is the injected
``YYYY-MM-DDTHH:MM:SSZ`` form.
"""

from __future__ import annotations

from .errors import SharingError, SharingReasonCode


def epoch_seconds(instant: str) -> int:
    """RFC 3339 UTC ``YYYY-MM-DDTHH:MM:SSZ`` -> epoch seconds
    (Howard Hinnant's days-from-civil algorithm, pure integers)."""
    try:
        year = int(instant[0:4])
        month = int(instant[5:7])
        day = int(instant[8:10])
        hour = int(instant[11:13])
        minute = int(instant[14:16])
        second = int(instant[17:19])
        if instant[4] != "-" or instant[7] != "-" or instant[10] != "T":
            raise ValueError("separator")
        if instant[13] != ":" or instant[16] != ":" or instant[19] != "Z":
            raise ValueError("separator")
    except (ValueError, IndexError) as error:
        raise SharingError(
            SharingReasonCode.INVALID_INPUT,
            "instant %r must be RFC 3339 UTC (YYYY-MM-DDTHH:MM:SSZ): %s"
            % (instant, error),
        ) from error
    y = year - (1 if month <= 2 else 0)
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    days = era * 146097 + doe - 719468
    return days * 86400 + hour * 3600 + minute * 60 + second


def instant_from_epoch(seconds: int) -> str:
    """Epoch seconds -> RFC 3339 UTC (civil-from-days, pure
    integers; the inverse of :func:`epoch_seconds`)."""
    days = seconds // 86400
    rem = seconds - days * 86400
    hour = rem // 3600
    minute = (rem - hour * 3600) // 60
    second = rem % 60
    z = days + 719468
    era = (z if z >= 0 else z - 146096) // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    day = doy - (153 * mp + 2) // 5 + 1
    month = mp + (3 if mp < 10 else -9)
    year = y + (1 if month <= 2 else 0)
    return "%04d-%02d-%02dT%02d:%02d:%02dZ" % (
        year, month, day, hour, minute, second,
    )


def instant_plus_seconds(instant: str, seconds: int) -> int:
    """Epoch seconds of ``instant + seconds`` (deadline anchor)."""
    if not isinstance(seconds, int) or isinstance(seconds, bool) or seconds < 0:
        raise SharingError(
            SharingReasonCode.INVALID_INPUT,
            "seconds must be a non-negative integer",
        )
    return epoch_seconds(instant) + seconds


def instant_is_after(a: str, b: str) -> bool:
    """Deterministic strict ordering (``a`` strictly later than
    ``b``); equal instants are NOT after."""
    return epoch_seconds(a) > epoch_seconds(b)


__all__ = [
    "epoch_seconds",
    "instant_from_epoch",
    "instant_plus_seconds",
    "instant_is_after",
]
