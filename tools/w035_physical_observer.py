#!/usr/bin/env python3
"""W035 physical observer: map real Android OS observations via ADB into
mobile.PlatformSnapshot and exercise the MobileAgent seam without an APK.

Produces evidence/w035-device/physical_snapshots.json with timestamped snapshots.
"""
from __future__ import annotations

import json
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from mobile.platform import MobilePlatformSource
from mobile.model import PlatformSnapshot
from tools.w035_platform_calibration import collect_native_signals, snapshot_from_native


def adb(cmd: str, serial: str | None = None) -> str:
    # compatibility shim retained for the observer's external shell usage
    from tools.w035_platform_calibration import adb as _adb
    return _adb(cmd, serial)


class AdbPlatformSource(MobilePlatformSource):
    def __init__(self, serial: str):
        self.serial = serial

    def read(self) -> PlatformSnapshot:
        native = collect_native_signals(self.serial)
        return snapshot_from_native(self.serial, native)


def snapshot_record(source: AdbPlatformSource) -> dict:
    snap = source.read()
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "app_phase": snap.app_phase,
        "power_state": snap.power_state,
        "network_kind": snap.network_kind,
        "metered": snap.metered,
        "background_restricted": snap.background_restricted,
    }


def main():
    serial = None
    # try to discover a single physical device if not supplied
    out = subprocess.check_output(["adb", "devices"]).decode("utf-8", errors="replace")
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    devices = []
    for l in lines[1:]:
        parts = l.split()
        if parts and parts[1] == "device":
            devices.append(parts[0])
    if not devices:
        print("No device found (adb devices). Exiting.")
        sys.exit(2)
    serial = devices[0]
    print(f"Using device serial: {serial}")

    src = AdbPlatformSource(serial)

    # Attempt to instantiate the MobileAgent with the AdbPlatformSource
    try:
        import tools.mobile_selftest as battery  # reuse the battery world helper

        # battery._world expects a ScriptedPlatformSource-like object; AdbPlatformSource
        # implements MobilePlatformSource so this should succeed if interfaces match.
        mobile, peer = battery._world(src)
        mobile_ok = True
    except Exception as e:
        mobile = None
        peer = None
        mobile_ok = False
        mobile_error = str(e)

    evidence_dir = REPO_ROOT / "evidence" / "w035-device"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    out_file = evidence_dir / "physical_snapshots.jsonl"

    records = []
    # baseline
    records.append({"action": "baseline", **snapshot_record(src)})
    time.sleep(1)

    # home (simulate background)
    print("Sending HOME keyevent to induce background")
    adb("shell input keyevent 3", serial)
    time.sleep(2)
    records.append({"action": "home", **snapshot_record(src)})

    # power toggle (screen off)
    print("Toggling POWER (screen) to induce lock/sleep)")
    adb("shell input keyevent 26", serial)
    time.sleep(2)
    records.append({"action": "power_toggle", **snapshot_record(src)})

    # power toggle back
    adb("shell input keyevent 26", serial)
    time.sleep(2)
    records.append({"action": "power_toggle_back", **snapshot_record(src)})

    # wifi off/on
    print("Disabling wifi")
    adb("shell svc wifi disable", serial)
    time.sleep(3)
    records.append({"action": "wifi_disable", **snapshot_record(src)})

    print("Enabling wifi")
    adb("shell svc wifi enable", serial)
    time.sleep(3)
    records.append({"action": "wifi_enable", **snapshot_record(src)})

    # write out file
    with out_file.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, default=str) + "\n")

    print(f"Wrote {len(records)} snapshots to {out_file}")


if __name__ == "__main__":
    main()
