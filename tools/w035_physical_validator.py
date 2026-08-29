#!/usr/bin/env python3
"""W035 physical validator: instantiate MobileAgent with ADB-backed
MobilePlatformSource and exercise real device-driven transitions.

Produces evidence/w035-device/mobile_reactions.jsonl with mobile snapshots,
mobile events, and run results.
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
from mobile.participation import MobileCommand, MobileCommandKind


def adb(cmd: str, serial: str | None = None) -> str:
    base = ["adb"]
    if serial:
        base += ["-s", serial]
    base += shlex.split(cmd)
    try:
        out = subprocess.check_output(base, stderr=subprocess.STDOUT, timeout=10)
        return out.decode("utf-8", errors="replace")
    except subprocess.CalledProcessError as e:
        return e.output.decode("utf-8", errors="replace")


class AdbPlatformSource(MobilePlatformSource):
    def __init__(self, serial: str):
        self.serial = serial

    def read(self) -> PlatformSnapshot:
        # Use simple heuristics similar to prior observer
        dumpsys_power = adb("shell dumpsys power", self.serial)
        screen_on = "mHoldingDisplaySuspendBlocker=true" in dumpsys_power or (
            "Display Power" in dumpsys_power and "state=ON" in dumpsys_power
        )
        dumpsys_window = adb("shell dumpsys window policy", self.serial)
        if "mShowingLockscreen=true" in dumpsys_window or "mDreamingLockscreen=true" in dumpsys_window:
            background = True
        else:
            background = not screen_on

        dumpsys_batt = adb("shell dumpsys battery", self.serial)
        charging = "AC powered: true" in dumpsys_batt or "USB powered: true" in dumpsys_batt or "Wireless powered: true" in dumpsys_batt
        from mobile.model import PowerState, NetworkKind, MobilePhase
        power_state = PowerState.CHARGING if charging else PowerState.ON_BATTERY

        dumpsys_conn = adb("shell dumpsys connectivity", self.serial)
        if "WIFI" in dumpsys_conn:
            network_kind = NetworkKind.WIFI
            metered = False
        elif "MOBILE" in dumpsys_conn or "CELLULAR" in dumpsys_conn:
            network_kind = NetworkKind.CELLULAR
            metered = True
        else:
            network_kind = NetworkKind.NONE
            metered = False

        dumpsys_deviceidle = adb("shell dumpsys deviceidle", self.serial)
        background_restricted = "mActiveIdle=true" in dumpsys_deviceidle or "isIgnoringBatteryOptimizations=true" not in dumpsys_batt

        app_phase = MobilePhase.FOREGROUND if not background else MobilePhase.BACKGROUND

        return PlatformSnapshot(
            app_phase=app_phase,
            power_state=power_state,
            network_kind=network_kind,
            metered=metered,
            background_restricted=background_restricted,
        )


def discover_device() -> str | None:
    out = subprocess.check_output(["adb", "devices"]).decode("utf-8", errors="replace")
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    devices = []
    for l in lines[1:]:
        parts = l.split()
        if parts and parts[1] == "device":
            devices.append(parts[0])
    if not devices:
        return None
    # Prefer non-ADB-TLS serials (real USB) if possible
    for d in devices:
        if not d.startswith("adb-"):
            return d
    return devices[0]


def now_ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def main():
    serial = discover_device()
    if serial is None:
        print("No device present for validation. Exiting.")
        sys.exit(2)
    print(f"Using device: {serial}")
    src = AdbPlatformSource(serial)

    # attempt to build a mobile world using battery helper
    try:
        import tools.mobile_selftest as battery
    except Exception as e:
        print("Cannot import battery helper:", e)
        sys.exit(1)

    try:
        mobile, peer = battery._world(src)
    except Exception as e:
        print("Failed to build mobile world with AdbPlatformSource:", e)
        sys.exit(1)

    evidence_dir = REPO_ROOT / "evidence" / "w035-device"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    out_file = evidence_dir / "mobile_reactions.jsonl"

    records = []

    # baseline run to capture initial mobile_snapshot and events
    print("Baseline run_mobile (platform refresh)")
    result = mobile.run_mobile([])
    records.append({"ts": now_ts(), "action": "baseline", "mobile_snapshot": mobile.mobile_snapshot(), "run_result": result.to_dict(), "events": [e.__dict__ for e in mobile.mobile_events]})

    # HOME -> platform change
    print("Sending HOME")
    adb("shell input keyevent 3", serial)
    time.sleep(2)
    result = mobile.run_mobile([])
    records.append({"ts": now_ts(), "action": "home", "mobile_snapshot": mobile.mobile_snapshot(), "run_result": result.to_dict(), "events": [e.__dict__ for e in mobile.mobile_events]})

    # POWER toggle (screen off)
    print("Toggling POWER")
    adb("shell input keyevent 26", serial)
    time.sleep(2)
    result = mobile.run_mobile([])
    records.append({"ts": now_ts(), "action": "power_off", "mobile_snapshot": mobile.mobile_snapshot(), "run_result": result.to_dict(), "events": [e.__dict__ for e in mobile.mobile_events]})

    # POWER toggle back
    adb("shell input keyevent 26", serial)
    time.sleep(2)
    result = mobile.run_mobile([])
    records.append({"ts": now_ts(), "action": "power_on", "mobile_snapshot": mobile.mobile_snapshot(), "run_result": result.to_dict(), "events": [e.__dict__ for e in mobile.mobile_events]})

    # disable wifi
    print("Disabling wifi")
    adb("shell svc wifi disable", serial)
    time.sleep(3)
    result = mobile.run_mobile([])
    records.append({"ts": now_ts(), "action": "wifi_disable", "mobile_snapshot": mobile.mobile_snapshot(), "run_result": result.to_dict(), "events": [e.__dict__ for e in mobile.mobile_events]})

    # enable wifi
    print("Enabling wifi")
    adb("shell svc wifi enable", serial)
    time.sleep(3)
    result = mobile.run_mobile([])
    records.append({"ts": now_ts(), "action": "wifi_enable", "mobile_snapshot": mobile.mobile_snapshot(), "run_result": result.to_dict(), "events": [e.__dict__ for e in mobile.mobile_events]})

    # write records
    with out_file.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, default=str) + "\n")

    print(f"Wrote {len(records)} runs to {out_file}")


if __name__ == "__main__":
    main()
