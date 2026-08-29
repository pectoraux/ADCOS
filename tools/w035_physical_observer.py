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
from mobile.model import PlatformSnapshot, PowerState, NetworkKind


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
        # screen on/off -> map to foreground/background heuristic
        dumpsys_power = adb("shell dumpsys power", self.serial)
        screen_on = "mHoldingDisplaySuspendBlocker=true" in dumpsys_power or (
            "Display Power" in dumpsys_power and "state=ON" in dumpsys_power
        )
        # fallback: check input keyevent state via dumpsys window
        dumpsys_window = adb("shell dumpsys window policy", self.serial)
        if "mShowingLockscreen=true" in dumpsys_window or "mDreamingLockscreen=true" in dumpsys_window:
            background = True
        else:
            background = not screen_on

        # battery: charging vs on-battery
        dumpsys_batt = adb("shell dumpsys battery", self.serial)
        charging = (
            "AC powered: true" in dumpsys_batt
            or "USB powered: true" in dumpsys_batt
            or "Wireless powered: true" in dumpsys_batt
        )
        power_state = PowerState.CHARGING if charging else PowerState.ON_BATTERY

        # network: more robust check using dumpsys, netstats and ip addr as fallbacks
        dumpsys_conn = adb("shell dumpsys connectivity", self.serial)
        dumpsys_netstats = adb("shell dumpsys netstats", self.serial)
        ip_addr = adb("shell ip addr", self.serial)

        network_kind = NetworkKind.NONE
        metered = False

        # Prefer explicit transport tokens in dumpsys connectivity
        if "TRANSPORT_WIFI" in dumpsys_conn or "WIFI" in dumpsys_conn:
            network_kind = NetworkKind.WIFI
            metered = False
        elif "TRANSPORT_CELLULAR" in dumpsys_conn or "MOBILE" in dumpsys_conn or "CELLULAR" in dumpsys_conn:
            network_kind = NetworkKind.CELLULAR
            metered = True
        else:
            # Fallback to inspecting kernel interfaces for wifi/cellular hints
            if "wlan" in ip_addr and ("state UP" in ip_addr or "inet " in ip_addr):
                network_kind = NetworkKind.WIFI
                metered = False
            elif any(k in ip_addr for k in ("rmnet", "ccmni", "rmnet_data")):
                network_kind = NetworkKind.CELLULAR
                metered = True
            else:
                # final fallback: inspect netstats for recent rx/tx on wifi interfaces
                if "WIFI" in dumpsys_netstats or "wlan" in dumpsys_netstats:
                    network_kind = NetworkKind.WIFI
                elif "MOBILE" in dumpsys_netstats or "cell" in dumpsys_netstats:
                    network_kind = NetworkKind.CELLULAR
                    metered = True

        # background restriction: best-effort using app standby or battery saver
        dumpsys_deviceidle = adb("shell dumpsys deviceidle", self.serial)
        background_restricted = "mActiveIdle=true" in dumpsys_deviceidle or "isIgnoringBatteryOptimizations=true" not in dumpsys_batt

        # app_phase heuristic:
        from mobile import MobilePhase
        app_phase = MobilePhase.FOREGROUND if not background else MobilePhase.BACKGROUND

        return PlatformSnapshot(
            app_phase=app_phase,
            power_state=power_state,
            network_kind=network_kind,
            metered=metered,
            background_restricted=background_restricted,
        )


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
