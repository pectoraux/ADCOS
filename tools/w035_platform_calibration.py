#!/usr/bin/env python3
"""Shared, signal-based Android platform calibration for W035 evidence.

This module intentionally keeps the raw native signals separate from the
PlatformSnapshot translation. The aim is to make the adapter evidence-led
and per-device calibrated, rather than guessing from single keyword hits in
unrelated dumpsys output.
"""
from __future__ import annotations

import json
import shlex
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict

from mobile.model import MobilePhase, NetworkKind, PlatformSnapshot, PowerState


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


def discover_device() -> str | None:
    out = subprocess.check_output(["adb", "devices"]).decode("utf-8", errors="replace")
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    devices = []
    for line in lines[1:]:
        parts = line.split()
        if parts and len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    if not devices:
        return None
    for serial in devices:
        if not serial.startswith("adb-"):
            return serial
    return devices[0]


def collect_native_signals(serial: str) -> Dict[str, str]:
    """Collect the raw ADB-native signals used for a per-device mapping."""
    return {
        "dumpsys_power": adb("shell dumpsys power", serial),
        "dumpsys_window": adb("shell dumpsys window policy", serial),
        "dumpsys_battery": adb("shell dumpsys battery", serial),
        "dumpsys_connectivity": adb("shell dumpsys connectivity", serial),
        "dumpsys_deviceidle": adb("shell dumpsys deviceidle", serial),
        "dumpsys_netstats": adb("shell dumpsys netstats", serial),
        "ip_addr": adb("shell ip addr", serial),
        "ip_link": adb("shell ip link", serial),
    }


def parse_display_state(native: Dict[str, str]) -> bool:
    power = native.get("dumpsys_power", "").lower()
    window = native.get("dumpsys_window", "").lower()
    screen_on = (
        "mholdingdisplaysuspendblocker=true" in power
        or "state=on" in power
        or "display power" in power and "state=on" in power
    )
    lockscreen = (
        "mshowinglockscreen=true" in window
        or "mdreaminglockscreen=true" in window
    )
    return bool(screen_on and not lockscreen)


def parse_network_kind(native: Dict[str, str]) -> NetworkKind:
    connectivity = native.get("dumpsys_connectivity", "").lower()
    ip_addr = native.get("ip_addr", "").lower()
    ip_link = native.get("ip_link", "").lower()

    wifi_evidence = (
        "transport_wifi" in connectivity
        or ("networkagentinfo" in connectivity and "wifi" in connectivity)
        or ("wlan" in ip_addr and "inet " in ip_addr)
        or ("wlan" in ip_link and "state up" in ip_link)
    )
    cellular_evidence = (
        "transport_cellular" in connectivity
        or "transport_mms" in connectivity
        or "mobile" in connectivity and "networkagentinfo" in connectivity
        or any(tok in ip_addr for tok in ("rmnet", "ccmni", "rmnet_data"))
    )

    if wifi_evidence and not cellular_evidence:
        return NetworkKind.WIFI
    if cellular_evidence and not wifi_evidence:
        return NetworkKind.CELLULAR
    return NetworkKind.NONE


def parse_power_state(native: Dict[str, str]) -> PowerState:
    battery = native.get("dumpsys_battery", "").lower()
    charging = (
        "ac powered: true" in battery
        or "usb powered: true" in battery
        or "wireless powered: true" in battery
    )
    return PowerState.CHARGING if charging else PowerState.ON_BATTERY


def parse_background_restricted(native: Dict[str, str]) -> bool:
    deviceidle = native.get("dumpsys_deviceidle", "").lower()
    battery = native.get("dumpsys_battery", "").lower()
    idle_true = "mactiveidle=true" in deviceidle or "light_idle" in deviceidle or "idle" in deviceidle and "true" in deviceidle
    battery_mod = "isignoringbatteryoptimizations=true" in battery
    if idle_true or battery_mod:
        return True
    return False


def parse_app_phase(native: Dict[str, str]) -> MobilePhase:
    window = native.get("dumpsys_window", "").lower()
    lockscreen = "mshowinglockscreen=true" in window or "mdreaminglockscreen=true" in window
    return MobilePhase.BACKGROUND if lockscreen else MobilePhase.FOREGROUND


def calibration_record(serial: str, native: Dict[str, str]) -> Dict[str, Any]:
    return {
        "serial": serial,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "parser": {
            "display_state": {
                "signal": ["dumpsys power", "dumpsys window policy"],
                "mapping": "screen_on = mHoldingDisplaySuspendBlocker=true or state=ON in power; lockscreen is distinguished separately from display state",
            },
            "app_phase": {
                "signal": ["dumpsys window policy"],
                "mapping": "lockscreen=true => foreground/background boundary is background; otherwise foreground",
            },
            "network_kind": {
                "signal": ["dumpsys connectivity", "ip addr", "ip link"],
                "mapping": "require active-network evidence (TRANSPORT_WIFI or interface wlan + inet) before classifying wifi; require active transport evidence before classifying cellular",
            },
            "background_restricted": {
                "signal": ["dumpsys deviceidle", "dumpsys battery"],
                "mapping": "only report true when an explicit device-idle or battery-optimization signal is observed; otherwise keep false and record this as not testable on the device",
            },
        },
        "raw_signal_summary": {
            "dumpsys_power_present": bool(native.get("dumpsys_power")),
            "dumpsys_window_present": bool(native.get("dumpsys_window")),
            "dumpsys_connectivity_present": bool(native.get("dumpsys_connectivity")),
            "dumpsys_deviceidle_present": bool(native.get("dumpsys_deviceidle")),
            "ip_addr_present": bool(native.get("ip_addr")),
            "ip_link_present": bool(native.get("ip_link")),
        },
    }


def snapshot_from_native(serial: str, native: Dict[str, str]) -> PlatformSnapshot:
    screen_on = parse_display_state(native)
    app_phase = parse_app_phase(native)
    power_state = parse_power_state(native)
    network_kind = parse_network_kind(native)
    background_restricted = parse_background_restricted(native)
    return PlatformSnapshot(
        app_phase=app_phase,
        power_state=power_state,
        network_kind=network_kind,
        metered=(network_kind == NetworkKind.CELLULAR),
        background_restricted=background_restricted,
    )


def dump_calibration_file(path, serial: str, native: Dict[str, str]) -> Dict[str, Any]:
    data = calibration_record(serial, native)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    return data
