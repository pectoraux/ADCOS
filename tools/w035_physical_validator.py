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
        # Use improved heuristics: combine dumpsys connectivity/netstats and ip addr
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
        charging = (
            "AC powered: true" in dumpsys_batt
            or "USB powered: true" in dumpsys_batt
            or "Wireless powered: true" in dumpsys_batt
        )
        from mobile.model import PowerState, NetworkKind, MobilePhase
        power_state = PowerState.CHARGING if charging else PowerState.ON_BATTERY

        dumpsys_conn = adb("shell dumpsys connectivity", self.serial)
        dumpsys_netstats = adb("shell dumpsys netstats", self.serial)
        ip_addr = adb("shell ip addr", self.serial)

        # determine network kind with multiple signals
        network_kind = NetworkKind.NONE
        metered = False
        if "TRANSPORT_WIFI" in dumpsys_conn or "WIFI" in dumpsys_conn:
            network_kind = NetworkKind.WIFI
            metered = False
        elif "TRANSPORT_CELLULAR" in dumpsys_conn or "MOBILE" in dumpsys_conn or "CELLULAR" in dumpsys_conn:
            network_kind = NetworkKind.CELLULAR
            metered = True
        else:
            # fallback: inspect kernel ip address output
            if "wlan" in ip_addr and ("state UP" in ip_addr or "inet " in ip_addr):
                network_kind = NetworkKind.WIFI
                metered = False
            elif any(k in ip_addr for k in ("rmnet", "ccmni", "rmnet_data")):
                network_kind = NetworkKind.CELLULAR
                metered = True
            else:
                # fallback to netstats/dumpsys_netstats
                if "WIFI" in dumpsys_netstats or "wlan" in dumpsys_netstats:
                    network_kind = NetworkKind.WIFI
                elif "MOBILE" in dumpsys_netstats or "cell" in dumpsys_netstats:
                    network_kind = NetworkKind.CELLULAR
                    metered = True

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

    # helper: poll platform snapshot for a condition
    def poll_for_change(check_fn, timeout=10, interval=0.5):
        start = time.time()
        last = None
        while time.time() - start < timeout:
            snap = src.read()
            if last is None:
                last = snap
            if check_fn(last, snap):
                return last, snap
            time.sleep(interval)
        return last, snap

    # structured experiments with assertions
    def run_experiment(action_name, action_fn, assert_fn, pre_sleep=0.5, post_sleep=0.5):
        print(f"Experiment: {action_name} — capturing precondition")
        pre_snap = src.read()
        raw_pre = {
            "dumpsys_power": adb("shell dumpsys power", serial),
            "dumpsys_window": adb("shell dumpsys window policy", serial),
            "dumpsys_conn": adb("shell dumpsys connectivity", serial),
            "dumpsys_batt": adb("shell dumpsys battery", serial),
        }
        time.sleep(pre_sleep)
        print(f"Action: {action_name}")
        action_fn()
        # poll for asserted change
        last, new = poll_for_change(assert_fn)
        # allow MobileAgent to react
        time.sleep(post_sleep)
        result = mobile.run_mobile([])
        record = {
            "ts": now_ts(),
            "action": action_name,
            "raw_pre": raw_pre,
            "pre_snapshot": {
                "app_phase": pre_snap.app_phase,
                "power_state": pre_snap.power_state,
                "network_kind": pre_snap.network_kind,
                "metered": pre_snap.metered,
                "background_restricted": pre_snap.background_restricted,
            },
            "post_snapshot": {
                "app_phase": new.app_phase,
                "power_state": new.power_state,
                "network_kind": new.network_kind,
                "metered": new.metered,
                "background_restricted": new.background_restricted,
            },
            "assertion_passed": assert_fn(pre_snap, new),
            "run_result": result.to_dict(),
            "events": [e.__dict__ for e in mobile.mobile_events],
        }
        records.append(record)
        print(f"Recorded experiment {action_name}, assertion_passed={record['assertion_passed']}")

    # Baseline
    print("Baseline run_mobile (platform refresh)")
    baseline = src.read()
    result = mobile.run_mobile([])
    records.append({"ts": now_ts(), "action": "baseline", "pre_snapshot": {"app_phase": baseline.app_phase, "network_kind": baseline.network_kind}, "run_result": result.to_dict(), "events": [e.__dict__ for e in mobile.mobile_events]})

    # HOME -> expect app_phase change to BACKGROUND (or mark not observed)
    def action_home():
        adb("shell input keyevent 3", serial)

    def assert_home(pre, post):
        return pre.app_phase != post.app_phase

    run_experiment("home", action_home, assert_home)

    # POWER toggle -> expect app_phase change
    def action_power():
        adb("shell input keyevent 26", serial)

    def assert_power(pre, post):
        return pre.app_phase != post.app_phase

    run_experiment("power_toggle", action_power, assert_power)

    # Wi-Fi disable -> expect an observable wifi presence change (dumpsys/ip addr)
    def action_wifi_disable():
        adb("shell svc wifi disable", serial)

    def wifi_present_in_raw():
        d_conn = adb("shell dumpsys connectivity", serial)
        ip_addr = adb("shell ip addr", serial)
        # detect transport or NetworkAgentInfo mentioning WIFI, or wlan/inet presence
        present = False
        if "TRANSPORT_WIFI" in d_conn or " NetworkAgentInfo{" in d_conn and "WIFI" in d_conn:
            present = True
        if "wlan" in ip_addr and "inet " in ip_addr:
            present = True
        return present

    def assert_wifi_disable(pre, post):
        # do a conservative check: compare explicit raw wifi presence before/after
        pre_present = False
        post_present = False
        try:
            d_conn_pre = adb("shell dumpsys connectivity", serial)
            ip_pre = adb("shell ip addr", serial)
            pre_present = ("TRANSPORT_WIFI" in d_conn_pre) or ("WIFI" in d_conn_pre) or ("wlan" in ip_pre and "inet " in ip_pre)
        except Exception:
            pre_present = False
        try:
            d_conn_post = adb("shell dumpsys connectivity", serial)
            ip_post = adb("shell ip addr", serial)
            post_present = ("TRANSPORT_WIFI" in d_conn_post) or ("WIFI" in d_conn_post) or ("wlan" in ip_post and "inet " in ip_post)
        except Exception:
            post_present = False
        return pre_present and not post_present

    run_experiment("wifi_disable", action_wifi_disable, assert_wifi_disable)

    # Wi-Fi enable -> expect wifi_presence to become true
    def action_wifi_enable():
        adb("shell svc wifi enable", serial)

    def assert_wifi_enable(pre, post):
        pre_present = False
        post_present = False
        try:
            d_conn_pre = adb("shell dumpsys connectivity", serial)
            ip_pre = adb("shell ip addr", serial)
            pre_present = ("TRANSPORT_WIFI" in d_conn_pre) or ("WIFI" in d_conn_pre) or ("wlan" in ip_pre and "inet " in ip_pre)
        except Exception:
            pre_present = False
        try:
            d_conn_post = adb("shell dumpsys connectivity", serial)
            ip_post = adb("shell ip addr", serial)
            post_present = ("TRANSPORT_WIFI" in d_conn_post) or ("WIFI" in d_conn_post) or ("wlan" in ip_post and "inet " in ip_post)
        except Exception:
            post_present = False
        return (not pre_present) and post_present

    run_experiment("wifi_enable", action_wifi_enable, assert_wifi_enable)

    # write records
    with out_file.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, default=str) + "\n")

    print(f"Wrote {len(records)} runs to {out_file}")


if __name__ == "__main__":
    main()
