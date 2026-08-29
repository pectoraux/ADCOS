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
from tools.w035_platform_calibration import (
    adb,
    collect_native_signals,
    dump_calibration_file,
    parse_display_state,
    snapshot_from_native,
)


class AdbPlatformSource(MobilePlatformSource):
    def __init__(self, serial: str):
        self.serial = serial

    def read(self) -> PlatformSnapshot:
        native = collect_native_signals(self.serial)
        return snapshot_from_native(self.serial, native)


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
    calibration_file = evidence_dir / "device_calibration.json"
    calibration = dump_calibration_file(calibration_file, serial, collect_native_signals(serial))
    out_file = evidence_dir / "mobile_reactions.jsonl"

    records = [{"ts": now_ts(), "action": "calibration", "calibration": calibration}]

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

    # POWER toggle -> expect the screen/display state to change, not necessarily app_phase
    def action_power():
        adb("shell input keyevent 26", serial)

    def assert_power(pre, post):
        pre_display = parse_display_state(collect_native_signals(serial))
        # re-read after action using the same raw signal parser
        time.sleep(0.5)
        post_display = parse_display_state(collect_native_signals(serial))
        return pre_display != post_display

    def run_power_experiment():
        pre_native = collect_native_signals(serial)
        pre_display = parse_display_state(pre_native)
        raw_pre = {
            "dumpsys_power": adb("shell dumpsys power", serial),
            "dumpsys_window": adb("shell dumpsys window policy", serial),
            "dumpsys_conn": adb("shell dumpsys connectivity", serial),
            "dumpsys_batt": adb("shell dumpsys battery", serial),
            "screen_on_before": pre_display,
        }
        time.sleep(0.5)
        action_power()
        time.sleep(1.0)
        post_native = collect_native_signals(serial)
        post_display = parse_display_state(post_native)
        result = mobile.run_mobile([])
        record = {
            "ts": now_ts(),
            "action": "power_toggle",
            "raw_pre": raw_pre,
            "display_before": pre_display,
            "display_after": post_display,
            "pre_snapshot": {
                "app_phase": src.read().app_phase,
                "power_state": src.read().power_state,
                "network_kind": src.read().network_kind,
                "metered": src.read().metered,
                "background_restricted": src.read().background_restricted,
            },
            "post_snapshot": {
                "app_phase": src.read().app_phase,
                "power_state": src.read().power_state,
                "network_kind": src.read().network_kind,
                "metered": src.read().metered,
                "background_restricted": src.read().background_restricted,
            },
            "assertion_passed": pre_display != post_display,
            "run_result": result.to_dict(),
            "events": [e.__dict__ for e in mobile.mobile_events],
        }
        records.append(record)
        print(f"Recorded experiment power_toggle, assertion_passed={record['assertion_passed']}")

    run_power_experiment()

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
