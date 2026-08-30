import json
import subprocess
import time
import re
from mobile.model import PlatformSnapshot
from mobile.platform import MobilePlatformSource

class AdbPlatformSource(MobilePlatformSource):
    """A MobilePlatformSource that reads from a physical device via ADB."""

    def __init__(self, serial=None):
        self.serial = serial
        self.base_cmd = ["adb"]
        if serial:
            self.base_cmd += ["-s", serial]
        self.trigger_next = True

    def _run_adb(self, args):
        cmd = self.base_cmd + args
        return subprocess.check_output(cmd).decode("utf-8")

    def read(self) -> PlatformSnapshot:
        triggered = self.trigger_next
        if triggered:
            print("[ADB-SOURCE] Triggering observation via broadcast...")
            # 1. Clear logcat to avoid reading old observations
            self._run_adb(["logcat", "-c"])

            # 2. Trigger observation via broadcast
            try:
                self._run_adb([
                    "shell", "am", "broadcast",
                    "-a", "org.adcos.w035.harness.OBSERVE",
                    "-n", "com.example.w035harness/.HarnessReceiver"
                ])
            except:
                print("[ADB-SOURCE] Broadcast trigger failed (possibly device locked or permissions).")

        else:
            print("[ADB-SOURCE] Reading EXISTING observation from logcat (no trigger)...")

        # 3. Poll logcat for the result
        start_time = time.time()
        while time.time() - start_time < 8:
            output = self._run_adb(["logcat", "-d", "-s", "W035_HARNESS:I"])
            match = re.search(r"OBSERVATION: (\{.*\})", output)
            if match:
                self.trigger_next = True # Reset for next
                data = json.loads(match.group(1))
                print(f"[ADB-SOURCE] Found observation: {data['app_phase']}")
                return PlatformSnapshot.from_dict(data)
            time.sleep(0.5)

        # Fallback to UI tap if broadcast failed (only if we were supposed to trigger)
        if triggered:
            print("[ADB-SOURCE] Broadcast trigger timed out, trying UI tap...")
            try:
                self._run_adb(["shell", "input", "tap", "141", "152"]) # "Emit Now" button
            except:
                pass

            start_time = time.time()
            while time.time() - start_time < 5:
                output = self._run_adb(["logcat", "-d", "-s", "W035_HARNESS:I"])
                match = re.search(r"OBSERVATION: (\{.*\})", output)
                if match:
                    self.trigger_next = True # Reset for next
                    data = json.loads(match.group(1))
                    print(f"[ADB-SOURCE] Found observation (via tap): {data['app_phase']}")
                    return PlatformSnapshot.from_dict(data)
                time.sleep(0.5)

        self.trigger_next = True # Ensure reset even on failure
        raise RuntimeError("Failed to obtain observation from device")
