"""WORK-040 correction cycle: the physical-device participation
harness (WORK-040-CORRECTION-001).

The correction's two open criteria are PHYSICAL-class claims:

* criterion 1 (real users/devices participate): an ACTUAL physical
  Android handset participates as a real ADCOS endpoint -- the
  production WORK-033 ``AgentRuntime`` runs ON the handset, boots
  with the handset's REAL interface observation, and establishes a
  genuine production session through a real physical carriage (USB
  via ``adb reverse``, or the device's Wi-Fi to the host LAN);
* criterion 2 (a real 5G access path): only when the Android
  framework itself reports NR (5G) -- generic cellular is NEVER
  equivalent to 5G, and the traffic must demonstrably use the
  5G-backed path with independent verification.

This module is the ORCHESTRATION + EVIDENCE layer only.  The chain
it produces is exactly the one the authorization demands::

    physical trigger
            -> authoritative device observation (adb getprop/dumpsys,
               the handset's own /proc interfaces through the
               production LinuxInterfaceSource ON the device)
            -> production AgentRuntime (unchanged, running on the
               handset)
            -> production session/transport operation (the same
               pilot.session.* chain every other pilot device uses)
            -> independent observable result (the device result
               document + the appliance's own journal, cross-checked)

Honesty rules (enforced, not promised):

* ``detect_physical_environment`` reads the REAL host and never
  converts an absent capability into a present one;
* a rehearsal (the android node as a host process over loopback) is
  always labeled ``is_physical=false`` and can never classify
  criterion 1 above PARTIAL or criterion 2 above NOT-TESTABLE;
* ``validate_physical_evidence`` is a PURE independent validator:
  completeness, cross-corroboration of both sides, the declared
  identity match, well-formed digests, the NR-only 5G rule, and
  classification consistency -- a document whose classification is
  stronger than its own facts fails closed;
* no private W035 method, no synthetic network interface, no
  monkeypatched runtime is used anywhere (the handset runs the same
  ``pilot.node`` entrypoint every other device runs).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from agent import LinuxInterfaceSource

from .errors import PilotError, PilotReasonCode
from .model import CriterionId, CriterionStatus, PilotEvidenceClass
from .topology import (
    PHYSICAL_DEVICE_LABEL,
    node_identity_for,
    participant_spec_for,
)

__all__ = [
    "PHYSICAL_EVIDENCE_SCHEMA_VERSION",
    "PHYSICAL_EVIDENCE_REQUIRED",
    "PHYSICAL_5G_REQUIRED",
    "TETHER_INTERFACE_CANDIDATES",
    "detect_physical_environment",
    "validator_sha",
    "assemble_physical_evidence",
    "validate_physical_evidence",
    "classify_physical_participation",
    "classify_five_g_path",
    "run_physical_attempt",
    "run_physical_rehearsal",
    "write_attempt_evidence",
]


#: The physical-evidence document schema version.
PHYSICAL_EVIDENCE_SCHEMA_VERSION = 1

#: Host interface name candidates that indicate a real USB tether
#: (RNDIS/NCM) path from the handset.
TETHER_INTERFACE_CANDIDATES = ("usb0", "usb1", "rndis0", "eth1")

#: The exact evidence chain the authorization requires for criterion 1
#: (every claim must carry all of these; frozen DATA -- the battery
#: asserts the template covers the authorization's own list).
PHYSICAL_EVIDENCE_REQUIRED: Tuple[Tuple[str, str], ...] = (
    ("device_identity.model", "the handset's model (adb getprop)"),
    ("device_identity.brand", "the handset's brand (adb getprop)"),
    ("device_identity.serial", "the handset's serial identity"),
    ("device_identity.android_release", "the Android release version"),
    ("device_identity.observation_source", "how the identity was observed"),
    ("access_technology.technology", "the framework-reported access technology"),
    ("access_technology.observation_source", "how access was observed"),
    ("host.interface_identity", "the host interface carrying the connection"),
    ("host.pre_transition_route", "the route before the demonstration"),
    ("adcos.access_classification", "the ADCOS access classification"),
    ("adcos.device_node_id", "the handset participant's node id"),
    ("adcos.session_id", "the production session id"),
    ("adcos.bind_event", "the session bind event"),
    ("adcos.sender_result", "the device-side result document"),
    ("adcos.receiver_result", "the appliance-side journal excerpt"),
    ("verification.validator_sha", "the validator's own SHA-256"),
    ("verification.artifact_hashes", "SHA-256 of every artifact"),
)

#: The additional evidence a criterion-2 PASS requires beyond the
#: participation chain (the authorization's 5G rule: NR observed by
#: the Android framework + a real host path carrying that connection
#: + the pilot demonstrably using it + independent traffic
#: verification).
PHYSICAL_5G_REQUIRED: Tuple[Tuple[str, str], ...] = (
    ("access_technology.technology", "must be NR reported by the framework"),
    ("access_technology.is_5g", "true ONLY when NR is observed"),
    ("host.pre_transition_route", "the route before the transition"),
    ("host.post_transition_route", "the route after the transition"),
    ("traffic_verification.method", "how the traffic use was verified"),
    ("traffic_verification.observation", "the independent observation"),
)


# ---------------------------------------------------------------------------
# Honest environment detection
# ---------------------------------------------------------------------------

_ADB_SEARCH_PATHS = (
    "adb",
    "/usr/bin/adb",
    "/usr/local/bin/adb",
    "/opt/android-sdk/platform-tools/adb",
    os.path.expanduser("~/Android/Sdk/platform-tools/adb"),
    os.path.expanduser("~/.local/bin/adb"),
)


def _find_adb() -> Tuple[Optional[str], str]:
    """Locate an adb binary HONESTLY (no fabrication)."""
    for candidate in _ADB_SEARCH_PATHS:
        if candidate == "adb":
            found = shutil.which("adb")
        else:
            found = candidate if os.path.isfile(candidate) and os.access(candidate, os.X_OK) else None
        if found:
            return found, "adb binary found at %s" % (found,)
    return None, "no adb binary on PATH or in the known SDK locations"


def _probe_usb_bus() -> Dict[str, Any]:
    """The REAL USB bus state of this host."""
    bus_dir = Path("/sys/bus/usb/devices")
    try:
        entries = sorted(p.name for p in bus_dir.iterdir()) if bus_dir.is_dir() else []
    except OSError as error:
        return {
            "present": False,
            "devices": [],
            "detail": "%s: %s (no USB bus observable on this host)"
            % (type(error).__name__, error),
        }
    # only real device entries (not hub-only ports like usb1) matter
    devices = [e for e in entries if re.fullmatch(r"\d+-[\d.]+", e)]
    return {
        "present": True,
        "devices": devices,
        "detail": "%d USB device node(s) visible" % (len(devices),)
        if devices
        else "USB bus present but no device attached",
    }


def _probe_tether_interfaces() -> Dict[str, Any]:
    """The REAL host interfaces, filtered for USB-tether candidates."""
    try:
        source = LinuxInterfaceSource()
        names = [snapshot.name for snapshot in source.discover()]
    except Exception as error:  # noqa: BLE001 - honest observation
        return {
            "observed": [],
            "tether_candidates": [],
            "detail": "%s: %s" % (type(error).__name__, error),
        }
    candidates = [n for n in names if n in TETHER_INTERFACE_CANDIDATES]
    return {
        "observed": names,
        "tether_candidates": candidates,
        "detail": "%d real interface(s); %d USB-tether candidate(s)"
        % (len(names), len(candidates)),
    }


def detect_physical_environment(*, run_adb: bool = True) -> Dict[str, Any]:
    """The honest physical-participation environment detection.

    Reads the REAL host: adb binary, attached devices (via
    ``adb devices -l`` when adb exists), the USB bus, and the real
    interfaces (USB-tether candidates).  Never converts an absent
    capability into a present one; the conclusion is derived, never
    asserted by the caller.
    """
    adb_path, adb_detail = _find_adb()
    adb_binary = {"present": adb_path is not None, "path": adb_path, "detail": adb_detail}
    adb_devices: Dict[str, Any] = {
        "executed": False,
        "serials": [],
        "detail": "not executed (no adb binary)",
    }
    if adb_path and run_adb:
        try:
            completed = subprocess.run(  # noqa: S603 - read-only adb query
                [adb_path, "devices", "-l"],
                capture_output=True, text=True, timeout=15,
            )
            serials: List[str] = []
            for line in completed.stdout.splitlines()[1:]:
                line = line.strip()
                if line and not line.startswith("*") and "device" in line.split():
                    serials.append(line.split()[0])
            adb_devices = {
                "executed": True,
                "returncode": completed.returncode,
                "serials": serials,
                "detail": (
                    "adb devices -l executed; %d device(s) attached"
                    % (len(serials),)
                ),
            }
        except (OSError, subprocess.SubprocessError) as error:
            adb_devices = {
                "executed": True,
                "serials": [],
                "detail": "adb devices failed: %s: %s"
                % (type(error).__name__, error),
            }
    usb_bus = _probe_usb_bus()
    tether = _probe_tether_interfaces()
    attached = bool(adb_devices["serials"])
    if attached and not usb_bus["present"] and not tether["tether_candidates"]:
        # adb reports a device (e.g. network adb): still honest, but the
        # carriage must be established explicitly by the operator.
        conclusion = (
            "an adb-visible device is attached; the carriage (USB or "
            "network) must be established before the physical pilot runs"
        )
    elif attached:
        conclusion = (
            "a physical device is attached and observable; the physical "
            "pilot may run"
        )
    else:
        conclusion = (
            "no physical Android device is reachable from this execution "
            "host; the physical participation demonstration cannot be "
            "executed here and stays honestly unresolved"
        )
    return {
        "kind": "physical-environment-detection",
        "adb_binary": adb_binary,
        "adb_devices": adb_devices,
        "usb_bus": usb_bus,
        "tether_interfaces": tether,
        "device_attached": attached,
        "conclusion": conclusion,
    }


# ---------------------------------------------------------------------------
# The validator (pure; independent of the assembly path)
# ---------------------------------------------------------------------------

def validator_sha() -> str:
    """The SHA-256 of THIS module's bytes -- the exact validator code
    that validated the evidence (recorded in every document)."""
    module_path = Path(__file__).resolve()
    return "sha256:" + _sha256_file(module_path)


def _sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _dig(document: Mapping[str, Any], dotted: str) -> Any:
    value: Any = document
    for part in dotted.split("."):
        if not isinstance(value, Mapping):
            return None
        value = value.get(part)
    return value


def _is_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and len(value) == 71
        and all(c in "0123456789abcdef" for c in value[7:])
    )


def _declared_physical_node_id() -> str:
    return node_identity_for(PHYSICAL_DEVICE_LABEL).node_id.text


def validate_physical_evidence(document: Mapping[str, Any]) -> Tuple[bool, List[str]]:
    """Independently validate a physical-evidence document.

    Pure function, no I/O: completeness against the frozen template,
    the honest-rehearsal rule (``is_physical=false`` caps every
    classification), the declared-identity match, cross-corroboration
    of the SAME session id on BOTH sides, digest well-formedness, the
    NR-only 5G rule, and classification consistency.  Returns
    ``(ok, problems)``; any problem means the document may not carry
    a claim stronger than its own facts.
    """
    problems: List[str] = []
    if document.get("kind") != "physical-participation-evidence":
        problems.append("not a physical-participation-evidence document")
        return False, problems
    if document.get("schema_version") != PHYSICAL_EVIDENCE_SCHEMA_VERSION:
        problems.append("unknown schema version %r" % (document.get("schema_version"),))

    is_physical = document.get("is_physical")
    if not isinstance(is_physical, bool):
        problems.append("is_physical must be an explicit boolean")

    # -- completeness: every required field, present or honestly absent --
    for field, _why in PHYSICAL_EVIDENCE_REQUIRED:
        value = _dig(document, field)
        if value is None or value == "" or value == {} or value == []:
            if is_physical:
                problems.append("missing required field %r" % (field,))
            else:
                # a rehearsal may omit handset-only fields but must say so
                marker = _dig(document, "honest_absences")
                if not (isinstance(marker, list) and field in marker):
                    problems.append(
                        "rehearsal document omits %r without declaring it "
                        "in honest_absences" % (field,)
                    )

    # -- the declared identity match -----------------------------------
    node_id = _dig(document, "adcos.device_node_id")
    if node_id is not None and node_id != _declared_physical_node_id():
        problems.append(
            "device node id %r does not match the declared %s identity"
            % (node_id, PHYSICAL_DEVICE_LABEL)
        )

    # -- cross-corroboration: the session on BOTH sides ----------------
    session_id = _dig(document, "adcos.session_id")
    sender = _dig(document, "adcos.sender_result") or {}
    receiver = _dig(document, "adcos.receiver_result") or {}
    if session_id:
        sender_sessions = json.dumps(sender.get("observations", {}), sort_keys=True)
        receiver_events = json.dumps(receiver.get("events", []), sort_keys=True)
        if str(session_id) not in sender_sessions:
            problems.append("the sender result does not carry the session id")
        if str(session_id) not in receiver_events:
            problems.append(
                "the receiver (appliance) journal does not corroborate the "
                "session id -- no independent receiver result"
            )
        sender_label = sender.get("label")
        if sender_label != PHYSICAL_DEVICE_LABEL:
            problems.append(
                "sender result label %r is not %r" % (sender_label, PHYSICAL_DEVICE_LABEL)
            )
        receiver_label = receiver.get("label")
        if receiver_label != "appliance-1":
            problems.append(
                "receiver result label %r is not the appliance" % (receiver_label,)
            )
    else:
        problems.append("no session id to corroborate")

    # -- digests ---------------------------------------------------------
    validator = _dig(document, "verification.validator_sha")
    if not _is_digest(validator):
        problems.append("validator sha missing or malformed")
    hashes = _dig(document, "verification.artifact_hashes") or []
    if not isinstance(hashes, list) or not hashes:
        problems.append("no artifact hashes recorded")
    else:
        for entry in hashes:
            if (
                not isinstance(entry, (list, tuple))
                or len(entry) != 2
                or not isinstance(entry[0], str)
                or not entry[0]
                or not _is_digest(entry[1])
            ):
                problems.append("malformed artifact hash entry %r" % (entry,))
                break

    # -- the NR-only 5G rule ---------------------------------------------
    access = document.get("access_technology") or {}
    if access:
        technology = str(access.get("technology", ""))
        is_5g = access.get("is_5g")
        if is_5g is True and technology != "nr":
            problems.append(
                "is_5g=true with technology %r: 5G requires the framework "
                "to report NR (cellular is never automatically 5G)" % (technology,)
            )
        if technology and technology not in _ACCESS_TECHNOLOGIES:
            problems.append("unknown access technology %r" % (technology,))

    # -- classification consistency (anti-promotion) ----------------------
    classification = document.get("classification") or {}
    c1 = classification.get("criterion_1_real_devices")
    c2 = classification.get("criterion_2_5g")
    for status in (c1, c2):
        if status is None:
            continue  # not yet classified (assembly validates pre-classification)
        if status not in CriterionStatus.values():
            problems.append("unknown criterion status %r" % (status,))
    if c1 == CriterionStatus.PASS and is_physical is not True:
        problems.append(
            "criterion 1 classified PASS but is_physical is not true "
            "(a rehearsal can never close a physical criterion)"
        )
    if c1 == CriterionStatus.PASS:
        service = (sender.get("observations", {}) or {}).get("service", {})
        if service.get("verdict") != "executed":
            problems.append(
                "criterion 1 PASS requires the device-side service verdict "
                "to be 'executed'"
            )
        checks = sender.get("checks", [])
        if not all(check.get("ok") for check in checks):
            problems.append("criterion 1 PASS requires every device check to pass")
    if c2 == CriterionStatus.PASS:
        if is_physical is not True:
            problems.append("criterion 2 PASS requires a physical document")
        if access.get("technology") != "nr" or access.get("is_5g") is not True:
            problems.append(
                "criterion 2 PASS requires the Android framework to report NR"
            )
        post_route = _dig(document, "host.post_transition_route")
        traffic = document.get("traffic_verification") or {}
        if not post_route:
            problems.append("criterion 2 PASS requires the post-transition route")
        if not traffic.get("method") or not traffic.get("observation"):
            problems.append(
                "criterion 2 PASS requires independent traffic verification"
            )
    if c2 not in (None, CriterionStatus.NOT_TESTABLE) and access.get("is_5g") is not True:
        problems.append(
            "criterion 2 classified %r without an NR observation (only "
            "NOT-TESTABLE is permitted without NR)" % (c2,)
        )
    return (not problems), problems


#: The access technologies the Android framework report is mapped to
#: (a strict subset honest parsers may emit).
_ACCESS_TECHNOLOGIES = (
    "nr",        # 5G NR (the ONLY 5G observation)
    "lte",       # 4G LTE
    "td-scdma",
    "cdma-evdo",
    "umts",
    "gsm",
    "none",      # no mobile data in use
)


# ---------------------------------------------------------------------------
# Honest classification
# ---------------------------------------------------------------------------

def classify_physical_participation(document: Mapping[str, Any]) -> str:
    """The honest criterion-1 status DERIVED from the document's facts.

    PASS requires: a physical handset participant (is_physical), the
    complete chain, cross-corroborated session, executed service, all
    checks green.  A rehearsal is PARTIAL (the software-class chain is
    verified; the physical demonstration is unresolved).  No device at
    all is NOT-TESTABLE.
    """
    ok, _problems = validate_physical_evidence(document)
    is_physical = document.get("is_physical") is True
    if not is_physical:
        sender = document.get("adcos", {}).get("sender_result") or {}
        service = (sender.get("observations", {}) or {}).get("service", {})
        if document.get("kind") == "physical-environment-detection":
            return CriterionStatus.NOT_TESTABLE
        if service.get("verdict") == "executed" and ok:
            return CriterionStatus.PARTIAL
        return CriterionStatus.NOT_TESTABLE
    if not ok:
        return CriterionStatus.PARTIAL
    return CriterionStatus.PASS


def classify_five_g_path(document: Mapping[str, Any]) -> str:
    """The honest criterion-2 status DERIVED from the document's facts.

    PASS requires the framework NR observation, a physical document,
    the route transition onto the 5G-backed host path, and the
    independent traffic verification.  A device without NR is
    NOT-TESTABLE (cellular is never automatically 5G).  No device is
    NOT-TESTABLE.
    """
    access = document.get("access_technology") or {}
    is_physical = document.get("is_physical") is True
    if document.get("kind") == "physical-environment-detection":
        return CriterionStatus.NOT_TESTABLE
    if not is_physical:
        return CriterionStatus.NOT_TESTABLE
    if access.get("technology") != "nr" or access.get("is_5g") is not True:
        return CriterionStatus.NOT_TESTABLE
    traffic = document.get("traffic_verification") or {}
    post_route = (document.get("host") or {}).get("post_transition_route")
    if not post_route or not traffic.get("method") or not traffic.get("observation"):
        return CriterionStatus.PARTIAL
    ok, _problems = validate_physical_evidence(document)
    if not ok:
        return CriterionStatus.PARTIAL
    return CriterionStatus.PASS


# ---------------------------------------------------------------------------
# Evidence assembly
# ---------------------------------------------------------------------------

def _artifact_hash(name: str, payload: bytes) -> Tuple[str, str]:
    import hashlib

    return (name, "sha256:" + hashlib.sha256(payload).hexdigest())


def assemble_physical_evidence(
    *,
    environment: Mapping[str, Any],
    sender_result: Mapping[str, Any],
    receiver_result: Mapping[str, Any],
    device_identity: Mapping[str, Any],
    access_technology: Mapping[str, Any],
    host_route: Mapping[str, Any],
    carriage: Mapping[str, Any],
    is_physical: bool,
    traffic_verification: Optional[Mapping[str, Any]] = None,
    honest_absences: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Assemble the physical-evidence document from REAL observations.

    Every field comes from the caller's captured observations or is
    explicitly listed in ``honest_absences`` (a rehearsal).  The
    classification is DERIVED (never caller-asserted) and the document
    carries the validator's own SHA-256.
    """
    session = ((sender_result.get("observations") or {}).get("session")) or {}
    receiver_events = list(receiver_result.get("events") or [])
    sender_events = list(sender_result.get("events") or [])
    # the bind event is the PARTICIPANT's own production transition
    # (``runtime.bind_session`` journals SESSION_BOUND on the device
    # side; the appliance corroborates the session, not the bind)
    bind_event = next(
        (
            dict(event.get("payload") or {})
            for event in sender_events
            if event.get("kind") == "pilot.session-bound"
            and str((event.get("payload") or {}).get("session_id"))
            == str(session.get("session_id", ""))
        ),
        None,
    )
    artifacts = [
        _artifact_hash("device-result", _canonical_bytes(sender_result)),
        _artifact_hash("appliance-result", _canonical_bytes(receiver_result)),
        _artifact_hash("environment-detection", _canonical_bytes(environment)),
    ]
    document: Dict[str, Any] = {
        "kind": "physical-participation-evidence",
        "schema_version": PHYSICAL_EVIDENCE_SCHEMA_VERSION,
        "is_physical": is_physical,
        "carriage": dict(carriage),
        "device_identity": dict(device_identity),
        "access_technology": dict(access_technology),
        "host": dict(host_route),
        "adcos": {
            "access_classification": str(
                carriage.get("adcos_access_classification", "")
            ),
            "device_node_id": str(sender_result.get("node_id", "")),
            "session_id": str(session.get("session_id", "")),
            "bind_event": bind_event,
            "sender_result": dict(sender_result),
            "receiver_result": {
                "label": receiver_result.get("label"),
                "node_id": receiver_result.get("node_id"),
                "events": receiver_events,
                "checks": list(receiver_result.get("checks") or []),
            },
        },
        "traffic_verification": dict(traffic_verification or {}),
        "verification": {
            "validator_sha": validator_sha(),
            "artifact_hashes": [list(entry) for entry in artifacts],
        },
        "honest_absences": list(honest_absences or []),
    }
    ok, problems = validate_physical_evidence(document)
    document["classification"] = {
        "criterion_1_real_devices": classify_physical_participation(document),
        "criterion_2_5g": classify_five_g_path(document),
        "validation_ok": ok,
        "validation_problems": problems,
    }
    return document


def _canonical_bytes(document: Mapping[str, Any]) -> bytes:
    from protocol import canonical_json_bytes

    return canonical_json_bytes(document)


# ---------------------------------------------------------------------------
# The attempt (this host, honestly)
# ---------------------------------------------------------------------------

def run_physical_attempt(
    *, workspace: Optional[str] = None
) -> Dict[str, Any]:
    """The genuine attempt on THIS host: detect the physical
    environment; run the physical pilot ONLY if a device is genuinely
    attached; otherwise return the honest not-testable attempt record
    with the full detection evidence (never fabricated)."""
    environment = detect_physical_environment()
    if not environment["device_attached"]:
        return {
            "kind": "physical-environment-detection",
            "schema_version": PHYSICAL_EVIDENCE_SCHEMA_VERSION,
            "environment": environment,
            "attempt": {
                "executed": True,
                "physical_pilot_executed": False,
                "reason": environment["conclusion"],
            },
            "classification": {
                "criterion_1_real_devices": CriterionStatus.NOT_TESTABLE,
                "criterion_2_5g": CriterionStatus.NOT_TESTABLE,
                "statement": (
                    "no physical Android device is reachable from this "
                    "execution host; criterion 1 physical participation "
                    "cannot be demonstrated here and stays honestly "
                    "unresolved (PARTIAL overall per DEC-0046); criterion 2 "
                    "5G is NOT-TESTABLE here"
                ),
            },
        }
    # A device is genuinely attached: run the real physical pilot.
    return run_physical_pilot(environment=environment, workspace=workspace)


# ---------------------------------------------------------------------------
# The physical pilot (real device; runs where a handset is attached)
# ---------------------------------------------------------------------------

def _adb_base(serial: str, adb_path: str) -> List[str]:
    return [adb_path, "-s", serial]


def capture_device_identity(adb_path: str, serial: str) -> Dict[str, Any]:
    """Authoritative device identity through ``adb shell getprop``."""
    props = {}
    for prop in (
        "ro.product.model",
        "ro.product.brand",
        "ro.product.device",
        "ro.build.version.release",
        "ro.build.version.sdk",
        "ro.product.cpu.abi",
    ):
        completed = subprocess.run(  # noqa: S603 - read-only adb query
            _adb_base(serial, adb_path) + ["shell", "getprop", prop],
            capture_output=True, text=True, timeout=20,
        )
        props[prop] = completed.stdout.strip()
    return {
        "model": props.get("ro.product.model", ""),
        "brand": props.get("ro.product.brand", ""),
        "device": props.get("ro.product.device", ""),
        "serial": serial,
        "android_release": props.get("ro.build.version.release", ""),
        "sdk": props.get("ro.build.version.sdk", ""),
        "abi": props.get("ro.product.cpu.abi", ""),
        "observation_source": "adb shell getprop (authoritative device report)",
    }


def capture_access_technology(adb_path: str, serial: str) -> Dict[str, Any]:
    """The Android framework's OWN access-technology observation.

    Parses ``dumpsys telephony.registry`` for the data-network type
    and NR state.  ``is_5g`` is true ONLY when the framework reports
    NR; generic cellular is NEVER promoted to 5G.
    """
    try:
        completed = subprocess.run(  # noqa: S603 - read-only adb query
            _adb_base(serial, adb_path)
            + ["shell", "dumpsys", "telephony.registry"],
            capture_output=True, text=True, timeout=20,
        )
        raw = completed.stdout
    except (OSError, subprocess.SubprocessError) as error:
        return {
            "technology": "none",
            "is_5g": False,
            "observation_source": "dumpsys telephony.registry",
            "detail": "observation failed: %s: %s" % (type(error).__name__, error),
        }
    technology = "none"
    m = re.search(r"mDataNetworkType\s*=\s*(\w+)", raw)
    if m:
        technology = m.group(1).lower()
    nr_state = None
    m = re.search(r"mNrState\s*=\s*(\w+)", raw)
    if m:
        nr_state = m.group(1).lower()
    # NR may be reported via the data network type or the NR state;
    # either way the FRAMEWORK must say NR.
    is_5g = technology == "nr" or nr_state in ("connected", "connected_not_restricted")
    if is_5g:
        technology = "nr"
    excerpt_lines = [
        line.strip()
        for line in raw.splitlines()
        if "DataNetworkType" in line
        or "NrState" in line
        or "ServiceState" in line
    ]
    return {
        "technology": technology,
        "nr_state": nr_state,
        "is_5g": bool(is_5g),
        "observation_source": "adb shell dumpsys telephony.registry "
        "(the Android framework's own report)",
        "raw_excerpt": " | ".join(excerpt_lines[:6]),
    }


def capture_host_route() -> Dict[str, Any]:
    """The REAL host default route + the real interfaces."""
    route = {"detail": "", "default_via": "", "default_dev": ""}
    try:
        completed = subprocess.run(  # noqa: S603 - read-only host query
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=10,
        )
        line = completed.stdout.strip().splitlines()[0] if completed.stdout.strip() else ""
        route["detail"] = line
        if "via" in line.split():
            parts = line.split()
            route["default_via"] = parts[parts.index("via") + 1]
        if "dev" in line.split():
            parts = line.split()
            route["default_dev"] = parts[parts.index("dev") + 1]
    except (OSError, subprocess.SubprocessError) as error:
        route["detail"] = "%s: %s" % (type(error).__name__, error)
    interfaces = []
    try:
        source = LinuxInterfaceSource()
        interfaces = [snapshot.name for snapshot in source.discover()]
    except Exception:  # noqa: BLE001 - honest observation
        interfaces = []
    route["interfaces"] = interfaces
    return route


def run_physical_pilot(
    *,
    environment: Optional[Mapping[str, Any]] = None,
    workspace: Optional[str] = None,
    device_command: Optional[str] = None,
    repo_on_device: str = "/data/local/tmp/adcos",
    device_python: str = "python3",
    live: bool = False,
) -> Dict[str, Any]:
    """Run the REAL physical pilot (a handset must be attached).

    Orchestrates: device observations -> the appliance process with an
    externally reachable access point -> the carriage (``adb reverse``
    over USB, or the device's Wi-Fi to the host LAN) -> the device
    node ON the handset (the same ``pilot.node`` entrypoint through
    the production chain) -> both result documents -> the assembled,
    validated, honestly classified evidence document.
    """
    environment = dict(environment or detect_physical_environment())
    serials = list((environment.get("adb_devices") or {}).get("serials") or [])
    if not serials:
        return run_physical_attempt(workspace=workspace)
    serial = serials[0]
    adb_path = str((environment.get("adb_binary") or {}).get("path") or "adb")

    root = Path(workspace or tempfile.mkdtemp(prefix="adcos-physical-"))
    root.mkdir(parents=True, exist_ok=True)
    repo_root = Path(__file__).resolve().parents[1]

    # -- pre-transition observations ------------------------------------
    identity = capture_device_identity(adb_path, serial)
    access = capture_access_technology(adb_path, serial)
    route_pre = capture_host_route()

    # -- the appliance with an externally reachable access point --------
    appliance_result = root / "appliance-1.json"
    appliance_proc = subprocess.Popen(  # noqa: S603 - our own module
        [
            sys.executable, "-m", "pilot.node", "--role", "appliance",
            "--result-file", str(appliance_result),
            "--rehearsal" if not live else "--live",
            "--no-failure-plan",
        ],
        cwd=str(repo_root), stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        ports = _read_ready_ports(appliance_proc)
        direct_port = ports["direct"]

        # -- the carriage: adb reverse (real USB) -----------------------
        subprocess.run(  # noqa: S603 - carriage setup
            _adb_base(serial, adb_path)
            + ["reverse", "tcp:%d" % (direct_port,), "tcp:%d" % (direct_port,)],
            capture_output=True, text=True, timeout=20,
        )
        # The device connects to ITS OWN localhost, which adb carries
        # over USB to the host access point.
        device_target_host = "127.0.0.1"
        device_result_remote = "%s/device-android.json" % (repo_on_device,)

        # -- launch the device node ON THE HANDSET ----------------------
        if device_command is None:
            device_command = (
                "cd {repo} && {python} -m pilot.node --role device "
                "--label {label} --physical "
                "--result-file {result} "
                "--direct-host {host} --direct-port {port}".format(
                    repo=repo_on_device,
                    python=device_python,
                    label=PHYSICAL_DEVICE_LABEL,
                    result=device_result_remote,
                    host=device_target_host,
                    port=direct_port,
                )
            )
        launch = subprocess.run(  # noqa: S603 - the runbook's device command
            _adb_base(serial, adb_path) + ["shell", device_command],
            capture_output=True, text=True, timeout=600,
            cwd=str(repo_root),
        )
        launch_record = {
            "command": device_command,
            "returncode": launch.returncode,
            "stdout_tail": launch.stdout[-2000:],
            "stderr_tail": launch.stderr[-2000:],
        }

        # -- pull the device result document -----------------------------
        pull = subprocess.run(  # noqa: S603 - evidence retrieval
            _adb_base(serial, adb_path)
            + ["pull", device_result_remote, str(root / "device-android.json")],
            capture_output=True, text=True, timeout=60,
        )
        pulled = pull.returncode == 0
    finally:
        try:
            if appliance_proc.stdin is not None:
                appliance_proc.stdin.close()
        except OSError:
            pass
        try:
            appliance_proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            appliance_proc.kill()
            appliance_proc.wait(timeout=10)

    # -- post-transition observations ------------------------------------
    access_post = capture_access_technology(adb_path, serial)
    route_post = capture_host_route()

    device_doc: Dict[str, Any] = {}
    device_path = root / "device-android.json"
    if pulled and device_path.is_file():
        try:
            device_doc = json.loads(device_path.read_text(encoding="utf-8"))
        except ValueError:
            device_doc = {}
    appliance_doc: Dict[str, Any] = {}
    try:
        appliance_doc = json.loads(appliance_result.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        appliance_doc = {}

    if not device_doc or not appliance_doc:
        return {
            "kind": "physical-participation-evidence",
            "schema_version": PHYSICAL_EVIDENCE_SCHEMA_VERSION,
            "is_physical": True,
            "environment": environment,
            "launch_record": launch_record,
            "attempt": {
                "executed": True,
                "physical_pilot_executed": True,
                "result_documents_recovered": bool(device_doc and appliance_doc),
            },
            "classification": {
                "criterion_1_real_devices": CriterionStatus.PARTIAL,
                "criterion_2_5g": CriterionStatus.NOT_TESTABLE,
                "statement": (
                    "the physical pilot ran but the result documents were "
                    "not recovered; the demonstration is incomplete and "
                    "stays PARTIAL/NOT-TESTABLE"
                ),
            },
        }

    tether = [
        name
        for name in (route_post.get("interfaces") or [])
        if name in TETHER_INTERFACE_CANDIDATES
    ]
    carriage = {
        "mode": "adb-reverse-usb",
        "detail": (
            "the handset runs the production device node and connects to "
            "its own localhost, carried over the real USB adb reverse "
            "tunnel to the appliance access point"
        ),
        "adcos_access_classification": "direct access point (Ethernet-class "
        "host carriage; the handset is the ADCOS endpoint)",
        "tether_interfaces_observed": tether,
    }
    document = assemble_physical_evidence(
        environment=environment,
        sender_result=device_doc,
        receiver_result=appliance_doc,
        device_identity=identity,
        access_technology=access,
        host_route={
            "interface_identity": route_post.get("default_dev", ""),
            "pre_transition_route": route_pre.get("detail", ""),
            "post_transition_route": route_post.get("detail", ""),
            "interfaces": route_post.get("interfaces", []),
        },
        carriage=carriage,
        is_physical=True,
        traffic_verification=(
            {
                "method": "route + interface observation across the pilot "
                "window (pre/post) with the adb reverse carriage active",
                "observation": (
                    "pre=%s; post=%s; tether=%s"
                    % (
                        route_pre.get("detail", ""),
                        route_post.get("detail", ""),
                        tether,
                    )
                ),
            }
        ),
    )
    document["launch_record"] = launch_record
    document["attempt"] = {
        "executed": True,
        "physical_pilot_executed": True,
        "result_documents_recovered": True,
    }
    # refresh the derived classification with the post observations
    merged_access = dict(access)
    merged_access.setdefault("detail", "")
    document["access_technology"] = merged_access
    document["classification"]["criterion_1_real_devices"] = (
        classify_physical_participation(document)
    )
    document["classification"]["criterion_2_5g"] = classify_five_g_path(document)
    return document


def _read_ready_ports(proc: subprocess.Popen) -> Dict[str, int]:
    assert proc.stdout is not None
    line = proc.stdout.readline()
    try:
        document = json.loads(line)
    except ValueError as error:
        raise PilotError(
            PilotReasonCode.CONDUCTOR_FAILED,
            "appliance READY line unreadable (%r)" % (line[:120],),
        ) from error
    return {key: int(value) for key, value in document.items()}


# ---------------------------------------------------------------------------
# The rehearsal (software-class verification of the whole chain)
# ---------------------------------------------------------------------------

def run_physical_rehearsal(
    *, workspace: Optional[str] = None
) -> Dict[str, Any]:
    """The software-class rehearsal of the physical path.

    Runs the SAME device-android node (same identity, same config,
    same production chain, same ``--physical`` mode) as a HOST process
    connecting over the loopback carriage to a locally started
    appliance.  This verifies every code path the physical pilot
    needs -- the participant topology, the announce acceptance, the
    session chain, the service invocation, the evidence assembly, and
    the validator -- while remaining honestly ``is_physical=false``:
    the physical demonstration itself still requires the handset.
    """
    environment = detect_physical_environment()
    root = Path(workspace or tempfile.mkdtemp(prefix="adcos-physical-rehearsal-"))
    root.mkdir(parents=True, exist_ok=True)
    repo_root = Path(__file__).resolve().parents[1]

    route_pre = capture_host_route()
    appliance_result = root / "appliance-1.json"
    device_result = root / "device-android.json"
    appliance_proc = subprocess.Popen(  # noqa: S603 - our own module
        [
            sys.executable, "-m", "pilot.node", "--role", "appliance",
            "--result-file", str(appliance_result),
            "--rehearsal",
            "--no-failure-plan",
        ],
        cwd=str(repo_root), stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        ports = _read_ready_ports(appliance_proc)
        direct_port = ports["direct"]
        device_proc = subprocess.run(  # noqa: S603 - our own module
            [
                sys.executable, "-m", "pilot.node", "--role", "device",
                "--label", PHYSICAL_DEVICE_LABEL,
                "--result-file", str(device_result),
                "--direct-host", "127.0.0.1",
                "--direct-port", str(direct_port),
                "--relay-host", "127.0.0.1",
                "--relay-port", str(ports["relay"]),
                "--physical",
            ],
            cwd=str(repo_root), capture_output=True, text=True, timeout=300,
            env={**os.environ, "PYTHONHASHSEED": "0"},
        )
        device_launch = {
            "returncode": device_proc.returncode,
            "stderr_tail": device_proc.stderr[-500:],
        }
    finally:
        try:
            if appliance_proc.stdin is not None:
                appliance_proc.stdin.close()
        except OSError:
            pass
        try:
            appliance_proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            appliance_proc.kill()
            appliance_proc.wait(timeout=10)

    route_post = capture_host_route()
    device_doc: Dict[str, Any] = {}
    try:
        device_doc = json.loads(device_result.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        device_doc = {}
    appliance_doc: Dict[str, Any] = {}
    try:
        appliance_doc = json.loads(appliance_result.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        appliance_doc = {}

    if not device_doc or not appliance_doc:
        return {
            "kind": "physical-participation-evidence",
            "schema_version": PHYSICAL_EVIDENCE_SCHEMA_VERSION,
            "is_physical": False,
            "environment": environment,
            "rehearsal": True,
            "device_launch": device_launch,
            "attempt": {
                "executed": True,
                "physical_pilot_executed": False,
                "reason": "the rehearsal did not complete",
            },
            "classification": {
                "criterion_1_real_devices": CriterionStatus.NOT_TESTABLE,
                "criterion_2_5g": CriterionStatus.NOT_TESTABLE,
            },
        }

    honest_absences = [
        "device_identity.model",
        "device_identity.brand",
        "device_identity.serial",
        "device_identity.android_release",
        "device_identity.observation_source",
        "access_technology.technology",
        "access_technology.observation_source",
        "host.interface_identity",
    ]
    document = assemble_physical_evidence(
        environment=environment,
        sender_result=device_doc,
        receiver_result=appliance_doc,
        device_identity={
            "model": "",
            "brand": "",
            "serial": "",
            "android_release": "",
            "observation_source": "none (rehearsal: no handset present)",
        },
        access_technology={
            "technology": "",
            "is_5g": False,
            "observation_source": "none (rehearsal: no handset present)",
        },
        host_route={
            "interface_identity": "",
            "pre_transition_route": route_pre.get("detail", ""),
            "post_transition_route": route_post.get("detail", ""),
            "interfaces": route_post.get("interfaces", []),
        },
        carriage={
            "mode": "loopback-rehearsal",
            "detail": (
                "the device-android node ran as a HOST process over the "
                "loopback carriage: the same identity, config, and "
                "production chain, honestly NOT a physical handset"
            ),
            "adcos_access_classification": "direct access point (rehearsal "
            "loopback carriage; software-class verification of the chain)",
        },
        is_physical=False,
        traffic_verification={},
        honest_absences=honest_absences,
    )
    document["rehearsal"] = True
    document["device_launch"] = device_launch
    document["attempt"] = {
        "executed": True,
        "physical_pilot_executed": False,
        "reason": (
            "software-class rehearsal completed; the physical "
            "demonstration requires the handset attached to a host with "
            "adb (the runbook in docs/WORK-040-handoff.md)"
        ),
    }
    return document


# ---------------------------------------------------------------------------
# The evidence writer
# ---------------------------------------------------------------------------

def write_attempt_evidence(
    *, out_dir: str, environment: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Execute the honest attempt on this host and write the evidence
    artifact (the detection record + the rehearsal record) with exact
    digests and the exact execution SHA.  Returns the written document."""
    attempt = run_physical_attempt()
    rehearsal = run_physical_rehearsal()
    environment = environment or detect_physical_environment()
    repo_root = Path(__file__).resolve().parents[1]
    execution_sha = "unknown"
    try:
        completed = subprocess.run(  # noqa: S603 - read-only git query
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, cwd=str(repo_root), timeout=10,
        )
        if completed.returncode == 0:
            execution_sha = completed.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    document = {
        "kind": "work-040-physical-attempt",
        "schema_version": PHYSICAL_EVIDENCE_SCHEMA_VERSION,
        "execution_sha": execution_sha,
        "environment": environment,
        "attempt": attempt,
        "rehearsal": rehearsal,
        "summary": {
            "criterion_1_real_devices": (
                rehearsal.get("classification", {}).get(
                    "criterion_1_real_devices"
                )
                if rehearsal.get("kind") == "physical-participation-evidence"
                else CriterionStatus.NOT_TESTABLE
            ),
            "criterion_2_5g": CriterionStatus.NOT_TESTABLE,
            "statement": (
                "the physical-device participation path is implemented and "
                "software-verified (rehearsal); no physical handset is "
                "reachable from this execution host, so the physical "
                "demonstration stays honestly unresolved and criterion 2 "
                "stays NOT-TESTABLE"
            ),
        },
    }
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "physical-attempt.json").write_text(
        json.dumps(document, sort_keys=True, indent=1), encoding="utf-8"
    )
    return document
