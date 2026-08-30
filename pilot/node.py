"""WORK-040 pilot node process entrypoint.

Each pilot node runs as a REAL OS process (``python3 -m pilot.node
...``): the process boots its production runtime, serves/drives its
declared role over real TCP carriages, and writes its honest result
document on exit.  The conductor (``pilot.deployment``) spawns and
coordinates these processes.

The correction cycle (WORK-040-CORRECTION-001) adds:

- ``--physical`` (device role): the participation demonstration of
  the declared physical participant ``device-android`` -- the same
  production chain as every pilot device, launched ON the actual
  handset (or, honestly labeled, as a host-side rehearsal);
- ``--bind-host`` / ``--no-failure-plan`` (appliance role): let the
  physical pilot expose an externally reachable access point and
  disarm device-1's failover plan for the participation scenario.

The correction's second cycle adds the physical HANDOVER mode:

- ``--handover`` (device role, with ``--physical``): the
  path-transition demonstration -- the production chain over the
  primary physical carriage, a REAL path death (the appliance's
  declared failure plan in the rehearsal; the operator disabling
  Wi-Fi on the handset in the physical run), the production re-bind
  onto the secondary (USB-tether relayed) carriage on the SAME
  logical session, and the service invocation on the new path;
  ``--handover-wait-seconds`` bounds the wait for the physical
  trigger (honest incomplete record on timeout) and
  ``--handover-attempt-interval`` paces the transition attempts;
- ``--bind-host`` (relay role): bind an externally reachable relay
  listener for the physical handover's secondary carriage (the
  default loopback keeps the delivered deployment byte-identical).
"""

from __future__ import annotations

import argparse
import sys
from typing import List


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="pilot.node", description="one WORK-040 pilot deployment node"
    )
    parser.add_argument("--role", required=True,
                        choices=("appliance", "relay", "device"))
    parser.add_argument("--label", default="")
    parser.add_argument("--result-file", required=True)
    parser.add_argument("--direct-host", default="127.0.0.1")
    parser.add_argument("--direct-port", type=int, default=0)
    parser.add_argument("--relay-host", default="127.0.0.1")
    parser.add_argument("--relay-port", type=int, default=0)
    parser.add_argument("--upstream-host", default="127.0.0.1")
    parser.add_argument("--upstream-port", type=int, default=0)
    parser.add_argument("--relayed-only", action="store_true")
    parser.add_argument("--rehearsal", action="store_true")
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--physical", action="store_true",
                        help="the physical-participation demonstration "
                             "(device-android)")
    parser.add_argument("--handover", action="store_true",
                        help="the physical path-transition demonstration "
                             "(device-android, with --physical): the "
                             "production re-bind onto the secondary "
                             "(USB-tether relayed) carriage on the SAME "
                             "logical session")
    parser.add_argument("--handover-wait-seconds", type=float,
                        default=600.0,
                        help="the bounded wait for the physical trigger "
                             "(the operator disabling Wi-Fi on the "
                             "handset); honest incomplete record on "
                             "timeout")
    parser.add_argument("--handover-attempt-interval", type=float,
                        default=5.0,
                        help="the pause between transition attempts "
                             "while the primary carriage is still alive")
    parser.add_argument("--bind-host", default="127.0.0.1",
                        help="the address the appliance access points "
                             "bind (default: loopback, the delivered "
                             "rehearsal behavior)")
    parser.add_argument("--no-failure-plan", action="store_true",
                        help="disarm the declared direct-path failure "
                             "plan (physical participation scenario)")
    args = parser.parse_args(argv)

    from .deployment import (
        run_appliance_node,
        run_device_node,
        run_relay_node,
    )

    if args.role == "appliance":
        return run_appliance_node(
            result_path=args.result_file,
            rehearsal=not args.live,
            bind_host=args.bind_host,
            failure_plan=not args.no_failure_plan,
        )
    if args.role == "relay":
        return run_relay_node(
            result_path=args.result_file,
            upstream_host=args.upstream_host,
            upstream_port=args.upstream_port,
            bind_host=args.bind_host,
        )
    if not args.label:
        parser.error("the device role requires --label")
    return run_device_node(
        label=args.label,
        result_path=args.result_file,
        direct_host=args.direct_host,
        direct_port=args.direct_port,
        relay_host=args.relay_host,
        relay_port=args.relay_port,
        relayed_only=args.relayed_only,
        physical=args.physical,
        handover=args.handover,
        handover_wait_seconds=args.handover_wait_seconds,
        handover_attempt_interval=args.handover_attempt_interval,
    )
    # unreachable


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
