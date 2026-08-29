"""WORK-040 pilot node process entrypoint.

Each pilot node runs as a REAL OS process (``python3 -m pilot.node
...``): the process boots its production runtime, serves/drives its
declared role over real TCP carriages, and writes its honest result
document on exit.  The conductor (``pilot.deployment``) spawns and
coordinates these processes.
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
        )
    if args.role == "relay":
        return run_relay_node(
            result_path=args.result_file,
            upstream_host=args.upstream_host,
            upstream_port=args.upstream_port,
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
    )
    # unreachable


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
