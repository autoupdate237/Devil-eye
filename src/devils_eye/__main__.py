"""Devil's Eye CLI.

Examples:
    python -m devils_eye scan                 # full scan on this Windows host
    python -m devils_eye monitor --interval 10
    python -m devils_eye scan --forensic      # post-session forensic mode
    python -m devils_eye serve --port 8080
    python -m devils_eye selftest
"""

from __future__ import annotations

import argparse
import json
import sys

from . import APP_NAME, __version__
from .core.config import Policy, default_workspace
from .core.logging_setup import setup_logging


def _load_policy(args) -> Policy:
    return Policy.load(args.policy) if args.policy else Policy.load()


def cmd_scan(args) -> int:
    from .pipeline.orchestrator import Orchestrator

    orch = Orchestrator(policy=_load_policy(args), etw=args.etw)
    mode = "forensic" if args.forensic else "scan"
    session = orch.run(mode=mode)
    v = session.verdict
    print(f"\n{'=' * 62}\n{APP_NAME} v{__version__} — scan {session.scan_id} ({mode})")
    print(f"VERDICT:  {v.level}   score={v.score:.1f}/100   confidence={v.confidence:.0%}   coverage={v.telemetry_coverage:.0%}")
    print("-" * 62)
    for line in v.rationale:
        print(" •", line)
    if session.limitations:
        print("-" * 62)
        print(f"telemetry limitations ({len(session.limitations)}):")
        for lim in session.limitations[:8]:
            print(f"  - {lim.source}: {lim.reason}")
    print("-" * 62)
    for path in session.report_paths:
        print("report:", path)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(session.to_dict(), fh, indent=2, default=str)
        print("json:", args.json_out)
    return 0


def cmd_monitor(args) -> int:
    from .pipeline.orchestrator import Orchestrator

    orch = Orchestrator(policy=_load_policy(args), etw=args.etw)
    for session in orch.monitor(interval=args.interval, iterations=args.iterations):
        v = session.verdict
        new = ", ".join(session.new_subjects) or "none"
        print(f"[monitor] {session.scan_id} {v.level} score={v.score:.1f} new_subjects: {new}")
    return 0


def cmd_serve(args) -> int:
    from .api.server import serve

    serve(host=args.host, port=args.port, policy=_load_policy(args),
          initial_scan=not args.no_scan)
    return 0


def cmd_selftest(args) -> int:
    from .integrity.self_check import self_check

    report = self_check(default_workspace())
    print(json.dumps(report, indent=2))
    return 0 if not (report["changed"] or report["removed"]) else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="devils-eye", description=f"{APP_NAME} — defensive Windows integrity monitor")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--policy", type=str, default=None, help="path to a policy JSON file")
    common.add_argument("--etw", action="store_true", help="opt-in: enable ETW trace capture")
    common.add_argument("--verbose", action="store_true")

    p_scan = sub.add_parser("scan", parents=[common], help="one-shot full scan")
    p_scan.add_argument("--forensic", action="store_true", help="post-session forensic mode")
    p_scan.add_argument("--json-out", type=str, default=None)
    p_scan.set_defaults(func=cmd_scan)

    p_mon = sub.add_parser("monitor", parents=[common], help="real-time monitoring loop")
    p_mon.add_argument("--interval", type=float, default=10.0)
    p_mon.add_argument("--iterations", type=int, default=None, help="stop after N passes (tests)")
    p_mon.set_defaults(func=cmd_monitor)

    p_serve = sub.add_parser("serve", parents=[common], help="dashboard (runs a scan first)")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8080)
    p_serve.add_argument("--no-scan", action="store_true")
    p_serve.set_defaults(func=cmd_serve)

    p_self = sub.add_parser("selftest", help="self-integrity check")
    p_self.set_defaults(func=cmd_selftest)

    args = parser.parse_args(argv)
    import logging

    setup_logging(logging.DEBUG if getattr(args, "verbose", False) else logging.INFO)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
