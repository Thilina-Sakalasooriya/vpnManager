"""CLI for the VPN manager."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import config as config_module
from .backends import Runner, VPNError
from .manager import VPNManager


def _fmt_bool(value: bool | None) -> str:
    if value is None:
        return "?"
    return "yes" if value else "no"


def cmd_list(args: argparse.Namespace, manager: VPNManager) -> int:
    servers = manager.servers
    print(f"Config: {manager.config_path}")
    print(f"{'#':<4}{'Name':<24}{'Protocol':<12}{'Location':<24}{'Tags'}")
    print("-" * 80)
    for i, server in enumerate(servers, 1):
        tags = ",".join(server.tags)
        print(
            f"{i:<4}{server.name:<24}{server.protocol:<12}{server.label:<24}{tags}"
        )
    return 0


def cmd_status(args: argparse.Namespace, manager: VPNManager) -> int:
    status = manager.status()
    if not status.connected:
        print("Disconnected")
        return 0
    print(f"Connected: {status.backend}")
    if status.interface:
        print(f"Interface:  {status.interface}")
    if status.server:
        print(f"Server:     {status.server}")
    if status.details:
        for key, value in status.details.items():
            print(f"  {key}: {value}")
    report = manager.check_current()
    if report.error:
        print(f"IP check:   error - {report.error}")
    else:
        print(f"Public IP:  {report.ip} ({report.country} {report.city})")
        print(f"Org:        {report.org or '?'} | hosting: {_fmt_bool(report.hosting)}")
        print(f"Netflix:    {report.netflix.verdict} - {report.netflix.reason}")
    return 0


def cmd_connect(args: argparse.Namespace, manager: VPNManager) -> int:
    try:
        server = manager.connect(args.server)
        print(f"Connected to {server.label} via {server.protocol}")
        if args.check:
            report = manager.check_current()
            if report.error:
                print(f"IP check failed: {report.error}")
            else:
                print(f"Public IP: {report.ip} ({report.org or 'unknown org'})")
                print(f"Netflix: {report.netflix.verdict} - {report.netflix.reason}")
        return 0
    except (VPNError, config_module.ConfigError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def cmd_disconnect(args: argparse.Namespace, manager: VPNManager) -> int:
    if manager.disconnect():
        print("Disconnected")
        return 0
    print("Already disconnected")
    return 0


def cmd_test(args: argparse.Namespace, manager: VPNManager) -> int:
    refs = args.servers if args.servers else None
    try:
        results = manager.test(refs)
    except (VPNError, config_module.ConfigError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Results (cached at {manager.results_path})")
    print(
        f"{'Server':<24}{'Proto':<10}{'IP':<16}{'Hosting':<10}{'Netflix':<12}{'Latency':<10}{'Error'}"
    )
    print("-" * 95)
    for r in results:
        latency = f"{r.latency_ms:.0f}ms" if r.latency_ms is not None else "?"
        error_text = r.error or (r.netflix_reason[:40] if r.netflix_reason else "")
        print(
            f"{r.server:<24}{r.protocol:<10}{r.ip:<16}{_fmt_bool(r.hosting):<10}{r.netflix:<12}{latency:<10}{error_text}"
        )
    streamable = [r for r in results if r.streamable]
    if streamable:
        print(f"\nStreamable (residential/non-hosting): {', '.join(r.server for r in streamable)}")
    else:
        print("\nNo server tested streamable. Free/public servers & datacenter VPS are generally blocked.")
        print("Add a residential VPN provider's OpenVPN profile, or a WireGuard config from one.")
    return 0


def cmd_best(args: argparse.Namespace, manager: VPNManager) -> int:
    try:
        winner = manager.connect_best(args.servers if args.servers else None)
        print(f"Connected to best server: {winner.server} ({winner.ip}, netflix={winner.netflix})")
        return 0
    except (VPNError, config_module.ConfigError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def cmd_check(args: argparse.Namespace, manager: VPNManager) -> int:
    report = manager.check_current()
    if report.error:
        print(f"Error: {report.error}", file=sys.stderr)
        return 1
    print(f"Public IP: {report.ip}")
    print(f"Location:  {report.country} {report.city}")
    print(f"Org:       {report.org or '?'}")
    print(f"Hosting:   {_fmt_bool(report.hosting) if report.hosting is not None else '?'}")
    print(f"Latency:   {report.latency_ms}ms" if report.latency_ms is not None else "Latency:   ?")
    print(f"Netflix:   {report.netflix.verdict} - {report.netflix.reason}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vpnmanager",
        description="VPN manager that tests connections for Netflix usability.",
        epilog="Config: ~/.config/vpnmanager/servers.json",
    )
    parser.add_argument("--config", help="Path to servers.json")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without executing")
    parser.add_argument("--no-sudo", action="store_true", help="Run commands without sudo (if already root)")
    parser.add_argument("--json", action="store_true", help="Output in JSON")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list", help="List configured servers")
    subparsers.add_parser("status", help="Connection and exit IP status")
    subparsers.add_parser("disconnect", help="Disconnect active VPN")
    subparsers.add_parser("check", help="Check current exit IP and Netflix reachability")

    p_connect = subparsers.add_parser("connect", help="Connect to a server")
    p_connect.add_argument("server", help="Server name or number from `list`")
    p_connect.add_argument("--check", action="store_true", help="Probe after connecting")

    p_test = subparsers.add_parser("test", help="Test servers for streaming usability (connects/disconnects each)")
    p_test.add_argument("servers", nargs="*", help="Servers to test (default: all)")
    p_test.set_defaults(func="test")

    p_best = subparsers.add_parser("best", help="Connect to the best cached/tested streamable server")
    p_best.add_argument("servers", nargs="*", help="Only consider these servers")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    runner = Runner(dry_run=args.dry_run, use_sudo=not args.no_sudo)
    try:
        manager = VPNManager(config_path=args.config, runner=runner)
    except config_module.ConfigError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    try:
        if args.command == "list":
            return cmd_list(args, manager)
        if args.command == "status":
            return cmd_status(args, manager)
        if args.command == "connect":
            return cmd_connect(args, manager)
        if args.command == "disconnect":
            return cmd_disconnect(args, manager)
        if args.command == "test":
            return cmd_test(args, manager)
        if args.command == "best":
            return cmd_best(args, manager)
        if args.command == "check":
            return cmd_check(args, manager)
        print(f"Unknown command {args.command}", file=sys.stderr)
        return 1
    except VPNError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
