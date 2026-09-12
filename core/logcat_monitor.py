#!/usr/bin/env python3
"""
Android Enterprise Security Lab - Live MDM Telemetry / Logcat Monitor
---------------------------------------------------------------------
Module: core/logcat_monitor.py
Description: NON-DESTRUCTIVE real-time monitoring of device logs for
             DevicePolicyManager activity, MDM agent behavior, and
             enterprise attestation traffic indicators via ``adb logcat``.

             Use cases:
               * Observing which components react to boot / network events.
               * Correlating DPM IPC broadcasts with cloud check-in timing.
               * Profiling unknown agents in the lab before deeper analysis.

             The monitor is strictly read-only: it never clears logs by
             default, never restarts services, and never modifies the device.

License: Apache License 2.0
"""

import argparse
import signal
import subprocess
import sys
from datetime import datetime, timezone
from typing import IO, List, Optional

TOOL_NAME = "Android Enterprise Security Lab - Logcat Telemetry Monitor"
TOOL_VERSION = "1.0.0"

# Keyword families used for live highlighting/filtering. Case-insensitive.
DEFAULT_KEYWORDS: List[str] = [
    "devicepolicy",
    "devicepolicymanager",
    "deviceadmin",
    "dpm",
    "mdm",
    "knox",
    "device owner",
    "profile owner",
    "devicelock",
    "device_lock",
    "payjoy",
    "workprofile",
    "managed profile",
    "attestation",
]

# Priority buckets for keyword highlighting in the terminal output.
HIGH_PRIORITY_KEYWORDS: List[str] = [
    "devicepolicy",
    "deviceadmin",
    "device owner",
    "profile owner",
    "devicelock",
    "knox",
]

ANSI_RED = "\033[0;31m"
ANSI_YELLOW = "\033[1;33m"
ANSI_GREEN = "\033[0;32m"
ANSI_BLUE = "\033[0;34m"
ANSI_NC = "\033[0m"


def matches_any_keyword(line: str, keywords: List[str]) -> bool:
    """Return True when the line contains any keyword (case-insensitive)."""
    lowered = line.lower()
    return any(keyword in lowered for keyword in keywords)


def verify_adb() -> bool:
    """Check that adb is available on PATH."""
    try:
        subprocess.run(
            ["adb", "version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            timeout=15,
        )
        return True
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def device_serials() -> List[str]:
    """List attached, authorized ADB device serials."""
    try:
        result = subprocess.run(
            ["adb", "devices"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return []
    serials: List[str] = []
    for line in result.stdout.split("\n")[1:]:
        parts = line.strip().split()
        if len(parts) >= 2 and parts[1] == "device":
            serials.append(parts[0])
    return serials


def monitor(
    keywords: List[str],
    device_id: Optional[str] = None,
    log_path: Optional[str] = None,
    clear_first: bool = False,
    use_color: bool = True,
    output_stream: IO[str] = sys.stdout,
) -> int:
    """Stream and filter ``adb logcat`` until interrupted.

    Args:
        keywords: Case-insensitive keywords to highlight/flag.
        device_id: Optional ADB device serial.
        log_path: Optional path to tee matched lines into (append mode).
        clear_first: Clear the logcat buffer before streaming (opt-in only,
            so the default behavior never discards device state).
        use_color: Toggle ANSI coloring.
        output_stream: Stream to write to (injectable for tests).

    Returns:
        Process exit status code.
    """
    base = ["adb"] + (["-s", device_id] if device_id else [])

    if clear_first:
        subprocess.run(
            base + ["logcat", "-c"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )

    print(f"[*] Streaming logcat telemetry (Ctrl+C to stop)...", file=output_stream)
    print(f"[*] Flagging keywords: {', '.join(keywords)}", file=output_stream)
    print("-" * 65, file=output_stream)

    log_file: Optional[IO[str]] = None
    if log_path:
        log_file = open(log_path, "a", encoding="utf-8")
        print(f"[*] Matched lines are also appended to '{log_path}'", file=output_stream)

    process = subprocess.Popen(
        base + ["logcat", "-v", "threadtime"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    matched = 0
    started = datetime.now(timezone.utc)

    def handle_sigterm(signum, frame):  # noqa: ANN001 - signal handler signature
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, handle_sigterm)

    try:
        assert process.stdout is not None
        for line in process.stdout:
            line = line.rstrip("\n")
            if matches_any_keyword(line, keywords):
                matched += 1
                lowered = line.lower()
                if use_color:
                    if any(k in lowered for k in HIGH_PRIORITY_KEYWORDS):
                        rendered = f"{ANSI_RED}[MDM]{ANSI_NC} {line}"
                    else:
                        rendered = f"{ANSI_YELLOW}[POLICY]{ANSI_NC} {line}"
                else:
                    prefix = "[MDM]" if any(
                        k in lowered for k in HIGH_PRIORITY_KEYWORDS
                    ) else "[POLICY]"
                    rendered = f"{prefix} {line}"
                print(rendered, file=output_stream)
                if log_file:
                    log_file.write(line + "\n")
                    log_file.flush()
            elif use_color:
                # Render unflagged traffic dimmed so flagged lines stand out.
                print(f"{ANSI_BLUE}  {line}{ANSI_NC}", file=output_stream)
            else:
                print(f"  {line}", file=output_stream)
    except KeyboardInterrupt:
        pass
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        if log_file:
            log_file.close()

    elapsed = (datetime.now(timezone.utc) - started).total_seconds()
    print("-" * 65, file=output_stream)
    print(
        f"[+] Monitor stopped. {matched} flagged line(s) in {elapsed:.1f}s.",
        file=output_stream,
    )
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logcat_monitor",
        description=(
            "Read-only live monitor of adb logcat for DevicePolicyManager / "
            "MDM activity. Highlights policy-related events in real time."
        ),
        epilog="Example: python3 core/logcat_monitor.py --log output/telemetry.log",
    )
    parser.add_argument("--device", "-s", metavar="SERIAL",
                        help="ADB device serial to monitor.")
    parser.add_argument("--log", "-l", metavar="PATH",
                        help="Tee flagged lines to a log file (append mode).")
    parser.add_argument("--clear", action="store_true",
                        help="Clear the logcat buffer before streaming "
                             "(default: keep device logs untouched).")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colors (useful when piping).")
    parser.add_argument("--keyword", "-k", action="append", metavar="WORD",
                        help="Extra keyword to flag (repeatable).")
    parser.add_argument("--keywords-only", action="store_true",
                        help="Print only flagged lines instead of all traffic.")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {TOOL_VERSION}")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    print("=" * 65)
    print(f"      {TOOL_NAME.upper()}      ")
    print("=" * 65)

    if not verify_adb():
        print("[X] Error: 'adb' executable not found in PATH. "
              "Run scripts/setup.sh or scripts/setup.ps1 first.", file=sys.stderr)
        return 2

    serials = device_serials()
    if not serials:
        print("[!] No authorized ADB device connected.", file=sys.stderr)
        return 1
    if args.device is None and len(serials) > 1:
        print("[!] Multiple devices attached; pass --device <serial>:", file=sys.stderr)
        for serial in serials:
            print(f"    {serial}", file=sys.stderr)
        return 1

    keywords = list(DEFAULT_KEYWORDS) + (args.keyword or [])

    if args.keywords_only:
        # Filtered mode: wrap monitor with a stream that drops unflagged lines.
        class _FlaggedOnly:
            def __init__(self, inner: IO[str]) -> None:
                self.inner = inner

            def write(self, text: str) -> int:
                stripped = text.strip()
                if stripped.startswith(("[MDM]", "[POLICY]", "[*]", "[+]", "-")) or not stripped:
                    return self.inner.write(text)
                return 0

            def flush(self) -> None:
                self.inner.flush()

        return monitor(
            keywords,
            device_id=args.device,
            log_path=args.log,
            clear_first=args.clear,
            use_color=not args.no_color,
            output_stream=_FlaggedOnly(sys.stdout),  # type: ignore[arg-type]
        )

    return monitor(
        keywords,
        device_id=args.device,
        log_path=args.log,
        clear_first=args.clear,
        use_color=not args.no_color,
    )


if __name__ == "__main__":
    sys.exit(main())
