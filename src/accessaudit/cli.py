import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .engine import SEVERITIES
from .model import InputError, json_bytes, load
from .report import compile_report


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Review effective authorization in a normalized NAC model."
    )
    parser.add_argument(
        "--version", action="version", version=f"network-access-auditor {__version__}"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser(
        "validate", help="Check input contract only; not a security audit."
    )
    validate.add_argument("--input", type=Path, required=True)
    audit = commands.add_parser("audit", help="Create an offline audit package in a new directory.")
    audit.add_argument("--input", type=Path, required=True)
    audit.add_argument("--output", type=Path, required=True)
    audit.add_argument("--fail-on", choices=[*SEVERITIES, "none"], default="medium")
    args = parser.parse_args(argv)
    try:
        data, source_hash = load(args.input)
        if args.command == "validate":
            print(
                json_bytes({"input_valid": True, "scope": "input-contract-only"}).decode(), end=""
            )
            return 0
        files, result = compile_report(data, source_hash, args.fail_on)
        args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
        for name, raw in files.items():
            fd = os.open(args.output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw)
        print(
            f"{result['status'].upper()} | {result['counts']['findings']} findings | "
            f"{result['counts']['states']} modeled states | "
            f"gate={'FAIL' if result['gate']['failed'] else 'PASS'} ({args.fail_on}) | "
            "offline-normalized-nac-model"
        )
        return 1 if result["gate"]["failed"] else 0
    except InputError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
    except FileExistsError:
        print("Output exists; choose a new directory. No files overwritten.", file=sys.stderr)
    except OSError:
        print(
            "File operation failed. Partial output may remain; require a complete manifest "
            "and matching hashes before use.",
            file=sys.stderr,
        )
    return 2


if __name__ == "__main__":
    sys.exit(main())
