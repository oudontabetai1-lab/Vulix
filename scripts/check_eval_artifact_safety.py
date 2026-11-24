#!/usr/bin/env python3
"""Validate the allowlisted public Agent evaluation artifacts."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wscan.eval_artifact_safety import check_artifacts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", nargs="+", type=Path)
    args = parser.parse_args(argv)
    try:
        check_artifacts(args.artifacts)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print("PASS: evaluation artifacts contain only allowed safe content")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
