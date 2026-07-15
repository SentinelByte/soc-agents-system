"""
~~ CLI

Thin command-line entry point for TriAgen.

Usage:
  triagen --alert-file scenarios/reverse_shell.json
  triagen --alert '{"alert_type": "process_start", ...}'
  triagen --replay scenarios/
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .alert_processor import process_alert
from .enrichment_engine import enrich_alert
from .reasoning_engine import triage


def _load_alert(raw: str) -> dict[str, Any]:
    path = Path(raw)
    if path.is_file():
        return json.loads(path.read_text())
    return json.loads(raw)


def _run_one(alert: dict[str, Any], use_llm: bool) -> dict[str, Any]:
    processed = process_alert(alert)
    enriched = enrich_alert(processed)
    return triage(enriched, use_llm=use_llm)


def _print_result(name: str, result: dict[str, Any]) -> None:
    print(f"\n=== {name} ===")
    print(json.dumps(result, indent=2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="triagen", description="Local SOC alert triage agent")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--alert-file", help="Path to a JSON alert file")
    group.add_argument("--alert", help="Raw JSON alert string")
    group.add_argument("--replay", metavar="DIR", help="Run every *.json alert in DIR through the pipeline")
    parser.add_argument(
        "--use-llm",
        action="store_true",
        help="Use the Anthropic-backed reasoning engine instead of the deterministic fallback "
        "(requires ANTHROPIC_API_KEY and the `llm` extra)",
    )
    args = parser.parse_args(argv)

    if args.replay:
        scenario_dir = Path(args.replay)
        for scenario_file in sorted(scenario_dir.glob("*.json")):
            alert = json.loads(scenario_file.read_text())
            result = _run_one(alert, args.use_llm)
            _print_result(scenario_file.name, result)
        return 0

    raw = args.alert_file if args.alert_file else args.alert
    alert = _load_alert(raw)
    result = _run_one(alert, args.use_llm)
    _print_result("result", result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
