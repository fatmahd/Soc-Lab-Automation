#!/usr/bin/env python3

import argparse
import json
import subprocess
import sys
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple


EXPECTED_RULES = {
    "linux": {
        "100402", "100404", "100407", "100400", "100401", "100403",
        "100460", "100461", "100405", "100410",
    },
    "windows": {
        "100434", "100435", "100418", "100421", "100500", "100501",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate expected Wazuh rule.id values after PHASE4 tests.",
    )
    parser.add_argument(
        "--mode",
        choices=["linux", "windows", "full", "custom"],
        required=True,
        help="Validation profile to use.",
    )
    parser.add_argument(
        "--expected",
        default="",
        help="Comma-separated expected IDs when mode=custom.",
    )
    parser.add_argument(
        "--agent",
        default="",
        help="Optional filter on alert.agent.name.",
    )
    parser.add_argument(
        "--since-minutes",
        type=int,
        default=30,
        help="Only include alerts newer than now - N minutes (default: 30).",
    )
    parser.add_argument(
        "--container",
        default="",
        help="Optional Wazuh manager container name to read alerts via docker exec.",
    )
    parser.add_argument(
        "--alerts-file",
        default="/var/ossec/logs/alerts/alerts.json",
        help="Alert file path (inside container or local filesystem).",
    )
    parser.add_argument(
        "--tail-lines",
        type=int,
        default=50000,
        help="Number of trailing alert lines to inspect (default: 50000).",
    )
    return parser.parse_args()


def parse_iso8601(raw: str) -> Optional[datetime]:
    raw = (raw or "").strip()
    if not raw:
        return None

    candidates = [raw]
    if raw.endswith("Z"):
        candidates.append(raw[:-1] + "+00:00")

    if len(raw) >= 5 and raw[-5] in ("+", "-") and raw[-3] != ":":
        candidates.append(raw[:-2] + ":" + raw[-2:])

    for candidate in candidates:
        try:
            dt = datetime.fromisoformat(candidate)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue

    return None


def read_tail_local(path: Path, tail_lines: int) -> List[str]:
    queue: deque[str] = deque(maxlen=tail_lines)
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            queue.append(line)
    return list(queue)


def read_tail_container(container: str, alerts_file: str, tail_lines: int) -> List[str]:
    cmd = [
        "docker",
        "exec",
        container,
        "sh",
        "-lc",
        f"tail -n {tail_lines} {alerts_file}",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(
            "Unable to read alerts from container. "
            f"docker exit code={result.returncode}, stderr={result.stderr.strip()}"
        )
    return result.stdout.splitlines()


def iter_alert_objects(lines: Iterable[str]) -> Iterable[Dict]:
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        if isinstance(data, dict):
            yield data


def resolve_expected_ids(mode: str, custom_expected: str) -> Set[str]:
    if mode == "linux":
        return set(EXPECTED_RULES["linux"])
    if mode == "windows":
        return set(EXPECTED_RULES["windows"])
    if mode == "full":
        return set(EXPECTED_RULES["linux"]) | set(EXPECTED_RULES["windows"])

    items = [item.strip() for item in custom_expected.split(",") if item.strip()]
    if not items:
        raise ValueError("mode=custom requires --expected")
    return set(items)


def main() -> int:
    args = parse_args()

    try:
        expected_ids = resolve_expected_ids(args.mode, args.expected)
    except ValueError as exc:
        print(f"[ERROR] {exc}")
        return 1

    if args.container:
        lines = read_tail_container(args.container, args.alerts_file, args.tail_lines)
        source_label = f"container={args.container}, file={args.alerts_file}"
    else:
        alerts_path = Path(args.alerts_file)
        if not alerts_path.is_file():
            print(f"[ERROR] Alerts file not found: {alerts_path}")
            return 1
        lines = read_tail_local(alerts_path, args.tail_lines)
        source_label = f"file={alerts_path}"

    now_utc = datetime.now(timezone.utc)
    cutoff = now_utc - timedelta(minutes=max(0, args.since_minutes))

    found_ids: Set[str] = set()
    first_seen: Dict[str, Tuple[str, str]] = {}
    inspected = 0
    matched_time_window = 0

    for alert in iter_alert_objects(lines):
        inspected += 1

        ts = parse_iso8601(str(alert.get("timestamp", "")))
        if ts is None or ts < cutoff:
            continue

        matched_time_window += 1

        if args.agent:
            agent_name = str(alert.get("agent", {}).get("name", "")).strip()
            if agent_name != args.agent:
                continue

        rule_id = str(alert.get("rule", {}).get("id", "")).strip()
        if not rule_id:
            continue

        if rule_id in expected_ids:
            found_ids.add(rule_id)
            if rule_id not in first_seen:
                timestamp = str(alert.get("timestamp", ""))
                agent_name = str(alert.get("agent", {}).get("name", ""))
                first_seen[rule_id] = (timestamp, agent_name)

    missing_ids = sorted(expected_ids - found_ids, key=lambda x: int(x))
    present_ids = sorted(found_ids, key=lambda x: int(x))

    print("[INFO ] PHASE4 rule.id validation")
    print(f"[INFO ] Source: {source_label}")
    print(f"[INFO ] Mode: {args.mode}")
    print(f"[INFO ] Agent filter: {args.agent or 'none'}")
    print(f"[INFO ] Time window: last {args.since_minutes} minutes")
    print(f"[INFO ] Parsed alerts: {inspected}")
    print(f"[INFO ] Alerts in time window: {matched_time_window}")
    print("")

    print("[INFO ] Present expected IDs:")
    if present_ids:
        for rule_id in present_ids:
            ts, agent_name = first_seen.get(rule_id, ("", ""))
            print(f"- {rule_id} (first_seen={ts}, agent={agent_name})")
    else:
        print("- none")

    print("")
    print("[INFO ] Missing expected IDs:")
    if missing_ids:
        for rule_id in missing_ids:
            print(f"- {rule_id}")
    else:
        print("- none")

    print("")
    if missing_ids:
        print("[FAIL ] Some expected rule.id values were not observed.")
        return 2

    print("[PASS ] All expected rule.id values were observed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
