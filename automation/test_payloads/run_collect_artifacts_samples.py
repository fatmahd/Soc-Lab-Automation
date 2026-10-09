#!/usr/bin/env python3

import json
import sys
import types
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

try:
    import requests as _requests  # noqa: F401
except ModuleNotFoundError:
    # collect_artifacts does not use requests, but the main module imports it.
    sys.modules["requests"] = types.SimpleNamespace(
        RequestException=Exception,
        post=None,
    )

from wazuh_to_thehive import collect_artifacts


def main() -> int:
    samples_dir = Path(__file__).resolve().parent
    sample_files = sorted(samples_dir.glob("*.json"))

    if not sample_files:
        print("No sample JSON files found in test_payloads directory.")
        return 1

    for sample_file in sample_files:
        with sample_file.open("r", encoding="utf-8") as handle:
            alert = json.load(handle)

        artifacts = collect_artifacts(alert)
        artifacts = sorted(
            artifacts,
            key=lambda item: (item.get("dataType", ""), item.get("data", "")),
        )

        print("=" * 90)
        print(f"Sample: {sample_file.name}")
        print(f"Extracted observables: {len(artifacts)}")

        for item in artifacts:
            dtype = item.get("dataType", "")
            value = item.get("data", "")
            tags = ", ".join(item.get("tags", []))
            print(f"- {dtype:11} | {value} | {tags}")

        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
