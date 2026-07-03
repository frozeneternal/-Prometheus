from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "servers.json"
LOCAL_CONFIG_PATH = ROOT / "config" / "servers.local.json"
OUTPUT_PATH = ROOT / "prometheus" / "prometheus.yml"


def load_config(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def default_config_path() -> Path:
    return LOCAL_CONFIG_PATH if LOCAL_CONFIG_PATH.exists() else CONFIG_PATH


def yaml_quote(value: object) -> str:
    text = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def server_targets(config: dict) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    for server in config.get("servers", []):
        labels = server.get("labels") or {}
        instance = labels.get("instance")
        if not instance:
            continue
        role = str(server.get("type") or "server")
        groups.setdefault(role, []).append(str(instance))
    return groups


def website_targets(config: dict) -> list[str]:
    targets = []
    for website in config.get("websites", []):
        url = website.get("url")
        if url:
            targets.append(str(url))
    return targets


def render(config: dict) -> str:
    lines = [
        "global:",
        "  scrape_interval: 15s",
        "  evaluation_interval: 15s",
        "",
        "scrape_configs:",
        "  - job_name: prometheus",
        "    static_configs:",
        "      - targets:",
        "          - 127.0.0.1:9090",
        "",
        "  - job_name: node",
        "    static_configs:",
    ]

    targets_by_role = server_targets(config)
    if targets_by_role:
        for role, targets in sorted(targets_by_role.items()):
            lines.append("      - targets:")
            for target in sorted(set(targets)):
                lines.append(f"          - {target}")
            lines.extend(
                [
                    "        labels:",
                    f"          role: {yaml_quote(role)}",
                ]
            )
    else:
        lines.extend(
            [
                "      - targets:",
                "          - 127.0.0.1:9100",
                "        labels:",
                '          role: "example"',
            ]
        )

    websites = sorted(set(website_targets(config)))
    lines.extend(
        [
            "",
            "  - job_name: blackbox",
            "    metrics_path: /probe",
            "    params:",
            "      module:",
            "        - http_2xx",
            "    static_configs:",
            "      - targets:",
        ]
    )
    if websites:
        for target in websites:
            lines.append(f"          - {target}")
    else:
        lines.append("          - https://example.com")

    lines.extend(
        [
            "    relabel_configs:",
            "      - source_labels:",
            "          - __address__",
            "        target_label: __param_target",
            "      - source_labels:",
            "          - __param_target",
            "        target_label: instance",
            "      - target_label: __address__",
            "        replacement: blackbox:9115",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Render prometheus/prometheus.yml from the active monitor config")
    parser.add_argument("--config", type=Path, default=default_config_path())
    parser.add_argument("--output", type=Path, default=OUTPUT_PATH)
    parser.add_argument("--check", action="store_true", help="Exit non-zero if the output file differs")
    args = parser.parse_args()

    print(f"Using config {args.config}")
    content = render(load_config(args.config))
    if args.check:
        existing = args.output.read_text(encoding="utf-8") if args.output.exists() else ""
        if existing.replace("\r\n", "\n").rstrip("\n") != content.rstrip("\n"):
            print(f"{args.output} is out of date.")
            return 1
        print(f"{args.output} is up to date.")
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(content, encoding="utf-8")
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
