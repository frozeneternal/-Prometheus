from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import paramiko


DEFAULT_LOOPBACK_LISTEN = "127.0.0.1:9100"
DEFAULT_DIRECT_LISTEN = "0.0.0.0:9100"
NODE_EXPORTER_BINARIES = (
    "$HOME/.local/bin/node_exporter",
    "/usr/local/bin/node_exporter",
    "/usr/bin/node_exporter",
)


@dataclass(frozen=True)
class Target:
    name: str
    ip: str
    role: str
    has_tunnel: bool


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def tunnel_hosts(path: Path | None) -> set[str]:
    if path is None or not path.exists():
        return set()
    payload = load_json(path)
    hosts = set()
    for tunnel in payload.get("tunnels") or []:
        if isinstance(tunnel, dict) and tunnel.get("enabled", True) is not False:
            host = str(tunnel.get("sshHost") or "").strip()
            if host:
                hosts.add(host)
    return hosts


def linux_targets(targets_path: Path, tunnels_path: Path | None, host_filter: str = "") -> list[Target]:
    payload = load_json(targets_path)
    tunnels = tunnel_hosts(tunnels_path)
    host_filter = host_filter.lower().strip()
    targets = []
    for item in payload.get("servers") or []:
        if not isinstance(item, dict) or str(item.get("os") or "").lower() != "linux":
            continue
        ip = str(item.get("ip") or "").strip()
        name = str(item.get("name") or ip).strip() or ip
        role = str(item.get("role") or "").strip()
        if not ip:
            continue
        if host_filter and host_filter not in ip.lower() and host_filter not in name.lower():
            continue
        targets.append(Target(name=name, ip=ip, role=role, has_tunnel=ip in tunnels))
    return targets


def run_ssh(client: paramiko.SSHClient, command: str, timeout: float = 12.0) -> tuple[int, str, str]:
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    try:
        stdin.close()
    except OSError:
        pass
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    return stdout.channel.recv_exit_status(), out, err


def connect(host: str, port: int, username: str, password: str, timeout: float) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        banner_timeout=timeout,
        auth_timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def find_binary(client: paramiko.SSHClient) -> str:
    probes = " ".join(shlex.quote(path) for path in NODE_EXPORTER_BINARIES)
    command = (
        "for path in "
        + probes
        + '; do expanded=$(eval echo "$path"); if [ -x "$expanded" ]; then printf "%s" "$expanded"; exit 0; fi; done; exit 1'
    )
    code, out, _err = run_ssh(client, command)
    return out if code == 0 else ""


def loopback_metrics_ok(client: paramiko.SSHClient) -> bool:
    code, out, _err = run_ssh(
        client,
        "curl -fsS --max-time 3 http://127.0.0.1:9100/metrics >/dev/null && echo metrics_ok || echo metrics_failed",
        timeout=8.0,
    )
    return code == 0 and out.strip().endswith("metrics_ok")


def wait_for_metrics(client: paramiko.SSHClient, timeout: float) -> bool:
    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        if loopback_metrics_ok(client):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(1.0)


def listener_summary(client: paramiko.SSHClient) -> str:
    _code, out, _err = run_ssh(client, "ss -ltnp 2>/dev/null | grep ':9100' || true")
    return out


def linger_status(client: paramiko.SSHClient) -> str:
    _code, out, _err = run_ssh(client, "loginctl show-user $(id -un) -p Linger --value 2>/dev/null || echo unknown")
    return out or "unknown"


def systemd_user_active(client: paramiko.SSHClient) -> str:
    _code, out, _err = run_ssh(client, "systemctl --user is-active node_exporter 2>/dev/null || true")
    return out or "unknown"


def shell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def install_user_service(client: paramiko.SSHClient, binary: str, listen_address: str) -> tuple[bool, str]:
    service = f"""[Unit]
Description=User node_exporter for ops monitor

[Service]
ExecStart={binary} --web.listen-address={listen_address}
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
"""
    command = (
        "mkdir -p ~/.config/systemd/user ~/.local/state/node_exporter && "
        f"cat > ~/.config/systemd/user/node_exporter.service <<'EOF'\n{service}EOF\n"
        "systemctl --user daemon-reload && "
        "systemctl --user enable --now node_exporter"
    )
    code, out, err = run_ssh(client, command, timeout=20.0)
    return code == 0, (out or err)


def install_crontab_fallback(client: paramiko.SSHClient, binary: str, listen_address: str) -> tuple[bool, str]:
    quoted_binary = shell_single_quote(binary)
    quoted_listen = shell_single_quote(listen_address)
    command = f"""
mkdir -p ~/.local/state/node_exporter
if ! ss -ltn 2>/dev/null | awk '{{print $4}}' | grep -Eq '(^|:)9100$'; then
  nohup {quoted_binary} --web.listen-address={quoted_listen} > ~/.local/state/node_exporter/node_exporter.out.log 2> ~/.local/state/node_exporter/node_exporter.err.log < /dev/null &
fi
( crontab -l 2>/dev/null | grep -v 'ops-monitor-node-exporter' ; echo "@reboot {binary} --web.listen-address={listen_address} >> ~/.local/state/node_exporter/node_exporter.out.log 2>> ~/.local/state/node_exporter/node_exporter.err.log # ops-monitor-node-exporter" ) | crontab -
"""
    code, out, err = run_ssh(client, command, timeout=20.0)
    return code == 0, (out or err)


def inspect_or_apply(
    target: Target,
    *,
    username: str,
    password: str,
    ssh_port: int,
    timeout: float,
    apply: bool,
    listen_address: str,
    verify_timeout: float,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "name": target.name,
        "ip": target.ip,
        "role": target.role,
        "hasTunnel": target.has_tunnel,
        "listenAddress": listen_address,
        "plan_only": not apply,
        "status": "unknown",
        "changed": False,
        "message": "",
    }
    try:
        client = connect(target.ip, ssh_port, username, password, timeout)
    except Exception as exc:  # noqa: BLE001 - inventory diagnostics must continue per host.
        record["status"] = "ssh_unreachable"
        record["message"] = str(exc)
        return record

    try:
        binary = find_binary(client)
        record["binary"] = binary
        record["listener"] = listener_summary(client)
        record["systemdUser"] = systemd_user_active(client)
        record["linger"] = linger_status(client)

        if loopback_metrics_ok(client):
            record["status"] = "healthy"
            record["message"] = "node_exporter already returns metrics on loopback."
            return record

        if not binary:
            record["status"] = "missing_binary"
            record["message"] = "node_exporter binary was not found in known safe paths."
            return record

        if not apply:
            record["status"] = "planned"
            record["message"] = "Run again with -Apply to create a user-level node_exporter service or crontab fallback."
            return record

        service_ok, service_detail = install_user_service(client, binary, listen_address)
        record["systemdUserInstall"] = service_detail
        if not service_ok:
            fallback_ok, fallback_detail = install_crontab_fallback(client, binary, listen_address)
            record["crontabFallbackInstall"] = fallback_detail
            if not fallback_ok:
                record["status"] = "apply_failed"
                record["message"] = "Both user systemd and crontab fallback failed."
                return record

        record["changed"] = True
        if wait_for_metrics(client, verify_timeout):
            record["status"] = "healthy"
            record["message"] = "node_exporter is running after apply."
        else:
            record["status"] = "apply_unverified"
            record["message"] = "Apply ran but loopback metrics did not verify."
        record["listener"] = listener_summary(client)
        record["systemdUser"] = systemd_user_active(client)
        record["linger"] = linger_status(client)
        return record
    finally:
        client.close()


def print_text(records: list[dict[str, Any]]) -> None:
    for record in records:
        changed = "changed" if record.get("changed") else "no-change"
        print(
            f"{record.get('ip')} {record.get('name')} "
            f"status={record.get('status')} mode={'plan' if record.get('plan_only') else 'apply'} "
            f"{changed} listen={record.get('listenAddress')} message={record.get('message')}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Safely plan or apply user-level Linux node_exporter startup.")
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--tunnels", type=Path)
    parser.add_argument("--host-filter", default="")
    parser.add_argument("--listen-address", default="")
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--verify-timeout", type=float, default=15.0)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    username = os.environ.get("OPS_SSH_USER", "")
    password = os.environ.get("OPS_SSH_PASSWORD", "")
    if not username or not password:
        raise SystemExit("OPS_SSH_USER and OPS_SSH_PASSWORD are required.")

    records = []
    for target in linux_targets(args.targets, args.tunnels, args.host_filter):
        listen_address = args.listen_address or (DEFAULT_LOOPBACK_LISTEN if target.has_tunnel else DEFAULT_DIRECT_LISTEN)
        records.append(
            inspect_or_apply(
                target,
                username=username,
                password=password,
                ssh_port=args.ssh_port,
                timeout=args.timeout,
                apply=args.apply,
                listen_address=listen_address,
                verify_timeout=args.verify_timeout,
            )
        )

    if args.json:
        print(json.dumps(records, ensure_ascii=False, indent=2))
    else:
        print_text(records)

    return 1 if any(record.get("status") in {"ssh_unreachable", "apply_failed", "apply_unverified"} for record in records) else 0


if __name__ == "__main__":
    raise SystemExit(main())
