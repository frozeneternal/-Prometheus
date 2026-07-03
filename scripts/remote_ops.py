from __future__ import annotations

import argparse
import shlex
import subprocess
import sys


def quote_shell(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def ssh_base(user: str, host: str, connect_timeout: int) -> list[str]:
    return [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={max(1, connect_timeout)}",
        f"{user}@{host}",
    ]


def remote_script_for_action(args: argparse.Namespace) -> str:
    if args.action == "service-restart":
        services = [item for item in args.service if item]
        if not services:
            raise ValueError("--service is required for service-restart")
        service_list = " ".join(quote_shell(item) for item in services)
        return (
            "set -eu\n"
            f"for service in {service_list}; do\n"
            "  if systemctl list-unit-files \"$service.service\" >/dev/null 2>&1 || systemctl status \"$service\" >/dev/null 2>&1; then\n"
            "    echo \"Restarting service: $service\"\n"
            "    sudo systemctl restart \"$service\"\n"
            "    sudo systemctl --no-pager --full status \"$service\" | sed -n '1,18p' || true\n"
            "    exit 0\n"
            "  fi\n"
            "done\n"
            f"echo \"No matching service found: {', '.join(services)}\" >&2\n"
            "exit 3\n"
        )

    if args.action == "service-status":
        if not args.service:
            raise ValueError("--service is required for service-status")
        service_list = " ".join(quote_shell(item) for item in args.service)
        return (
            "set -u\n"
            f"for service in {service_list}; do\n"
            "  echo \"===== $service =====\"\n"
            "  sudo systemctl --no-pager --full status \"$service\" | sed -n '1,40p' || true\n"
            "done\n"
        )

    if args.action == "certbot-renew":
        post_hook = ""
        if args.reload_service:
            post_hook = " --post-hook " + quote_shell(f"systemctl reload {args.reload_service}")
        return (
            "set -eu\n"
            "if ! command -v certbot >/dev/null 2>&1; then echo 'certbot not found.' >&2; exit 3; fi\n"
            f"sudo certbot renew --quiet{post_hook}\n"
        )

    if args.action == "acme-renew":
        if not args.domain:
            raise ValueError("--domain is required for acme-renew")
        reload_cmd = f" --reloadcmd {quote_shell('systemctl reload ' + args.reload_service)}" if args.reload_service else ""
        return (
            "set -eu\n"
            "if [ ! -x \"$HOME/.acme.sh/acme.sh\" ]; then echo 'acme.sh not found.' >&2; exit 3; fi\n"
            f"\"$HOME/.acme.sh/acme.sh\" --renew -d {quote_shell(args.domain)}{reload_cmd}\n"
        )

    if args.action == "reboot":
        return "set -eu\necho 'Rebooting host.'\nsudo systemctl reboot\n"

    raise ValueError(f"Unsupported action: {args.action}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run safe remote operations over SSH for the monitor console")
    parser.add_argument("--host", required=True, help="Remote host IP or DNS name")
    parser.add_argument("--user", required=True, help="Remote SSH user")
    parser.add_argument("--action", required=True, choices=["service-restart", "service-status", "certbot-renew", "acme-renew", "reboot"])
    parser.add_argument("--service", action="append", default=[], help="Service name. Repeat to try multiple names.")
    parser.add_argument("--reload-service", default="", help="Service to reload after certificate renewal")
    parser.add_argument("--domain", default="", help="Domain name for acme.sh renewal")
    parser.add_argument("--connect-timeout", type=int, default=5)
    parser.add_argument("--dry-run", action="store_true", help="Print the SSH command without running it")
    args = parser.parse_args()

    try:
        script = remote_script_for_action(args)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    command = ssh_base(args.user, args.host, args.connect_timeout) + ["bash -lc " + quote_shell(script)]
    if args.dry_run:
        print(shlex.join(command))
        return 0

    completed = subprocess.run(command, capture_output=True, text=True)
    if completed.stdout:
        print(completed.stdout.strip())
    if completed.stderr:
        print(completed.stderr.strip(), file=sys.stderr)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
