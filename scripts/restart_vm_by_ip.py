from __future__ import annotations

import argparse
import subprocess
import sys


def build_remote_script(guest_ip: str, vm_name: str) -> str:
    if vm_name:
        return (
            "set -eu\n"
            f"domain={quote_shell(vm_name)}\n"
            "if ! command -v virsh >/dev/null 2>&1; then echo 'virsh not found on host.'; exit 3; fi\n"
            "state=$(virsh domstate \"$domain\" 2>/dev/null || true)\n"
            "if [ -z \"$state\" ]; then echo \"VM not found: $domain\"; exit 2; fi\n"
            "echo \"Matched VM: $domain\"\n"
            "echo \"Current state: $state\"\n"
            "if printf '%s' \"$state\" | grep -iq running; then\n"
            "  echo \"Issuing virsh reboot $domain\"\n"
            "  virsh reboot \"$domain\" || { echo 'virsh reboot failed, trying destroy/start'; virsh destroy \"$domain\"; sleep 2; virsh start \"$domain\"; }\n"
            "else\n"
            "  echo \"VM not running, starting $domain\"\n"
            "  virsh start \"$domain\"\n"
            "fi\n"
        )

    return (
        "set -eu\n"
        f"target_ip={quote_shell(guest_ip)}\n"
        "if ! command -v virsh >/dev/null 2>&1; then echo 'virsh not found on host.'; exit 3; fi\n"
        "domain=''\n"
        "for candidate in $(virsh list --all --name); do\n"
        "  [ -n \"$candidate\" ] || continue\n"
        "  if virsh domifaddr \"$candidate\" 2>/dev/null | grep -Fq \"$target_ip\"; then domain=\"$candidate\"; break; fi\n"
        "  if virsh domifaddr \"$candidate\" --source agent 2>/dev/null | grep -Fq \"$target_ip\"; then domain=\"$candidate\"; break; fi\n"
        "done\n"
        "if [ -z \"$domain\" ]; then echo \"No VM matched guest IP $target_ip\"; exit 2; fi\n"
        "state=$(virsh domstate \"$domain\" 2>/dev/null || true)\n"
        "echo \"Matched VM: $domain\"\n"
        "echo \"Current state: $state\"\n"
        "if printf '%s' \"$state\" | grep -iq running; then\n"
        "  echo \"Issuing virsh reboot $domain\"\n"
        "  virsh reboot \"$domain\" || { echo 'virsh reboot failed, trying destroy/start'; virsh destroy \"$domain\"; sleep 2; virsh start \"$domain\"; }\n"
        "else\n"
        "  echo \"VM not running, starting $domain\"\n"
        "  virsh start \"$domain\"\n"
        "fi\n"
    )


def quote_shell(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def main() -> int:
    parser = argparse.ArgumentParser(description="Restart or start a libvirt VM by guest IP or VM name")
    parser.add_argument("--host", required=True, help="Virtualization host IP or hostname")
    parser.add_argument("--user", required=True, help="SSH username on the virtualization host")
    parser.add_argument("--guest-ip", default="", help="Guest IP used to locate the VM")
    parser.add_argument("--vm-name", default="", help="Optional explicit VM name")
    parser.add_argument("--connect-timeout", type=int, default=5, help="SSH connect timeout in seconds")
    args = parser.parse_args()

    if not args.guest_ip and not args.vm_name:
        print("Either --guest-ip or --vm-name must be provided.", file=sys.stderr)
        return 2

    remote_script = build_remote_script(args.guest_ip, args.vm_name)
    remote_command = f"bash -lc {quote_shell(remote_script)}"
    command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={max(1, args.connect_timeout)}",
        f"{args.user}@{args.host}",
        remote_command,
    ]

    completed = subprocess.run(command, capture_output=True, text=True)
    if completed.stdout:
        print(completed.stdout.strip())
    if completed.stderr:
        print(completed.stderr.strip(), file=sys.stderr)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
