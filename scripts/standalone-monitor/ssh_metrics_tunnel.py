from __future__ import annotations

import argparse
import json
import os
import select
import socket
import socketserver
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import paramiko


BUFFER_SIZE = 65536
CONNECT_RETRY_SECONDS = 10


@dataclass(frozen=True)
class TunnelConfig:
    name: str
    ssh_host: str
    ssh_port: int
    local_host: str
    local_port: int
    remote_host: str
    remote_port: int


class TunnelForwarder(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, tunnel: TunnelConfig, username: str, password: str):
        self.tunnel = tunnel
        self.username = username
        self.password = password
        self._ssh_client: paramiko.SSHClient | None = None
        self._ssh_lock = threading.Lock()
        super().__init__((tunnel.local_host, tunnel.local_port), TunnelHandler)

    def ssh_client(self) -> paramiko.SSHClient:
        with self._ssh_lock:
            if self._ssh_client and self._ssh_client.get_transport() and self._ssh_client.get_transport().is_active():
                return self._ssh_client

            if self._ssh_client:
                self._ssh_client.close()

            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                self.tunnel.ssh_host,
                port=self.tunnel.ssh_port,
                username=self.username,
                password=self.password,
                timeout=8,
                banner_timeout=8,
                auth_timeout=8,
                look_for_keys=False,
                allow_agent=False,
            )
            self._ssh_client = client
            return client

    def close(self) -> None:
        if self._ssh_client:
            self._ssh_client.close()
        self.server_close()


class TunnelHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: TunnelForwarder = self.server  # type: ignore[assignment]
        tunnel = server.tunnel
        try:
            transport = server.ssh_client().get_transport()
            if transport is None or not transport.is_active():
                raise RuntimeError("SSH transport is not active")
            channel = transport.open_channel(
                "direct-tcpip",
                (tunnel.remote_host, tunnel.remote_port),
                self.request.getpeername(),
            )
        except Exception as exc:
            print(f"[{tunnel.name}] failed to open SSH channel: {exc}", flush=True)
            return

        try:
            proxy(self.request, channel)
        finally:
            channel.close()


def proxy(local_sock: socket.socket, remote_channel: paramiko.Channel) -> None:
    sockets = [local_sock, remote_channel]
    while True:
        readable, _, _ = select.select(sockets, [], [], 30)
        if not readable:
            continue
        for sock in readable:
            data = sock.recv(BUFFER_SIZE)
            if not data:
                return
            if sock is local_sock:
                remote_channel.sendall(data)
            else:
                local_sock.sendall(data)


def read_tunnels(path: Path) -> list[TunnelConfig]:
    raw = json.loads(path.read_text(encoding="utf-8-sig"))
    tunnels: list[TunnelConfig] = []
    for item in raw.get("tunnels", []):
        if item.get("enabled") is False:
            continue
        tunnels.append(
            TunnelConfig(
                name=str(item["name"]),
                ssh_host=str(item["sshHost"]),
                ssh_port=int(item.get("sshPort", 22)),
                local_host=str(item.get("localHost", "127.0.0.1")),
                local_port=int(item["localPort"]),
                remote_host=str(item.get("remoteHost", "127.0.0.1")),
                remote_port=int(item.get("remotePort", 9100)),
            )
        )
    return tunnels


def serve(config_path: Path, username: str, password: str) -> int:
    tunnels = read_tunnels(config_path)
    if not tunnels:
        print("No enabled tunnels found.", flush=True)
        return 2

    servers: list[TunnelForwarder] = []
    try:
        for tunnel in tunnels:
            if tunnel.local_host != "127.0.0.1":
                raise ValueError(f"{tunnel.name}: localHost must be 127.0.0.1")
            server = TunnelForwarder(tunnel, username, password)
            thread = threading.Thread(target=server.serve_forever, name=f"tunnel-{tunnel.name}", daemon=True)
            thread.start()
            servers.append(server)
            print(
                f"[{tunnel.name}] 127.0.0.1:{tunnel.local_port} -> "
                f"{tunnel.ssh_host}:{tunnel.ssh_port} -> {tunnel.remote_host}:{tunnel.remote_port}",
                flush=True,
            )
        while True:
            time.sleep(CONNECT_RETRY_SECONDS)
    finally:
        for server in servers:
            server.close()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Forward local Prometheus scrapes through SSH.")
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args()

    username = os.environ.get("OPS_SSH_USER", "")
    password = os.environ.get("OPS_SSH_PASSWORD", "")
    if not username or not password:
        print("OPS_SSH_USER and OPS_SSH_PASSWORD must be set in the process environment.", file=sys.stderr)
        return 2

    return serve(args.config, username, password)


if __name__ == "__main__":
    raise SystemExit(main())
