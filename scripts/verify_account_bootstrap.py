from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ACTION_TOKEN = "bootstrap-verification-token"
ADMIN_USERNAME = "bootstrap-admin"
ADMIN_PASSWORD = "BootstrapPass-2026"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request_json(base_url: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
    data = None
    headers = {"Accept": "application/json"}
    method = "GET"
    if payload is not None:
        method = "POST"
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(f"{base_url}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            body = response.read().decode("utf-8")
            return response.status, json.loads(body or "{}")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            payload_body = json.loads(body or "{}")
        except json.JSONDecodeError:
            payload_body = {"ok": False, "message": body}
        return exc.code, payload_body


def wait_for_dashboard(base_url: str, process: subprocess.Popen, timeout_seconds: float = 25.0) -> dict:
    deadline = time.time() + timeout_seconds
    last_error = ""
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"verification server exited early with code {process.returncode}")
        try:
            status, payload = request_json(base_url, "/api/dashboard")
            if status == 200 and payload.get("ok") is True:
                return payload
            last_error = f"HTTP {status}: {payload.get('message') or payload}"
        except (OSError, urllib.error.URLError) as exc:
            last_error = str(exc)
        time.sleep(0.25)
    raise RuntimeError(f"verification server did not become ready: {last_error}")


def write_temp_config(config_path: Path) -> None:
    config = {
        "appName": "Account Bootstrap Verifier",
        "listenHost": "127.0.0.1",
        "listenPort": 0,
        "prometheusUrl": "http://127.0.0.1:1",
        "actionToken": ACTION_TOKEN,
        "sessionSecret": "",
        "authPolicy": {
            "maxLoginFailures": 5,
            "failureWindowSeconds": 300,
            "lockoutSeconds": 900,
            "passwordMinLength": 8,
        },
        "monitoring": {
            "pollIntervalSeconds": 30,
            "recoveryLogLimit": 50,
            "incidentLogLimit": 50,
            "resourceExpiryWarningDays": 30,
            "resourceExpiryCriticalDays": 7,
            "resourceAckMaxDays": 7,
        },
        "servers": [],
        "websites": [],
        "resources": [],
        "users": [],
    }
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def tail(path: Path, limit: int = 4000) -> str:
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8", errors="replace")
    return text[-limit:]


def verify_bootstrap_flow(base_url: str, temp_config_path: Path, process: subprocess.Popen) -> None:
    dashboard = wait_for_dashboard(base_url, process)
    account_security = dashboard.get("accountSecurity") or {}
    if account_security.get("requiresBootstrapAdmin") is not True:
        raise RuntimeError("dashboard did not report first-admin bootstrap requirement")
    print("dashboard ready; first-admin bootstrap is required")

    status, payload = request_json(
        base_url,
        "/api/auth/users/upsert",
        {
            "token": ACTION_TOKEN,
            "username": ADMIN_USERNAME,
            "displayName": "Bootstrap Admin",
            "role": "admin",
            "enabled": True,
            "password": ADMIN_PASSWORD,
        },
    )
    if status != 200 or payload.get("ok") is not True:
        raise RuntimeError(f"admin bootstrap failed: HTTP {status} {payload.get('message') or payload}")
    print("first admin account created")

    status, payload = request_json(
        base_url,
        "/api/auth/login",
        {"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
    )
    session_token = str(payload.get("sessionToken") or "")
    if status != 200 or payload.get("ok") is not True or not session_token:
        raise RuntimeError(f"admin login failed: HTTP {status} {payload.get('message') or payload}")
    print("admin login accepted")

    status, payload = request_json(base_url, "/api/auth/users", {"sessionToken": session_token})
    users = payload.get("users") or []
    if status != 200 or payload.get("ok") is not True or not any(user.get("username") == ADMIN_USERNAME for user in users):
        raise RuntimeError(f"session-auth user listing failed: HTTP {status} {payload.get('message') or payload}")
    print("session token can manage users")

    status, payload = request_json(base_url, "/api/auth/users", {"token": ACTION_TOKEN})
    if status not in {401, 403} or payload.get("ok") is not False:
        raise RuntimeError("legacy action token was not rejected after account mode enabled")
    print(f"legacy action token rejected after account mode enabled: HTTP {status}")

    saved_config = json.loads(temp_config_path.read_text(encoding="utf-8"))
    session_secret = str(saved_config.get("sessionSecret") or "")
    if len(session_secret) < 32 or session_secret == ACTION_TOKEN:
        raise RuntimeError("sessionSecret was not generated independently")
    if not any(user.get("username") == ADMIN_USERNAME for user in saved_config.get("users", [])):
        raise RuntimeError("admin user was not persisted to the isolated config")
    print("isolated config persisted with independent sessionSecret")


def run() -> None:
    with tempfile.TemporaryDirectory(prefix="ops-account-bootstrap-") as tmpdir:
        temp_root = Path(tmpdir)
        temp_config_path = temp_root / "config" / "runtime.json"
        temp_data_dir = temp_root / "data"
        stdout_path = temp_root / "server.stdout.log"
        stderr_path = temp_root / "server.stderr.log"
        write_temp_config(temp_config_path)
        port = free_port()
        base_url = f"http://127.0.0.1:{port}"

        env = os.environ.copy()
        env["OPS_MONITOR_CONFIG_PATH"] = str(temp_config_path)
        env["OPS_MONITOR_DATA_DIR"] = str(temp_data_dir)
        command = [sys.executable, str(ROOT / "app.py"), "--host", "127.0.0.1", "--port", str(port)]
        with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open("w", encoding="utf-8") as stderr:
            process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=stdout, stderr=stderr)
            try:
                verify_bootstrap_flow(base_url, temp_config_path, process)
            except Exception as exc:
                stdout.flush()
                stderr.flush()
                raise RuntimeError(
                    f"{exc}\nserver stdout:\n{tail(stdout_path)}\nserver stderr:\n{tail(stderr_path)}"
                ) from exc
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)

    print("account bootstrap verification passed")


if __name__ == "__main__":
    run()
