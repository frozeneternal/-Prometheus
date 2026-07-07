# Standalone Prometheus + Grafana Stack

This folder contains public-safe templates for a local Windows-based
Prometheus + Grafana stack. The private runtime installation can live outside
the repository, for example under `E:\ops-monitor`.

Safety rules:

- Do not store SSH passwords in repository files.
- Keep private target inventories in `E:\ops-monitor\config\targets.local.json`.
- The stop script only stops processes whose executable path is under the
  configured standalone root.
- The stack uses native Windows processes and does not require containers.
- Remote exporter installation should be done as a separate, audited step.

Typical runtime layout:

```text
E:\ops-monitor
  apps\
    grafana\
    prometheus\
    windows_exporter\
  config\
    prometheus.yml
    targets.local.json
    grafana-custom.ini
  data\
  logs\
  run\
  scripts\
```

Common commands:

```powershell
powershell -ExecutionPolicy Bypass -File E:\ops-monitor\scripts\start-local-monitor.ps1
powershell -ExecutionPolicy Bypass -File E:\ops-monitor\scripts\status-local-monitor.ps1
powershell -ExecutionPolicy Bypass -File E:\ops-monitor\scripts\stop-local-monitor.ps1
```

SSH tunnel commands for hosts where exporter ports are blocked:

```powershell
$env:OPS_SSH_USER = "<private user>"
$env:OPS_SSH_PASSWORD = "<private password>"
powershell -ExecutionPolicy Bypass -File E:\ops-monitor\scripts\start-ssh-tunnels.ps1
powershell -ExecutionPolicy Bypass -File E:\ops-monitor\scripts\stop-ssh-tunnels.ps1
```

Prometheus should scrape the tunnel listeners as `127.0.0.1:19xxx` targets.
This avoids opening remote firewall ports while keeping metrics collection
centralized.

Default local endpoints:

- Grafana: `http://127.0.0.1:3000`
- Prometheus: `http://127.0.0.1:19090`
- Local Windows exporter: `http://127.0.0.1:9182/metrics`
