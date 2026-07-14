# Platform Readiness Design

## Goal

Build a first-stage platform readiness layer for the local operations console. It must show which automation capabilities are implemented in code but not yet safely connected to the live environment, so operators can fix coverage gaps before enabling broader certificate renewal, resource expiry, account management, emergency response, backup, and recovery automation.

## Current Evidence

The current runtime dashboard is available at `http://127.0.0.1:8787/api/dashboard`.

Latest observed state before this design:

- Servers: 11
- Websites: 2
- Resource expiry records: 0
- Emergency items: 8 total, 3 critical
- Auto recovery summary: `attention`
- Auto backups enabled: 0
- Certificate renewals enabled: 0
- Account mode: `token`
- Target coverage: `degraded`
- Data quality: `ok`

The codebase already has domain summaries for many of these areas, but they are scattered across dashboard payload fields, notice text, panels, and Prometheus metrics. Operators need a single readiness view that tells them what is ready, what is incomplete, what is risky, and what to do next.

## Scope

This phase creates a read-only readiness view. It must not execute recovery, backup, certificate renewal, account changes, or config mutations.

In scope:

- Add a backend readiness domain module.
- Add readiness data to `/api/dashboard`.
- Add readiness metrics to `/metrics`.
- Add a frontend readiness module and visible dashboard panel.
- Add tests for backend behavior, frontend wiring, metrics, and live payload shape.
- Keep `app.py` as route/runtime glue only; new readiness logic must live under `backend/` and `public/js/`.

Out of scope for this phase:

- Enabling certificate renewal in `config/servers.local.json`.
- Creating live user accounts.
- Adding live resource expiry records.
- Starting, stopping, or restarting monitored services.
- Changing Prometheus, Grafana, Docker, scheduled tasks, or exporter configuration.
- Reworking all of `app.py`.

## Design

### Backend Domain

Create `backend/readiness.py`.

Responsibilities:

- Accept existing dashboard summaries and config state.
- Produce a stable `platformReadiness` payload.
- Classify each readiness area as `ready`, `attention`, or `blocked`.
- Provide concise operator actions for each area.
- Avoid exposing secrets, command lines, raw private host data, or token values.

Readiness areas:

- `resources`: resource expiry tracking is configured and actionable.
- `certificates`: certificate renewal coverage is configured for applicable HTTPS sites.
- `accounts`: account mode is user-based and has at least one admin/operator path.
- `backups`: backup automation or at least manual backup handling exists.
- `recovery`: automatic recovery is enabled only where data quality and action safety allow it.
- `collection`: Prometheus target coverage and target health are sufficient for automation decisions.
- `platform`: platform health has no critical local runtime risks.
- `emergency`: active emergency items are visible and actionable.

The aggregate status follows the worst area status:

- `blocked` if any area is blocked.
- `attention` if no area is blocked but any area needs attention.
- `ready` only when all areas are ready.

### Dashboard Integration

Update `backend/dashboard.py` to include:

```python
"platformReadiness": platform_readiness(...),
```

The dashboard module should assemble existing summaries and pass them into `backend.readiness`. It should not implement readiness rules inline.

### Metrics

Update `backend/metrics.py` to export readiness gauges:

- `ops_platform_readiness_status`
- `ops_platform_readiness_area_status{area="..."}`
- `ops_platform_readiness_action_required_total`

Status values:

- `ready` = 0
- `attention` = 1
- `blocked` = 2

Metrics should be derived from either the runtime dashboard snapshot or the same backend readiness helper, without exposing per-host private labels.

### Frontend

Create `public/js/readiness.js`.

Responsibilities:

- Render a `platformReadiness` panel from `state.dashboard.platformReadiness`.
- Show aggregate status, area counts, and the action list.
- Keep text concise and operational.
- Avoid adding a marketing-style layout; this is an operations dashboard.

Update `public/index.html` with a readiness section near the top of the dashboard, after the system notice and before detailed runbooks.

Update `public/js/app.js` to import and call the readiness renderer during `render()`.

Update `public/styles.css` with compact dashboard styling consistent with existing panels. Do not introduce large hero sections, decorative backgrounds, nested cards, or unrelated visual changes.

### System Notice

Keep `public/js/notices.js` focused on short global warnings. Add exactly one concise platform readiness line when the aggregate readiness status is not `ready`; the detailed action list belongs in `public/js/readiness.js`.

### Validation

Required verification for this phase:

- Focused backend readiness tests.
- Dashboard payload tests proving `platformReadiness` is present and populated.
- Metrics tests proving readiness gauges are exported.
- Frontend module tests proving the panel, renderer, import, and render call exist.
- Full test suite: `python -m unittest discover -s tests`.
- Live HTTP check for `/api/dashboard` showing `platformReadiness`.
- Live HTTP check for `/metrics` showing `ops_platform_readiness_*`.
- Live UTF-8 fetch for `/` and `/js/readiness.js` to confirm Chinese labels are served correctly.

## Acceptance Criteria

The phase is complete when:

- `/api/dashboard` contains a `platformReadiness` object with aggregate status, areas, and actions.
- The readiness panel is visible in the dashboard when data is available.
- The panel explains current gaps without requiring operators to inspect several unrelated panels.
- `/metrics` exports aggregate and per-area readiness metrics.
- No live automation actions are executed as part of rendering readiness.
- No private config values are newly exposed.
- `app.py` does not gain readiness business rules.
- All tests pass.
- The completed change is committed and pushed to `origin/master`.

## Risks And Controls

- Risk: readiness duplicates existing warning text.
  Control: put detailed guidance only in the readiness panel; keep system notice concise.

- Risk: readiness becomes a vague score.
  Control: report named areas and concrete next actions instead of a percentage.

- Risk: metrics expose private infrastructure details.
  Control: use aggregate counts and fixed area labels only.

- Risk: this phase delays actual automation.
  Control: keep it read-only and narrow; the output directly drives the next implementation phases.

## Next Phase After Approval

After this spec is reviewed, create an implementation plan with small TDD tasks:

1. Backend readiness module.
2. Dashboard payload integration.
3. Metrics export.
4. Frontend readiness module and panel.
5. Live validation and git sync.
