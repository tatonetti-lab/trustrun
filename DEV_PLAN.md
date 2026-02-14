# TrustRun Development Plan

Remaining work to bring TrustRun from current state to the full vision described in PRODUCT.md.

## Phase 1: Wire Up Enforcement Actions

**Goal:** Make `block` and `kill` policy actions functional.

**Current state:** `BlockAction` and `KillAction` classes are implemented but `SessionManager._handle_verdict()` always dispatches to `AlertAction` regardless of the matched rule's action.

**Tasks:**
- [ ] Modify `SessionManager.__init__()` to instantiate `BlockAction` and `KillAction`
- [ ] Update `_handle_verdict()` to dispatch to the correct action based on `verdict.action`
  - `Action.ALERT` on a default/unmatched connection → `AlertAction`
  - `Action.BLOCK` → `BlockAction.execute()`, fall back to `AlertAction` if blocking fails
  - `Action.KILL` → `KillAction.execute()` (terminates the monitored process)
- [ ] Call `BlockAction.cleanup()` in `_finalize()` to remove temporary firewall rules on session end
- [ ] Add privilege checks — warn at session start if policy contains block/kill rules but we're not running as root
- [ ] Add tests for each dispatch path
- [ ] Update TUI to display block/kill status per connection

## Phase 2: Persist Sessions to SQLite

**Goal:** CLI commands write session data to the SQLite database so the web UI (and future reporting) can read it.

**Current state:** The `storage/` module has repos for sessions, events, violations, and scans, but the CLI commands (`run`, `watch`, `scan`) never call them. Data only lives in memory during a session.

**Tasks:**
- [ ] In `cli/run.py` and `cli/watch.py`: initialize the database and create a `SessionRepo` at session start
- [ ] Wire `on_event` and `on_violation` callbacks to write to `EventRepo` and `ViolationRepo`
- [ ] Update session status in the DB on finalize (stopped, error)
- [ ] In `cli/scan.py`: persist scan results and findings to `ScanRepo`
- [ ] Add a `trustrun history` command to list past sessions from the DB
- [ ] Test that data round-trips correctly through the repos

## Phase 3: Web UI

**Goal:** A functional web interface for viewing sessions, scans, and policies.

**Current state:** FastAPI backend with REST endpoints and WebSocket streaming exists. A basic HTML/JS frontend shell (`index.html`) renders tables from the API. However, since CLI doesn't persist to SQLite (Phase 2), the API always returns empty results. No live session integration exists — WebSocket endpoint polls the DB but nothing writes to it in real-time.

**Depends on:** Phase 2 (database persistence).

**Tasks:**
- [ ] Validate that API endpoints return correct data once Phase 2 persistence is in place
- [ ] Add live session management: start/stop monitoring from the web UI
- [ ] Connect the WebSocket endpoint to stream events in real-time (either via DB polling or direct event bus)
- [ ] Build out the frontend: session detail views, scan findings with source context, policy editor
- [ ] Add basic access control (optional — currently localhost-only which provides some protection)

## Phase 4: Platform-Specific Capture Backends

**Goal:** Use native OS facilities for more efficient/complete capture.

**Current state:** `capture/platform/linux.py` and `capture/platform/macos.py` are implemented (parsing `/proc/net/tcp`, `lsof`, `ss`) but never imported or used. `PsutilCapture` is hardcoded as the only backend.

**Tasks:**
- [ ] Define a common interface (or use the existing `CaptureBackend` protocol) that the platform modules implement
- [ ] Add auto-detection: choose the best available backend for the current OS
- [ ] Wire platform backends as alternatives to `PsutilCapture` in `SessionManager`
- [ ] Benchmark: compare psutil polling vs native `/proc` parsing vs `ss` on Linux
- [ ] Test on both macOS and Linux

## Phase 5: Headers/Full Capture Levels

**Goal:** Support `headers` and `full` capture levels for HTTP inspection.

**Current state:** `CaptureLevel` enum defines `METADATA`, `HEADERS`, and `FULL`, but only metadata is implemented. No TLS interception code exists. PRODUCT.md mentions mitmproxy but it's not in dependencies.

**Tasks:**
- [ ] Evaluate mitmproxy vs custom scapy-based approach for TLS interception
- [ ] Implement a proxy-based capture backend that intercepts HTTP headers
- [ ] For `full` mode: capture request/response bodies with configurable size limits
- [ ] Add PHI warnings in the UI and logs when headers/full mode is active
- [ ] Encrypt captured payloads at rest in SQLite (they may contain PHI)
- [ ] Add `capture_level` support to the policy loader (already in the model)
- [ ] Document the setup (CA cert installation, proxy configuration)

## Phase 6: Test Coverage Gaps

**Current gaps identified:**
- [ ] `BlockAction` / `KillAction` execution paths
- [ ] `PassiveSniffer` DNS and TLS packet handling (mock scapy packets)
- [ ] Storage layer: round-trip persistence for sessions, events, violations, scans
- [ ] Web API endpoints (FastAPI TestClient)
- [ ] `PolicyLearner` export-to-YAML flow
- [ ] Integration tests: full `run`/`watch`/`scan` CLI workflows end-to-end
- [ ] Platform capture modules (`linux.py`, `macos.py`)

## Phase 7: Smaller Improvements

- [ ] **Whois timeout**: Make configurable (currently hardcoded at 2 seconds in `resolve.py`). Add retry logic or caching
- [ ] **TUI policy mutations**: When the user edits a policy in the TUI, apply it to the running session (currently only exports to a file)
- [ ] **R language analyzer**: PRODUCT.md mentions R support (`httr`, `curl` patterns) but no `languages/r.py` exists
- [ ] **tree-sitter integration**: PRODUCT.md mentions tree-sitter for AST parsing; currently using regex + Python's built-in `ast`. Evaluate whether tree-sitter adds value for JS/TS/R analysis

## Priority Order

1. **Phase 1** (enforcement actions) — highest impact, the core value proposition depends on it
2. **Phase 6** (tests) — needed to support confident changes for everything else
3. **Phase 2** (persistence) — enables the web UI and history/audit features
4. **Phase 3** (web UI) — blocked by Phase 2
5. **Phase 4** (platform backends) — performance/completeness improvement
6. **Phase 7** (smaller items) — quality of life
7. **Phase 5** (headers/full capture) — significant scope, evaluate need before starting
