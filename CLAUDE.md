# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TrustRun is a network trust verification tool for HIPAA-sensitive environments. It monitors processes' network activity at runtime and statically analyzes codebases to ensure all network calls go only to authorized endpoints (e.g., BAA-covered Azure/AWS services). It is designed for medical/clinical AI teams who need to verify that no PHI/PII leaks to unauthorized destinations.

See `PRODUCT.md` for the full product specification.

## Tech Stack

- **Python 3.11+** — entire codebase
- **FastAPI** — web UI backend + WebSocket streaming for live sessions
- **SQLite** — session data, policies, scan results (via `aiosqlite`)
- **scapy** — packet capture (elevated privilege modes)
- **psutil** — process and connection enumeration (unprivileged)
- **tree-sitter** — multi-language AST parsing for static analysis
- **YAML** — policy file format (via `pyyaml`)
- **pytest** — test framework

## Build & Development Commands

```bash
# Setup
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest                          # all tests
pytest tests/unit/              # unit tests only
pytest tests/integration/       # integration tests only
pytest -x tests/unit/test_policy.py::test_allowlist_match  # single test

# Lint & format
ruff check src/                 # lint
ruff format src/                # format
mypy src/                       # type check

# Run the tool
trustrun watch <PID>            # attach to running process
trustrun run <cmd> [args...]    # launch process under monitoring
trustrun scan <directory>       # static analysis of codebase
trustrun server                 # start web UI (default: http://127.0.0.1:8470)
```

## Architecture

### Package Layout

```
src/trustrun/
├── cli/              # Click-based CLI entry points (watch, run, scan, server)
├── capture/          # Network capture abstraction layer
│   ├── base.py       # CaptureBackend protocol
│   ├── psutil_.py    # Unprivileged: poll connections via psutil
│   ├── pcap.py       # Elevated: scapy/libpcap packet capture
│   └── platform/     # macOS vs Linux specifics
├── policy/           # Policy engine
│   ├── models.py     # Policy, Rule, Action dataclasses
│   ├── loader.py     # YAML policy file parsing
│   ├── presets/      # Built-in BAA presets (azure.yaml, aws.yaml)
│   ├── evaluator.py  # Match connections against policy rules
│   └── learner.py    # Auto-learn mode: observe → build profile → approve
├── scanner/          # Static code analysis
│   ├── engine.py     # Orchestrates scan across files
│   ├── patterns.py   # Universal regex patterns (URLs, IPs, secrets)
│   └── languages/    # Language-specific analyzers (python.py, javascript.py, r.py)
├── session/          # Monitoring session lifecycle
│   ├── manager.py    # Start/stop sessions, manage capture + policy eval loop
│   └── models.py     # Session, ConnectionEvent, Violation dataclasses
├── actions/          # Response actions when violations are detected
│   ├── alert.py      # Log + notify
│   ├── block.py      # Firewall rule injection (platform-specific)
│   └── kill.py       # Process termination
├── storage/          # SQLite persistence layer
│   ├── db.py         # Connection management, migrations
│   └── repos.py      # Repository classes for sessions, policies, violations
├── web/              # FastAPI web UI
│   ├── app.py        # FastAPI application factory
│   ├── api/          # REST + WebSocket endpoints
│   └── frontend/     # Static assets (HTML/JS/CSS)
└── config.py         # Global config loading (XDG paths, env vars)
```

### Key Design Decisions

**Capture abstraction**: All network monitoring goes through the `CaptureBackend` protocol. The `psutil_` backend polls `/proc/net` or `lsof` and requires no privileges. The `pcap` backend uses scapy for real packet capture and needs root/sudo. Code should never call platform APIs directly — always go through the backend protocol.

**Policy evaluation is synchronous and hot-path**: The evaluator runs on every connection event. Keep it fast. Policies are compiled into a matcher on load, not re-parsed per event.

**Sessions own the lifecycle**: A `Session` ties together a capture backend, a policy evaluator, and an action dispatcher. The `SessionManager` is the only thing that creates sessions.

**Static analysis is separate from runtime**: The scanner has no dependency on the capture or session modules. They share only the policy models for evaluating findings against rules.

**Storage is append-mostly**: Connection events and violations are appended. Sessions and policies are created/updated. Nothing is deleted in normal operation (audit trail).

## Policy File Format

Policies are YAML files. Example:

```yaml
name: hipaa-azure-only
description: Allow only Azure BAA-covered endpoints
capture_level: metadata    # metadata | headers | full
inherit:
  - preset:azure           # built-in Azure BAA endpoints
  - preset:aws             # built-in AWS BAA endpoints
rules:
  - match: "*.openai.com"
    action: block
    reason: "Direct OpenAI API bypasses BAA"
  - match: "0.0.0.0/0"
    action: alert
    reason: "Unexpected destination"
defaults:
  action: alert            # alert | block | kill
```

## Platform-Specific Concerns

Network capture uses different mechanisms per OS. The `capture/platform/` directory contains platform-specific implementations. When adding capture features:
- macOS: `lsof -i -n -P`, BPF via scapy, `networksetup` for proxy (headers/full mode)
- Linux: `/proc/<pid>/net/tcp`, `ss -tnp`, eBPF or libpcap via scapy

Always provide both implementations behind the `CaptureBackend` protocol.

## HIPAA/Security Constraints

- **The web UI binds to 127.0.0.1 only** — never 0.0.0.0. This is not configurable by design.
- **Captured payloads (headers/full mode) may contain PHI**. They are stored in the local SQLite DB which must never be transmitted off-machine. Warn in documentation and UI.
- **No telemetry, no phoning home, no update checks**. TrustRun itself must pass its own policy.
- **Policy files may reference internal hostnames**. Treat policy YAML as sensitive — do not commit examples with real infrastructure names.
