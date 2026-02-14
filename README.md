# TrustRun

Network trust verification for HIPAA-sensitive environments.

TrustRun monitors process network activity at runtime and statically analyzes codebases to ensure all connections go only to authorized endpoints. It's built for medical/clinical AI teams who need to verify that no PHI/PII leaks to unauthorized destinations — for example, confirming that LLM calls route through a BAA-covered Azure endpoint rather than directly to a public API.

![TrustRun interactive TUI monitoring a process](screenshot.jpg)

## How It Works

**Runtime monitoring** — Attach to a running process or launch one under supervision. TrustRun polls connections via psutil and, with elevated privileges, passively captures DNS responses and TLS SNI to resolve the actual hostnames being contacted.

**Static analysis** — Scan a codebase for hardcoded URLs, IP addresses, API keys, and SDK client configurations across Python, JavaScript, and other languages.

**Policy evaluation** — Define allowed destinations with YAML policy files. Built-in presets cover BAA-covered Azure and AWS services. Connections that don't match any allow rule are flagged as violations.

## Quick Start

```bash
# Install
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Optional: enable DNS/SNI hostname resolution (requires sudo at runtime)
pip install -e ".[capture]"
```

### Runtime Monitoring

```bash
# Launch a command under monitoring
trustrun run -- curl -s https://api.openai.com

# Attach to a running process
trustrun watch <PID>

# With elevated privileges, hostnames are resolved via DNS/SNI capture
sudo .venv/bin/trustrun run -- python my_app.py
```

### Static Analysis

```bash
# Scan a codebase for network endpoints and secrets
trustrun scan ./my-project
```

## Policy Files

Policies are YAML files that define allowed network destinations:

```yaml
name: hipaa-azure-only
description: Allow only Azure BAA-covered endpoints
inherit:
  - preset:azure
  - preset:aws
rules:
  - match: "*.openai.com"
    action: block
    reason: "Direct OpenAI API bypasses BAA"
  - match: "0.0.0.0/0"
    action: alert
    reason: "Unexpected destination"
defaults:
  action: alert
```

Apply a policy with the `--policy` flag:

```bash
trustrun run --policy policy.yaml -- python my_app.py
```

**Note:** User policy files may reference internal hostnames. They are excluded from version control via `.gitignore` — treat them as sensitive.

## Example Output

Without elevated privileges:
```
TrustRun running curl -s https://api.openai.com with policy default-alert-all
  Rules: 0, Default: alert
  DNS/SNI capture: unavailable (run with sudo for hostname resolution)

  curl -> 104.16.6.34:443 (Cloudflare) (tcp)
```

With elevated privileges:
```
TrustRun running curl -s https://api.openai.com with policy default-alert-all
  Rules: 0, Default: alert
  DNS/SNI capture: active (elevated)

  curl -> api.openai.com:443 (Cloudflare) (tcp)
```

## Architecture

```
src/trustrun/
├── cli/           # Click-based CLI (watch, run, scan, server)
├── capture/       # Network capture backends
│   ├── psutil_.py # Unprivileged: poll connections via psutil
│   ├── pcap.py    # Elevated: scapy packet capture
│   └── sniffer.py # Passive DNS/SNI hostname enrichment
├── policy/        # YAML policy engine with BAA presets
├── scanner/       # Static code analysis (Python, JS, generic)
├── session/       # Monitoring session lifecycle
├── actions/       # Violation response (alert, block, kill)
├── storage/       # SQLite persistence layer
├── tui/           # Interactive terminal UI for run/watch
└── web/           # FastAPI REST API (frontend in progress)
```

## Current Status

**Working:**
- Runtime monitoring via `trustrun run` and `trustrun watch` with interactive TUI
- Policy engine with YAML loading, preset inheritance (azure, aws), glob/CIDR matching
- Static code analysis via `trustrun scan` (Python AST + regex, JavaScript, generic patterns)
- Policy learning mode (`trustrun learn`) — observe traffic then generate a policy
- Passive DNS/SNI hostname enrichment (with elevated privileges)
- IP-to-organization resolution (built-in CIDR map, reverse DNS, whois fallback)
- Alert action on policy violations

**Not yet functional:**
- Block and kill enforcement actions (code exists but not wired to the violation handler)
- Headers/full capture levels (only metadata level is implemented)
- Web UI (API endpoints exist but CLI doesn't persist sessions to the database; frontend is a shell)
- Platform-specific capture modules (linux.py, macos.py exist but aren't used; psutil backend handles both)

## Development

```bash
# Run tests
pytest                     # all tests
pytest tests/unit/         # unit tests only

# Lint and format
ruff check src/
ruff format src/

# Type check
mypy src/
```

## Security Constraints

- The web UI binds to **127.0.0.1 only** — never 0.0.0.0.
- Captured payloads may contain PHI and are stored locally only.
- No telemetry, no phoning home, no update checks. TrustRun itself must pass its own policy.
- Policy files may reference internal hostnames — treat them as sensitive and don't commit them.

## Platform Support

| Platform | Unprivileged | Elevated (sudo) |
|----------|-------------|-----------------|
| **macOS** | psutil connection polling | DNS/SNI capture via scapy |
| **Linux** | psutil connection polling | DNS/SNI capture via scapy |

## License

MIT
