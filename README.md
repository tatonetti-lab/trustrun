# TrustRun

Network trust verification for HIPAA-sensitive environments.

TrustRun monitors process network activity at runtime and statically analyzes codebases to ensure all connections go only to authorized endpoints. It's built for medical/clinical AI teams who need to verify that no PHI/PII leaks to unauthorized destinations — for example, confirming that LLM calls route through a BAA-covered Azure endpoint rather than directly to a public API.

![TrustRun interactive TUI monitoring a process](screenshot.jpg)

## How It Works

**Runtime monitoring** — Attach to a running process or launch one under supervision. TrustRun polls connections via psutil and, with elevated privileges, passively captures DNS responses and TLS SNI to resolve the actual hostnames being contacted.

**Static analysis** — Scan a codebase for hardcoded URLs, IP addresses, API keys, and SDK client configurations across Python, JavaScript, and other languages.

**Policy enforcement** — Define allowed destinations with YAML policy files. Built-in presets cover BAA-covered Azure and AWS services. Violations trigger alerts, connection blocks, or process termination.

## Quick Start

```bash
# Install
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Optional: enable DNS/SNI hostname resolution
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

### Web UI

```bash
pip install -e ".[web]"
trustrun server    # http://127.0.0.1:8470
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
├── storage/       # SQLite persistence
└── web/           # FastAPI web UI with WebSocket streaming
```

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
- Policy files may reference internal hostnames — treat them as sensitive.

## Platform Support

| Platform | Unprivileged | Elevated (sudo) |
|----------|-------------|-----------------|
| **macOS** | psutil + lsof | BPF via scapy, DNS/SNI capture |
| **Linux** | psutil + /proc/net | libpcap via scapy, DNS/SNI capture |

## License

MIT
