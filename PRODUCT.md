# TrustRun — Product Description

## Problem

Organizations handling PHI/PII (especially under HIPAA) increasingly use AI-generated code and third-party tools that make outbound network calls. There is no practical way to verify at runtime that an application's actual network behavior matches what was intended — e.g., that all LLM API calls route through a BAA-covered Azure endpoint and not directly to OpenAI's public API, or that patient data isn't being exfiltrated to an unauthorized server.

Code review alone is insufficient: dependencies can phone home, AI-generated code may embed unexpected endpoints, and runtime behavior can differ from what source code suggests.

## Solution

**TrustRun** is a network trust verification tool for sensitive environments. It combines:

1. **Runtime network monitoring** — Observe and enforce what network connections a process actually makes.
2. **Static code analysis** — Scan codebases for hardcoded endpoints, API keys, outbound URL patterns, and suspicious network calls before the code ever runs.
3. **Policy-based enforcement** — Define allowed network destinations via allowlists, auto-learned profiles, and built-in BAA presets (Azure, AWS). Flag or block anything outside the policy.

## Core Concepts

### Policy
A policy defines what network behavior is acceptable. Policies are composable and consist of:
- **Allowlists**: Explicit domains, IPs, CIDR ranges that are permitted.
- **BAA presets**: Built-in lists of known endpoints for BAA-covered cloud providers (Azure OpenAI, Azure Cognitive Services, AWS Bedrock, AWS HealthLake, etc.).
- **Auto-learned profiles**: TrustRun observes a process during a learning phase, catalogs all destinations, and presents them for approval/denial.
- **Response actions**: Per-rule configuration of what happens on violation — `alert`, `block`, or `kill`.

### Monitoring Session
A runtime observation period where TrustRun tracks all network activity for a target process (and optionally its children). Sessions produce structured event logs.

### Scan
A static analysis pass over a codebase directory that extracts endpoints, URLs, API keys, and network-related patterns from source code across multiple languages.

## Subcommands

### `trustrun watch <PID>`
Attach to an already-running process. Monitor its network connections against the active policy.

### `trustrun run <cmd> [args...]`
Launch a command under TrustRun's supervision. The target process inherits TrustRun's monitoring from the start — no connections are missed.

### `trustrun scan <directory>`
Static analysis of source code. Extracts URLs, IP addresses, API endpoint patterns, hardcoded keys, and SDK client configurations. Reports findings against the active policy.

### `trustrun server`
Start the web UI for viewing live and historical sessions, managing policies, and reviewing scan results.

## Network Capture Detail (Configurable)

Three levels, configurable per-policy:

| Level | What's Captured | Use Case |
|-------|----------------|----------|
| **metadata** (default) | Src/dst IP, port, protocol, DNS queries, TLS SNI hostname | Lightweight compliance verification |
| **headers** | Above + HTTP method, path, headers (requires TLS intercept) | API call auditing |
| **full** | Above + request/response bodies | Deep inspection, incident investigation |

## Static Analysis Capabilities

Language-agnostic pattern matching plus language-specific analyzers:

- **Universal**: URL/IP extraction via regex, secret detection patterns (API keys, tokens, connection strings).
- **Python**: AST-based analysis of `requests`, `httpx`, `urllib`, `aiohttp`, `openai`, `azure-*`, `boto3` SDK client instantiation and call sites.
- **JavaScript/TypeScript**: AST-based analysis of `fetch`, `axios`, `node-fetch`, SDK clients.
- **R**: Pattern matching for `httr`, `curl`, API call patterns common in biostatistics/clinical code.
- **General**: Regex-based extraction for any other language.

## Web UI

Local web interface (not exposed to the network by default) providing:

- **Live dashboard**: Real-time view of active monitoring sessions with connection events streaming in.
- **Session history**: Browse past sessions with filtering and search.
- **Policy editor**: Create and manage policies with a visual editor. Import/export as YAML.
- **Scan results**: View static analysis findings with source code context and links.
- **Alerts**: Chronological feed of policy violations with severity and suggested actions.

## Platform Support

- **macOS**: Uses `nettop`, `lsof`, and BPF-based packet capture for network monitoring.
- **Linux**: Uses `/proc/net`, `ss`, eBPF (where available), or `libpcap` for network monitoring.

Cross-platform abstraction layer so policies and the UI work identically on both.

## Technology Stack

- **Language**: Python 3.11+
- **Network capture**: `psutil` for connection enumeration, `scapy` for packet capture, `mitmproxy` for TLS interception (headers/full modes).
- **Static analysis**: `tree-sitter` for multi-language AST parsing, regex for universal patterns.
- **Web UI**: FastAPI backend with WebSocket for live streaming, lightweight frontend (htmx or React — TBD).
- **Storage**: SQLite for session data and policies (portable, zero-config).
- **Config**: YAML policy files.

## Non-Goals (Current Scope)

- Not a general-purpose firewall or IDS.
- Not a network security scanner (doesn't probe targets).
- Does not modify or encrypt traffic.
- Does not require kernel modules or root access for basic metadata capture (elevated privileges needed only for packet capture and blocking modes).

## Target Users

- Medical/clinical AI developers who need to verify code handles PHI correctly.
- Security/compliance teams auditing AI-powered applications.
- Researchers working with sensitive data under IRB or HIPAA requirements.
