# Nocturna Engine

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-0.1.0-informational?style=flat-square)](https://github.com/Muran-prog/nocturna-engine)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-3405%20passing-brightgreen?style=flat-square)](#)
[![Async-first](https://img.shields.io/badge/async-first-blueviolet?style=flat-square)](#)

Async-first modular orchestration core for security tooling. Drop in your tools, wire up the pipeline, get normalized findings.

---

## Quick Start

```bash
pip install nocturna-engine
```

```python
import asyncio
from nocturna_engine import NocturnaEngine
from nocturna_engine.models import ScanRequest, Target

async def main():
    engine = NocturnaEngine()
    engine.register_tool(SemgrepTool)

    async with engine:
        request = ScanRequest(targets=[Target(host="example.com")])
        result = await engine.run_scan(request)
        print(result["findings"])

asyncio.run(main())
```

Or skip the boilerplate entirely with the AI-first API:

```python
async with engine:
    result = await engine.ai_scan("example.com", goal="max_external_pentest", mode="auto")
    plan = engine.plan_ai("target=example.com goal=full")
    print(plan.explain())
```

---

## Core Concepts

### Engine

`NocturnaEngine` is the main orchestrator. It owns the plugin registry, event bus, and pipeline. Use it as an async context manager to ensure clean startup and shutdown.

```python
engine = NocturnaEngine()
engine.register_tool(MyTool)

async with engine:
    result = await engine.run_scan(request)
```

### Plugins

Plugins are `BaseTool` subclasses. Implement two methods and register.

| Interface | Purpose |
|---|---|
| `BaseTool` | Core scan tool (subprocess or API) |
| `BaseApiTool` | HTTP-based tool with session management |
| `BaseSubprocessTool` | CLI wrapper with subprocess handling |
| `BaseAnalyzer` | Post-scan finding analysis |
| `BaseReporter` | Report generation |

### Pipeline

The default pipeline runs three ordered phases: `scan -> analyze -> report`. Each phase supports conditions, parallel step groups, per-step timeouts, and retries.

`PhaseDAGRunner` extends this to a full DAG: phases declare dependencies, the runner resolves them and executes in parallel where possible, storing artifacts between phases.

### Event Bus

Async pub/sub. Subscribe to any event by name, or use `*` for wildcards.

```python
@engine.event_bus.on("on_finding_detected")
async def handle_finding(event):
    print(event.finding.severity, event.finding.title)
```

| Event | Fires when |
|---|---|
| `on_scan_started` | Scan request accepted |
| `on_scan_finished` | All phases complete |
| `on_phase_started` / `on_phase_finished` / `on_phase_failed` | Phase lifecycle |
| `on_tool_started` / `on_tool_finished` / `on_tool_error` | Tool lifecycle |
| `on_finding_detected` | Normalized finding produced |
| `on_raw_finding_detected` | Raw parser output available |
| `on_scope_denied` | Target blocked by scope firewall |
| `on_policy_invalid` | Policy payload failed validation |
| `on_ai_plan_rejected` | AI planner rejected a scan plan |

### Normalization

Nine parsers, automatic format detection. Feed in raw output from any supported tool; get back a list of typed `Finding` objects.

Detection order: explicit hint -> structural sniffing (BOM, XML declaration, JSON braces, JSONL line structure) -> plaintext fallback.

<details>
<summary>Supported formats and tools</summary>

| Format | Parser | Supported Tools | Streaming |
|---|---|---|---|
| SARIF | `SarifParser` | Semgrep, CodeQL, ESLint, Bandit | SAX |
| XML (Nmap) | `NmapXmlParser` | Nmap | SAX (defusedxml) |
| XML (Generic) | `GenericXmlParser` | Nessus, OpenVAS, Burp, Qualys, Nikto | SAX |
| XML (JUnit) | `JunitXmlParser` | Trivy, Checkov, Bandit, Safety, Snyk, ZAP | SAX |
| JSON | `GenericJsonParser` | Nuclei, Semgrep, Subfinder, httpx | — |
| JSONL | `JsonlNormalizationParser` | Nuclei, Subfinder, httpx, Katana, ffuf | Streaming |
| CSV | `GenericCsvParser` | Nikto, OpenVAS, Nessus | — |
| HTML | `HtmlParser` | Nikto, ZAP, Burp, Arachni, Wapiti | — |
| Plaintext | `PlaintextParser` | Masscan, Zmap, Dirb, Gobuster | — |

All XML parsing goes through `defusedxml` to prevent XXE.

</details>

### Security

<details>
<summary>Scope firewall and egress controls</summary>

The scope firewall runs before any tool touches a target. Set `kill_switch: true` to block all outbound activity unconditionally.

```yaml
security:
  scope_firewall:
    kill_switch: false
    allowlist_hosts:
      - example.com
    allowlist_cidrs:
      - 10.0.0.0/8
    denylist_hosts:
      - internal.corp
    denylist_cidrs:
      - 192.168.0.0/16
```

Granular egress controls (v2 policy):

| Rule type | Config key | Example value |
|---|---|---|
| Host allow/deny | `egress_allow_hosts` / `egress_deny_hosts` | `api.example.com`, `host:443`, `https://api.example.com` |
| CIDR allow/deny | `egress_allow_cidrs` / `egress_deny_cidrs` | `10.0.0.0/8` |
| Port gates | `egress_allow_ports` / `egress_deny_ports` | `443`, `8080` |
| Protocol gates | `egress_allow_protocols` / `egress_deny_protocols` | `https`, `tcp` |
| Default action | `default_egress_action` | `allow` or `deny` |

</details>

---

## Usage Examples

### Run a scan with specific tools

```python
from nocturna_engine.models import ScanRequest, Target

request = ScanRequest(
    targets=[Target(host="example.com")],
    tool_names=["semgrep", "nmap"],
)

async with engine:
    result = await engine.run_scan(request)
    for finding in result["findings"]:
        print(f"[{finding.severity}] {finding.title} — {finding.tool}")
```

### AI-first scan

```python
async with engine:
    # Natural language goal
    result = await engine.ai("target=example.com goal=web+recon speed=fast safe=true")

    # Structured goal with mode
    result = await engine.ai_scan("example.com", goal="max_external_pentest", mode="auto")

    # Inspect the plan before running
    plan = engine.plan_ai("target=example.com goal=full")
    print(plan.explain())
```

### Subscribe to events

```python
@engine.event_bus.on("on_tool_error")
async def on_error(event):
    print(f"Tool {event.tool_name} failed: {event.error}")

@engine.event_bus.on("*")
async def log_all(event):
    print(event)
```

---

## Plugin Development

### Minimal plugin

```python
from typing import Any
from nocturna_engine.interfaces import BaseTool
from nocturna_engine.models import Finding, ScanRequest, ScanResult, SeverityLevel


class SemgrepTool(BaseTool):
    name = "semgrep"
    version = "0.1.0"
    timeout_seconds = 120.0
    max_retries = 1

    async def execute(self, request: ScanRequest) -> ScanResult:
        raw_output = {"matches": []}  # your integration here
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output=raw_output,
        )

    async def parse_output(
        self, raw_output: dict[str, Any] | list[Any] | str | None, request: ScanRequest
    ) -> list[Finding]:
        return [
            Finding(
                title="SQL Injection in login handler",
                description="User input flows unsanitized into SQL query.",
                severity=SeverityLevel.HIGH,
                tool=self.name,
                target="example.com",
                cwe="CWE-89",
                evidence={"file": "src/auth.py", "line": 42},
            )
        ]
```

Then register and run:

```python
engine.register_tool(SemgrepTool)
```

### Plugin v2 with manifest

```python
from nocturna_engine.core.plugin_v2 import PluginManifest, CapabilityDescriptor

manifest = PluginManifest(
    id="semgrep",
    capabilities=[
        CapabilityDescriptor(
            category="sast",
            tags=["code-analysis", "injection"],
            coverage_hint="source",
            cost_hint="medium",
        )
    ],
    supported_targets=["repository", "directory"],
    supported_phases=["scan"],
)
```

The capability-aware planner scores plugins against your goal and picks the best fit automatically.

---

## Configuration

<details>
<summary>Full config reference</summary>

```yaml
engine:
  max_concurrency: 4
  default_timeout_seconds: 60

plugins:
  auto_discover_packages: []

events:
  handler_timeout_seconds: 5
  handler_retries: 1

pipeline:
  scan_timeout_seconds: 90
  analyze_timeout_seconds: 60
  report_timeout_seconds: 45

logging:
  level: INFO  # DEBUG, INFO, WARNING, ERROR

security:
  scope_firewall:
    kill_switch: false
    allowlist_hosts: []
    allowlist_cidrs: []
    denylist_hosts: []
    denylist_cidrs: []

policy:
  allow_subprocess: true
  allow_network: true
  allow_filesystem: true
  default_egress_action: allow  # or deny
  egress_allow_hosts: []
  egress_deny_hosts: []
  egress_allow_cidrs: []
  egress_deny_cidrs: []
  egress_allow_ports: []
  egress_deny_ports: []
  egress_allow_protocols: []
  egress_deny_protocols: []

features:
  plugin_system_v2: false
  event_contract_v2: false
  ai_api_v2: false
  phase_dag_pipeline: false
  policy_fail_closed: true   # recommended for production
```

**`policy_fail_closed`:** when `true`, invalid policy payloads are denied outright (`reason_code=policy_invalid`). When `false`, the engine falls back to the default policy and emits `on_policy_invalid` with `action=fallback`.

</details>

<details>
<summary>Policy profiles</summary>

```yaml
# Safe — default-deny, no subprocess or filesystem
policy:
  allow_network: false
  allow_subprocess: false
  allow_filesystem: false
  default_egress_action: deny

# Permissive — compatible with most tool integrations
policy:
  allow_network: true
  allow_subprocess: true
  allow_filesystem: true
  default_egress_action: allow
```

</details>

---

## Project Structure

<details>
<summary>Directory layout</summary>

```
nocturna_engine/
├── __init__.py
├── config/
│   └── default_config.yaml
├── core/
│   ├── engine/           # NocturnaEngine — lifecycle, scan, AI, pipeline mixins
│   ├── event_bus.py      # Async pub/sub
│   ├── event_contract.py # Event v2 models
│   ├── pipeline/         # Step runner + DAG runner
│   ├── plugin_manager/   # Discovery, execution, lifecycle
│   ├── plugin_v2/        # Manifests, registry, policy, planner, health, cache
│   └── security/         # Scope firewall
├── exceptions/
├── interfaces/           # BaseTool, BaseAnalyzer, BaseReporter, BaseApiTool, BaseSubprocessTool
├── models/               # Finding, ScanRequest, ScanResult, Target
├── normalization/
│   ├── detector/         # Format auto-detection
│   ├── parsers/          # 9 format parsers + shared patterns
│   ├── pipeline/         # Normalization pipeline runner
│   ├── registry/         # Parser registry
│   └── severity.py       # Severity mapping with per-tool overrides
├── services/             # Config, Logging, Secret services
├── streaming/            # JSONL streaming engine
└── utils/
tests/                    # 3405 tests
```

</details>

---

## Severity Levels

| Level | Value |
|---|---|
| `CRITICAL` | Remote code execution, auth bypass |
| `HIGH` | Injection, privilege escalation |
| `MEDIUM` | Config issues, weak defaults |
| `LOW` | Info leaks, minor misconfigs |
| `INFO` | Informational, no direct risk |

---

## Status

The project is under active development. APIs and config format may change between versions.

If you find a bug or a security issue and have a minute to spare — [open an issue](https://github.com/Muran-prog/nocturna-engine/issues). Feature requests and improvement suggestions are welcome there too.

## Contributing

Open an issue or pull request. Match the existing code style. All submissions must pass the full test suite.

---

*Author: [Muran-prog](https://github.com/Muran-prog)*
