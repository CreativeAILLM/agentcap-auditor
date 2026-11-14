# AgentCap Auditor v0.2

An offline Python CLI for reviewing agent authority and compiling explicit task
requirements into a default-deny capability policy. Version **0.2.0**, MIT license.
No runtime dependencies, network calls, configured process execution, telemetry,
or model API calls. Python 3.10 or newer.

## Install and quickstart

From the repository root in a clean checkout:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt .
python -m pytest -q
agentcap --version
agentcap audit examples/manifest.json --format markdown
agentcap audit examples/mcp.json --format json -o audit.json
agentcap compile examples/manifest.json --tasks examples/tasks.json -o policy.json
agentcap benchmark
```

For runtime-only installation, use `python -m pip install .`. Build and test
requirements are pinned. `python -m agentcap` is equivalent to `agentcap`.
`audit --fail-on high` exits 1 for high/critical findings; `--fail-on critical`
only fails for critical findings. Without the flag, findings do not change the
exit status. Successful commands exit 0; invalid input or I/O errors exit 2.
All commands accept `-o PATH`; audit supports JSON and Markdown, benchmark
supports text and JSON, compile emits JSON. Outputs are deterministic.

## Agent tool manifest format

```json
{
  "version": 1,
  "tools": [
    {"name": "read_documents", "tiers": ["read"], "scopes": ["*"],
     "paths": [], "hosts": [], "env": {}}
  ]
}
```

`version` and `tools` are required. Each tool needs a unique, nonempty `name`.
Optional `tiers`, `scopes`, `paths`, `hosts` are arrays of nonempty strings;
`env` is an object. Omitted arrays mean unspecified authority, not proof of
isolation. Unknown metadata fields are ignored. Scopes are opaque exact resource
identifiers such as `doc:42`, `recipient:help@example.org`, or `command:pytest`.
Paths and hosts are separate allowlist dimensions. Tiers describe overlapping
classes of authority rather than an ordinal numeric score.

## MCP input

```json
{
  "mcpServers": {
    "docs": {
      "url": "https://docs.example.org/mcp",
      "tools": [{"name": "read_page", "scopes": ["page:42"]}]
    }
  }
}
```

Accepts the common `mcpServers` object with either a nonempty `command` and
optional `args`/`env`, or an HTTP(S) `url` and optional `env`. A configured
command is conservatively classified as process/shell execution even when the
client launches it without a shell. URLs supply a transport host, **not** a
server tool egress allowlist. URL credentials/query strings and environment
values are never copied into reports or policies.

MCP configuration alone does not describe the remote tool inventory. An optional
`tools` array is this product's explicit inventory extension (same tool fields
as above). Without it, an `unknown_authority` finding is emitted for
`server:undiscovered`. Inventory tools use `server:tool` identities; transport
uses `server:transport`. Tool compilation requires a separate explicit transport
requirement. No live MCP discovery is performed, and command arguments are not
assumed to constrain server filesystem authority. Supply reviewed tool metadata.

## Classification rules

`agentcap/core.py::RULES` is the authoritative table. Camel case is normalized;
terms match token boundaries (not substrings inside words). All matching tiers
are combined with explicit declarations; declaring `read` cannot hide an
inferred shell grant. Unrecognized names without declarations become `unknown`,
are flagged high, and cannot be compiled.

| Tier | Matching terms |
| --- | --- |
| read | read, list, get, search, query, inspect |
| write | write, create, update, delete, send, publish, insert |
| network_egress | http, fetch, request, browse, network, url |
| shell_execution | shell, exec, execute, bash, sh, terminal, subprocess |
| filesystem_write | write_file, delete_file, mkdir, filesystem |
| secrets_access | secret, credential, token, password, vault, api_key |
| payments | pay, payment, charge, purchase, refund, transfer |

Names are heuristics, not semantic verification. Explicit reviewed tiers are
needed for opaque tool names. Environment key inspection is a separate finding,
not an assertion that the tool exposes a secret-reading API.

## Findings

Every finding has `capability`, `code`, `severity`, `evidence`, and `remediation`.
Evidence records the capability identity and relevant condition; secret findings
record environment **key names only**, never values. Configuration authors should
also avoid placing secrets in tool names or environment key names.

| Code | Severity | Trigger |
| --- | --- | --- |
| wildcard_scope | high | Scope contains `*`, `?`, or `[` |
| shell_execution | critical | Process/shell execution tier |
| unrestricted_filesystem | high | Root, drive root, home, current/parent directory or glob path |
| unscoped_network | high | Egress with absent or wildcard host allowlist |
| secret_environment | high | Env key resembles secret/token/password/credential/private key/API key/access key |
| missing_allowlist | high | Required scope, path, or host dimension absent |
| unknown_authority | high | Unrecognized capability or undiscovered MCP inventory |

Read/write require scopes or paths for auditing; filesystem writes need paths;
network egress needs hosts; execution, secrets and payments need scopes.
Compilation is stricter: read/write always require explicit scopes, plus all
other dimensions required by the tool's complete tier set.

## Task requirements and compilation

```json
{
  "tasks": [{
    "name": "summarize_handbook",
    "requires": [{"name": "read_documents", "scopes": ["docs:handbook"]}]
  }]
}
```

Tasks are explicit structured requirements, not natural-language inference.
The result retains only referenced capabilities, unions their requested scopes
across tasks, preserves all of each retained tool's tiers, and sets `default` to
`deny`. It does not split a tool into fictional smaller tools. Empty tasks emit
an empty policy. Duplicate task/tool names, unknown capabilities, broad task
requirements, missing dimensions and scope escalation are rejected.

A requested value must equal a granted value, or the broad grant must contain
literal `*`. Partial glob grants and directory-prefix inference are intentionally
unsupported. Requirements must use exact values, not wildcards or filesystem
roots. No environment values or launch commands are copied to the policy.
MCP transports must be explicitly selected with their required constraints.

**This is a policy compiler, not a sandbox or enforcement runtime.** The JSON is
an interchange artifact that an adapter must enforce. A server may not support
fine-grained restrictions. Validate adapter semantics, path traversal/symlinks,
DNS/redirect behavior, argument injection and credential handling separately.
Static name rules cannot prove absence of hidden effects. Findings are review
signals, not certification.

## Benchmark definition

Ten bundled synthetic fixtures each contain a broad `manifest` and one intended
`task`. Run `agentcap benchmark --fixtures PATH` to benchmark another directory
of JSON fixtures. The bundled resources ship inside the installed package.

Granted authority is the number of unique `(capability name, risk tier)` pairs.
Per-task reduction is `100 * (broad_count - compiled_count) / broad_count`.
Zero-to-zero is defined as 0%; invalid negative/increasing counts are rejected.
The reported mean is the arithmetic mean of per-task percentages, not a pooled
ratio. Counts and percentages are recomputed from fixture contents every run.

This transparent metric measures removal of capability-tier grants. It does not
weight severity, quantify wildcard cardinality, credit narrower scopes, or
measure real-world attack probability. The synthetic examples demonstrate
mechanics, not an empirical security efficacy claim. Unknown inventory counts
as an unknown grant and cannot silently be compiled.

## Real example output

The following outputs were captured from the bundled examples, not used as
benchmark constants:

```text
$ agentcap audit examples/mcp.json --format markdown
# AgentCap audit

Capabilities: 2
Findings: 4

- **CRITICAL shell_execution** — local:transport
  Evidence: "Process execution authority is present."
  Remediation: Remove execution or isolate it with a reviewed command allowlist.
- **HIGH secret_environment** — local:transport
  Evidence: {"environment_keys": &#91;"API_TOKEN"&#93;}
  Remediation: Use short-lived scoped credentials; avoid secrets in config files.
- **HIGH missing_allowlist** — local:transport
  Evidence: {"tiers": &#91;"shell_execution"&#93;}
  Remediation: Declare explicit scopes, paths or destination hosts for each grant.
- **HIGH unknown_authority** — local:undiscovered
  Evidence: "Tool authority is not declared or recognized."
  Remediation: Provide an explicit reviewed tool inventory and risk tiers.
```

```text
$ agentcap benchmark
Task                     Granted Compiled Reduction
summarize_handbook            13        1    92.31%
search_products               13        1    92.31%
triage_ticket                 13        2    84.62%
email_digest                  13        3    76.92%
research_docs                 13        2    84.62%
write_report                  13        3    76.92%
run_tests                     13        1    92.31%
check_staging                 13        3    76.92%
pay_invoice                   13        1    92.31%
cleanup_record                13        2    84.62%
Mean reduction: 85.38%
```

## MCP server mode

The same engine also runs as a Model Context Protocol server over stdio, so
an MCP client can call the audit and the compiler as tools. The server is a
thin transport layer: it runs the identical core functions and returns the
identical output the CLI prints for the same input. It adds no network calls,
no telemetry, and no process execution of its own.

Install and run:

```sh
python -m pip install agentcap-auditor
agentcap-server
```

Until the package is on PyPI, install from a repository checkout instead
(`python -m pip install .`); the `agentcap-server` entry point is the same.
`python -m agentcap.server` is equivalent.

Client configuration:

```json
{
  "mcpServers": {
    "agentcap-auditor": {
      "command": "agentcap-server"
    }
  }
}
```

Tools published:

- `audit` takes a `config` object (an agent tool manifest or an `mcpServers`
  configuration) and an optional `format` (`json` or `markdown`), and returns
  the audit report exactly as `agentcap audit` prints it.
- `compile` takes a `config` object and a `tasks` object (the same document
  the CLI reads with `--tasks`) and returns the default-deny policy exactly
  as `agentcap compile` prints it.

Invalid input is returned as a tool error carrying the same message the CLI
writes to stderr. The server speaks newline-delimited JSON-RPC 2.0 on stdio
and answers the standard `initialize`, `tools/list`, and `tools/call`
methods.

Registry name: `mcp-name: io.github.CreativeAILLM/agentcap-auditor`. A
registry submission draft lives in `server.json` at the repository root.

## Development

Tests cover parsers, classification, findings, redaction, compilation rejection
paths, MCP transport dependencies, CLI output and fixture-driven benchmark math.
GitHub Actions runs pytest on push and pull requests for Python 3.10–3.13.
Only the local interpreter run is claimed until hosted CI actually executes.

## AgentCap Auditor Pro

The packaged release of AgentCap Auditor 0.1.0 is also available under a
Pro license. The source code in this repository remains free under the MIT
License; the Pro purchase covers the official packaged distribution, the
Pro license seat rights, and 12 months of packaged updates.

- **AgentCap Auditor Pro, USD 49 one-time.** 1 seat (one individual user).
  Buy: https://buy.stripe.com/eVq6oG2YaaTFafff25aVa03
- **AgentCap Auditor Pro Team, USD 149 one-time.** 5 seats (up to five
  individual users within one organization).
  Buy: https://buy.stripe.com/6oU3cubuGgdZ9bb7zDaVa04

The package contains the v0.1.0 CLI source, the examples, the full test
suite, the MIT License, the Pro license, and README-Pro with install and
quickstart instructions. Use of v0.1.0 is perpetual; after the 12-month
update window an optional renewal (USD 19 to 24 per year) extends the
updates. There is no subscription.
