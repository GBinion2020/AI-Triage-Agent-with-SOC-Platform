# MCP Tools, Specialists, and SIEM Guardrails

This page documents the evidence collection layer used by the orchestrated pipeline.

## Execution Layers

1. MCP tools (`/mcp_server/tools/*`)
- Direct integrations (Elastic SIEM, VirusTotal, OSINT, feedback ingestion helpers).

2. Tool specialists (`/orchestrator/specialists/*`)
- Bounded task modules that implement tool-specific investigation logic.
- Return strict structured outputs and extracted IOC sets.

3. Tool runner (`/orchestrator/runner.py`)
- Parallel wave execution with idempotency and retry behavior.

## SIEM Specialist Guardrails

- Uses bounded query loops (`max_queries` 1..6).
- Starts with deterministic baseline queries.
- Restricts query time windows through policy engine.
- Keeps request payloads scoped to observed host/time/evidence.
- Blocks duplicate equivalent query executions within a specialist action.

## Reputation and OSINT Safety

### VirusTotal
- Skips internal/private/non-routable IPs.
- Bounded indicator count.

### OSINT
- Uses safe-search capable providers (`Brave`, `SerpAPI`, optional `DuckDuckGo`).
- Trusted-domain filtering enabled by default (`OSINT_TRUSTED_DOMAINS_ONLY=true`).
- Skips internal/private IP indicators.
- Never downloads/executes remote content.

## Entra Specialist

- Client-credential Graph flow when env credentials are present.
- Returns `skipped` when credentials are absent.
- Read-only sign-in telemetry collection.

## Capability Cards

Each specialist is defined by a capability card in `tool_registry/cards/*.json`:
- input schema
- output schema
- guardrails
- timeout budget
- retry count
- cost class

This contract-based model makes adding future tools deterministic and reviewable.
