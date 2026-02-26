# Pipeline Summary (Orchestrated v2)

```mermaid
flowchart TB
  A[Elastic Alert] --> B[Normalize + Deterministic Signals]
  B --> C[Pre-Classifier]
  C -->|investigate| D[IntakeAgent]
  D -->|investigate| E[SOCAnalystOrchestrator]

  E --> F[Wave 1 Parallel Specialists]
  F --> G[Artifacts + Event Log + Evidence Merge]
  G --> H[Confidence Meter]
  H -->|continue| I[Wave 2 Parallel Specialists]
  I --> G

  H -->|stop| J[SOC2DecisionAgent]
  G --> J
  J --> K[Final Output + Email Notification]

  L[Jira Webhook] --> M[Feedback DB]
  M --> N[Feedback Retrieval]
  N --> D
```

## Key Properties

- Two-wave max orchestration with deterministic limits.
- Tool actions are strict JSON contracts via `tool_registry/cards/*.json`.
- Parallel fan-out/fan-in inside each wave.
- Every tool call writes immutable artifact output.
- Final score/classification remain deterministic; LLM only writes close-note/action narrative.
