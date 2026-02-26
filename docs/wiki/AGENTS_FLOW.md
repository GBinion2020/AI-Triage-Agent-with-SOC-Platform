# Agent Flow (Orchestrated v2)

```mermaid
flowchart LR
  A[Normalized Alert + Signals + Feedback Context] --> B[IntakeAgent]
  B -->|close_benign| X[Close]
  B -->|investigate| C[SOCAnalystOrchestrator]

  C --> D[Wave 1 Action Plan JSON]
  D --> E[ToolRunner Parallel Execution]
  E --> F[Specialists Output JSON]
  F --> G[Artifacts + State Evidence]

  G --> H[Confidence Report]
  H -->|continue| I[Wave 2 Action Plan JSON]
  I --> E

  H -->|stop| J[SOC2DecisionAgent]
  G --> J
  J --> K[Classification + Action + Journal]
```

## Agent Responsibilities

1. `IntakeAgent`
- Decides `close_benign` vs `investigate`.
- Uses deterministic signals + feedback context.

2. `SOCAnalystOrchestrator`
- Produces strict JSON action plans.
- Chooses specialists/tools and scoped inputs.

3. `Tool Specialists`
- Execute bounded, role-specific evidence collection.
- Return structured findings + extracted IOCs.

4. `SOC2DecisionAgent`
- Consumes orchestration evidence summary and artifact references.
- Generates final close note/action without overriding deterministic score/classification.
