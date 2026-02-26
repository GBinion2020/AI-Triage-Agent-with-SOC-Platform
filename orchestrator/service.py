from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List
from uuid import uuid4

from control.policy_engine import PolicyEngine
from llm.client import LLMClient
from orchestrator.artifacts import ArtifactStore
from orchestrator.confidence import evaluate_wave_confidence
from orchestrator.models import OrchestratorRunReport, ToolExecutionResult, ToolExecutionStatus
from orchestrator.policy import OrchestrationPolicy
from orchestrator.runner import ToolRunner
from orchestrator.soc_analyst_agent import SOCAnalystOrchestrator
from orchestrator.tool_registry import ToolRegistry
from schemas.state import Evidence, EvidenceType, InvestigationState, LoopAudit
from utils.pipeline_logger import PipelineLogger


class OrchestrationService:
    """Coordinates two-wave SOC orchestrator execution and state enrichment."""

    def __init__(self, llm_client: LLMClient, policy_engine: PolicyEngine):
        self.llm_client = llm_client
        self.policy_engine = policy_engine

    def run(self, state: InvestigationState, pipeline_log: PipelineLogger) -> OrchestratorRunReport:
        run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S") + "_" + uuid4().hex[:8]
        alert_id = state.alert.alert.id

        registry = ToolRegistry()
        artifact_store = ArtifactStore(alert_id=alert_id, run_id=run_id)
        orchestration_policy = OrchestrationPolicy(base_policy=self.policy_engine)
        runner = ToolRunner(
            llm_client=self.llm_client,
            registry=registry,
            policy_engine=self.policy_engine,
            artifact_store=artifact_store,
            pipeline_log=pipeline_log,
            max_workers=orchestration_policy.max_parallel_actions,
        )
        orchestrator_agent = SOCAnalystOrchestrator(self.llm_client)

        run_report = OrchestratorRunReport(run_id=run_id, alert_id=alert_id)
        prior_results: List[ToolExecutionResult] = []
        artifact_store.append_event("run_started", {"run_id": run_id, "alert_id": alert_id})

        for wave in range(1, orchestration_policy.max_waves + 1):
            pipeline_log.log_section(f"SOC ORCHESTRATION WAVE {wave}")
            agent_start = pipeline_log.log_agent_start(
                "SOCAnalystOrchestrator",
                f"Planning wave {wave} actions",
            )
            plan = orchestrator_agent.plan_wave(
                state=state,
                wave=wave,
                registry=registry,
                prior_results=prior_results,
            )
            plan = orchestration_policy.sanitize_plan(plan=plan, state=state, registry=registry)
            pipeline_log.log_agent_end(
                "SOCAnalystOrchestrator",
                agent_start,
                f"Planned {len(plan.actions)} action(s) for wave {wave}",
            )
            pipeline_log.log_agent_io_exact(
                "SOCAnalystOrchestrator",
                {
                    "alert_id": alert_id,
                    "wave": wave,
                    "evidence_count": len(state.evidence),
                    "tool_cards": [c.name for c in registry.list_cards(enabled_only=True)],
                    "prompt": orchestrator_agent.last_prompt,
                },
                {
                    "raw_response": orchestrator_agent.last_raw_response,
                    "parsed_plan": plan.model_dump(),
                    "error": orchestrator_agent.last_error,
                },
            )

            run_report.plans.append(plan)
            artifact_store.append_event(
                "wave_planned",
                {
                    "run_id": run_id,
                    "wave": wave,
                    "objective": plan.objective,
                    "actions": [a.model_dump() for a in plan.actions],
                },
            )
            pipeline_log.log_data(
                "WAVE_PLAN",
                [
                    {
                        "tool": action.tool_name,
                        "reason": action.reason,
                        "priority": action.priority,
                    }
                    for action in plan.actions
                ],
            )

            wave_report = runner.run_wave(
                run_id=run_id,
                alert_id=alert_id,
                wave=wave,
                actions=plan.actions,
                state=state,
            )
            run_report.waves.append(wave_report)
            prior_results = wave_report.action_results

            # Feed successful results back into InvestigationState for scoring + final decision.
            loop_audit = LoopAudit(
                iteration=wave,
                intent=plan.objective,
                tools_planned=[a.tool_name for a in plan.actions],
            )

            for result in wave_report.action_results:
                content = json.dumps(self._build_evidence_payload(result), default=str)
                state.add_evidence(
                    Evidence(
                        content=content,
                        summary=result.summary,
                        source_tool=result.tool_name,
                        type=EvidenceType.LOG if result.status != ToolExecutionStatus.failed else EvidenceType.ERROR,
                        confidence=1.0,
                    )
                )

                # Record high-level tool execution and audit details.
                record = state.record_tool_execution(
                    tool=result.tool_name,
                    args=result.request,
                    status=result.status.value,
                    result=result.summary,
                )
                loop_audit.executions.append(record)

                if result.error:
                    loop_audit.errors.append(result.error)

                # Merge discovered IOCs into state store.
                for ioc_type in ("ip", "domain", "url", "hash"):
                    for value in result.extracted_iocs.get(ioc_type, []):
                        if not value:
                            continue
                        exists = any(
                            item.get("type") == ioc_type and item.get("value", "").lower() == value.lower()
                            for item in state.ioc_store
                        )
                        if not exists:
                            state.ioc_store.append(
                                {
                                    "type": ioc_type,
                                    "value": value,
                                    "source": result.tool_name,
                                }
                            )

                run_report.artifact_refs.extend(result.artifacts)

            state.audit_trail.append(loop_audit)

            confidence = evaluate_wave_confidence(state=state, wave_report=wave_report, wave_index=wave)
            run_report.confidence = confidence
            artifact_store.append_event(
                "wave_completed",
                {
                    "run_id": run_id,
                    "wave": wave,
                    "confidence": confidence.model_dump(),
                    "action_results": [r.model_dump() for r in wave_report.action_results],
                },
            )
            pipeline_log.log_step(
                "WAVE_CONFIDENCE",
                f"Score: {confidence.score:.1f} | Continue: {confidence.should_continue}\n   Rationale: {confidence.rationale}",
            )

            if not confidence.should_continue:
                break

        run_report.evidence_summary = self._build_evidence_summary(run_report.waves)
        run_meta_artifact = artifact_store.write_run_metadata(run_report.model_dump())
        run_report.artifact_refs.append(run_meta_artifact)
        artifact_store.append_event("run_completed", {"run_id": run_id, "waves_executed": len(run_report.waves)})

        pipeline_log.log_step(
            "ORCHESTRATION_COMPLETE",
            f"Run ID: {run_id}\n   Artifact directory: {artifact_store.absolute_base_path()}\n   Waves executed: {len(run_report.waves)}",
        )
        return run_report

    @staticmethod
    def _build_evidence_payload(result: ToolExecutionResult) -> dict:
        findings = []
        for item in result.findings[:20]:
            if hasattr(item, "model_dump"):
                findings.append(item.model_dump(exclude_none=True))
            elif isinstance(item, dict):
                findings.append(item)
            else:
                findings.append({"detail": str(item)})

        payload = {
            "action_id": result.action_id,
            "tool_name": result.tool_name,
            "status": result.status.value,
            "summary": result.summary,
            "request": result.request,
            "findings": findings,
            "extracted_iocs": result.extracted_iocs,
            "error": result.error or "",
        }
        # Avoid embedding large raw payloads in InvestigationState context; canonical raw data remains in artifacts.
        raw_result = result.raw_result if isinstance(result.raw_result, dict) else {}
        if raw_result:
            payload["result_meta"] = {
                "keys": sorted(raw_result.keys())[:20],
                "query_count": len(raw_result.get("query_log", [])) if isinstance(raw_result.get("query_log"), list) else 0,
            }
        return payload

    @staticmethod
    def _build_evidence_summary(waves) -> str:
        lines = []
        for wave_report in waves:
            lines.append(f"Wave {wave_report.wave}:")
            for result in wave_report.action_results:
                lines.append(f"- {result.tool_name}: {result.summary}")
        return "\n".join(lines)
