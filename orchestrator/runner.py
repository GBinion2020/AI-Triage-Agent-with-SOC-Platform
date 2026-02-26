from __future__ import annotations

import hashlib
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from control.policy_engine import PolicyEngine
from llm.client import LLMClient
from orchestrator.artifacts import ArtifactStore
from orchestrator.models import (
    OrchestratorAction,
    ToolExecutionResult,
    ToolExecutionStatus,
    WaveExecutionReport,
)
from orchestrator.specialists import (
    EntraSpecialist,
    IOCEnrichmentSpecialist,
    OSINTSpecialist,
    SIEMSpecialist,
    TimelineSpecialist,
    VirusTotalSpecialist,
)
from orchestrator.tool_registry import ToolRegistry
from schemas.state import InvestigationState
from utils.pipeline_logger import PipelineLogger


class ToolRunner:
    """Runs tool actions in bounded parallel waves with retry, timeout, and idempotency."""

    def __init__(
        self,
        llm_client: LLMClient,
        registry: ToolRegistry,
        policy_engine: PolicyEngine,
        artifact_store: ArtifactStore,
        pipeline_log: PipelineLogger,
        max_workers: int = 4,
    ):
        self.registry = registry
        self.policy_engine = policy_engine
        self.artifact_store = artifact_store
        self.pipeline_log = pipeline_log
        self.max_workers = max_workers
        self.idempotency_cache = set()
        self.lock = threading.Lock()

        self.specialists = {
            "siem_specialist": SIEMSpecialist(llm_client),
            "osint_specialist": OSINTSpecialist(llm_client),
            "entra_specialist": EntraSpecialist(llm_client),
            "ioc_enrichment_specialist": IOCEnrichmentSpecialist(llm_client),
            "timeline_specialist": TimelineSpecialist(llm_client),
            "virustotal_specialist": VirusTotalSpecialist(llm_client),
        }

    def run_wave(
        self,
        run_id: str,
        alert_id: str,
        wave: int,
        actions: List[OrchestratorAction],
        state: InvestigationState,
    ) -> WaveExecutionReport:
        wave_report = WaveExecutionReport(
            run_id=run_id,
            alert_id=alert_id,
            wave=wave,
            actions_planned=actions,
        )

        workers = max(1, min(self.max_workers, len(actions)))
        futures = []

        with ThreadPoolExecutor(max_workers=workers) as pool:
            for idx, action in enumerate(actions, start=1):
                action_id = f"w{wave}_a{idx}_{self._short_hash(action)}"
                futures.append(
                    pool.submit(
                        self._execute_action,
                        action_id,
                        action,
                        state,
                    )
                )

            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception as exc:
                    result = ToolExecutionResult(
                        action_id="unknown",
                        tool_name="unknown",
                        status=ToolExecutionStatus.failed,
                        summary=f"Wave action future failed before result serialization: {exc}",
                        request={},
                        raw_result={},
                        error=str(exc),
                    )
                wave_report.action_results.append(result)

        wave_report.completed_at = datetime.now(timezone.utc)
        return wave_report

    def _execute_action(
        self,
        action_id: str,
        action: OrchestratorAction,
        state: InvestigationState,
    ) -> ToolExecutionResult:
        try:
            card = self.registry.get(action.tool_name)
        except KeyError as exc:
            result = ToolExecutionResult(
                action_id=action_id,
                tool_name=action.tool_name,
                status=ToolExecutionStatus.failed,
                summary=f"Tool card missing for '{action.tool_name}'",
                request=action.request,
                raw_result={},
                error=str(exc),
            )
            return self._finalize_result(action_id, action, result)
        self.artifact_store.append_event(
            "tool_action_started",
            {
                "action_id": action_id,
                "tool_name": action.tool_name,
                "request": action.request,
            },
        )

        idempotency_key = self._idempotency_key(action)
        with self.lock:
            if idempotency_key in self.idempotency_cache:
                result = ToolExecutionResult(
                    action_id=action_id,
                    tool_name=action.tool_name,
                    status=ToolExecutionStatus.skipped,
                    summary="Skipped due to idempotency: equivalent action already executed in this run.",
                    request=action.request,
                    raw_result={},
                    error="idempotency",
                )
                return self._finalize_result(action_id, action, result)
            self.idempotency_cache.add(idempotency_key)

        specialist = self.specialists.get(action.tool_name)
        if specialist is None:
            result = ToolExecutionResult(
                action_id=action_id,
                tool_name=action.tool_name,
                status=ToolExecutionStatus.failed,
                summary=f"No specialist mapped for tool '{action.tool_name}'",
                request=action.request,
                error="missing_specialist",
            )
            return self._finalize_result(action_id, action, result)

        # Retry loop with exponential backoff.
        max_attempts = card.max_retries + 1
        attempt = 0
        last_result: ToolExecutionResult | None = None
        while attempt < max_attempts:
            attempt += 1
            start = time.time()
            try:
                result = specialist.execute(
                    action_id=action_id,
                    request=action.request,
                    state=state,
                    card=card,
                    policy_engine=self.policy_engine,
                )
                elapsed = time.time() - start
                elapsed_ms = int(elapsed * 1000)
                if result.duration_ms <= 0:
                    result.duration_ms = elapsed_ms
                if elapsed > card.timeout_seconds:
                    result.status = ToolExecutionStatus.failed
                    result.error = (
                        f"Tool execution exceeded timeout budget "
                        f"({elapsed:.2f}s > {card.timeout_seconds}s)."
                    )
                    result.summary = f"{result.summary} Timeout budget exceeded."
                last_result = result

                if result.status in {ToolExecutionStatus.success, ToolExecutionStatus.skipped, ToolExecutionStatus.denied_policy}:
                    break
            except Exception as exc:
                elapsed = time.time() - start
                last_result = ToolExecutionResult(
                    action_id=action_id,
                    tool_name=action.tool_name,
                    status=ToolExecutionStatus.failed,
                    summary=f"Specialist exception: {exc}",
                    request=action.request,
                    raw_result={},
                    duration_ms=int(elapsed * 1000),
                    error=str(exc),
                )

            if attempt < max_attempts:
                backoff = min(4.0, 0.5 * (2 ** (attempt - 1)))
                time.sleep(backoff)

        assert last_result is not None
        return self._finalize_result(action_id, action, last_result, specialist=specialist)

    def _finalize_result(
        self,
        action_id: str,
        action: OrchestratorAction,
        result: ToolExecutionResult,
        specialist: Optional[Any] = None,
    ) -> ToolExecutionResult:
        # Persist full tool result artifact.
        try:
            artifact = self.artifact_store.write_json(
                category=action.tool_name,
                artifact_name=action_id,
                payload=result.model_dump(),
            )
            result.artifacts.append(artifact)
        except Exception as exc:
            result.error = f"{result.error} | artifact_write_failed: {exc}".strip(" |")

        self.pipeline_log.log_tool_execution(
            tool_name=action.tool_name,
            args={"action_id": action_id, **action.request},
            status=result.status.value,
            result=result.summary,
            execution_time=result.duration_ms / 1000.0,
        )

        llm_prompt = getattr(specialist, "last_prompt", "") if specialist is not None else ""
        llm_response = getattr(specialist, "last_raw_response", "") if specialist is not None else ""
        llm_error = getattr(specialist, "last_error", "") if specialist is not None else ""
        findings_payload = []
        for item in result.findings[:20]:
            if hasattr(item, "model_dump"):
                findings_payload.append(item.model_dump(exclude_none=True))
            elif isinstance(item, dict):
                findings_payload.append(item)
            else:
                findings_payload.append({"detail": str(item)})
        self.pipeline_log.log_agent_io_exact(
            action.tool_name,
            {
                "action_id": action_id,
                "tool_name": action.tool_name,
                "request": action.request,
                "llm_prompt": llm_prompt,
            },
            {
                "status": result.status.value,
                "summary": result.summary,
                "error": result.error or llm_error,
                "duration_ms": result.duration_ms,
                "raw_result": self._compact_for_audit(result.raw_result),
                "findings": findings_payload,
                "extracted_iocs": result.extracted_iocs,
                "llm_raw_response": self._compact_for_audit(llm_response),
            },
        )

        self.artifact_store.append_event(
            "tool_action_completed",
            {
                "action_id": action_id,
                "tool_name": action.tool_name,
                "status": result.status.value,
                "duration_ms": result.duration_ms,
                "error": result.error,
            },
        )
        return result

    @staticmethod
    def _short_hash(action: OrchestratorAction) -> str:
        raw = json.dumps(action.model_dump(), sort_keys=True, default=str)
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:8]

    @staticmethod
    def _idempotency_key(action: OrchestratorAction) -> str:
        raw = json.dumps(
            {
                "tool_name": action.tool_name,
                "request": action.request,
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def _compact_for_audit(value: Any, depth: int = 0) -> Any:
        if depth > 4:
            return "<truncated-depth>"
        if isinstance(value, str):
            value = value.strip()
            if len(value) > 1200:
                return value[:1200] + "...<truncated>"
            return value
        if isinstance(value, list):
            compacted = [ToolRunner._compact_for_audit(item, depth + 1) for item in value[:20]]
            return [item for item in compacted if item not in ("", None, [], {})]
        if isinstance(value, dict):
            out: Dict[str, Any] = {}
            for key, item in list(value.items())[:40]:
                compact_item = ToolRunner._compact_for_audit(item, depth + 1)
                if compact_item in ("", None, [], {}):
                    continue
                out[key] = compact_item
            return out
        return value
