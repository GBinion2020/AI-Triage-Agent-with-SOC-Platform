from __future__ import annotations

from typing import List

from orchestrator.models import ConfidenceReport, ToolExecutionStatus, WaveExecutionReport
from schemas.state import InvestigationState


def evaluate_wave_confidence(
    state: InvestigationState,
    wave_report: WaveExecutionReport,
    wave_index: int,
    max_waves: int = 2,
) -> ConfidenceReport:
    """Deterministic confidence meter to bound investigation loops."""
    results = wave_report.action_results
    if not results:
        return ConfidenceReport(
            score=10.0,
            rationale="No tool actions were executed in this wave.",
            should_continue=wave_index < max_waves,
        )

    successful = [r for r in results if r.status == ToolExecutionStatus.success]
    skipped = [r for r in results if r.status == ToolExecutionStatus.skipped]

    findings_count = sum(len(r.findings) for r in successful)
    new_ioc_count = sum(
        len(r.extracted_iocs.get("ip", []))
        + len(r.extracted_iocs.get("domain", []))
        + len(r.extracted_iocs.get("hash", []))
        for r in successful
    )

    score = 30.0
    score += min(35.0, len(successful) * 12.0)
    score += min(20.0, findings_count * 1.2)
    score += min(15.0, new_ioc_count * 3.0)

    # If everything skipped/failed, confidence should remain low.
    if not successful and skipped:
        score = min(score, 35.0)

    score = max(0.0, min(100.0, score))

    # Continue if we are under confidence threshold and still have a wave left.
    should_continue = wave_index < max_waves and score < 80.0

    rationale = (
        f"Wave {wave_index}: {len(successful)} successful action(s), {findings_count} finding(s), "
        f"{new_ioc_count} IOC(s) extracted."
    )

    return ConfidenceReport(score=score, rationale=rationale, should_continue=should_continue)
