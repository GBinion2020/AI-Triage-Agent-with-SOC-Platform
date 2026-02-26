import json
import re
from typing import Any, Dict, List

from llm.client import LLMClient
from schemas.state import InvestigationState


class SOC2DecisionAgent:
    """Final SOC2 analyst authority for close notes and action recommendation."""

    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client
        self.last_prompt: str = ""
        self.last_raw_response: str = ""
        self.last_error: str = ""

    def decide(
        self,
        state: InvestigationState,
        orchestration_summary: str,
        artifact_refs: List[Dict[str, Any]],
        scoring: Dict[str, Any],
    ) -> Dict[str, Any]:
        risk_score = scoring.get("risk_score", 0.0)
        classification = scoring.get("classification", "Suspicious")
        evidence_table = scoring.get("evidence_table", [])
        artifact_view = [
            {
                "path": item.get("path"),
                "content_type": item.get("content_type"),
                "created_at": item.get("created_at"),
            }
            for item in artifact_refs[:40]
        ]

        alert_json = json.dumps(state.alert.model_dump(exclude_none=True, exclude={"raw_data"}), default=str)
        evidence_summary = "\n".join([f"- {e.source_tool}: {e.summary}" for e in state.evidence[-30:]])

        prompt = f"""
ACT: SOC2 Final Analyst.
ROLE: Produce the final, defensible close note and action recommendation.

ALERT:
{alert_json}

ORCHESTRATION SUMMARY:
{orchestration_summary}

EVIDENCE SUMMARY:
{evidence_summary}

ARTIFACT REFERENCES:
{json.dumps(artifact_view, default=str)}

DETERMINISTIC SCORING (AUTHORITATIVE):
- risk_score: {risk_score}
- classification: {classification}
- evidence_table: {json.dumps(evidence_table, default=str)}

RULES:
- Do not change score/classification.
- Keep summary concrete with timestamps and specific evidence.
- Avoid internal host IPs unless directly relevant to malicious activity.
- Never include internal runtime labels (action IDs, wave IDs, artifact IDs) in analyst-facing narrative.
- Prefer analyst-readable source names (SIEM specialist, IOC enrichment, timeline, etc.).
- Action is advisory only; final action is enforced by deterministic scoring policy downstream.
- Confidence score must represent model confidence in the classification (0-100), not risk score.
- Output strict JSON only.

OUTPUT JSON:
{{
  "summary": "4-6 sentence SOC close note",
  "action": "Close" | "Escalate to Incident Response" | "Block Asset/User",
  "confidence_score": 0-100,
  "confidence_rationale": "1-2 sentences on why confidence is at this level",
  "mitre_techniques": ["TXXXX"],
  "journal": ["Step 1: ...", "Step 2: ..."]
}}
"""

        self.last_prompt = prompt
        self.last_raw_response = ""
        self.last_error = ""

        raw_response = ""
        try:
            raw_response = self.llm.generate(prompt)
            self.last_raw_response = raw_response
            payload = self._extract_json(raw_response)
            llm_action = str(payload.get("action") or "").strip() or "Escalate to Incident Response"
            deterministic_action = self._deterministic_action(risk_score, classification)
            confidence_score = self._resolve_confidence_score(
                payload=payload,
                state=state,
                classification=classification,
                evidence_table=evidence_table,
                risk_score=risk_score,
            )
            confidence_rationale = str(
                payload.get("confidence_rationale")
                or payload.get("confidence_reason")
                or payload.get("confidence_explanation")
                or self._fallback_confidence_rationale(classification, state)
            ).strip()
            return {
                "classification": classification,
                "final_score": risk_score,
                "summary": payload.get("summary", "Summary unavailable."),
                "action": deterministic_action,
                "recommended_action": llm_action,
                "action_policy": "deterministic_risk_policy",
                "confidence_score": confidence_score,
                "confidence_rationale": confidence_rationale,
                "evidence_table": evidence_table,
                "mitre_techniques": payload.get("mitre_techniques", []),
                "journal": payload.get("journal", []),
            }
        except Exception as exc:
            self.last_error = str(exc)
            deterministic_action = self._deterministic_action(risk_score, classification)
            confidence_score = self._fallback_confidence_score(
                state=state,
                classification=classification,
                evidence_table=evidence_table,
            )
            return {
                "classification": classification,
                "final_score": risk_score,
                "summary": f"SOC2 decision generation failed: {exc}",
                "action": deterministic_action,
                "recommended_action": "Escalate to Incident Response",
                "action_policy": "deterministic_risk_policy",
                "confidence_score": confidence_score,
                "confidence_rationale": self._fallback_confidence_rationale(classification, state),
                "evidence_table": evidence_table,
                "mitre_techniques": [],
                "journal": [],
            }

    @staticmethod
    def _extract_json(value: str) -> Dict[str, Any]:
        value = value.strip()
        if value.startswith("{") and value.endswith("}"):
            return json.loads(value)

        match = re.search(r"(\{.*\})", value, re.DOTALL)
        if not match:
            raise ValueError("No JSON object found in response")

        candidate = match.group(1)
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            candidate = re.sub(r",\s*([}\]])", r"\1", candidate)
            return json.loads(candidate)

    @staticmethod
    def _normalize_confidence(value: Any) -> float | None:
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            return None
        if 0.0 <= numeric <= 1.0:
            numeric *= 100.0
        return round(max(0.0, min(100.0, numeric)), 1)

    @classmethod
    def _fallback_confidence_score(
        cls,
        state: InvestigationState,
        classification: str,
        evidence_table: List[Dict[str, Any]],
    ) -> float:
        cls_key = str(classification or "").strip().lower()
        base = 56.0 if cls_key in {"benign", "malicious"} else 48.0
        evidence_boost = min(24.0, len(state.evidence) * 2.5)
        category_boost = min(14.0, len({row.get("category") for row in evidence_table if row.get("category")}) * 2.0)
        contribution_sum = sum(
            max(0.0, float(row.get("contribution", 0.0)))
            for row in evidence_table
            if isinstance(row, dict)
        )
        support_boost = min(12.0, contribution_sum / 18.0)
        return round(max(5.0, min(97.0, base + evidence_boost + category_boost + support_boost)), 1)

    @classmethod
    def _resolve_confidence_score(
        cls,
        payload: Dict[str, Any],
        state: InvestigationState,
        classification: str,
        evidence_table: List[Dict[str, Any]],
        risk_score: Any,
    ) -> float:
        for key in (
            "confidence_score",
            "classification_confidence",
            "model_confidence",
            "confidence",
            "confidence_percent",
            "confidence_pct",
        ):
            parsed = cls._normalize_confidence(payload.get(key))
            if parsed is not None:
                resolved = parsed
                break
        else:
            resolved = cls._fallback_confidence_score(state, classification, evidence_table)

        try:
            risk_value = float(risk_score)
        except (TypeError, ValueError):
            risk_value = None

        # Keep confidence semantically distinct from deterministic risk.
        if risk_value is not None and abs(resolved - risk_value) < 0.05:
            resolved = round(max(1.0, min(99.0, resolved + (7.0 if resolved <= 50.0 else -7.0))), 1)
        return resolved

    @staticmethod
    def _fallback_confidence_rationale(classification: str, state: InvestigationState) -> str:
        return (
            f"Confidence derived from evidence consistency across {len(state.evidence)} collected records "
            f"for a {classification} classification."
        )

    @staticmethod
    def _deterministic_action(risk_score: Any, classification: str) -> str:
        try:
            score = float(risk_score)
        except (TypeError, ValueError):
            score = 0.0
        cls = str(classification or "").strip().lower()

        if cls == "benign":
            return "Close"
        if cls == "malicious":
            return "Escalate to Incident Response" if score >= 70.0 else "Block Asset/User"

        # Suspicious / unknown classes remain score-driven and stable run-to-run.
        if score >= 80.0:
            return "Escalate to Incident Response"
        if score >= 60.0:
            return "Block Asset/User"
        return "Close"
