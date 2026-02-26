import json
from llm.client import LLMClient
from schemas.state import InvestigationState

class DecisionAgent:
    """
    Final Authority.
    Produces the final structured output.
    """
    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client
        self.last_prompt: str = ""
        self.last_raw_response: str = ""
        self.last_error: str = ""
        
    def decide(self, state: InvestigationState, reasoning_trace: str = "", scoring: dict = None) -> dict:
        """
        Produce final verdict.
        """
        scoring = scoring or {}
        risk_score = scoring.get("risk_score", 0.0)
        classification = scoring.get("classification", "Suspicious")
        evidence_table = scoring.get("evidence_table", [])

        # Prepare Context
        alert_json = json.dumps(state.alert.model_dump(exclude_none=True, exclude={"raw_data"}), default=str)
        evidence_summary = "\n".join([f"- {e.source_tool}: {e.summary}" for e in state.evidence])
        lessons = state.lessons_learned if state.lessons_learned else "No relevant past incidents found."
        feedback_override = self._detect_feedback_override(lessons)

        prompt = f"""
        ACT: SOC Manager.
        ROLE: You are the final authority. You translate technical analysis into business risk and actionable outcomes using the ENTERPRISE TRIAGE RUBRIC.
        
        FULL NORMALIZED ALERT DATA (Minified):
        {alert_json}
        
        TECHNICAL SIGNALS (DETERMINISTIC):
        {json.dumps(state.alert.analysis_signals.model_dump(exclude_none=True), default=str)}
        
        FINAL ANALYTICAL REASONING:
        {reasoning_trace}
        
        EVIDENCE SUMMARIES:
        {evidence_summary}

        FEEDBACK LOOP (AUTHORITATIVE CONTEXT):
        {lessons}

        FEEDBACK OVERRIDE FLAG:
        {feedback_override}

        --- DETERMINISTIC RISK OUTPUTS ---
        Final Risk Score (0-100): {risk_score}
        Final Classification: {classification}
        Evidence Table (authoritative):
        {json.dumps(evidence_table, indent=2, default=str)}

        TASK:
        Provide only the narrative summary and recommended action.
        The final score and classification are already determined. Do not change them.
        The action is advisory only and will be validated against deterministic score policy.
        Confidence score must represent model confidence in the classification, not the deterministic risk score.
        If FEEDBACK OVERRIDE FLAG is true, you MUST state in the summary that the activity is likely benign/known testing based on prior analyst feedback, while keeping the same score/classification.
        Write like a SOC L2/L3 analyst close note with relevant timestamps, IOCs, and findings.
        Avoid listing internal host IPs unless they are directly tied to malicious activity.
        Do not mention scoring, weights, or rubric mechanics.

        OUTPUT FORMAT (STRICT JSON):
        {{
            "summary": "4-6 sentences explaining the why, SOC L2/L3 close note style with timestamps and IOCs.",
            "action": "Close" | "Escalate to Incident Response" | "Block Asset/User",
            "confidence_score": 0-100,
            "confidence_rationale": "1-2 sentences on confidence basis",
            "mitre_techniques": ["TXXXX"],
            "journal": ["Step 1: ...", "Step 2: ..."]
        }}
        """
        self.last_prompt = prompt
        self.last_raw_response = ""
        self.last_error = ""
        
        resp = ""
        try:
            resp = self.llm.generate(prompt)
            self.last_raw_response = resp
            
            # Robust JSON extraction
            import re
            # Find the outermost { }
            match = re.search(r'(\{.*\})', resp, re.DOTALL)
            if match:
                json_str = match.group(1)
                try:
                    parsed = json.loads(json_str)
                    llm_action = str(parsed.get("action") or "").strip() or "Escalate to Incident Response"
                    deterministic_action = self._deterministic_action(risk_score, classification)
                    confidence_score = self._resolve_confidence_score(
                        payload=parsed,
                        state=state,
                        classification=classification,
                        evidence_table=evidence_table,
                        risk_score=risk_score,
                    )
                    return {
                        "classification": classification,
                        "final_score": risk_score,
                        "summary": parsed.get("summary", "Summary unavailable."),
                        "action": deterministic_action,
                        "recommended_action": llm_action,
                        "action_policy": "deterministic_risk_policy",
                        "confidence_score": confidence_score,
                        "confidence_rationale": str(
                            parsed.get("confidence_rationale")
                            or parsed.get("confidence_reason")
                            or parsed.get("confidence_explanation")
                            or self._fallback_confidence_rationale(classification, state)
                        ).strip(),
                        "evidence_table": evidence_table,
                        "mitre_techniques": parsed.get("mitre_techniques", []),
                        "journal": parsed.get("journal", []),
                    }
                except json.JSONDecodeError:
                    # Final attempt: try to clean up common LLM artifacts like trailing commas or comments
                    # (Simplified for now)
                    json_str = re.sub(r',\s*\}', '}', json_str)
                    parsed = json.loads(json_str)
                    llm_action = str(parsed.get("action") or "").strip() or "Escalate to Incident Response"
                    deterministic_action = self._deterministic_action(risk_score, classification)
                    confidence_score = self._resolve_confidence_score(
                        payload=parsed,
                        state=state,
                        classification=classification,
                        evidence_table=evidence_table,
                        risk_score=risk_score,
                    )
                    return {
                        "classification": classification,
                        "final_score": risk_score,
                        "summary": parsed.get("summary", "Summary unavailable."),
                        "action": deterministic_action,
                        "recommended_action": llm_action,
                        "action_policy": "deterministic_risk_policy",
                        "confidence_score": confidence_score,
                        "confidence_rationale": str(
                            parsed.get("confidence_rationale")
                            or parsed.get("confidence_reason")
                            or parsed.get("confidence_explanation")
                            or self._fallback_confidence_rationale(classification, state)
                        ).strip(),
                        "evidence_table": evidence_table,
                        "mitre_techniques": parsed.get("mitre_techniques", []),
                        "journal": parsed.get("journal", []),
                    }
            else:
                 # If no braces found, the model failed completely
                 raise ValueError("No JSON object found in response")
        except Exception as e:
             self.last_error = str(e)
             deterministic_action = self._deterministic_action(risk_score, classification)
             confidence_score = self._fallback_confidence_score(
                 state=state,
                 classification=classification,
                 evidence_table=evidence_table,
             )
             return {
                 "classification": classification,
                 "final_score": risk_score,
                 "summary": f"Failed to generate decision json. Error: {e}",
                 "action": deterministic_action,
                 "recommended_action": "Escalate to Incident Response",
                 "action_policy": "deterministic_risk_policy",
                 "confidence_score": confidence_score,
                 "confidence_rationale": self._fallback_confidence_rationale(classification, state),
                 "evidence_table": evidence_table,
                 "mitre_techniques": [],
                 "journal": [],
             }

    def _detect_feedback_override(self, lessons: str) -> bool:
        if not lessons:
            return False
        lowered = lessons.lower()
        return "false positive" in lowered or "benign" in lowered or "not malicious" in lowered

    @staticmethod
    def _normalize_confidence(value):
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            return None
        if 0.0 <= numeric <= 1.0:
            numeric *= 100.0
        return round(max(0.0, min(100.0, numeric)), 1)

    @classmethod
    def _fallback_confidence_score(cls, state: InvestigationState, classification: str, evidence_table: list) -> float:
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
        payload: dict,
        state: InvestigationState,
        classification: str,
        evidence_table: list,
        risk_score,
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
    def _deterministic_action(risk_score, classification: str) -> str:
        try:
            score = float(risk_score)
        except (TypeError, ValueError):
            score = 0.0
        cls = str(classification or "").strip().lower()

        if cls == "benign":
            return "Close"
        if cls == "malicious":
            return "Escalate to Incident Response" if score >= 70.0 else "Block Asset/User"
        if score >= 80.0:
            return "Escalate to Incident Response"
        if score >= 60.0:
            return "Block Asset/User"
        return "Close"
