import os
import logging
from datetime import datetime

try:
    import resend
except Exception:  # pragma: no cover - optional runtime dependency
    resend = None

logger = logging.getLogger("EnterpriseSOC.Email")

class EmailNotifier:
    """
    Handles sending structured triage reports via Resend SDK.
    """
    def __init__(self):
        # We'll use RE_SEND_KEY from .env
        self.api_key = os.getenv("RE_SEND_KEY")
        self.notify_email = os.getenv("NOTIFY_EMAIL")
        self.from_email = os.getenv("FROM_EMAIL", "onboarding@resend.dev")
        
        self.enabled = all([self.api_key, self.notify_email, resend is not None])
        
        if self.enabled:
            resend.api_key = self.api_key
        else:
            if resend is None:
                logger.warning("Email notifications are disabled because `resend` is not installed.")
            else:
                logger.warning("Email notifications (Resend SDK) are disabled. Please configure RE_SEND_KEY and NOTIFY_EMAIL in .env")

    def send_triage_report(self, alert_data: dict, triage_result: dict, journal: list, elapsed_time: float, ioc_list: list = []):
        """
        Formats and sends the triage report email using Resend SDK.
        """
        if not self.enabled:
            return

        try:
            # Format high-level alert details
            alert_name = alert_data.get('name', 'N/A')
            severity = alert_data.get('severity', 'N/A')
            tags = ", ".join(alert_data.get('tags', [])) if isinstance(alert_data.get('tags'), list) else str(alert_data.get('tags'))
            description = alert_data.get('description', 'N/A')
            
            # Format triage results
            classification = triage_result.get('classification', 'Unknown')
            final_score = triage_result.get('final_score', 'N/A')
            action = triage_result.get('action', 'N/A')
            summary = triage_result.get('summary', 'No summary provided.')
            evidence_table = triage_result.get('evidence_table', [])
            
            # Format journal
            journal_str = "\n".join([f"- {step}" for step in journal])

            def _source_display(raw_source: str) -> str:
                source = str(raw_source or "").strip()
                if not source:
                    return "Unknown"
                # Drop internal runtime suffixes such as "(w1_a2_xxxxxxxx)".
                if "(" in source:
                    source = source.split("(", 1)[0].strip()
                return source.replace("_", " ").strip().title()

            # Format IOCs
            if ioc_list:
                ioc_lines = []
                for ioc in ioc_list:
                    ioc_type = str(ioc.get("type", "")).upper() or "IOC"
                    value = str(ioc.get("value", "")).strip()
                    if not value:
                        continue
                    source = _source_display(ioc.get("source", ""))
                    ioc_lines.append(f"- [{ioc_type}] {value} (Source: {source})")
                ioc_str = "\n".join(ioc_lines) if ioc_lines else "No specific IOCs flagged."
            else:
                ioc_str = "No specific IOCs flagged."

            # Format evidence table (no scoring mechanics)
            if evidence_table:
                evidence_lines = []
                for row in evidence_table:
                    evidence_lines.append(
                        f"- {row.get('category', 'Unknown')}: {row.get('evidence', 'N/A')}"
                    )
                evidence_str = "\n".join(evidence_lines)
            else:
                evidence_str = "No evidence table entries provided."
            
            # Build the template
            body = f"""**Alert Name:** {alert_name}
**Severity:** {severity}
**Tags:** {tags}
**Description:** {description}
--------------------------------------------
Found Indicators (IOCs)
--------------------------------------------
{ioc_str}

--------------------------------------------
LLM Triage Agent
--------------------------------------------
**Classification:** {classification}
**Final Score:** {final_score}
**Action:** {action}
**Investigation Summary:** {summary}

--------------------------------------------
Evidence Table
--------------------------------------------
{evidence_str}

---------------------------------------------
**LLM-Triage time:** {elapsed_time:.2f}s
**Triage Journal:**
{journal_str}
"""

            # Resend SDK Email Send
            params = {
                "from": self.from_email,
                "to": self.notify_email,
                "subject": f"[{classification}] SOC Triage Report: {alert_name}",
                "text": body
            }
            
            email = resend.Emails.send(params)
            
            if email and 'id' in email:
                logger.info(f"Triage report email sent to {self.notify_email} via Resend SDK (ID: {email['id']})")
            else:
                logger.error(f"Resend SDK failed to return a valid email ID: {email}")
                
        except Exception as e:
            logger.error(f"Failed to send triage report email via Resend SDK: {e}")
