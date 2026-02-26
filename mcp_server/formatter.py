from typing import Any, Dict, List
import json

def _truncate(value: str, max_len: int = 300) -> str:
    if value is None:
        return ""
    if len(value) <= max_len:
        return value
    return value[:max_len] + "..."


def _compact_value(value: Any, depth: int = 0) -> Any:
    """
    Recursively remove empty/null-heavy branches and truncate noisy text values.
    """
    if depth > 5:
        return None

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        return _truncate(text, max_len=350)

    if isinstance(value, list):
        compacted = []
        for item in value:
            compact_item = _compact_value(item, depth + 1)
            if compact_item in (None, "", [], {}):
                continue
            compacted.append(compact_item)
        if not compacted:
            return None
        return compacted[:25]

    if isinstance(value, dict):
        compacted_dict: Dict[str, Any] = {}
        for key, item in value.items():
            compact_item = _compact_value(item, depth + 1)
            if compact_item in (None, "", [], {}):
                continue
            compacted_dict[key] = compact_item
        return compacted_dict or None

    return value

def _coalesce_iocs(events: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    iocs = {"ip": [], "domain": [], "hash": []}
    for event in events:
        for key in ("source_ip", "destination_ip"):
            val = event.get(key)
            if val and val not in iocs["ip"]:
                iocs["ip"].append(val)
        for key in ("dns_question", "url_full", "domain"):
            val = event.get(key)
            if val and val not in iocs["domain"]:
                iocs["domain"].append(val)
        for key in ("file_hash_sha256", "file_hash_md5", "file_hash_sha1"):
            val = event.get(key)
            if val and val not in iocs["hash"]:
                iocs["hash"].append(val)
    return iocs

def normalize_tool_output(tool_name: str, raw_result: Any) -> str:
    """
    Wraps raw tool output in a consistent schema-aligned structure.
    This helps agents understand depth and entity relationships.
    """
    
    # If it's already an error string, just return it
    if isinstance(raw_result, str) and raw_result.startswith("Error"):
        return raw_result

    # Base structure
    normalized = {
        "tool_metadata": {
            "name": tool_name,
            "interpretation": "technical_evidence"
        },
        "extracted_entities": {},
        "raw_data_summary": None
    }

    try:
        # If it's a string that looks like JSON, parse it
        if isinstance(raw_result, str):
            try:
                data = json.loads(raw_result)
            except:
                data = {"content": raw_result}
        else:
            data = raw_result

        # Tool-specific mapping
        if tool_name == "query_siem_host_logs":
            if isinstance(data, dict) and "events" in data:
                events = data.get("events", [])
                iocs = _coalesce_iocs(events)
                normalized["query_context"] = data.get("query_context", {})
                normalized["results"] = {
                    "count": data.get("results_count", 0),
                    "truncated": data.get("truncated", False)
                }
                normalized_events = _compact_value(events) or []
                normalized["key_events"] = normalized_events[:12] if isinstance(normalized_events, list) else []
                normalized["extracted_entities"]["iocs"] = iocs
                normalized["raw_data_summary"] = (
                    f"Gathered {data.get('results_count', 0)} log entries for host "
                    f"{data.get('query_context', {}).get('host_name', 'unknown')}."
                )
            else:
                normalized["extracted_entities"]["process_events"] = data
                normalized["raw_data_summary"] = (
                    f"Gathered {len(data) if isinstance(data, list) else 1} process/log entries."
                )
        
        elif tool_name == "query_recent_host_alerts":
            if isinstance(data, dict) and "alerts" in data:
                normalized["query_context"] = data.get("query_context", {})
                normalized["results"] = {
                    "count": data.get("results_count", 0)
                }
                compact_alerts = _compact_value(data.get("alerts", [])) or []
                normalized["alerts"] = compact_alerts[:20] if isinstance(compact_alerts, list) else []
                normalized["raw_data_summary"] = (
                    f"Gathered {data.get('results_count', 0)} alerts for host "
                    f"{data.get('query_context', {}).get('host_name', 'unknown')}."
                )
            else:
                normalized["data"] = _compact_value(data)
                normalized["raw_data_summary"] = "Alert search results retrieved."
        
        elif tool_name == "check_virustotal":
            normalized["extracted_entities"]["reputation"] = data
            normalized["raw_data_summary"] = "Reputation analysis retrieved."

        elif tool_name == "search_entra_logs":
            normalized["extracted_entities"]["identity_events"] = data
            normalized["raw_data_summary"] = "Identity/Auth logs retrieved."

        else:
            normalized["data"] = _compact_value(data)
            normalized["raw_data_summary"] = "Standard tool output retrieved."

        compact_normalized = _compact_value(normalized) or normalized
        return json.dumps(compact_normalized, indent=2)

    except Exception as e:
        return f"Normalization Error: {str(e)}\nRaw: {str(raw_result)[:500]}"
