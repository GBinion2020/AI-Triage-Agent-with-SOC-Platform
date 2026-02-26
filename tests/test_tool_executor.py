import json

from tools.executor import ToolExecutor


def test_tool_executor_routes_osint(monkeypatch):
    def fake_safe_search_indicator(indicator: str, max_results: int = 3):
        return {
            "status": "ok",
            "provider": "fake",
            "results": [{"title": indicator, "url": "https://cisa.gov", "snippet": "test"}],
            "max_results": max_results,
        }

    monkeypatch.setattr("tools.executor.osint.safe_search_indicator", fake_safe_search_indicator)

    result = ToolExecutor().execute(
        "safe_search_osint",
        {"indicator": "example.com", "max_results": 2},
    )
    payload = json.loads(result)
    assert payload["tool_metadata"]["name"] == "safe_search_osint"
    assert payload["data"]["status"] == "ok"
