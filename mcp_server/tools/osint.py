from __future__ import annotations

import ipaddress
import os
from typing import Dict, List
from urllib.parse import urlparse

import requests

TRUSTED_OSINT_DOMAINS = {
    "cisa.gov",
    "attack.mitre.org",
    "microsoft.com",
    "security.microsoft.com",
    "virustotal.com",
    "abuseipdb.com",
    "crowdstrike.com",
    "talosintelligence.com",
    "unit42.paloaltonetworks.com",
}


def safe_search_indicator(indicator: str, max_results: int = 3) -> dict:
    """Safely search public internet intelligence for an indicator using configured APIs."""
    value = (indicator or "").strip()
    if not value:
        return {"status": "error", "message": "indicator is required", "results": []}

    if _is_internal_ip(value):
        return {
            "status": "skipped",
            "message": f"Indicator {value} is internal/non-routable and was not searched.",
            "results": [],
        }

    max_results = max(1, min(5, int(max_results)))

    brave_key = os.getenv("BRAVE_SEARCH_API_KEY", "").strip()
    serpapi_key = os.getenv("SERPAPI_API_KEY", "").strip()

    if brave_key:
        return {
            "status": "ok",
            "provider": "brave",
            "results": _search_brave(value, brave_key, max_results),
        }

    if serpapi_key:
        return {
            "status": "ok",
            "provider": "serpapi",
            "results": _search_serpapi(value, serpapi_key, max_results),
        }

    if os.getenv("OSINT_ENABLE_DUCKDUCKGO", "false").strip().lower() == "true":
        return {
            "status": "ok",
            "provider": "duckduckgo",
            "results": _search_duckduckgo(value, max_results),
        }

    return {
        "status": "skipped",
        "message": "No OSINT provider credentials configured.",
        "results": [],
    }


def _search_brave(query: str, api_key: str, max_results: int) -> List[Dict[str, str]]:
    headers = {
        "Accept": "application/json",
        "X-Subscription-Token": api_key,
    }
    params = {
        "q": query,
        "count": max_results,
        "safesearch": "strict",
    }
    resp = requests.get(
        "https://api.search.brave.com/res/v1/web/search",
        headers=headers,
        params=params,
        timeout=20,
    )
    resp.raise_for_status()
    payload = resp.json()

    results: List[Dict[str, str]] = []
    for item in (payload.get("web") or {}).get("results", [])[:max_results]:
        url = item.get("url", "")
        if _is_trusted_url(url):
            results.append(
                {
                    "title": item.get("title", ""),
                    "url": url,
                    "snippet": item.get("description", ""),
                }
            )

    return results


def _search_serpapi(query: str, api_key: str, max_results: int) -> List[Dict[str, str]]:
    params = {
        "engine": "google",
        "q": query,
        "num": max_results,
        "safe": "active",
        "api_key": api_key,
    }
    resp = requests.get("https://serpapi.com/search.json", params=params, timeout=20)
    resp.raise_for_status()
    payload = resp.json()

    results: List[Dict[str, str]] = []
    for item in payload.get("organic_results", [])[:max_results]:
        url = item.get("link", "")
        if _is_trusted_url(url):
            results.append(
                {
                    "title": item.get("title", ""),
                    "url": url,
                    "snippet": item.get("snippet", ""),
                }
            )

    return results


def _search_duckduckgo(query: str, max_results: int) -> List[Dict[str, str]]:
    params = {
        "q": query,
        "format": "json",
        "no_html": "1",
        "skip_disambig": "1",
    }
    resp = requests.get("https://api.duckduckgo.com/", params=params, timeout=20)
    resp.raise_for_status()
    payload = resp.json()

    results: List[Dict[str, str]] = []
    abstract_url = payload.get("AbstractURL", "")
    if abstract_url and _is_trusted_url(abstract_url):
        results.append(
            {
                "title": payload.get("Heading", "DuckDuckGo"),
                "url": abstract_url,
                "snippet": payload.get("AbstractText", ""),
            }
        )

    for topic in payload.get("RelatedTopics", [])[:max_results]:
        if isinstance(topic, dict):
            url = topic.get("FirstURL", "")
            if url and _is_trusted_url(url):
                results.append(
                    {
                        "title": topic.get("Text", ""),
                        "url": url,
                        "snippet": topic.get("Text", ""),
                    }
                )

    return results[:max_results]


def _is_internal_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _is_trusted_url(url: str) -> bool:
    trusted_only = os.getenv("OSINT_TRUSTED_DOMAINS_ONLY", "true").strip().lower() != "false"
    if not trusted_only:
        return True

    host = urlparse(url).hostname or ""
    host = host.lower()
    return any(host == domain or host.endswith(f".{domain}") for domain in TRUSTED_OSINT_DOMAINS)
