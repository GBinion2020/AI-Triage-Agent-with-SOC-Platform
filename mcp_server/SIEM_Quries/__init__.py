from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module(module_name: str, file_name: str):
    base_dir = Path(__file__).resolve().parents[1] / "SIEM Quries"
    module_path = base_dir / file_name
    if not module_path.exists():
        raise ModuleNotFoundError(f"SIEM query module not found: {module_path}")

    spec = importlib.util.spec_from_file_location(f"mcp_server.SIEM_Quries.{module_name}", module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load SIEM query module: {module_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


process_tree = _load_module("process_tree", "process_tree.py")
network_beaconing = _load_module("network_beaconing", "network_beaconing.py")
persistence_hunt = _load_module("persistence_hunt", "persistence_hunt.py")
user_logons = _load_module("user_logons", "user_logons.py")
powershell_deep_dive = _load_module("powershell_deep_dive", "powershell_deep_dive.py")
file_tampering = _load_module("file_tampering", "file_tampering.py")
registry_monitor = _load_module("registry_monitor", "registry_monitor.py")
scheduled_tasks = _load_module("scheduled_tasks", "scheduled_tasks.py")
dns_trace = _load_module("dns_trace", "dns_trace.py")
security_events = _load_module("security_events", "security_events.py")

