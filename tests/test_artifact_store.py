from orchestrator.artifacts import ArtifactStore


def test_artifact_store_writes_json(tmp_path):
    store = ArtifactStore(alert_id="a1", run_id="r1", base_dir=str(tmp_path))
    ref = store.write_json("siem_specialist", "action_1", {"ok": True, "value": 123})

    assert ref.sha256
    assert ref.size_bytes > 0
    assert "action_1.json" in ref.path

    with open(ref.path, "r", encoding="utf-8") as handle:
        body = handle.read()

    assert '"ok": true' in body
