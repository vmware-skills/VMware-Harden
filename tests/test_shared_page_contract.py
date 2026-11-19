from vmware_harden.mcp import stig, tools


def test_stig_pagination_keeps_legacy_flags_and_adds_next_offset(monkeypatch):
    from vmware_harden.baselines import stig as baseline

    monkeypatch.setattr(baseline, "stig_catalog", lambda: [{"id": n} for n in range(5)])
    first = stig.list_stig_controls(limit=2, offset=0)
    last = stig.list_stig_controls(limit=2, offset=4)
    assert first["next_offset"] == 2
    assert last["next_offset"] is None
    assert last["truncated"] is False
    assert last["hint"] is None
    assert last["items"] == [{"id": 4}]


def test_no_snapshot_is_explicitly_terminal(tmp_path, monkeypatch):
    monkeypatch.setattr(tools, "_resolve_db", lambda: tmp_path / "empty.db")
    result = tools.list_violations(limit=2, offset=0)
    assert result["next_offset"] is None
    assert result["has_more"] is False
    assert result["snapshot"] is None
    assert result["violations"] == []
