"""The latency benchmark runs and reports every pipeline step. Spec section 14 'Telemetry check'. Owner: Person 4."""
from __future__ import annotations

from pathlib import Path

import pytest

from tests import bench


def test_fixed_prompt_set_has_twenty_plain_data_and_blocked_prompts() -> None:
    kinds = [p.kind for p in bench.prompts()]
    assert len(kinds) == 20
    assert (kinds.count("plain"), kinds.count("data"), kinds.count("blocked")) == (7, 7, 6)


def test_stub_bench_writes_a_markdown_table_per_step(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "bench_results.md"
    assert bench.main(["--out", str(out)]) == 0

    table = out.read_text(encoding="utf-8")
    assert table in capsys.readouterr().out
    assert "Mode: stub. 20 prompts (7 plain, 7 data, 6 blocked): 14 answered, 6 blocked." in table
    assert "| Step | Median ms | p95 ms | Requests |" in table
    for step in (*bench.STEPS, "total"):
        assert f"| {step} |" in table, step
    assert "| total |" in table and "| 20 |" in table
    assert "Unexpected verdicts" not in table  # every prompt got the verdict its kind expects


def test_every_scripted_prompt_gets_its_expected_verdict() -> None:
    result = bench.run()
    assert [v for _, v in result.verdicts] == [p.expect for p in bench.prompts()]
    for step, median, p95, count in result.rows:
        assert 0 <= median <= p95 and count > 0, step


def test_percentile_is_nearest_rank() -> None:
    values = [float(i) for i in range(1, 21)]
    assert (bench.percentile(values, 0.5), bench.percentile(values, 0.95)) == (10.0, 19.0)


def test_live_without_ollama_exits_with_a_message(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(bench, "ollama_up", lambda: False)
    out = tmp_path / "b.md"
    assert bench.main(["--live", "--out", str(out)]) == 2
    assert "Ollama is not running" in capsys.readouterr().err and not out.exists()


def test_bench_leaves_the_environment_as_it_found_it(audit_log: Path) -> None:
    import os

    bench.run()
    assert os.environ["ACL_AUDIT_PATH"] == str(audit_log)
    assert not audit_log.exists()  # the bench wrote to its own temp log
