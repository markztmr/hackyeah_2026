"""Signature feed update command (spec section 9 'Externally managed feed'). Owner: Person 2.

Every rejected feed must leave the installed signatures.json byte-for-byte untouched,
with no temp file left beside it.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from gateway.cli import fetch_feed as ff
from gateway.cli.fetch_feed import FetchError, feed_sha256, fetch_feed, main, verify
from gateway.inbound.signatures import FeedStore

REPO_ROOT = Path(__file__).resolve().parent.parent


def _repo_feed() -> dict[str, Any]:
    return json.loads((REPO_ROOT / "signatures.json").read_text(encoding="utf-8"))


def _feed(version: str = "2026-10-04.1", **changes: Any) -> dict[str, Any]:
    data = copy.deepcopy(_repo_feed())
    data["version"] = version
    data["sha256"] = feed_sha256(data["signatures"])
    data.update(changes)
    return data


def _raw(data: dict[str, Any]) -> bytes:
    return json.dumps(data, indent=2).encode("utf-8")


@pytest.fixture
def installed(tmp_path: Path) -> Path:
    """The feed the gateway is using, in its own directory (temp files would appear beside it)."""
    folder = tmp_path / "live"
    folder.mkdir()
    path = folder / "signatures.json"
    path.write_bytes((REPO_ROOT / "signatures.json").read_bytes())
    return path


@pytest.fixture
def source(tmp_path: Path) -> Path:
    return tmp_path / "download.json"


def _assert_untouched(installed: Path) -> None:
    assert installed.read_bytes() == (REPO_ROOT / "signatures.json").read_bytes()
    assert [p.name for p in installed.parent.iterdir()] == ["signatures.json"]


# ---------------------------------------------------------------------------
# Allowed
# ---------------------------------------------------------------------------


def test_valid_feed_replaces_signatures_json(installed: Path, source: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source.write_bytes(_raw(_feed()))
    assert main([str(source), "--dest", str(installed)]) == 0
    assert installed.read_bytes() == source.read_bytes()
    assert [p.name for p in installed.parent.iterdir()] == ["signatures.json"]
    assert "2026-10-04.1" in capsys.readouterr().out


def test_file_url_is_accepted(installed: Path, source: Path) -> None:
    source.write_bytes(_raw(_feed()))
    assert fetch_feed(source.as_uri(), installed).version == "2026-10-04.1"


def test_matching_out_of_band_hash_is_accepted(installed: Path, source: Path) -> None:
    raw = _raw(_feed())
    source.write_bytes(raw)
    assert main([str(source), "--dest", str(installed), "--sha256", "sha256:" + hashlib.sha256(raw).hexdigest()]) == 0


def test_gateway_feed_store_picks_up_the_new_version(installed: Path, source: Path) -> None:
    store = FeedStore(installed)
    assert store.snapshot().version == _repo_feed()["version"]
    source.write_bytes(_raw(_feed("2099-01-01.1")))
    fetch_feed(str(source), installed)
    os.utime(installed, ns=(installed.stat().st_atime_ns, installed.stat().st_mtime_ns + 10**9))
    assert store.snapshot().version == "2099-01-01.1"


def test_default_destination_is_the_feed_named_in_the_policy(policy: Path, source: Path) -> None:
    source.write_bytes(_raw(_feed()))
    fetch_feed(str(source))
    assert json.loads((policy.parent / "signatures.json").read_text(encoding="utf-8"))["version"] == "2026-10-04.1"


def test_repository_feed_carries_a_current_hash() -> None:
    """Editing signatures.json by hand needs a new sha256 (gateway.cli.fetch_feed.feed_sha256)."""
    assert verify((REPO_ROOT / "signatures.json").read_bytes()).signatures


# ---------------------------------------------------------------------------
# Rejected: the old file stays untouched
# ---------------------------------------------------------------------------


def test_wrong_hash_leaves_the_old_file_untouched(installed: Path, source: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source.write_bytes(_raw(_feed(sha256="0" * 64)))
    before = installed.stat().st_mtime_ns
    assert main([str(source), "--dest", str(installed)]) == 1
    _assert_untouched(installed)
    assert installed.stat().st_mtime_ns == before
    assert "sha256 does not match" in capsys.readouterr().out


def test_tampered_signatures_with_the_old_hash_are_rejected(installed: Path, source: Path) -> None:
    data = _feed()
    data["signatures"][0]["severity"] = "low"  # downgrade a blocking signature, keep the hash
    source.write_bytes(_raw(data))
    with pytest.raises(FetchError, match="sha256"):
        fetch_feed(str(source), installed)
    _assert_untouched(installed)


def test_wrong_out_of_band_hash_leaves_the_old_file_untouched(installed: Path, source: Path) -> None:
    source.write_bytes(_raw(_feed()))
    assert main([str(source), "--dest", str(installed), "--sha256", "ab" * 32]) == 1
    _assert_untouched(installed)


@pytest.mark.parametrize("data", [
    {"version": "x", "signatures": []},                                     # no sha256
    {"version": "", "sha256": feed_sha256([]), "signatures": []},           # no version
    {"version": "x", "sha256": feed_sha256({}), "signatures": {}},          # signatures not a list
    {"version": "x", "sha256": "sha256:<hash>", "signatures": []},          # placeholder hash
    {"version": "x", "sha256": feed_sha256([]), "signatures": []},          # empty: every signature off
])
def test_feed_missing_required_fields_is_rejected(installed: Path, source: Path, data: dict[str, Any]) -> None:
    source.write_bytes(_raw(data))
    with pytest.raises(FetchError):
        fetch_feed(str(source), installed)
    _assert_untouched(installed)


def test_schema_invalid_feed_with_a_correct_hash_is_rejected(installed: Path, source: Path) -> None:
    data = _feed()
    data["signatures"][0]["severity"] = "critical"
    data["sha256"] = feed_sha256(data["signatures"])
    source.write_bytes(_raw(data))
    with pytest.raises(FetchError, match="schema"):
        fetch_feed(str(source), installed)
    _assert_untouched(installed)


@pytest.mark.parametrize("raw", [b"", b"not json", b"[1, 2]", b"\xff\xfe"])
def test_garbage_download_is_rejected(installed: Path, source: Path, raw: bytes) -> None:
    source.write_bytes(raw)
    with pytest.raises(FetchError):
        fetch_feed(str(source), installed)
    _assert_untouched(installed)


def test_failed_rename_leaves_the_old_file_and_no_temp_file(
    installed: Path, source: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source.write_bytes(_raw(_feed()))

    def fail(src: str, dst: str) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(ff.os, "replace", fail)
    with pytest.raises(FetchError, match="Cannot write"):
        fetch_feed(str(source), installed)
    _assert_untouched(installed)


def test_missing_source_and_unsupported_scheme_are_rejected(installed: Path, tmp_path: Path) -> None:
    for url in (str(tmp_path / "nope.json"), "ftp://feeds.example/signatures.json"):
        with pytest.raises(FetchError):
            fetch_feed(url, installed)
    _assert_untouched(installed)


# ---------------------------------------------------------------------------
# HTTP download (faked; no network)
# ---------------------------------------------------------------------------


class _Response:
    def __init__(self, status: int, body: bytes) -> None:
        self.status_code, self._body = status, body

    def iter_bytes(self) -> Iterator[bytes]:
        for i in range(0, len(self._body), 1024):
            yield self._body[i:i + 1024]


def _serve(monkeypatch: pytest.MonkeyPatch, status: int, body: bytes) -> list[dict[str, Any]]:
    seen: list[dict[str, Any]] = []

    @contextmanager
    def stream(method: str, url: str, **kwargs: Any) -> Iterator[_Response]:
        seen.append({"method": method, "url": url, **kwargs})
        yield _Response(status, body)

    monkeypatch.setattr(ff.httpx, "stream", stream)
    return seen


def test_https_feed_is_downloaded_without_following_redirects(installed: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _serve(monkeypatch, 200, _raw(_feed()))
    assert fetch_feed("https://feeds.example.internal/ai-signatures", installed).version == "2026-10-04.1"
    assert seen[0]["follow_redirects"] is False and seen[0]["timeout"] > 0


@pytest.mark.parametrize("status", [301, 404, 500])
def test_non_200_download_is_rejected(installed: Path, monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    _serve(monkeypatch, status, _raw(_feed()))
    with pytest.raises(FetchError, match="HTTP"):
        fetch_feed("https://feeds.example.internal/ai-signatures", installed)
    _assert_untouched(installed)


def test_oversized_download_is_rejected(installed: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ff, "MAX_FEED_BYTES", 2048)
    _serve(monkeypatch, 200, _raw(_feed()))
    with pytest.raises(FetchError, match="too large"):
        fetch_feed("https://feeds.example.internal/ai-signatures", installed)
    _assert_untouched(installed)
