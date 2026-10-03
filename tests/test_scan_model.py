"""Model file scanner (spec section 9 'Model file scanner', section 14 test_scan_model.py). Owner: Person 2.

Fixtures are generated in a temp dir with ``pickle.dumps`` (which never runs
``__reduce__``'s callable). Nothing here, and nothing in the scanner, ever unpickles:
``test_scanner_never_unpickles`` makes every unpickling entry point raise.
"""
from __future__ import annotations

import ast
import collections
import os
import pickle
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from gateway.cli import scan_model
from gateway.cli.scan_model import ScanError, is_allowed, main, scan_bytes, scan_file

REPO_ROOT = Path(__file__).resolve().parent.parent
PROTOCOLS = range(0, pickle.HIGHEST_PROTOCOL + 1)


class Malicious:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (os.system, ("echo pwned",))


SAFE = {"weights": [0.1, 0.2], "meta": collections.OrderedDict(layers=2), "raw": b"\x00\x01"}
SYSTEM_MODULE = os.system.__module__  # "nt" on Windows, "posix" elsewhere


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _zip(tmp_path: Path, name: str, members: dict[str, bytes]) -> Path:
    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as z:
        for member, data in members.items():
            z.writestr(member, data)
    return path


def _imports(data: bytes) -> list[tuple[str, str | None, str | None]]:
    return [(i.opcode, i.module, i.name) for i in scan_bytes(data)[0]]


@pytest.fixture(autouse=True)
def no_unpickling(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every unpickling entry point raises: a scanner that loads would fail these tests."""
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("The scanner must never unpickle.")

    for name in ("load", "loads", "Unpickler"):
        monkeypatch.setattr(pickle, name, refuse)
    import _pickle

    for name in ("load", "loads", "Unpickler"):
        monkeypatch.setattr(_pickle, name, refuse)


# ---------------------------------------------------------------------------
# Allowed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_safe_pickle_of_a_dict_passes(tmp_path: Path, protocol: int, capsys: pytest.CaptureFixture[str]) -> None:
    path = _write(tmp_path, "safe.pkl", pickle.dumps(SAFE, protocol=protocol))
    assert main([str(path)]) == 0
    out = capsys.readouterr().out
    assert "collections.OrderedDict" in out
    assert out.strip().splitlines()[-1].startswith("OK ")


def test_safe_torch_style_archive_passes(tmp_path: Path) -> None:
    path = _zip(tmp_path, "model.pt", {
        "archive/data.pkl": pickle.dumps(SAFE, protocol=2),
        "archive/data/0": b"\x00" * 64,  # tensor storage: not a pickle, not scanned
        "archive/version": b"3\n",
    })
    report = scan_file(path)
    assert report.safe
    assert report.members == ["archive/data.pkl"]


@pytest.mark.parametrize("data", [
    b"ctorch._utils\n_rebuild_tensor_v2\n.",
    b"cnumpy.core.multiarray\n_reconstruct\n.",
    b"c_codecs\nencode\n.",
    b"ccollections\nOrderedDict\n.",
])
def test_allowlisted_imports_pass(data: bytes) -> None:
    imports, _ = scan_bytes(data)
    assert len(imports) == 1 and imports[0].allowed


# ---------------------------------------------------------------------------
# Blocked
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_pickle_whose_reduce_calls_os_system_fails(
    tmp_path: Path, protocol: int, capsys: pytest.CaptureFixture[str],
) -> None:
    path = _write(tmp_path, "evil.pkl", pickle.dumps(Malicious(), protocol=protocol))
    assert main([str(path)]) == 1
    out = capsys.readouterr().out
    assert "BLOCKED evil.pkl@" in out and f"{SYSTEM_MODULE}.system" in out
    assert out.strip().splitlines()[-1].startswith("FAIL ")


def test_global_and_stack_global_are_both_listed() -> None:
    assert _imports(pickle.dumps(Malicious(), protocol=2)) == [("GLOBAL", SYSTEM_MODULE, "system")]
    assert _imports(pickle.dumps(Malicious(), protocol=4)) == [("STACK_GLOBAL", SYSTEM_MODULE, "system")]


def test_archive_with_a_malicious_member_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _zip(tmp_path, "model.pt", {
        "archive/data.pkl": pickle.dumps(SAFE, protocol=2),
        "archive/extra.pkl": pickle.dumps(Malicious(), protocol=4),
    })
    assert main([str(path)]) == 1
    out = capsys.readouterr().out
    assert "ok      archive/data.pkl" in out
    assert "BLOCKED archive/extra.pkl@" in out


def test_stack_global_names_fetched_from_the_memo_are_resolved() -> None:
    data = (b"\x80\x04"
            b"\x8c\x02os\x94"          # SHORT_BINUNICODE 'os', MEMOIZE -> memo[0]
            b"\x8c\x06system\x94"      # memo[1]
            b"00"                      # POP, POP: the names are no longer on the stack
            b"h\x00h\x01\x93.")        # BINGET 0, BINGET 1, STACK_GLOBAL, STOP
    assert _imports(data) == [("STACK_GLOBAL", "os", "system")]


def test_stack_global_with_unresolvable_names_fails() -> None:
    imports, _ = scan_bytes(b"\x80\x04NN\x93.")
    assert [(i.module, i.name, i.allowed) for i in imports] == [(None, None, False)]


def test_inst_opcode_import_is_listed_and_fails() -> None:
    imports, _ = scan_bytes(b"(S'echo pwned'\nios\nsystem\n.")
    assert [(i.opcode, i.module, i.name, i.allowed) for i in imports] == [("INST", "os", "system", False)]


def test_extension_registry_import_fails() -> None:
    imports, _ = scan_bytes(b"\x80\x02\x82\x01.")
    assert [(i.opcode, i.allowed) for i in imports] == [("EXT1", False)]


@pytest.mark.parametrize("data", [
    b"cnumpy.testing._private.utils\nrunstring\n.",  # exec inside an allowed package
    b"ctorch\nload\n.",                             # nested pickle load
    b"ctorch.hub\nload_state_dict_from_url\n.",
    b"cnumpy\nload\n.",
])
def test_code_execution_entry_points_inside_allowed_packages_fail(data: bytes) -> None:
    assert not scan_bytes(data)[0][0].allowed


@pytest.mark.parametrize("module", ["torchvision", "numpyx", "collections_evil", "_codecs2", "builtins", "subprocess"])
def test_module_prefix_lookalikes_fail(module: str) -> None:
    assert not is_allowed(module, "OrderedDict")


def test_a_second_pickle_after_a_safe_one_is_scanned(tmp_path: Path) -> None:
    path = _write(tmp_path, "legacy.pt", pickle.dumps(SAFE, protocol=2) + pickle.dumps(Malicious(), protocol=2))
    assert main([str(path)]) == 1


def test_trailing_bytes_that_are_not_a_pickle_are_reported_not_scanned(tmp_path: Path) -> None:
    path = _write(tmp_path, "legacy.pt", pickle.dumps(SAFE, protocol=2) + b"\xff\x00raw tensor bytes")
    report = scan_file(path)
    assert report.safe
    assert report.notes and "not scanned" in report.notes[0]


@pytest.mark.parametrize("data", [b"", b"not a pickle at all", b"\x80\x04\x8c\x02os"])
def test_unreadable_or_truncated_pickle_cannot_pass(tmp_path: Path, data: bytes) -> None:
    assert main([str(_write(tmp_path, "bad.pkl", data))]) == 2


def test_archive_without_pickle_members_cannot_pass(tmp_path: Path) -> None:
    assert main([str(_zip(tmp_path, "model.zip", {"weights.bin": b"\x00" * 16}))]) == 2


def test_oversized_member_is_not_scanned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scan_model, "MAX_PICKLE_BYTES", 16)
    path = _zip(tmp_path, "model.pt", {"archive/data.pkl": pickle.dumps(SAFE, protocol=2)})
    with pytest.raises(ScanError):
        scan_file(path)


def test_missing_file_cannot_pass(tmp_path: Path) -> None:
    assert main([str(tmp_path / "nope.pkl")]) == 2


# ---------------------------------------------------------------------------
# Never unpickle
# ---------------------------------------------------------------------------


def test_scanner_never_unpickles(tmp_path: Path) -> None:
    """With every unpickling entry point raising (autouse fixture), the scan still completes."""
    marker = tmp_path / "pwned"

    class Touch:
        def __reduce__(self) -> tuple[object, tuple[str]]:
            return (os.system, (f'echo pwned > "{marker}"',))

    assert main([str(_write(tmp_path, "evil.pkl", pickle.dumps(Touch(), protocol=4)))]) == 1
    assert not marker.exists()


def test_no_gateway_module_calls_pickle_load() -> None:
    """Source check: nothing under gateway/ imports pickle or calls a load/Unpickler on it."""
    offenders = []
    for path in (REPO_ROOT / "gateway").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) and any(a.name in ("pickle", "_pickle", "dill") for a in node.names):
                offenders.append(f"{path.name}: import")
            if isinstance(node, ast.ImportFrom) and node.module in ("pickle", "_pickle", "dill"):
                offenders.append(f"{path.name}: from-import")
            if isinstance(node, ast.Attribute) and node.attr in ("load", "loads", "Unpickler") \
                    and isinstance(node.value, ast.Name) and node.value.id in ("pickle", "_pickle", "dill", "torch"):
                offenders.append(f"{path.name}: {node.value.id}.{node.attr}")
    assert offenders == []


def test_cli_entry_point_exits_non_zero_on_a_malicious_file(tmp_path: Path) -> None:
    path = _write(tmp_path, "evil.pkl", pickle.dumps(Malicious(), protocol=4))
    r = subprocess.run([sys.executable, "-m", "gateway.cli.scan_model", str(path)],
                       cwd=REPO_ROOT, capture_output=True, text=True, timeout=60)
    assert r.returncode == 1
    assert f"{SYSTEM_MODULE}.system" in r.stdout
