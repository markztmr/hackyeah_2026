"""Pickle opcode scanner. Spec section 9 'Model file scanner'. Owner: Person 2.

``python -m gateway.cli.scan_model <path>`` scans a pickle file, or a zip archive (the
PyTorch ``.pt`` format) whose ``.pkl`` members are pickles, before the model is imported.
It only walks opcodes with ``pickletools.genops``; nothing is ever unpickled, so the
file's code cannot run. Every import is listed:

- ``GLOBAL`` and ``INST`` carry ``module name`` in the opcode argument;
- ``STACK_GLOBAL`` takes module and name from the stack, so a small stack simulation
  tracks string pushes and the memo (``PUT``/``GET``/``MEMOIZE``) to resolve them;
- ``EXT1``/``EXT2``/``EXT4`` import through the copyreg extension registry, which the
  scanner cannot see.

An import is allowed only if its module is in ``ALLOWED_MODULES`` (or a submodule) and
it is not a known code-execution or nested-load entry point inside those packages
(``DENIED``). Unresolvable imports, extension codes, malformed pickles, oversized
members and archives without pickles all fail (deny by default).

Exit codes: 0 every import allowed, 1 a disallowed or unresolved import, 2 the file
could not be scanned.
"""
from __future__ import annotations

import argparse
import pickletools
import sys
import zipfile
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

ALLOWED_MODULES: tuple[str, ...] = ("torch", "numpy", "collections", "_codecs")
# Inside allowed packages: entry points that execute code or load another pickle.
DENIED_MODULE_PREFIXES: tuple[str, ...] = ("numpy.testing", "numpy.f2py", "numpy.distutils", "torch.hub",
                                           "torch.package", "torch.jit", "torch.utils.cpp_extension")
DENIED_NAMES: frozenset[str] = frozenset({"load", "loads", "runstring", "exec", "eval", "compile", "system",
                                          "popen", "__import__", "import_module", "load_library"})
MAX_PICKLE_BYTES = 64 * 1024 * 1024  # a model's data.pkl is small; tensors live in other members
_STRING_OPS = frozenset({"STRING", "BINSTRING", "SHORT_BINSTRING", "UNICODE", "BINUNICODE",
                         "SHORT_BINUNICODE", "BINUNICODE8"})
_PUT_OPS = frozenset({"PUT", "BINPUT", "LONG_BINPUT"})
_GET_OPS = frozenset({"GET", "BINGET", "LONG_BINGET"})
_EXT_OPS = frozenset({"EXT1", "EXT2", "EXT4"})
_MARK, _UNKNOWN = object(), object()


class ScanError(ValueError):
    """The file cannot be scanned (unreadable, not a pickle, too large)."""


@dataclass(frozen=True, slots=True)
class Import:
    """One import found in a pickle. ``module``/``name`` are None when the scanner cannot resolve them."""

    member: str
    offset: int
    opcode: str
    module: str | None
    name: str | None

    @property
    def allowed(self) -> bool:
        return is_allowed(self.module, self.name)

    def describe(self) -> str:
        what = f"{self.module}.{self.name}" if self.module is not None and self.name is not None else "<unresolved>"
        return f"{'ok     ' if self.allowed else 'BLOCKED'} {self.member}@{self.offset} {self.opcode} {what}"


@dataclass(slots=True)
class ScanReport:
    path: str
    imports: list[Import] = field(default_factory=list)
    members: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def blocked(self) -> list[Import]:
        return [i for i in self.imports if not i.allowed]

    @property
    def safe(self) -> bool:
        return not self.blocked


def is_allowed(module: str | None, name: str | None) -> bool:
    """Module in the allowlist (or a submodule of it), and not a denied entry point."""
    if not module or not name:
        return False
    if not any(module == m or module.startswith(m + ".") for m in ALLOWED_MODULES):
        return False
    if any(module == d or module.startswith(d + ".") for d in DENIED_MODULE_PREFIXES):
        return False
    return not any(part in DENIED_NAMES for part in name.split("."))


def _text(arg: object) -> object:
    if isinstance(arg, bytes):
        return arg.decode("latin-1")
    return arg


def _pop(stack: list[object], n: int) -> list[object]:
    if n > len(stack):
        raise ScanError("Malformed pickle: stack underflow.")
    if n == 0:
        return []
    items = stack[-n:]
    del stack[-n:]
    if any(i is _MARK for i in items):
        raise ScanError("Malformed pickle: unexpected mark.")
    return items


def _pop_to_mark(stack: list[object]) -> None:
    for i in range(len(stack) - 1, -1, -1):
        if stack[i] is _MARK:
            del stack[i:]
            return
    raise ScanError("Malformed pickle: missing mark.")


def scan_pickle(data: bytes, member: str = "<file>") -> tuple[list[Import], int]:
    """Imports in one pickle starting at the beginning of ``data``, and the offset after its STOP."""
    imports: list[Import] = []
    stack: list[object] = []
    memo: dict[object, object] = {}
    end = None
    try:
        for op, arg, pos in pickletools.genops(data):
            name = op.name
            if name in ("GLOBAL", "INST"):
                module, _, attr = str(_text(arg)).partition(" ")
                imports.append(Import(member, pos, name, module or None, attr or None))
            elif name == "STACK_GLOBAL":
                module, attr = _pop(stack, 2)
                ok = isinstance(module, str) and isinstance(attr, str)
                imports.append(Import(member, pos, name, module if ok else None, attr if ok else None))  # type: ignore[arg-type]
                stack.append(_UNKNOWN)
                continue
            elif name in _EXT_OPS:
                imports.append(Import(member, pos, name, None, None))
            if name in _STRING_OPS:
                stack.append(_text(arg))
            elif name in _PUT_OPS or name == "MEMOIZE":
                if not stack:
                    raise ScanError("Malformed pickle: memo store on an empty stack.")
                memo[arg if name != "MEMOIZE" else len(memo)] = stack[-1]
            elif name in _GET_OPS:
                stack.append(memo.get(arg, _UNKNOWN))
            elif name == "DUP":
                stack.append(_pop(stack, 1)[0])
                stack.append(stack[-1])
            elif name == "MARK":
                stack.append(_MARK)
            elif "mark" in [str(x) for x in op.stack_before]:
                _pop_to_mark(stack)
                _pop(stack, [str(x) for x in op.stack_before].index("mark"))
                stack.extend(_UNKNOWN for _ in op.stack_after)
            else:
                _pop(stack, len(op.stack_before))
                stack.extend(_UNKNOWN for _ in op.stack_after)
            if name == "STOP":
                end = pos + 1
    except ScanError:
        raise
    except Exception as e:  # noqa: BLE001 - anything genops rejects is not a scannable pickle
        raise ScanError(f"Not a valid pickle ({type(e).__name__}).") from None
    if end is None:
        raise ScanError("Not a valid pickle (no STOP opcode).")
    return imports, end


def scan_bytes(data: bytes, member: str = "<file>") -> tuple[list[Import], list[str]]:
    """Every pickle stored back to back in ``data`` (the legacy torch format has several).

    Bytes after the last complete pickle that are not a pickle are reported, not scanned:
    ``pickle.load`` reads pickles in sequence and cannot reach past them either.
    """
    if not data:
        raise ScanError("Empty file.")
    imports, offset = scan_pickle(data, member)
    notes: list[str] = []
    while offset < len(data):
        try:
            more, used = scan_pickle(data[offset:], member)
        except ScanError:
            notes.append(f"{member}: {len(data) - offset} trailing bytes are not a pickle (not scanned).")
            break
        imports += [Import(i.member, i.offset + offset, i.opcode, i.module, i.name) for i in more]
        offset += used
    return imports, notes


def _members(path: Path) -> Iterator[tuple[str, bytes]]:
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            if info.is_dir() or not info.filename.lower().endswith(".pkl"):
                continue
            if info.file_size > MAX_PICKLE_BYTES:
                raise ScanError(f"{info.filename}: member is too large to scan.")
            with z.open(info) as f:
                data = f.read(MAX_PICKLE_BYTES + 1)
            if len(data) > MAX_PICKLE_BYTES:
                raise ScanError(f"{info.filename}: member is too large to scan.")
            yield info.filename, data


def scan_file(path: str | Path) -> ScanReport:
    """Scan a pickle file or a zip archive of ``.pkl`` members. Raises ScanError if it cannot be scanned."""
    path = Path(path)
    report = ScanReport(str(path))
    try:
        if zipfile.is_zipfile(path):
            for member, data in _members(path):
                found, notes = scan_bytes(data, member)
                report.members.append(member)
                report.imports += found
                report.notes += notes
            if not report.members:
                raise ScanError("Archive contains no .pkl members to scan.")
            return report
        if path.stat().st_size > MAX_PICKLE_BYTES:
            raise ScanError("File is too large to scan.")
        found, notes = scan_bytes(path.read_bytes(), path.name)
    except (OSError, zipfile.BadZipFile) as e:
        raise ScanError(f"Cannot read {path.name} ({type(e).__name__}).") from None
    report.members.append(path.name)
    report.imports += found
    report.notes += notes
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m gateway.cli.scan_model",
                                     description="List every import in a pickle or .pt archive; never unpickles.")
    parser.add_argument("path")
    args = parser.parse_args(argv)
    out = sys.stdout
    try:
        report = scan_file(args.path)
    except ScanError as e:
        out.write(f"FAIL {args.path}: {e}\n")
        return 2
    for imp in report.imports:
        out.write(imp.describe() + "\n")
    for note in report.notes:
        out.write("note: " + note + "\n")
    blocked = report.blocked
    if blocked:
        out.write(f"FAIL {args.path}: {len(blocked)} of {len(report.imports)} import(s) outside the allowlist "
                  f"({', '.join(ALLOWED_MODULES)}).\n")
        return 1
    out.write(f"OK {args.path}: {len(report.imports)} import(s), all allowed.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
