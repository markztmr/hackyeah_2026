"""Download, verify, replace signatures.json. Spec section 9 'Externally managed feed'. Owner: Person 2.

``python -m gateway.cli.fetch_feed <url> [--dest PATH] [--sha256 HEX]``

1. Download: ``http(s)://`` (no redirects, size-capped), ``file://`` or a local path
   (at the hackathon the source is a local file).
2. Verify: the feed's ``sha256`` field must equal ``feed_sha256(signatures)``, the hash
   of the canonical JSON of the ``signatures`` array (sorted keys, no spaces, UTF-8). With
   ``--sha256`` the whole downloaded file must also match a hash obtained out of band:
   the embedded hash only detects corruption, the out-of-band one also detects tampering.
3. Validate: ``version`` and at least one signature are required, then the gateway's
   own ``parse_feed`` schema.
4. Replace atomically: write a temp file beside the destination, fsync, ``os.replace``.
   Any failure leaves the old file untouched; the gateway picks up the new one by mtime.

Exit codes: 0 replaced, 1 rejected (nothing written).
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import url2pathname

import httpx

from gateway.inbound.signatures import FeedError, parse_feed
from gateway.models import SignatureFeed
from gateway.policy.loader import load_policy, policy_path, setting

MAX_FEED_BYTES = 5 * 1024 * 1024
TIMEOUT_S = 10.0


class FetchError(ValueError):
    """The feed was not installed. Messages never contain feed patterns."""


def feed_sha256(signatures: Any) -> str:
    """Hex sha256 of the canonical JSON of the ``signatures`` array (what the feed's ``sha256`` field holds)."""
    canonical = json.dumps(signatures, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _hex(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    s = value.strip().lower().removeprefix("sha256:")
    return s if len(s) == 64 and all(c in "0123456789abcdef" for c in s) else None


def download(url: str, *, timeout_s: float = TIMEOUT_S) -> bytes:
    """Bytes of the feed at ``url``: http(s), file:// or a local path; at most MAX_FEED_BYTES."""
    scheme = urlparse(url).scheme.lower()
    if scheme in ("http", "https"):
        try:
            with httpx.stream("GET", url, timeout=timeout_s, follow_redirects=False) as r:
                if r.status_code != 200:
                    raise FetchError(f"Download failed: HTTP {r.status_code}.")
                data = bytearray()
                for chunk in r.iter_bytes():
                    data += chunk
                    if len(data) > MAX_FEED_BYTES:
                        raise FetchError("Feed is too large.")
                return bytes(data)
        except httpx.HTTPError as e:
            raise FetchError(f"Download failed ({type(e).__name__}).") from None
    if scheme == "file":
        path = Path(url2pathname(urlparse(url).path))
    elif scheme == "" or (len(scheme) == 1 and os.name == "nt"):  # a path, or a Windows drive letter
        path = Path(url)
    else:
        raise FetchError("Unsupported feed URL scheme.")
    try:
        if path.stat().st_size > MAX_FEED_BYTES:
            raise FetchError("Feed is too large.")
        return path.read_bytes()
    except OSError as e:
        raise FetchError(f"Cannot read the feed file ({type(e).__name__}).") from None


def verify(raw: bytes, *, expected_sha256: str | None = None) -> SignatureFeed:
    """Hash checks, then schema validation. Raises FetchError; returns the parsed feed."""
    if expected_sha256 is not None:
        want = _hex(expected_sha256)
        if want is None:
            raise FetchError("--sha256 is not a sha256 hex value.")
        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), want):
            raise FetchError("Feed file sha256 does not match the expected hash.")
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError):
        raise FetchError("Feed is not valid JSON.") from None
    if not isinstance(data, dict):
        raise FetchError("Feed must be a JSON object.")
    if not isinstance(data.get("version"), str) or not data["version"].strip():
        raise FetchError("Feed has no version.")
    if not isinstance(data.get("signatures"), list):
        raise FetchError("Feed has no signatures list.")
    if not data["signatures"]:
        raise FetchError("Feed has no signatures; an empty feed would switch every signature off.")
    embedded = _hex(data.get("sha256"))
    if embedded is None:
        raise FetchError("Feed has no valid sha256 field.")
    if not hmac.compare_digest(feed_sha256(data["signatures"]), embedded):
        raise FetchError("Feed sha256 does not match its signatures.")
    try:
        return parse_feed(raw)
    except FeedError as e:
        raise FetchError(f"Feed schema is invalid: {e}") from None


def replace_atomically(dest: Path, raw: bytes) -> None:
    """Write ``raw`` to a temp file in dest's directory, fsync, then rename over ``dest``."""
    fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix="." + dest.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, dest)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def default_dest() -> Path:
    """``prompt_controls.signatures.feed`` of the active policy, relative to the policy file."""
    path = policy_path()
    feed = Path(setting(load_policy(path), "prompt_controls.signatures.feed"))
    return feed if feed.is_absolute() else Path(path).parent / feed


def fetch_feed(url: str, dest: str | Path | None = None, *, expected_sha256: str | None = None) -> SignatureFeed:
    """Download, verify, validate, replace. Raises FetchError and leaves ``dest`` untouched on any failure."""
    target = Path(dest) if dest is not None else default_dest()
    raw = download(url)
    feed = verify(raw, expected_sha256=expected_sha256)
    try:
        replace_atomically(target, raw)
    except OSError as e:
        raise FetchError(f"Cannot write the feed ({type(e).__name__}).") from None
    return feed


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m gateway.cli.fetch_feed",
                                     description="Download, verify and atomically install a signature feed.")
    parser.add_argument("url", help="http(s)://, file:// URL or local path of the feed")
    parser.add_argument("--dest", help="file to replace (default: the feed named in the active policy)")
    parser.add_argument("--sha256", dest="expected", help="expected sha256 of the whole file, obtained out of band")
    args = parser.parse_args(argv)
    try:
        feed = fetch_feed(args.url, args.dest, expected_sha256=args.expected)
    except FetchError as e:
        sys.stdout.write(f"FAIL: {e} The existing feed was not changed.\n")
        return 1
    sys.stdout.write(f"OK: installed feed {feed.version} ({len(feed.signatures)} signatures).\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
