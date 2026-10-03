"""Injection phrase list (EN + PL) and client tool definition scan. Spec section 4 steps 3d and 4. Owner: Person 2.

Implemented by Person 1. Phrases are matched on normalized text: Unicode
compatibility forms folded (full-width letters), zero-width and other format
characters removed, common Cyrillic/Greek look-alike letters folded to Latin,
diacritics stripped (including Polish ł), lower case, punctuation and runs of
whitespace collapsed to one space. Two more variants are tried: common digit
substitutions undone (1gn0re -> ignore) and runs of single letters joined
(i-g-n-o-r-e -> ignore).

Decisions name a rule ID and a neutral label, never the phrase itself: a block
message the client resends as history must not trigger the check again.

This is the cheap deterministic layer; paraphrases are left to the judge model.
"""
from __future__ import annotations

import re
import time
import unicodedata
from typing import Any

from gateway.inbound.masker import find_sensitive
from gateway.inbound.signatures import match_signatures
from gateway.models import Decision, Policy, SignatureFeed
from gateway.policy.loader import setting

QUERY_DATA = "query_data"

_FOLD = str.maketrans({
    "ł": "l", "Ł": "l", "ß": "ss", "ø": "o", "đ": "d", "ı": "i",
    # Cyrillic look-alikes
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "ӏ": "l", "к": "k", "м": "m", "т": "t", "в": "b", "н": "h",
    "А": "a", "В": "b", "Е": "e", "К": "k", "М": "m", "Н": "h", "О": "o", "Р": "p", "С": "c", "Т": "t",
    "Х": "x", "І": "i", "Ј": "j", "Ѕ": "s",
    # Greek look-alikes
    "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ρ": "p", "τ": "t", "υ": "u",
    "Ο": "o", "Α": "a", "Ε": "e", "Ι": "i", "Κ": "k", "Ν": "n", "Ρ": "p", "Τ": "t", "Υ": "y",
})
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_SPACED = re.compile(r"(?<!\S)(?:\w ){2,}\w(?!\S)")  # "i g n o r e": three or more single characters


def normalize(text: str) -> str:
    """Case-, diacritic-, width-, look-alike- and spacing-insensitive form of ``text`` for phrase matching."""
    text = "".join(c for c in unicodedata.normalize("NFKD", text.translate(_FOLD))
                   if not unicodedata.combining(c) and unicodedata.category(c) != "Cf")
    text = text.translate(_FOLD).lower()
    return " ".join(re.sub(r"[^\w@$]+|_", " ", text).split())


def _variants(text: str) -> tuple[str, ...]:
    norm = normalize(text)
    leet = norm.translate(_LEET)
    return (norm, leet, _SPACED.sub(lambda m: m.group(0).replace(" ", ""), leet))


# (rule id, neutral label, pattern on normalized text). Labels must not match any pattern.
_W = r"(?:\w+ ){0,3}"  # up to three filler words: "ignore ALL OF THE previous instructions"
_PHRASES: tuple[tuple[str, str, str], ...] = (
    # English
    ("INJ-EN-01", "instruction override", rf"\b(?:ignore|disregard|override) {_W}(?:previous|prior|above|earlier|preceding|initial|original|system|your|all) (?:instructions?|rules|prompts?|directions|guidelines)\b"),
    ("INJ-EN-02", "context wipe", r"\b(?:ignore|disregard|forget) (?:everything|all|anything) (?:above|before|prior|previously said|you were told)\b"),
    ("INJ-EN-03", "instruction wipe", r"\bforget (?:about )?(?:all |everything )?(?:of )?(?:your|previous|prior|earlier|the previous|the above|the earlier|the system) (?:\w+ )?(?:instructions?|rules|guidelines|programming|training)\b"),
    # "you are now" and "system prompt" need context, so "you are now able to..." and
    # "how do I write a good system prompt" pass.
    ("INJ-EN-04", "persona switch", r"\byou are now (?:a|an|the|my|in|no longer|free|unrestricted|dan|jailbroken|evil|admin\w*)\b"),
    ("INJ-EN-05", "persona switch", r"\bfrom now on you (?:are|will be|act)\b"),
    ("INJ-EN-06", "restriction removal", r"\byou (?:now )?have no (?:restrictions|rules|limits|limitations|guidelines|filters)\b"),
    ("INJ-EN-07", "prompt extraction", r"\b(?:your|the(?: original| hidden| real| initial)?|its) system prompt\b"),
    ("INJ-EN-08", "prompt extraction", r"\b(?:reveal|show|print|repeat|output|tell me) (?:me )?(?:your|all your|the (?:system|hidden|initial|original)) (?:\w+ )?(?:instructions|prompt|rules)\b"),
    ("INJ-EN-09", "mode switch", r"\b(?:developer|dev|god|jailbreak|dan) mode\b"),
    ("INJ-EN-10", "known jailbreak", r"\bdo anything now\b"),
    ("INJ-EN-11", "role-play opener", r"\b(?:pretend (?:that )?you (?:are|re)|pretend to be|role ?play as|imagine (?:that )?you (?:are|re)"
                                      r"|act as if you|let ?s play a game|you will play the role|stay in character)\b"),
    # Polish (after normalization: no diacritics)
    ("INJ-PL-01", "instruction override", rf"\b(?:zignoruj|zignorujcie|ignoruj|pomin) {_W}(?:poprzednie|wczesniejsze|powyzsze|dotychczasowe|systemowe|swoje|twoje|wszystkie) (?:instrukcje|polecenia|zasady|reguly|wytyczne)\b"),
    ("INJ-PL-02", "instruction wipe", rf"\bzapomnij {_W}(?:instrukcj\w*|polece\w*|zasad\w*|regul\w*)\b"),
    # A role noun in the instrumental case must follow: "jestes teraz administratorem", not "jestes teraz dostepny".
    ("INJ-PL-03", "persona switch", r"\b(?:jestes teraz|od teraz jestes|teraz jestes) (?:\w+ )?\w+(?:em|iem|ym|im|ka)\b"),
    ("INJ-PL-04", "prompt extraction", r"\b(?:swoj|twoj|ten|tw[oó]j) (?:prompt systemowy|systemowy prompt)\b|\b(?:swoje|twoje) instrukcje systemowe\b"),
    ("INJ-PL-05", "mode switch", r"\btryb (?:dewelopera|programisty|deweloperski|boga)\b"),
    ("INJ-PL-06", "role-play opener", r"\b(?:udawaj ze|wciel sie w|odgrywaj role|zagrajmy w gre)\b"),
)
# Extra phrases for tool definitions (tool poisoning), checked on top of the list above.
_TOOL_PHRASES: tuple[tuple[str, str, str], ...] = (
    ("TOOL-01", "hidden instruction", r"\b(?:do not|don t|never) (?:tell|inform|mention|show)\b[^.]*\buser\b"
                                      r"|\bwithout (?:telling|informing) the user\b"
                                      r"|\bbefore using this tool (?:\w+ ){0,3}(?:read|send|include|pass|call|fetch|access|ignore|upload|copy)\b"
                                      r"|\bnie (?:mow|informuj|wspominaj)\b[^.]*\buzytkownik\w*"),
)
_TOOL_RAW = re.compile(r"(?i)<\s*/?\s*(?:important|system|instructions?)\s*>|~/\.ssh|\bid_rsa\b|/etc/passwd|\.aws/credentials")

_Compiled = tuple[tuple[str, str, re.Pattern[str]], ...]
_COMPILED: _Compiled = tuple((rid, label, re.compile(p)) for rid, label, p in _PHRASES)
_COMPILED_TOOL: _Compiled = _COMPILED + tuple((rid, label, re.compile(p)) for rid, label, p in _TOOL_PHRASES)


def _find(text: str, phrases: _Compiled) -> str | None:
    """``"<rule id>, <label>"`` of the first matching phrase, or None."""
    for variant in _variants(text):
        for rid, label, pattern in phrases:
            if pattern.search(variant):
                return f"{rid}, {label}"
    return None


def check_injection(text: str, policy: Policy) -> Decision:
    """Match sanitized text against injection phrases. Spec section 4 step 4."""
    start = time.perf_counter()
    mode = setting(policy, "prompt_controls.injection.mode")
    hit = None if mode == "off" else _find(text, _COMPILED)
    ms = (time.perf_counter() - start) * 1000
    if hit is None:
        return Decision("input_checks", "injection", "allow", "", ms)
    verdict = "block" if mode == "block" else "log"
    return Decision("input_checks", "injection", verdict, f"The prompt matches a known injection phrase ({hit}).", ms)


# ---------------------------------------------------------------------------
# Client tool definitions
# ---------------------------------------------------------------------------

_SAFE_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def is_query_data_name(name: str) -> bool:
    """True for ``query_data`` and look-alikes (case, spacing, separators, zero-width, homoglyphs, digits)."""
    return any(re.sub(r"[^a-z0-9]", "", v) == "querydata" for v in _variants(name))


def safe_tool_label(name: Any, index: int) -> str:
    """The tool name for reasons and audit records if it is a plain identifier with no secret or PII in it;
    otherwise ``client tool #<n>``. Tool names are client input (I8)."""
    if isinstance(name, str) and _SAFE_NAME.match(name) and not find_sensitive(name):
        return name
    return f"client tool #{index + 1}"


def _tool_texts(tool: Any) -> tuple[str, list[str]] | None:
    """(name, every key and string value anywhere in the definition) or None if malformed.

    The model receives the whole definition, so property names and strings under
    ``default``, ``const``, ``examples`` or any other key are scanned too.
    """
    fn = tool.get("function") if isinstance(tool, dict) else None
    if not isinstance(fn, dict) or not isinstance(fn.get("name"), str) or not fn["name"].strip():
        return None
    texts: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(k, str):
                    texts.append(k)
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
        elif isinstance(node, str):
            texts.append(node)

    walk(tool)
    return fn["name"], texts


def scan_tool_definitions(tools: list[dict[str, Any]], policy: Policy, feed: SignatureFeed) -> Decision:
    """Scan everything in client tool definitions (tool poisoning). Spec section 4 step 3d.

    A tool named ``query_data`` (or a look-alike) or a malformed definition blocks in
    every mode. Otherwise ``tool_definitions.mode`` decides; feed entries for
    ``tool_definition`` apply with their own severity. Reasons carry ``safe_tool_label``
    and rule IDs, never the definition's text.
    """
    start = time.perf_counter()

    def decision(verdict: str, reason: str = "") -> Decision:
        return Decision("inbound", "tool_definitions", verdict, reason, (time.perf_counter() - start) * 1000)  # type: ignore[arg-type]

    mode = setting(policy, "prompt_controls.tool_definitions.mode")
    logged: list[str] = []
    for i, tool in enumerate(tools):
        parsed = _tool_texts(tool)
        if parsed is None:
            return decision("block", f"Client tool #{i + 1} has a malformed definition.")
        name, texts = parsed
        label = safe_tool_label(name, i)
        if is_query_data_name(name):
            return decision("block", f"Client tool {label} collides with the built-in tool query_data.")
        if mode == "off":
            continue
        joined = "\n".join(texts)
        hit = _find(joined, _COMPILED_TOOL) or ("TOOL-02, sensitive path or hidden tag" if _TOOL_RAW.search(joined) else None)
        if hit is not None:
            if mode == "block":
                return decision("block", f"Client tool {label} contains instructions for the model ({hit}).")
            logged.append(label)
        sig = match_signatures(joined, "tool_definition", feed, policy)
        if sig.verdict == "block":
            return decision("block", f"Client tool {label}: {sig.reason}")
        if sig.verdict == "log":
            logged.append(label)
    if logged:
        return decision("log", f"Client tool(s) {', '.join(dict.fromkeys(logged))} matched tool-poisoning checks; logged only.")
    return decision("allow")
