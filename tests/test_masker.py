"""Secrets and PII masking (spec section 4 step 3a-3b, section 8 'Inbound stage'). Owner: Person 2."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from gateway.inbound.masker import mask_messages, masking_decisions
from gateway.models import Policy
from gateway.policy.loader import parse_policy

REPO_ROOT = Path(__file__).resolve().parent.parent

# Valid test values: checksums verified by the tests below, never real people or accounts.
OPENAI = "sk-proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z"
AWS = "AKIAIOSFODNN7EXAMPLE"
GITHUB = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbm5hIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7bq\nq3Zx9d==\n-----END RSA PRIVATE KEY-----"
EMAIL = "anna.kowalska@company.pl"
PHONE = "+48 601 234 567"
CARD = "4111 1111 1111 1111"            # Luhn-valid test Visa
PESEL = "44051401359"                  # checksum and date valid
IBAN = "PL61 1090 1014 0000 0712 1981 2874"
NRB = "61 1090 1014 0000 0712 1981 2874"  # the same account without the country code

SECRETS = {"openai_key": OPENAI, "aws_key": AWS, "github_token": GITHUB, "jwt": JWT, "private_key": PEM}
PII = {"email": EMAIL, "phone": PHONE, "card": CARD, "pesel": PESEL, "iban": IBAN}


def _policy(profile: str = "balanced", **controls: dict[str, Any]) -> Policy:
    data = copy.deepcopy(yaml.safe_load((REPO_ROOT / "policy.yaml").read_text(encoding="utf-8")))
    data["profile"] = profile
    pc = data["prompt_controls"]
    pc.pop("secrets", None)  # let the profile decide unless a test sets it
    pc["pii"].pop("mode", None)
    for name, value in controls.items():
        pc.setdefault(name, {}).update(value)
    return parse_policy(yaml.safe_dump(data).encode("utf-8"))


def _user(content: Any) -> list[dict[str, Any]]:
    return [{"role": "user", "content": content}]


def _masked_text(messages: list[dict[str, Any]]) -> str:
    return messages[-1]["content"]


# ---------------------------------------------------------------------------
# Allowed: nothing to mask
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "question",
    [
        "What is my salary?",
        "How many people work in sales in 2026?",
        "Order 123 costs 45.50 PLN; room 3.14 is free.",
        "Use the password reset page.",
        "My employee number is 1234.",
    ],
)
def test_plain_question_is_unchanged(question: str) -> None:
    messages = _user(question)
    out, vault, findings = mask_messages(messages, _policy())
    assert out == messages
    assert findings == []
    assert vault.mask_count == 0


def test_input_messages_are_not_modified_in_place() -> None:
    messages = _user(f"my key is {OPENAI}")
    before = copy.deepcopy(messages)
    mask_messages(messages, _policy())
    assert messages == before


# ---------------------------------------------------------------------------
# Each type is masked
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("kind", "value"), sorted(SECRETS.items()))
def test_each_secret_type_is_masked(kind: str, value: str) -> None:
    out, vault, findings = mask_messages(_user(f"Here it is: {value} thanks"), _policy())
    assert _masked_text(out) == "Here it is: [SECRET_1] thanks"
    assert [(f.type, f.token, f.action) for f in findings] == [(kind, "[SECRET_1]", "redact")]
    assert vault.mask("[SECRET_1]") == value


@pytest.mark.parametrize("text", ["password=hunter2!", "pwd: hunter2!", "Password = 'hunter2!'", "hasło: hunter2!"])
def test_password_assignments_mask_only_the_value(text: str) -> None:
    out, vault, findings = mask_messages(_user(text), _policy())
    masked = _masked_text(out)
    assert "hunter2!" not in masked
    assert "[SECRET_1]" in masked
    assert masked.split("[SECRET_1]")[0].strip(" =:'\"").lower() in {"password", "pwd", "hasło"}
    assert findings[0].type == "password"
    assert vault.mask("[SECRET_1]").strip("'\"") == "hunter2!"


@pytest.mark.parametrize(("kind", "value"), sorted(PII.items()))
def test_each_pii_type_is_masked(kind: str, value: str) -> None:
    out, vault, findings = mask_messages(_user(f"Contact: {value}."), _policy())
    token = f"[{kind.upper()}_1]"
    assert _masked_text(out) == f"Contact: {token}."
    assert [(f.type, f.token) for f in findings] == [(kind, token)]
    assert vault.mask(token) == value


@pytest.mark.parametrize("phone", ["601234567", "601-234-567", "0048 601 234 567", "+48601234567", "22 123 45 67"])
def test_polish_phone_formats_are_masked(phone: str) -> None:
    out, _, findings = mask_messages(_user(f"call {phone} now"), _policy())
    assert _masked_text(out) == "call [PHONE_1] now"
    assert findings[0].type == "phone"


def test_polish_account_number_without_country_code_is_masked_as_iban() -> None:
    out, _, findings = mask_messages(_user(f"Account {NRB}"), _policy())
    assert _masked_text(out) == "Account [IBAN_1]"
    assert findings[0].type == "iban"


def test_unterminated_private_key_is_masked_to_the_end() -> None:
    out, _, _ = mask_messages(_user("key:\n-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC"), _policy())
    assert _masked_text(out) == "key:\n[SECRET_1]"


# ---------------------------------------------------------------------------
# No false positives: checksums must validate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "Card 4111 1111 1111 1112 failed",           # Luhn fails
        "Number 1234567812345678",                   # Luhn fails
        "PESEL 44051401358",                         # checksum fails
        "PESEL 44151401352",                         # checksum ok, month 15 invalid
        "IBAN PL61 1090 1014 0000 0712 1981 2875",    # mod-97 fails
        "Account 61 1090 1014 0000 0712 1981 2875",   # mod-97 fails without country code too
        "Tracking 00000000000",                      # 11 digits, not a PESEL date
        "Product 5901234123457",                     # EAN-13, Luhn-valid by chance, no card network starts 59 at 13 digits
    ],
)
def test_invalid_card_pesel_and_iban_numbers_are_not_masked(text: str) -> None:
    out, _, findings = mask_messages(_user(text), _policy())
    assert [f.type for f in findings if f.type in {"card", "pesel", "iban"}] == []
    for number in ("4111 1111 1111 1112", "1234567812345678", "44051401358", "44151401352", "2875", "00000000000",
                   "5901234123457"):
        if number in text:
            assert number in _masked_text(out)


# ---------------------------------------------------------------------------
# Tokens: numbered per type, reused for the same value
# ---------------------------------------------------------------------------


def test_tokens_are_numbered_per_type_and_reused_for_the_same_value() -> None:
    other = "marek.nowak@company.pl"
    messages = [
        {"role": "user", "content": f"Mail {EMAIL} and {other}, key {OPENAI}"},
        {"role": "assistant", "content": "ok"},
        {"role": "user", "content": f"Again {EMAIL}, key {AWS}"},
    ]
    out, vault, findings = mask_messages(messages, _policy())
    assert out[0]["content"] == "Mail [EMAIL_1] and [EMAIL_2], key [SECRET_1]"
    assert out[2]["content"] == "Again [EMAIL_1], key [SECRET_2]"
    assert vault.mask("[EMAIL_2]") == other
    assert vault.mask_count == 4  # the repeated email is stored once


def test_token_already_typed_by_the_user_is_not_reused() -> None:
    out, vault, _ = mask_messages(_user(f"[EMAIL_1] is a placeholder; mine is {EMAIL}"), _policy())
    assert _masked_text(out) == "[EMAIL_1] is a placeholder; mine is [EMAIL_2]"
    assert vault.mask("[EMAIL_1]") is None


# ---------------------------------------------------------------------------
# Which messages
# ---------------------------------------------------------------------------


def test_every_client_message_role_is_masked() -> None:
    """Spec section 4 step 3: every untrusted part. Client system and assistant turns are client data (RT-2)."""
    messages = [
        {"role": "system", "content": f"admin contact {EMAIL}"},
        {"role": "user", "content": "Read my inbox"},
        {"role": "assistant", "content": f"Writing to {EMAIL}", "tool_calls": []},
        {"role": "tool", "tool_call_id": "c1", "content": f"From: {EMAIL}, AWS key {AWS}"},
    ]
    out, _, findings = mask_messages(messages, _policy())
    assert out[0]["content"] == "admin contact [EMAIL_1]"
    assert out[2]["content"] == "Writing to [EMAIL_1]"
    assert out[3]["content"] == "From: [EMAIL_1], AWS key [SECRET_1]"
    assert {f.type for f in findings} == {"email", "aws_key"}


def test_text_parts_of_multipart_content_are_masked() -> None:
    content = [{"type": "text", "text": f"my mail {EMAIL}"}, {"type": "image_url", "image_url": {"url": "http://x"}}]
    out, _, _ = mask_messages(_user(content), _policy())
    assert out[0]["content"][0] == {"type": "text", "text": "my mail [EMAIL_1]"}
    assert out[0]["content"][1] == content[1]


# ---------------------------------------------------------------------------
# Modes: block, redact, log, off
# ---------------------------------------------------------------------------


def test_strict_blocks_secrets() -> None:
    out, vault, findings = mask_messages(_user(f"key {OPENAI}"), _policy("strict"))
    assert [(f.type, f.action) for f in findings] == [("openai_key", "block")]
    assert _masked_text(out) == "key [SECRET_1]"  # still masked: the raw value goes nowhere
    (decision,) = [d for d in masking_decisions(findings) if d.verdict == "block"]
    assert decision.control == "secrets"
    assert OPENAI not in decision.reason


def test_balanced_redacts_secrets_and_continues() -> None:
    out, vault, findings = mask_messages(_user(f"key {OPENAI}"), _policy("balanced"))
    assert findings[0].action == "redact"
    assert all(d.verdict != "block" for d in masking_decisions(findings))
    assert vault.mask("[SECRET_1]") == OPENAI


def test_strict_redacts_pii() -> None:
    _, _, findings = mask_messages(_user(f"mail {EMAIL}"), _policy("strict"))
    assert findings[0].action == "redact"


def test_log_mode_records_without_changing_the_text() -> None:
    out, vault, findings = mask_messages(_user(f"mail {EMAIL}"), _policy("relaxed"))  # relaxed: pii log
    assert _masked_text(out) == f"mail {EMAIL}"
    assert [(f.type, f.token, f.action) for f in findings] == [("email", "", "log")]
    assert vault.mask_count == 0
    assert [d.verdict for d in masking_decisions(findings)] == ["log"]


def test_mode_off_detects_nothing() -> None:
    p = _policy(secrets={"mode": "off"}, pii={"mode": "off"})
    messages = _user(f"key {OPENAI} mail {EMAIL}")
    out, _, findings = mask_messages(messages, p)
    assert (out, findings) == (messages, [])


def test_pii_types_not_listed_are_not_detected() -> None:
    p = _policy(pii={"types": ["email"]})
    out, _, findings = mask_messages(_user(f"mail {EMAIL} phone {PHONE}"), p)
    assert _masked_text(out) == f"mail [EMAIL_1] phone {PHONE}"
    assert [f.type for f in findings] == ["email"]


def test_explicit_block_on_pii_blocks() -> None:
    _, _, findings = mask_messages(_user(f"card {CARD}"), _policy(pii={"mode": "block"}))
    assert any(d.verdict == "block" and d.control == "pii" for d in masking_decisions(findings))


def test_no_findings_means_one_allow_decision() -> None:
    assert [d.verdict for d in masking_decisions([])] == ["allow"]


# ---------------------------------------------------------------------------
# Values never leave through findings, decisions or the vault's repr (I8)
# ---------------------------------------------------------------------------


def test_findings_decisions_and_vault_repr_contain_no_values() -> None:
    every = " ; ".join([*SECRETS.values(), *PII.values(), "password=hunter2!"])
    _, vault, findings = mask_messages(_user(every), _policy("strict"))
    assert len(findings) == len(SECRETS) + len(PII) + 1
    exposed = repr(findings) + json.dumps([vars_of(f) for f in findings]) + repr(vault) + str(vault)
    exposed += repr(masking_decisions(findings))
    for value in [*SECRETS.values(), *PII.values(), "hunter2!"]:
        assert value not in exposed
        for chunk in value.split():
            if len(chunk) >= 6:
                assert chunk not in exposed


def vars_of(f: Any) -> dict[str, Any]:
    return {k: getattr(f, k) for k in f.__slots__}


def test_vault_cannot_be_serialized_or_iterated() -> None:
    _, vault, _ = mask_messages(_user(f"key {OPENAI}"), _policy())
    for attempt in (lambda: json.dumps(vault), lambda: list(vault), lambda: copy.deepcopy(vault)):
        with pytest.raises(TypeError):
            attempt()


@pytest.mark.parametrize(
    "prose",
    [
        "The token: expires after an hour, so refresh it.",
        "Our secret: teamwork and patience.",
        "Password: required for every account.",
        "Set max_tokens: 512 in the config.",
        '{"model": "llama3.2", "max_tokens": 512}',
    ],
)
def test_credential_words_in_prose_are_not_masked(prose: str) -> None:
    _, _, findings = mask_messages(_user(prose), _policy())
    assert findings == []


@pytest.mark.parametrize("key", ["sk-test123", "sk-abc12345", "sk-proj-9x8y7z"])
def test_short_openai_style_keys_are_masked(key: str) -> None:
    """Regression: a judge's obvious test key (fewer than 20 characters after sk-) reached the model."""
    from gateway.inbound.masker import find_sensitive

    assert [t for _, _, t in find_sensitive("store this key: " + key)] == ["openai_key"]


@pytest.mark.parametrize("text", ["use sk-learn for that", "a risk-free plan", "desk-top", "sk-12"])
def test_sk_words_without_a_key_shape_are_not_masked(text: str) -> None:
    from gateway.inbound.masker import find_sensitive

    assert find_sensitive(text) == []
