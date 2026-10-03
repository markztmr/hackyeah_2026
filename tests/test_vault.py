"""Vault and raw-value containers never serialize (I8). Owner: Person 4."""
from __future__ import annotations

import copy
import json
import pickle

import pytest
from fastapi.encoders import jsonable_encoder

from gateway.models import Binding, FilledText, IssuedCache, ToolCall, Vault

SECRET = "6200"


def _vault_with_secret() -> Vault:
    v = Vault()
    v._masks["[EMAIL_1]"] = "anna@company.pl"
    v._placeholders["{x1}"] = SECRET
    return v


def test_vault_repr_shows_only_counts() -> None:
    v = _vault_with_secret()
    assert repr(v) == "Vault(mask_tokens=1, placeholders=1)"
    assert SECRET not in str(v)
    assert SECRET not in f"{v}"


@pytest.mark.parametrize(
    "leak",
    [
        lambda v: pickle.dumps(v),
        lambda v: json.dumps(v),
        lambda v: jsonable_encoder(v),
        lambda v: copy.copy(v),
        lambda v: copy.deepcopy(v),
        lambda v: dict(v),
        lambda v: list(v),
        lambda v: vars(v),
    ],
    ids=["pickle", "json", "jsonable_encoder", "copy", "deepcopy", "dict", "list", "vars"],
)
@pytest.mark.parametrize("container", [_vault_with_secret, IssuedCache])
def test_sealed_containers_refuse_every_serialization(container, leak) -> None:
    with pytest.raises((TypeError, ValueError)):
        leak(container())


def test_binding_repr_hides_value() -> None:
    b = Binding(name="{x1}", sql="SELECT 1", purpose="t", expect="scalar", status="resolved", value=SECRET)
    assert SECRET not in repr(b)


def test_filled_text_and_tool_call_reprs_hide_values() -> None:
    assert SECRET not in repr(FilledText(text=f"Your salary is {SECRET} PLN."))
    assert SECRET not in repr(ToolCall(id="c1", name="send_email", arguments={"body": SECRET}))
