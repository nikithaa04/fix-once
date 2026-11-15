"""Model call. Anything that takes (system, messages) and returns text can be swapped in."""
from __future__ import annotations

import os
from typing import Callable

Complete = Callable[[str, list[dict]], str]
DEFAULT_MODEL = "claude-sonnet-5-5"


def anthropic_complete(model: str | None = None) -> Complete:
    import anthropic

    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY
    model = model or os.environ.get("FIXONCE_MODEL") or DEFAULT_MODEL

    def complete(system: str, messages: list[dict]) -> str:
        resp = client.messages.create(model=model, max_tokens=4000, system=system, messages=messages)
        return "".join(block.text for block in resp.content if block.type == "text")

    return complete
