"""Chainlit chat UI for NetSentinel AI.

Run with:  chainlit run src/netsentinel/ui/app.py
Install the optional UI dependency first:  pip install chainlit
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Chainlit loads this file as a *standalone* module (no parent package), so make
# the `src` directory importable and use absolute imports instead of relative ones.
_SRC = Path(__file__).resolve().parents[2]
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

try:
    import chainlit as cl
except ImportError:  # pragma: no cover - Chainlit is an optional dependency
    cl = None

from netsentinel.config import Settings
from netsentinel.pipeline import AnalysisResult, analyze_path
from netsentinel.ui.chat import answer_query


async def on_chat_start():
    welcome = (
        "🛡️ **NetSentinel AI** - copilot phát hiện bất thường & phân tích mối đe dọa.\n"
        "Gửi đường dẫn file PCAP/flow (hoặc đính kèm file) để phân tích, "
        "sau đó đặt câu hỏi như `summary`, `events`, `beacons`, `explain 1`, `rules`."
    )
    await cl.Message(content=welcome).send()


async def on_message(message: cl.Message):
    settings = _load_settings()
    result: AnalysisResult | None = cl.user_session.get("result")

    file_path = _resolve_file_path(message)
    if file_path:
        try:
            result = analyze_path(file_path, settings=settings, use_llm=True)
            cl.user_session.set("result", result)
            await cl.Message(
                content=f"✅ Đã phân tích `{file_path}`: {len(result.report.events)} sự kiện."
            ).send()
        except Exception as exc:
            await cl.Message(content=f"❌ Lỗi phân tích: {exc}").send()
    else:
        reply = answer_query(result, message.content)
        await cl.Message(content=reply).send()


if cl is not None:  # pragma: no cover - handlers only register under `chainlit run`
    cl.on_chat_start(on_chat_start)
    cl.on_message(on_message)


def _resolve_file_path(message: cl.Message) -> str | None:
    # 1) Attached file
    for element in getattr(message, "elements", []) or []:
        if getattr(element, "path", None) and os.path.exists(element.path):
            return element.path
    # 2) Plain-text path
    text = (message.content or "").strip()
    if os.path.exists(text):
        return text
    return None


def _load_settings() -> Settings:
    return Settings.load()
