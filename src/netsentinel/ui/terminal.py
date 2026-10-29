"""Interactive terminal chat (fallback when Chainlit is not installed)."""
from __future__ import annotations

from ..config import Settings
from ..pipeline import AnalysisResult, analyze_path
from .chat import answer_query


def interactive_loop(settings: Settings | None = None) -> None:
    """Terminal REPL: load a file, then answer analyst questions."""
    settings = settings or Settings.load()
    result: AnalysisResult | None = None

    print("NetSentinel AI - interactive analyst console")
    print("Enter a PCAP / flow file path to analyze, or type 'help'.")

    while True:
        try:
            raw = input("netsentinel> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not raw:
            continue
        if raw.lower() in ("exit", "quit", "thoát", "thoat"):
            break

        # If the text looks like a file path, attempt analysis.
        if _looks_like_path(raw):
            try:
                result = analyze_path(raw, settings=settings, use_llm=True)
                print(f"Analyzed {raw}: found {len(result.report.events)} findings.")
            except Exception as exc:
                print(f"Analysis failed: {exc}")
            continue

        print(answer_query(result, raw))


def _looks_like_path(text: str) -> bool:
    import os

    return os.path.exists(text) or any(text.lower().endswith(ext) for ext in (
        ".pcap", ".pcapng", ".json", ".csv", ".log", ".conn"
    ))


if __name__ == "__main__":
    interactive_loop()
