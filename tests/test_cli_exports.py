"""Fresh-process CLI validation catches decoder registration and export regressions."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def run_cli(*args):
    root = Path(__file__).resolve().parents[1]
    env = {**os.environ, "PYTHONPATH": str(root / "src"), "PYTHONUTF8": "1"}
    return subprocess.run([sys.executable, "-m", "netsentinel", *map(str, args)],
                          cwd=root, env=env, text=True, capture_output=True, timeout=30)


def test_fresh_process_demo_exports_complete_artifacts(tmp_path):
    paths = [tmp_path / name for name in ("detection.json", "incident.md", "incident.html",
                                          "layer.json", "suricata.rules", "yara.yar")]
    flags = ("--output", "--report-md", "--report-html", "--mitre-layer", "--suricata-rules", "--yara-rules")
    export_args = [part for pair in zip(flags, paths) for part in pair]
    process = run_cli("analyze", "data/demo.pcap", "--offline", "--format", "json", *export_args)
    assert process.returncode == 0, process.stderr
    data = json.loads(process.stdout)
    assert data["stats"]["packets"] == 122 and data["flows_count"] == 98
    assert len(data["events"]) == 6 and len(data["campaigns"]) == 5
    assert all(row["assessment"]["reasoning_source"] == "offline-deterministic" for row in data["events"])
    assert all(path.stat().st_size > 0 for path in paths)
    assert json.loads(paths[0].read_text(encoding="utf-8")) == data
    assert len(json.loads(paths[3].read_text(encoding="utf-8"))["techniques"]) == 5
    assert list(map(int, re.findall(r"sid:(\d+);", paths[4].read_text(encoding="utf-8")))) == list(range(9000001, 9000007))


def test_invalid_capture_produces_actionable_cli_error():
    process = run_cli("analyze", "missing.pcap", "--offline")
    assert process.returncode == 2
    assert "NetSentinel:" in process.stderr and "Traceback" not in process.stderr
