"""SOC chat regressions and upload handling, without a running web server."""
from types import SimpleNamespace

from netsentinel.config import Settings
from netsentinel.engine.detector import DetectionReport
from netsentinel.llm.schemas import ThreatAssessment
from netsentinel.models import SuspiciousEvent
from netsentinel.pipeline import AnalysisResult
from netsentinel.ui import app
from netsentinel.ui.chat import answer_query


def test_chat_rejects_zero_index_and_escapes_capture_indicators():
    event = SuspiciousEvent(
        event_type="beacon", severity="high", description="Periodic requests",
        src_ip="192.0.2.5", iocs=["<script>alert(1)</script>"],
    )
    result = AnalysisResult(
        report=DetectionReport(events=[event], flows_count=6),
        assessments=[ThreatAssessment.from_event(event)],
    )
    assert "Choose a finding" in answer_query(result, "explain 0")
    assert "Choose a finding" in answer_query(result, "playbook 0")
    assert "<script>" not in answer_query(result, "iocs")
    assert "&lt;script&gt;" in answer_query(result, "iocs")
    assert "behavioral indicators" in answer_query(result, "Is this definitely a breach?")


def test_extensionless_upload_preserves_verified_file_type(tmp_path, monkeypatch):
    upload = tmp_path / "f03a6c0c-1234"
    upload.write_bytes(b"capture payload")
    message = SimpleNamespace(
        content="", elements=[SimpleNamespace(path=str(upload), name="network.pcap")]
    )
    path, suffix, name = app._resolve_input(message)
    assert path == upload and suffix == ".pcap" and name == "network.pcap"
    seen = []

    def parser(staged):
        assert staged.suffix == ".pcap"
        assert staged.read_bytes() == b"capture payload"
        seen.append(staged)
        return ["flow"]

    monkeypatch.setattr(app, "load_flows", parser)
    assert app._load_capture(path, suffix) == ["flow"]
    assert not seen[0].exists()


def test_welcome_status_and_project_relative_paths_do_not_depend_on_cwd(tmp_path, monkeypatch):
    settings = Settings()
    offline = app._welcome(settings)
    assert "muse-wonder-1.0" in offline and "muse-spark-1.3" in offline
    assert "Offline deterministic" in offline
    settings.meta.api_key = "never-display-this-credential"
    configured = app._welcome(settings)
    assert settings.meta.api_key not in configured
    assert "connection is verified when analysis runs" in configured
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app, "_REPO", tmp_path / "repository")
    capture = app._REPO / "data" / "demo.pcap"
    capture.parent.mkdir(parents=True)
    capture.write_bytes(b"demo")
    message = SimpleNamespace(content='"data/demo.pcap"', elements=[])
    assert app._resolve_file_path(message) == str(capture.resolve())
    assert len(app._ACTION_SPECS) == 4
