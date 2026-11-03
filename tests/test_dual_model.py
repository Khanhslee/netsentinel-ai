"""Offline-only contract tests for Meta routing, validation and graceful recovery."""
import json
from types import SimpleNamespace
from pathlib import Path

import pytest

from netsentinel.config import MetaModelConfig, Settings, resolve_api_key
from netsentinel.llm.client import MetaModelClient
from netsentinel.llm.offline import OfflineReasoningEngine
from netsentinel.llm.schemas import AssessmentOutput, strict_response_format
from netsentinel.models import SuspiciousEvent


def event(kind="beacon", severity="high", event_id="event-1"):
    return SuspiciousEvent(
        event_type=kind, severity=severity, description="Observed network anomaly",
        src_ip="10.0.0.5", dst_ip="203.0.113.10", dst_port=443,
        iocs=["203.0.113.10"], event_id=event_id,
        features={"connections": 12, "jitter_ratio": 0.01,
                  "coefficient_of_variation": 0.01, "mean_interval": 60.0},
    )


def wire_assessment(item):
    data = OfflineReasoningEngine().assess(item).model_dump()
    return {key: data[key] for key in AssessmentOutput.model_fields}


def verdict(item, **overrides):
    return {"event_id": item.event_id, "priority": 5, "is_noise": False,
            "confidence_score": 0.9, "kill_chain_stage": "Command and Control",
            "rationale": "Measured periodic traffic", **overrides}


def fake_sdk(client, responses):
    calls = []
    responses = iter(responses)

    def create(**kwargs):
        calls.append(kwargs)
        response = next(responses)
        if isinstance(response, Exception):
            raise response
        return SimpleNamespace(choices=[SimpleNamespace(
            finish_reason="stop", message=SimpleNamespace(content=json.dumps(response)),
        )])

    client._client = SimpleNamespace(chat=SimpleNamespace(
        completions=SimpleNamespace(create=create),
    ))
    return calls


def fake_sdk_text(client, texts):
    """Fake SDK returning raw message text (no json.dumps wrapping)."""
    calls = []
    responses = iter(texts)

    def create(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(choices=[SimpleNamespace(
            finish_reason="stop", message=SimpleNamespace(content=next(responses)),
        )])

    client._client = SimpleNamespace(chat=SimpleNamespace(
        completions=SimpleNamespace(create=create),
    ))
    return calls


def test_api_key_priority_and_blank_values(monkeypatch):
    monkeypatch.setenv("LLAMA_API_KEY", "legacy")
    monkeypatch.setenv("MODEL_API_KEY", "official")
    monkeypatch.setenv("META_API_KEY", "preferred")
    assert resolve_api_key() == "preferred"
    monkeypatch.setenv("META_API_KEY", "   ")
    assert resolve_api_key() == "official"
    monkeypatch.delenv("MODEL_API_KEY")
    assert resolve_api_key() == "legacy"
    assert "secret" not in repr(MetaModelConfig(api_key="secret"))


def test_canonical_configuration_wins_over_legacy_yaml(tmp_path, monkeypatch):
    for name in ("META_API_KEY", "MODEL_API_KEY", "LLAMA_API_KEY", "META_BASE_URL",
                 "MODEL_BASE_URL", "LLAMA_BASE_URL", "META_REASONING_MODEL",
                 "META_MODEL", "LLAMA_MODEL", "META_TRIAGE_MODEL", "META_FAST_MODEL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("netsentinel.config._load_dotenv", lambda: None)
    path = tmp_path / "settings.yaml"
    path.write_text("llama:\n  reasoning_model: legacy\nmeta:\n  reasoning_model: muse-wonder-1.0\n")
    cfg = Settings.load(path).meta
    assert cfg.base_url == "https://api.meta.ai/v1"
    assert cfg.reasoning_model == "muse-wonder-1.0"
    assert cfg.triage_model == "muse-spark-1.3"
    for endpoint in ("https://secret@api.meta.ai/v1", "http://api.meta.ai/v1",
                     "https://api.meta.ai/v1?key=secret"):
        client = MetaModelClient(MetaModelConfig(api_key="test", base_url=endpoint))
        result = client.analyze_event(event())
        assert result.reasoning_source == "offline-deterministic"
        assert result.model == "offline-deterministic"
        assert result.requested_model == "muse-wonder-1.0"
        assert "secret" not in json.dumps(client.routing_table())
    assert MetaModelConfig(base_url="http://127.0.0.1:8080/v1").validate_base_url()


def test_explicit_configuration_errors_are_clear_and_do_not_leak_yaml(tmp_path, monkeypatch):
    monkeypatch.setattr("netsentinel.config._load_dotenv", lambda: None)
    for name in ("META_TIMEOUT", "LLAMA_TIMEOUT"):
        monkeypatch.delenv(name, raising=False)
    missing = tmp_path / "missing.yaml"
    with pytest.raises(OSError, match="does not exist"):
        Settings.load(missing)
    monkeypatch.setattr("netsentinel.config._default_config_path", lambda: missing)
    assert Settings.load().meta.timeout == 60.0

    path = tmp_path / "invalid.yaml"
    for contents in ("meta: [sensitive-secret", "- sensitive-secret", "meta: sensitive-secret",
                     "meta:\n  timeout: .nan", "meta:\n  max_tokens: true"):
        path.write_text(contents, encoding="utf-8")
        with pytest.raises(ValueError) as error:
            Settings.load(path)
        assert "sensitive-secret" not in str(error.value)

    original_read = Path.read_text

    def denied_read(target, *args, **kwargs):
        if target == path:
            raise PermissionError("sensitive-secret")
        return original_read(target, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", denied_read)
    with pytest.raises(OSError, match="Cannot read configuration file"):
        Settings.load(path)


def test_spark_triage_then_wonder_reasoning_and_copilot(monkeypatch):
    item = event()
    urgent = event("exfiltration", event_id="event-2")
    client = MetaModelClient(MetaModelConfig(api_key="test"))
    calls = fake_sdk(client, [{"verdicts": [verdict(item, priority=1), verdict(urgent)]},
                              wire_assessment(urgent), wire_assessment(item), "answer"])
    sdk = client._client
    client._client = None
    construction = {}

    def openai_client(**kwargs):
        construction.update(kwargs)
        return sdk

    monkeypatch.setattr("openai.OpenAI", openai_client)
    results = client.analyze_events([item, urgent], campaigns=[{"scope": "host", "event_ids": [item.event_id]}])
    assert results[0].reasoning_source == "meta-model-api"
    assert "BEACON" in results[0].natural_language_explanation
    assert "EXFILTRATION" in results[1].natural_language_explanation
    assert '"event_id": "event-2"' in calls[1]["messages"][1]["content"]
    assert construction == {"base_url": "https://api.meta.ai/v1", "api_key": "test",
                            "timeout": 60.0, "max_retries": 0}
    assert [call["model"] for call in calls] == ["muse-spark-1.3", "muse-wonder-1.0", "muse-wonder-1.0"]
    assert "CORRELATION CONTEXT" in calls[1]["messages"][1]["content"]
    assert all(call["response_format"]["json_schema"]["strict"] for call in calls)
    assert client.chat("explain", ["evidence"]) == '"answer"'
    assert calls[-1]["model"] == "muse-wonder-1.0"
    assert "response_format" not in calls[-1]


def test_lenient_schema_repairs_partial_and_drifting_model_output():
    schema = strict_response_format(AssessmentOutput)["json_schema"]["schema"]
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"])
    nested = schema["$defs"]["IOCBundle"]
    assert nested["additionalProperties"] is False
    assert set(nested["required"]) == set(nested["properties"])
    # Nothing below is allowed to trip the fallback: the payload is repaired.
    drifting = [
        {},
        {**wire_assessment(event()), "confidence_score": 1.5},
        {"kill_chain_stage": "command_and_control", "severity": "SEVERE",
         "confidence_score": "92%", "mitre_technique": "T1071.001 - Web Protocols"},
        {"assessment": {"summary": "Suspicious beacon", "confidence": 0.7}},
        "```json\n{}\n```",
    ]
    for output in drifting:
        client = MetaModelClient(MetaModelConfig(api_key="test"))
        fake_sdk(client, [output])
        result = client.analyze_event(event())
        assert result.reasoning_source == "meta-model-api"
        assert 0.0 <= result.confidence_score <= 1.0
        assert result.root_cause_analysis and result.recommended_actions
        assert result.kill_chain_stage and result.mitre_technique_id
        assert client.mode == "meta-model-api"


def test_model_drift_is_normalised_instead_of_rejected():
    client = MetaModelClient(MetaModelConfig(api_key="test"))
    fake_sdk(client, [{"kill_chain_stage": "C2", "severity": "high",
                       "confidence_score": "95%", "mitre_technique_id": "1071.001",
                       "threat_assessment": "periodic beacon", "iocs": "203.0.113.10",
                       "recommended_actions": "Block egress\nIsolate host"}])
    result = client.analyze_event(event())
    assert result.reasoning_source == "meta-model-api"
    assert result.kill_chain_stage == "Command and Control"
    assert result.confidence_score == 0.95
    assert result.mitre_technique_id == "T1071.001"
    assert result.threat_summary == "periodic beacon"
    assert result.recommended_actions  # filled from the MITRE guidance


def test_http_and_network_failures_open_circuit_without_secret_leaks():
    for status in (401, 403, 429, None):
        error = RuntimeError("sensitive-key-and-capture-payload")
        if status:
            error.status_code = status
        client = MetaModelClient(MetaModelConfig(api_key="test"))
        calls = fake_sdk(client, [error])
        first = client.analyze_event(event())
        second = client.analyze_event(event(event_id="event-2"))
        assert len(calls) == 1
        assert first.reasoning_source == second.reasoning_source == "offline-deterministic"
        assert "sensitive" not in json.dumps(client.routing_summary())
        assert client.routing_summary()["offline_fallbacks"] == 2


def test_endpoint_rejecting_response_format_is_retried_as_plain_text():
    class UnsupportedParameter(RuntimeError):
        status_code = 400

        def __str__(self):
            return "Unsupported parameter: response_format"

    client = MetaModelClient(MetaModelConfig(api_key="test"))
    calls = fake_sdk(client, [UnsupportedParameter(), wire_assessment(event())])
    result = client.analyze_event(event())
    assert result.reasoning_source == "meta-model-api"
    assert "response_format" in calls[0]
    assert "response_format" not in calls[1]
    assert client._response_format_supported is False


def test_reasoning_truncation_retries_with_a_larger_budget():
    item = event()
    truncated = [
        SimpleNamespace(choices=[SimpleNamespace(
            finish_reason="length", message=SimpleNamespace(content=None))]),
        SimpleNamespace(choices=[SimpleNamespace(
            finish_reason="length",
            message=SimpleNamespace(content='{"threat_summary": "cut off'))]),
        SimpleNamespace(choices=[SimpleNamespace(
            finish_reason="stop",
            message=SimpleNamespace(content=json.dumps(wire_assessment(item))))]),
    ]
    calls = []
    pending = iter(truncated)

    def create(**kwargs):
        calls.append(kwargs)
        return next(pending)

    client = MetaModelClient(MetaModelConfig(api_key="test"))
    client._client = SimpleNamespace(chat=SimpleNamespace(
        completions=SimpleNamespace(create=create),
    ))
    result = client.analyze_event(item)
    assert result.reasoning_source == "meta-model-api"
    assert [call["max_tokens"] for call in calls] == [1400, 2800, 5600]


def test_triage_accepts_fenced_json_wrapped_in_prose():
    item = event()
    fenced = ("Here is the triage result:\n```json\n"
              + json.dumps({"verdicts": [verdict(item)]})
              + "\n```\nLet me know if you need anything else.")
    client = MetaModelClient(MetaModelConfig(api_key="test"))
    fake_sdk_text(client, [fenced, json.dumps(wire_assessment(item))])
    results = client.analyze_events([item])
    assert client.last_triage[0].source == "meta-model-api"
    assert client.last_triage[0].priority == 5
    assert results[0].reasoning_source == "meta-model-api"


def test_every_response_field_has_a_default_and_is_normalised():
    from netsentinel.llm.schemas import IOCBundle, TriageBatchOutput, TriageOutput

    # Requirement: a partial reply must always parse, so no field is required.
    for wire_model in (AssessmentOutput, TriageOutput, TriageBatchOutput, IOCBundle):
        assert not any(
            field.is_required() for field in wire_model.model_fields.values()
        ), f"{wire_model.__name__} still has required fields"
    assert AssessmentOutput.model_validate(None).confidence_score == 0.5
    assert AssessmentOutput.model_validate({}).iocs == []
    assert AssessmentOutput.model_validate({}).ioc_details.total == 0
    assert TriageBatchOutput.model_validate([]).verdicts == []
    assert TriageBatchOutput.model_validate({"unexpected": 1}).verdicts == []

    # Values are coerced rather than rejected.
    assert AssessmentOutput.model_validate({"confidence_score": 87}).confidence_score == 0.87
    assert AssessmentOutput.model_validate(
        {"confidence_score": "87%"}).confidence_score == 0.87
    assert AssessmentOutput.model_validate(
        {"kill_chain_stage": "command_and_control"}).kill_chain_stage == "Command and Control"
    assert AssessmentOutput.model_validate({"severity": "SEVERE"}).severity == "high"
    assert AssessmentOutput.model_validate(
        {"mitre_technique": "T1041 - Exfiltration"}).mitre_technique_id == "T1041"
    bundle = AssessmentOutput.model_validate(
        {"ioc_details": "203.0.113.10, evil.example"}).ioc_details
    assert bundle.ip_addresses == ["203.0.113.10"] and bundle.domains == ["evil.example"]
    # Comma-separated prose stays a single action.
    actions = AssessmentOutput.model_validate(
        {"recommended_actions": "Block 203.0.113.10, then isolate the host"}
    ).recommended_actions
    assert actions == ["Block 203.0.113.10, then isolate the host"]
    triage = TriageBatchOutput.model_validate({
        "triage": [{"id": "e1", "priority": 9, "noise": "no", "confidence": "40%"}]
    }).verdicts[0]
    assert (triage.event_id, triage.priority, triage.is_noise,
            triage.confidence_score) == ("e1", 5, False, 0.4)


def test_unknown_and_duplicate_triage_identifiers_are_repaired_without_misassigning():
    item = event()
    cases = (
        ([verdict(item, event_id="invented-id")], "offline-deterministic"),
        ([], "offline-deterministic"),
        ([verdict(item), verdict(item, rationale="duplicate")], "meta-model-api"),
    )
    for batch, expected_source in cases:
        client = MetaModelClient(MetaModelConfig(api_key="test"))
        # Tier-1 (repaired) + a single Tier-2 assessment for the only event.
        calls = fake_sdk(client, [{"verdicts": batch}, wire_assessment(item)])
        results = client.analyze_events([item])
        assert len(calls) == 2
        assert calls[0]["model"] == "muse-spark-1.3"
        assert calls[1]["model"] == "muse-wonder-1.0"
        assert [v.event_id for v in client.last_triage] == [item.event_id]
        assert client.last_triage[0].source == expected_source
        assert results[0].reasoning_source == "meta-model-api"
        assert results[0].iocs == item.iocs
        assert client.mode == "meta-model-api"


def test_noise_filter_preserves_detection_and_iocs_without_deep_api_call():
    item = event(severity="medium")
    client = MetaModelClient(MetaModelConfig(api_key="test"))
    calls = fake_sdk(client, [{"verdicts": [verdict(item, is_noise=True)]}])
    result = client.analyze_events([item])[0]
    assert len(calls) == 1
    assert result.iocs == item.iocs
    assert result.root_cause_analysis
    assert result.reasoning_source == "offline-deterministic"


def test_model_cannot_add_unobserved_iocs_and_offline_is_complete():
    item = event()
    payload = wire_assessment(item)
    payload["iocs"].append("invented.example")
    payload["ioc_details"]["domains"].append("invented.example")
    client = MetaModelClient(MetaModelConfig(api_key="test"))
    fake_sdk(client, [payload])
    result = client.analyze_event(item)
    assert "invented.example" not in result.iocs
    assert "invented.example" not in result.ioc_details.domains
    for kind in ("beacon", "port_scan", "nxdomain_storm", "dns_tunneling", "dga", "exfiltration"):
        result = MetaModelClient(MetaModelConfig()).analyze_event(event(kind))
        assert result.reasoning_source == "offline-deterministic"
        assert result.kill_chain_stage and result.mitre_technique_id
        assert 0.0 <= result.confidence_score <= 1.0
        assert result.threat_summary and result.root_cause_analysis and result.recommended_actions
