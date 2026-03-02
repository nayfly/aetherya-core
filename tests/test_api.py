from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from aetherya.api import AetheryaAPI, APISettings


def _write_policy(tmp_path: Path, mutate) -> Path:  # noqa: ANN001
    data = yaml.safe_load(Path("config/policy.yaml").read_text(encoding="utf-8"))
    mutate(data)
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def _read_last_event(path: Path) -> dict:
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return json.loads(lines[-1])


def test_api_health_ready_and_not_found_dispatch(tmp_path: Path) -> None:
    policy_path = _write_policy(tmp_path, lambda data: None)
    api = AetheryaAPI(
        APISettings(
            policy_path=policy_path,
            audit_path=tmp_path / "decisions.jsonl",
            default_actor="robert",
        )
    )

    status, payload = api.health()
    assert status == 200
    assert payload["ok"] is True
    assert payload["service"] == "aetherya-api"
    assert payload["policy_path"] == str(policy_path)

    nf_status, nf_payload = api.dispatch("GET", "/missing")
    assert nf_status == 404
    assert nf_payload["ok"] is False
    assert nf_payload["error_type"] == "NotFound"


def test_api_health_invalid_policy_returns_503(tmp_path: Path) -> None:
    api = AetheryaAPI(
        APISettings(
            policy_path=tmp_path / "missing.yaml",
            audit_path=tmp_path / "decisions.jsonl",
        )
    )
    status, payload = api.health()
    assert status == 503
    assert payload["ok"] is False
    assert payload["error_type"] == "FileNotFoundError"


def test_api_decide_success_with_audit_event_ids(tmp_path: Path) -> None:
    policy_path = _write_policy(tmp_path, lambda data: None)
    audit_path = tmp_path / "decisions.jsonl"
    api = AetheryaAPI(APISettings(policy_path=policy_path, audit_path=audit_path))

    status, payload = api.decide({"raw_input": "help user"})
    assert status == 200
    assert payload["ok"] is True
    assert payload["decision"]["abi_version"] == "v1"
    assert payload["meta"]["event_id"]
    assert payload["meta"]["decision_id"]


def test_api_decide_without_audit_path_has_null_event_ids(tmp_path: Path) -> None:
    policy_path = _write_policy(tmp_path, lambda data: None)
    api = AetheryaAPI(APISettings(policy_path=policy_path, audit_path=None))

    status, payload = api.decide({"raw_input": "help user"})
    assert status == 200
    assert payload["ok"] is True
    assert payload["meta"]["event_id"] is None
    assert payload["meta"]["decision_id"] is None
    assert payload["meta"]["audit_path"] is None


def test_api_decide_no_wait_shadow_disables_llm_shadow(tmp_path: Path) -> None:
    policy_path = _write_policy(
        tmp_path,
        lambda data: data["llm_shadow"].update(
            {"enabled": True, "provider": "dry_run", "model": "gpt-dry", "max_tokens": 32}
        ),
    )
    audit_path = tmp_path / "decisions.jsonl"
    api = AetheryaAPI(APISettings(policy_path=policy_path, audit_path=audit_path))

    status, payload = api.decide({"raw_input": "help user", "wait_shadow": False})
    assert status == 200
    assert payload["ok"] is True
    assert payload["meta"]["llm_shadow_enabled_config"] is True
    assert payload["meta"]["llm_shadow_enabled_effective"] is False

    event = _read_last_event(audit_path)
    assert "llm_shadow" not in event["context"]


def test_api_decide_validation_errors(tmp_path: Path) -> None:
    policy_path = _write_policy(tmp_path, lambda data: None)
    api = AetheryaAPI(APISettings(policy_path=policy_path, audit_path=tmp_path / "decisions.jsonl"))

    bad_shape_status, bad_shape_payload = api.decide(["no-object"])
    assert bad_shape_status == 400
    assert bad_shape_payload["ok"] is False

    missing_raw_status, missing_raw_payload = api.decide({})
    assert missing_raw_status == 400
    assert missing_raw_payload["ok"] is False
    assert "raw_input" in missing_raw_payload["error"]

    bad_actor_status, bad_actor_payload = api.decide({"raw_input": "help", "actor": 123})
    assert bad_actor_status == 400
    assert bad_actor_payload["ok"] is False
    assert "actor" in bad_actor_payload["error"]

    bad_wait_status, bad_wait_payload = api.decide({"raw_input": "help", "wait_shadow": "yes"})
    assert bad_wait_status == 400
    assert bad_wait_payload["ok"] is False
    assert "wait_shadow" in bad_wait_payload["error"]


def test_api_decide_internal_error_returns_500(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import aetherya.api as api_module

    policy_path = _write_policy(tmp_path, lambda data: None)
    api = AetheryaAPI(APISettings(policy_path=policy_path, audit_path=tmp_path / "decisions.jsonl"))

    def boom(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        raise RuntimeError("pipeline exploded")

    monkeypatch.setattr(api_module, "run_pipeline", boom)

    status, payload = api.decide({"raw_input": "help user"})
    assert status == 500
    assert payload["ok"] is False
    assert payload["error_type"] == "RuntimeError"


def test_api_audit_verify_success_and_invalid_chain(tmp_path: Path) -> None:
    policy_path = _write_policy(tmp_path, lambda data: None)
    audit_path = tmp_path / "decisions.jsonl"
    api = AetheryaAPI(APISettings(policy_path=policy_path, audit_path=audit_path))

    first_status, _ = api.decide({"raw_input": "test input 1"})
    second_status, _ = api.decide({"raw_input": "test input 2"})
    assert first_status == 200
    assert second_status == 200

    ok_status, ok_payload = api.audit_verify({"require_chain": True})
    assert ok_status == 200
    assert ok_payload["ok"] is True
    assert ok_payload["report"]["invalid"] == 0

    tampered_path = tmp_path / "tampered.jsonl"
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    lines[0], lines[1] = lines[1], lines[0]
    tampered_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tampered_api = AetheryaAPI(APISettings(policy_path=policy_path, audit_path=tampered_path))

    bad_status, bad_payload = tampered_api.audit_verify({"require_chain": True})
    assert bad_status == 200
    assert bad_payload["ok"] is False
    assert bad_payload["report"]["invalid"] > 0


def test_api_audit_verify_validation_and_disabled_path(tmp_path: Path) -> None:
    policy_path = _write_policy(tmp_path, lambda data: None)
    api = AetheryaAPI(APISettings(policy_path=policy_path, audit_path=tmp_path / "decisions.jsonl"))
    disabled_api = AetheryaAPI(APISettings(policy_path=policy_path, audit_path=None))

    status_a, payload_a = api.audit_verify(["bad"])
    assert status_a == 400
    assert payload_a["ok"] is False

    status_b, payload_b = api.audit_verify({"event_index": True})
    assert status_b == 400
    assert payload_b["ok"] is False
    assert "event_index" in payload_b["error"]

    status_c, payload_c = api.audit_verify({"attestation_key": 123})
    assert status_c == 400
    assert payload_c["ok"] is False
    assert "attestation_key" in payload_c["error"]

    status_d, payload_d = disabled_api.audit_verify({})
    assert status_d == 400
    assert payload_d["ok"] is False
    assert "audit_path is disabled" in payload_d["error"]


def test_api_audit_verify_internal_error_returns_500(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import aetherya.api as api_module

    policy_path = _write_policy(tmp_path, lambda data: None)
    api = AetheryaAPI(APISettings(policy_path=policy_path, audit_path=tmp_path / "decisions.jsonl"))

    def boom(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        raise RuntimeError("verify exploded")

    monkeypatch.setattr(api_module, "verify_audit_file", boom)

    status, payload = api.audit_verify({})
    assert status == 500
    assert payload["ok"] is False
    assert payload["error_type"] == "RuntimeError"


def test_api_internal_parsers_and_constitution_path_branch(tmp_path: Path) -> None:
    import aetherya.api as api_module

    assert api_module._as_mapping(None, field_name="payload") == {}  # noqa: SLF001

    with pytest.raises(ValueError, match="must be non-empty"):
        api_module._as_non_empty_str("   ", field_name="raw_input")  # noqa: SLF001

    assert api_module._as_optional_int(7, field_name="event_index") == 7  # noqa: SLF001
    with pytest.raises(ValueError, match="must be int"):
        api_module._as_optional_int("x", field_name="event_index")  # noqa: SLF001

    assert api_module._as_optional_str("   ", field_name="attestation_key") is None  # noqa: SLF001

    policy_path = _write_policy(tmp_path, lambda data: None)
    constitution_path = tmp_path / "constitution.yaml"
    constitution_path.write_text(
        yaml.safe_dump(
            {
                "principles": [
                    {
                        "name": "CustomRule",
                        "description": "custom rule",
                        "priority": 1,
                        "keywords": ["forbidden_token"],
                        "risk": 90,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    api = AetheryaAPI(
        APISettings(
            policy_path=policy_path,
            audit_path=tmp_path / "decisions.jsonl",
            constitution_path=constitution_path,
        )
    )
    core = api._resolve_constitution()  # noqa: SLF001
    assert core.principles[0].name == "CustomRule"


def test_api_dispatch_post_audit_verify_route(tmp_path: Path) -> None:
    policy_path = _write_policy(tmp_path, lambda data: None)
    audit_path = tmp_path / "decisions.jsonl"
    api = AetheryaAPI(APISettings(policy_path=policy_path, audit_path=audit_path))
    status_decide, _ = api.decide({"raw_input": "help user"})
    assert status_decide == 200

    status, payload = api.dispatch("POST", "/v1/audit/verify", {"require_chain": True})
    assert status == 200
    assert "report" in payload


def test_api_dispatch_method_not_allowed_for_post_routes(tmp_path: Path) -> None:
    policy_path = _write_policy(tmp_path, lambda data: None)
    api = AetheryaAPI(APISettings(policy_path=policy_path, audit_path=tmp_path / "decisions.jsonl"))

    status_decide, payload_decide = api.dispatch("GET", "/v1/decide")
    assert status_decide == 405
    assert payload_decide["ok"] is False
    assert payload_decide["error_type"] == "MethodNotAllowed"
    assert payload_decide["allowed_methods"] == ["POST"]

    status_verify, payload_verify = api.dispatch("GET", "/v1/audit/verify")
    assert status_verify == 405
    assert payload_verify["ok"] is False
    assert payload_verify["error_type"] == "MethodNotAllowed"
    assert payload_verify["allowed_methods"] == ["POST"]
