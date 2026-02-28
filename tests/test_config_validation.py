import pytest
import yaml

from aetherya.config import load_policy_config


def test_missing_required_key_raises(tmp_path):
    bad_config = {
        # version missing intentionally
        "modes": {}
    }

    path = tmp_path / "bad.yaml"
    path.write_text(yaml.dump(bad_config))

    with pytest.raises(ValueError):
        load_policy_config(path)


def test_missing_thresholds_raises(tmp_path):
    bad_config = {
        "version": 1,
        "modes": {
            "consultive": {
                "default_state": "log_only"
                # thresholds missing
            }
        },
        "aggregator": {"weights": {}, "hard_deny_if": []},
        "procedural_guard": {"critical_tags": [], "privileged_ops": []},
    }

    path = tmp_path / "bad2.yaml"
    path.write_text(yaml.dump(bad_config))

    with pytest.raises(ValueError):
        load_policy_config(path)


def test_execution_gate_defaults_when_missing(tmp_path):
    cfg_data = {
        "version": 1,
        "modes": {
            "consultive": {
                "default_state": "log_only",
                "thresholds": {"deny_at": 90, "confirm_at": 60, "log_only_at": 0},
            }
        },
        "aggregator": {"weights": {}, "hard_deny_if": []},
        "procedural_guard": {"critical_tags": [], "privileged_ops": []},
    }

    path = tmp_path / "minimal.yaml"
    path.write_text(yaml.dump(cfg_data))

    cfg = load_policy_config(path)
    assert cfg.execution_gate.enabled is True
    assert cfg.execution_gate.allowed_tools == []
    assert cfg.execution_gate.required_parameters == {}


def test_execution_gate_parses_tool_schemas(tmp_path):
    cfg_data = {
        "version": 1,
        "modes": {
            "consultive": {
                "default_state": "log_only",
                "thresholds": {"deny_at": 90, "confirm_at": 60, "log_only_at": 0},
            }
        },
        "aggregator": {"weights": {}, "hard_deny_if": []},
        "procedural_guard": {"critical_tags": [], "privileged_ops": []},
        "execution_gate": {
            "enabled": True,
            "allowed_tools": ["shell"],
            "require_target_for_operate": True,
            "required_parameters": {"shell": ["command"]},
            "allowed_parameters": {"shell": ["command", "timeout"]},
        },
    }

    path = tmp_path / "with_gate.yaml"
    path.write_text(yaml.dump(cfg_data))

    cfg = load_policy_config(path)
    assert cfg.execution_gate.require_target_for_operate is True
    assert cfg.execution_gate.required_parameters["shell"] == ["command"]
    assert cfg.execution_gate.allowed_parameters["shell"] == ["command", "timeout"]


def test_capability_matrix_defaults_when_missing(tmp_path):
    cfg_data = {
        "version": 1,
        "modes": {
            "consultive": {
                "default_state": "log_only",
                "thresholds": {"deny_at": 90, "confirm_at": 60, "log_only_at": 0},
            }
        },
        "aggregator": {"weights": {}, "hard_deny_if": []},
        "procedural_guard": {"critical_tags": [], "privileged_ops": []},
    }

    path = tmp_path / "minimal_with_capability_defaults.yaml"
    path.write_text(yaml.dump(cfg_data))

    cfg = load_policy_config(path)
    assert cfg.capability_matrix.enabled is False
    assert cfg.capability_matrix.default_allow is False
    assert cfg.capability_matrix.roles == {}
    assert cfg.capability_matrix.actors == {}


def test_capability_matrix_parses_roles_and_actors(tmp_path):
    cfg_data = {
        "version": 1,
        "modes": {
            "consultive": {
                "default_state": "log_only",
                "thresholds": {"deny_at": 90, "confirm_at": 60, "log_only_at": 0},
            }
        },
        "aggregator": {"weights": {}, "hard_deny_if": []},
        "procedural_guard": {"critical_tags": [], "privileged_ops": []},
        "capability_matrix": {
            "enabled": True,
            "default_allow": False,
            "roles": {
                "operator": {
                    "tools": ["shell", "filesystem"],
                    "operations": ["read", "write"],
                }
            },
            "actors": {
                "robert": {
                    "roles": ["operator"],
                    "tools": ["http"],
                    "operations": ["request"],
                }
            },
        },
    }

    path = tmp_path / "with_capability_matrix.yaml"
    path.write_text(yaml.dump(cfg_data))

    cfg = load_policy_config(path)
    assert cfg.capability_matrix.enabled is True
    assert cfg.capability_matrix.roles["operator"].tools == ["shell", "filesystem"]
    assert cfg.capability_matrix.actors["robert"].roles == ["operator"]


def test_confirmation_defaults_when_missing(tmp_path):
    cfg_data = {
        "version": 1,
        "modes": {
            "consultive": {
                "default_state": "log_only",
                "thresholds": {"deny_at": 90, "confirm_at": 60, "log_only_at": 0},
            }
        },
        "aggregator": {"weights": {}, "hard_deny_if": []},
        "procedural_guard": {"critical_tags": [], "privileged_ops": []},
    }

    path = tmp_path / "minimal_with_confirmation_defaults.yaml"
    path.write_text(yaml.dump(cfg_data))

    cfg = load_policy_config(path)
    assert cfg.confirmation.enabled is False
    assert cfg.confirmation.on_confirmed == "allow"
    assert cfg.confirmation.require_for.decisions == ["require_confirm"]
    assert cfg.confirmation.evidence.token_param == "confirm_token"


def test_confirmation_parsing(tmp_path):
    cfg_data = {
        "version": 1,
        "modes": {
            "consultive": {
                "default_state": "log_only",
                "thresholds": {"deny_at": 90, "confirm_at": 60, "log_only_at": 0},
            }
        },
        "aggregator": {"weights": {}, "hard_deny_if": []},
        "procedural_guard": {"critical_tags": [], "privileged_ops": []},
        "confirmation": {
            "enabled": True,
            "on_confirmed": "log_only",
            "require_for": {
                "decisions": ["require_confirm"],
                "tools": ["shell"],
                "operations": ["delete"],
                "min_risk_score": 50,
            },
            "evidence": {
                "token_param": "confirm_token",
                "context_param": "confirm_context",
                "token_pattern": "^ack:[a-z0-9_-]{8,}$",
                "min_context_length": 16,
            },
        },
    }

    path = tmp_path / "with_confirmation.yaml"
    path.write_text(yaml.dump(cfg_data))

    cfg = load_policy_config(path)
    assert cfg.confirmation.enabled is True
    assert cfg.confirmation.on_confirmed == "log_only"
    assert cfg.confirmation.require_for.tools == ["shell"]
    assert cfg.confirmation.evidence.min_context_length == 16


def test_capability_matrix_unknown_role_reference_raises(tmp_path):
    cfg_data = {
        "version": 1,
        "modes": {
            "consultive": {
                "default_state": "log_only",
                "thresholds": {"deny_at": 90, "confirm_at": 60, "log_only_at": 0},
            }
        },
        "aggregator": {"weights": {}, "hard_deny_if": []},
        "procedural_guard": {"critical_tags": [], "privileged_ops": []},
        "capability_matrix": {
            "enabled": True,
            "default_allow": False,
            "roles": {},
            "actors": {
                "robert": {
                    "roles": ["operator"],
                    "tools": [],
                    "operations": [],
                }
            },
        },
    }

    path = tmp_path / "with_bad_capability_role_ref.yaml"
    path.write_text(yaml.dump(cfg_data))

    with pytest.raises(ValueError):
        load_policy_config(path)


def test_confirmation_negative_min_context_length_raises(tmp_path):
    cfg_data = {
        "version": 1,
        "modes": {
            "consultive": {
                "default_state": "log_only",
                "thresholds": {"deny_at": 90, "confirm_at": 60, "log_only_at": 0},
            }
        },
        "aggregator": {"weights": {}, "hard_deny_if": []},
        "procedural_guard": {"critical_tags": [], "privileged_ops": []},
        "confirmation": {
            "enabled": True,
            "evidence": {
                "token_param": "confirm_token",
                "context_param": "confirm_context",
                "token_pattern": "^ack:[a-z0-9_-]{8,}$",
                "min_context_length": -1,
            },
        },
    }

    path = tmp_path / "with_bad_confirmation_context_len.yaml"
    path.write_text(yaml.dump(cfg_data))

    with pytest.raises(ValueError):
        load_policy_config(path)


def test_confirmation_negative_min_risk_score_raises(tmp_path):
    cfg_data = {
        "version": 1,
        "modes": {
            "consultive": {
                "default_state": "log_only",
                "thresholds": {"deny_at": 90, "confirm_at": 60, "log_only_at": 0},
            }
        },
        "aggregator": {"weights": {}, "hard_deny_if": []},
        "procedural_guard": {"critical_tags": [], "privileged_ops": []},
        "confirmation": {
            "enabled": True,
            "require_for": {"min_risk_score": -1},
            "evidence": {
                "token_param": "confirm_token",
                "context_param": "confirm_context",
                "token_pattern": "^ack:[a-z0-9_-]{8,}$",
                "min_context_length": 12,
            },
        },
    }

    path = tmp_path / "with_bad_confirmation_min_risk_score.yaml"
    path.write_text(yaml.dump(cfg_data))

    with pytest.raises(ValueError):
        load_policy_config(path)


def test_confirmation_empty_token_param_raises(tmp_path):
    cfg_data = {
        "version": 1,
        "modes": {
            "consultive": {
                "default_state": "log_only",
                "thresholds": {"deny_at": 90, "confirm_at": 60, "log_only_at": 0},
            }
        },
        "aggregator": {"weights": {}, "hard_deny_if": []},
        "procedural_guard": {"critical_tags": [], "privileged_ops": []},
        "confirmation": {
            "enabled": True,
            "evidence": {
                "token_param": "",
                "context_param": "confirm_context",
                "token_pattern": "^ack:[a-z0-9_-]{8,}$",
                "min_context_length": 12,
            },
        },
    }

    path = tmp_path / "with_bad_confirmation_empty_token_key.yaml"
    path.write_text(yaml.dump(cfg_data))

    with pytest.raises(ValueError):
        load_policy_config(path)


def test_confirmation_empty_context_param_raises(tmp_path):
    cfg_data = {
        "version": 1,
        "modes": {
            "consultive": {
                "default_state": "log_only",
                "thresholds": {"deny_at": 90, "confirm_at": 60, "log_only_at": 0},
            }
        },
        "aggregator": {"weights": {}, "hard_deny_if": []},
        "procedural_guard": {"critical_tags": [], "privileged_ops": []},
        "confirmation": {
            "enabled": True,
            "evidence": {
                "token_param": "confirm_token",
                "context_param": "",
                "token_pattern": "^ack:[a-z0-9_-]{8,}$",
                "min_context_length": 12,
            },
        },
    }

    path = tmp_path / "with_bad_confirmation_empty_context_key.yaml"
    path.write_text(yaml.dump(cfg_data))

    with pytest.raises(ValueError):
        load_policy_config(path)


def test_confirmation_same_evidence_keys_raise(tmp_path):
    cfg_data = {
        "version": 1,
        "modes": {
            "consultive": {
                "default_state": "log_only",
                "thresholds": {"deny_at": 90, "confirm_at": 60, "log_only_at": 0},
            }
        },
        "aggregator": {"weights": {}, "hard_deny_if": []},
        "procedural_guard": {"critical_tags": [], "privileged_ops": []},
        "confirmation": {
            "enabled": True,
            "evidence": {
                "token_param": "confirm",
                "context_param": "confirm",
                "token_pattern": "^ack:[a-z0-9_-]{8,}$",
                "min_context_length": 12,
            },
        },
    }

    path = tmp_path / "with_bad_confirmation_same_keys.yaml"
    path.write_text(yaml.dump(cfg_data))

    with pytest.raises(ValueError):
        load_policy_config(path)
