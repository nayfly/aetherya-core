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
    assert cfg.confirmation.evidence.signed_proof.enabled is False
    assert cfg.confirmation.evidence.signed_proof.proof_param == "confirm_proof"
    assert (
        cfg.confirmation.evidence.signed_proof.keyring_env == "AETHERYA_CONFIRMATION_HMAC_KEYRING"
    )
    assert cfg.confirmation.evidence.signed_proof.active_kid == "k1"
    assert cfg.confirmation.evidence.signed_proof.replay_mode == "single_use"
    assert cfg.confirmation.evidence.signed_proof.replay_store == "memory"
    assert (
        cfg.confirmation.evidence.signed_proof.replay_redis_url_env
        == "AETHERYA_CONFIRMATION_REPLAY_REDIS_URL"
    )
    assert cfg.confirmation.evidence.signed_proof.replay_redis_prefix == "aetherya:appr"


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
                "signed_proof": {
                    "enabled": True,
                    "proof_param": "confirm_proof",
                    "key_env": "AETHERYA_CONFIRMATION_HMAC_KEY",
                    "keyring_env": "AETHERYA_CONFIRMATION_HMAC_KEYRING",
                    "active_kid": "k2",
                    "max_valid_for_sec": 600,
                    "clock_skew_sec": 3,
                    "replay_mode": "idempotent",
                    "replay_store": "redis",
                    "replay_redis_url_env": "AETHERYA_TEST_REPLAY_URL",
                    "replay_redis_prefix": "aetherya:test:replay",
                },
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
    assert cfg.confirmation.evidence.signed_proof.enabled is True
    assert cfg.confirmation.evidence.signed_proof.proof_param == "confirm_proof"
    assert cfg.confirmation.evidence.signed_proof.key_env == "AETHERYA_CONFIRMATION_HMAC_KEY"
    assert (
        cfg.confirmation.evidence.signed_proof.keyring_env == "AETHERYA_CONFIRMATION_HMAC_KEYRING"
    )
    assert cfg.confirmation.evidence.signed_proof.active_kid == "k2"
    assert cfg.confirmation.evidence.signed_proof.max_valid_for_sec == 600
    assert cfg.confirmation.evidence.signed_proof.clock_skew_sec == 3
    assert cfg.confirmation.evidence.signed_proof.replay_mode == "idempotent"
    assert cfg.confirmation.evidence.signed_proof.replay_store == "redis"
    assert cfg.confirmation.evidence.signed_proof.replay_redis_url_env == "AETHERYA_TEST_REPLAY_URL"
    assert cfg.confirmation.evidence.signed_proof.replay_redis_prefix == "aetherya:test:replay"


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


def test_confirmation_signed_proof_empty_param_raises(tmp_path):
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
                "min_context_length": 12,
                "signed_proof": {
                    "enabled": True,
                    "proof_param": "",
                },
            },
        },
    }

    path = tmp_path / "with_bad_confirmation_empty_proof_param.yaml"
    path.write_text(yaml.dump(cfg_data))

    with pytest.raises(ValueError):
        load_policy_config(path)


def test_confirmation_signed_proof_window_constraints_raise(tmp_path):
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
                "min_context_length": 12,
                "signed_proof": {
                    "enabled": True,
                    "proof_param": "confirm_proof",
                    "key_env": "AETHERYA_CONFIRMATION_HMAC_KEY",
                    "max_valid_for_sec": 0,
                    "clock_skew_sec": 3,
                },
            },
        },
    }
    path = tmp_path / "with_bad_confirmation_signed_proof_window.yaml"
    path.write_text(yaml.dump(cfg_data))

    with pytest.raises(ValueError):
        load_policy_config(path)

    cfg_data["confirmation"]["evidence"]["signed_proof"]["max_valid_for_sec"] = 600
    cfg_data["confirmation"]["evidence"]["signed_proof"]["clock_skew_sec"] = -1
    path.write_text(yaml.dump(cfg_data))
    with pytest.raises(ValueError):
        load_policy_config(path)


def test_confirmation_signed_proof_param_conflict_and_empty_key_env_raise(tmp_path):
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
                "min_context_length": 12,
                "signed_proof": {
                    "enabled": True,
                    "proof_param": "confirm_token",
                    "key_env": "AETHERYA_CONFIRMATION_HMAC_KEY",
                    "keyring_env": "AETHERYA_CONFIRMATION_HMAC_KEYRING",
                    "active_kid": "k1",
                    "max_valid_for_sec": 600,
                    "clock_skew_sec": 1,
                    "replay_mode": "single_use",
                },
            },
        },
    }

    path = tmp_path / "with_bad_confirmation_signed_proof_conflict.yaml"
    path.write_text(yaml.dump(cfg_data))
    with pytest.raises(ValueError):
        load_policy_config(path)

    signed_proof = cfg_data["confirmation"]["evidence"]["signed_proof"]

    signed_proof["proof_param"] = "confirm_proof"
    signed_proof["key_env"] = ""
    path.write_text(yaml.dump(cfg_data))
    with pytest.raises(ValueError):
        load_policy_config(path)

    signed_proof["key_env"] = "AETHERYA_CONFIRMATION_HMAC_KEY"
    signed_proof["keyring_env"] = ""
    path.write_text(yaml.dump(cfg_data))
    with pytest.raises(ValueError):
        load_policy_config(path)

    signed_proof["keyring_env"] = "AETHERYA_CONFIRMATION_HMAC_KEYRING"
    signed_proof["active_kid"] = ""
    path.write_text(yaml.dump(cfg_data))
    with pytest.raises(ValueError):
        load_policy_config(path)

    signed_proof["active_kid"] = "k1"
    signed_proof["replay_mode"] = "invalid"
    path.write_text(yaml.dump(cfg_data))
    with pytest.raises(ValueError):
        load_policy_config(path)

    signed_proof["replay_mode"] = "single_use"
    signed_proof["replay_store"] = "bad-store"
    path.write_text(yaml.dump(cfg_data))
    with pytest.raises(ValueError):
        load_policy_config(path)

    signed_proof["replay_store"] = "redis"
    signed_proof["replay_redis_url_env"] = ""
    path.write_text(yaml.dump(cfg_data))
    with pytest.raises(ValueError):
        load_policy_config(path)

    signed_proof["replay_redis_url_env"] = "AETHERYA_CONFIRMATION_REPLAY_REDIS_URL"
    signed_proof["replay_redis_prefix"] = ""
    path.write_text(yaml.dump(cfg_data))
    with pytest.raises(ValueError):
        load_policy_config(path)


def test_policy_fingerprint_is_present_and_stable(tmp_path):
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

    path = tmp_path / "policy.yaml"
    path.write_text(yaml.dump(cfg_data))
    cfg1 = load_policy_config(path)
    cfg2 = load_policy_config(path)

    assert isinstance(cfg1.policy_fingerprint, str)
    assert cfg1.policy_fingerprint.startswith("sha256:")
    assert cfg1.policy_fingerprint == cfg2.policy_fingerprint


def test_llm_shadow_defaults_when_missing(tmp_path):
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

    path = tmp_path / "policy.yaml"
    path.write_text(yaml.dump(cfg_data))
    cfg = load_policy_config(path)

    assert cfg.llm_shadow.enabled is False
    assert cfg.llm_shadow.provider == "dry_run"
    assert cfg.llm_shadow.model == "gpt-dry"
    assert cfg.llm_shadow.temperature == 0.0
    assert cfg.llm_shadow.max_tokens == 128
    assert cfg.llm_shadow.timeout_sec == 10.0


def test_llm_shadow_parsing(tmp_path):
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
        "llm_shadow": {
            "enabled": True,
            "provider": "openai",
            "model": "gpt-shadow",
            "temperature": 0.4,
            "max_tokens": 64,
            "timeout_sec": 7.5,
        },
    }

    path = tmp_path / "policy_shadow.yaml"
    path.write_text(yaml.dump(cfg_data))
    cfg = load_policy_config(path)

    assert cfg.llm_shadow.enabled is True
    assert cfg.llm_shadow.provider == "openai"
    assert cfg.llm_shadow.model == "gpt-shadow"
    assert cfg.llm_shadow.temperature == 0.4
    assert cfg.llm_shadow.max_tokens == 64
    assert cfg.llm_shadow.timeout_sec == 7.5


def test_llm_shadow_invalid_temperature_raises(tmp_path):
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
        "llm_shadow": {
            "enabled": True,
            "model": "gpt-shadow",
            "temperature": 3.0,
            "max_tokens": 64,
        },
    }

    path = tmp_path / "policy_shadow_bad_temp.yaml"
    path.write_text(yaml.dump(cfg_data))

    with pytest.raises(ValueError, match="llm_shadow.temperature"):
        load_policy_config(path)


def test_llm_shadow_invalid_max_tokens_raises(tmp_path):
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
        "llm_shadow": {
            "enabled": True,
            "model": "gpt-shadow",
            "temperature": 0.2,
            "max_tokens": 0,
        },
    }

    path = tmp_path / "policy_shadow_bad_tokens.yaml"
    path.write_text(yaml.dump(cfg_data))

    with pytest.raises(ValueError, match="llm_shadow.max_tokens"):
        load_policy_config(path)


def test_llm_shadow_empty_model_raises(tmp_path):
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
        "llm_shadow": {
            "enabled": True,
            "model": "",
            "temperature": 0.2,
            "max_tokens": 64,
        },
    }

    path = tmp_path / "policy_shadow_bad_model.yaml"
    path.write_text(yaml.dump(cfg_data))

    with pytest.raises(ValueError, match="llm_shadow.model"):
        load_policy_config(path)


def test_llm_shadow_invalid_provider_raises(tmp_path):
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
        "llm_shadow": {
            "enabled": True,
            "provider": "anthropic",
            "model": "gpt-shadow",
            "temperature": 0.2,
            "max_tokens": 64,
            "timeout_sec": 5.0,
        },
    }

    path = tmp_path / "policy_shadow_bad_provider.yaml"
    path.write_text(yaml.dump(cfg_data))

    with pytest.raises(ValueError, match="llm_shadow.provider"):
        load_policy_config(path)


def test_llm_shadow_invalid_timeout_raises(tmp_path):
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
        "llm_shadow": {
            "enabled": True,
            "provider": "openai",
            "model": "gpt-shadow",
            "temperature": 0.2,
            "max_tokens": 64,
            "timeout_sec": 0.0,
        },
    }

    path = tmp_path / "policy_shadow_bad_timeout.yaml"
    path.write_text(yaml.dump(cfg_data))

    with pytest.raises(ValueError, match="llm_shadow.timeout_sec"):
        load_policy_config(path)


def test_policy_adapter_shadow_defaults_when_missing(tmp_path):
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

    path = tmp_path / "policy_adapter_shadow_defaults.yaml"
    path.write_text(yaml.dump(cfg_data))
    cfg = load_policy_config(path)

    assert cfg.policy_adapter_shadow.enabled is False
    assert cfg.policy_adapter_shadow.max_signals == 3


def test_policy_adapter_shadow_parsing(tmp_path):
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
        "policy_adapter_shadow": {
            "enabled": True,
            "max_signals": 5,
        },
    }

    path = tmp_path / "policy_adapter_shadow_parsing.yaml"
    path.write_text(yaml.dump(cfg_data))
    cfg = load_policy_config(path)

    assert cfg.policy_adapter_shadow.enabled is True
    assert cfg.policy_adapter_shadow.max_signals == 5


def test_policy_adapter_shadow_invalid_max_signals_raises(tmp_path):
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
        "policy_adapter_shadow": {
            "enabled": True,
            "max_signals": 0,
        },
    }

    path = tmp_path / "policy_adapter_shadow_bad_max.yaml"
    path.write_text(yaml.dump(cfg_data))

    with pytest.raises(ValueError, match="policy_adapter_shadow.max_signals"):
        load_policy_config(path)
