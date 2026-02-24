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
