from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class ModeThresholds:
    deny_at: int
    confirm_at: int
    log_only_at: int = 0


@dataclass(frozen=True)
class ModeConfig:
    default_state: str
    thresholds: ModeThresholds


@dataclass(frozen=True)
class AggregatorConfig:
    weights: dict[str, float]
    hard_deny_if: list[str]


@dataclass(frozen=True)
class ProceduralGuardConfig:
    critical_tags: list[str]
    privileged_ops: list[str]


@dataclass(frozen=True)
class ExecutionGateConfig:
    enabled: bool
    allowed_tools: list[str]
    require_target_for_operate: bool
    required_parameters: dict[str, list[str]]
    allowed_parameters: dict[str, list[str]]


@dataclass(frozen=True)
class CapabilityRoleConfig:
    tools: list[str]
    operations: list[str]


@dataclass(frozen=True)
class CapabilityActorConfig:
    roles: list[str]
    tools: list[str]
    operations: list[str]


@dataclass(frozen=True)
class CapabilityMatrixConfig:
    enabled: bool
    default_allow: bool
    roles: dict[str, CapabilityRoleConfig]
    actors: dict[str, CapabilityActorConfig]


@dataclass(frozen=True)
class ConfirmationRequireConfig:
    decisions: list[str]
    tools: list[str]
    operations: list[str]
    min_risk_score: int


@dataclass(frozen=True)
class ConfirmationSignedProofConfig:
    enabled: bool = False
    proof_param: str = "confirm_proof"
    key_env: str = "AETHERYA_CONFIRMATION_HMAC_KEY"
    keyring_env: str = "AETHERYA_CONFIRMATION_HMAC_KEYRING"
    active_kid: str = "k1"
    max_valid_for_sec: int = 900
    clock_skew_sec: int = 5
    replay_mode: str = "single_use"
    replay_store: str = "memory"
    replay_redis_url_env: str = "AETHERYA_CONFIRMATION_REPLAY_REDIS_URL"
    replay_redis_prefix: str = "aetherya:appr"


@dataclass(frozen=True)
class ConfirmationEvidenceConfig:
    token_param: str
    context_param: str
    token_pattern: str
    min_context_length: int
    signed_proof: ConfirmationSignedProofConfig = field(
        default_factory=ConfirmationSignedProofConfig
    )


@dataclass(frozen=True)
class ConfirmationConfig:
    enabled: bool
    on_confirmed: str
    require_for: ConfirmationRequireConfig
    evidence: ConfirmationEvidenceConfig


@dataclass(frozen=True)
class LLMShadowConfig:
    enabled: bool
    provider: str
    model: str
    temperature: float
    max_tokens: int
    timeout_sec: float


@dataclass(frozen=True)
class PolicyAdapterShadowConfig:
    enabled: bool
    max_signals: int


@dataclass(frozen=True)
class OutputGateConfig:
    """
    Configuration for the OutputGate response safety check.

    require_candidate_response: if True, run_pipeline will fail-closed when called
    without a candidate_response (response_text=None). Enforces that integrators
    who want output protection actually wire up the response. Default: False (opt-in).
    """

    require_candidate_response: bool = False


@dataclass(frozen=True)
class ConstitutionConfig:
    """
    Configuration for the semantic layer of the Constitution evaluator.

    Thresholds for SemanticEvaluator:
    - semantic_violation_threshold: cosine similarity above this → clear violation
    - semantic_gray_zone_threshold: cosine similarity above this (but below violation
      threshold) → gray zone with reduced risk score

    Defaults match the previously hardcoded values (0.55 / 0.35).
    """

    semantic_violation_threshold: float = 0.55
    semantic_gray_zone_threshold: float = 0.35


@dataclass(frozen=True)
class PolicyConfig:
    version: int
    modes: dict[str, ModeConfig]
    aggregator: AggregatorConfig
    procedural_guard: ProceduralGuardConfig
    execution_gate: ExecutionGateConfig
    capability_matrix: CapabilityMatrixConfig
    confirmation: ConfirmationConfig
    llm_shadow: LLMShadowConfig
    policy_adapter_shadow: PolicyAdapterShadowConfig
    policy_fingerprint: str | None = None
    output_gate_config: OutputGateConfig = field(default_factory=OutputGateConfig)
    constitution_config: ConstitutionConfig = field(default_factory=ConstitutionConfig)


def _require(d: dict[str, Any], key: str) -> Any:
    if key not in d:
        raise ValueError(f"Missing required key: {key}")
    return d[key]


def _policy_fingerprint(raw_text: str) -> str:
    return f"sha256:{hashlib.sha256(raw_text.encode('utf-8')).hexdigest()}"


def _load_execution_gate(raw: dict[str, Any] | None) -> ExecutionGateConfig:
    data = raw or {}

    enabled = bool(data.get("enabled", True))
    allowed_tools = [str(t) for t in data.get("allowed_tools", [])]
    require_target = bool(data.get("require_target_for_operate", False))

    required_raw = data.get("required_parameters", {})
    required_parameters: dict[str, list[str]] = {}
    for tool, params in dict(required_raw).items():
        required_parameters[str(tool)] = [str(p) for p in list(params)]

    allowed_raw = data.get("allowed_parameters", {})
    allowed_parameters: dict[str, list[str]] = {}
    for tool, params in dict(allowed_raw).items():
        allowed_parameters[str(tool)] = [str(p) for p in list(params)]

    return ExecutionGateConfig(
        enabled=enabled,
        allowed_tools=allowed_tools,
        require_target_for_operate=require_target,
        required_parameters=required_parameters,
        allowed_parameters=allowed_parameters,
    )


def _load_capability_matrix(raw: dict[str, Any] | None) -> CapabilityMatrixConfig:
    data = raw or {}

    enabled = bool(data.get("enabled", False))
    default_allow = bool(data.get("default_allow", False))

    roles_raw = dict(data.get("roles", {}))
    roles: dict[str, CapabilityRoleConfig] = {}
    for role_name, role_data in roles_raw.items():
        role_dict = dict(role_data)
        role_id = str(role_name).strip().lower()
        roles[role_id] = CapabilityRoleConfig(
            tools=[
                str(t).strip().lower() for t in list(role_dict.get("tools", [])) if str(t).strip()
            ],
            operations=[
                str(op).strip().lower()
                for op in list(role_dict.get("operations", []))
                if str(op).strip()
            ],
        )

    actors_raw = dict(data.get("actors", {}))
    actors: dict[str, CapabilityActorConfig] = {}
    for actor_name, actor_data in actors_raw.items():
        actor_dict = dict(actor_data)
        actor_id = str(actor_name).strip().lower()
        actors[actor_id] = CapabilityActorConfig(
            roles=[
                str(role).strip().lower()
                for role in list(actor_dict.get("roles", []))
                if str(role).strip()
            ],
            tools=[
                str(t).strip().lower() for t in list(actor_dict.get("tools", [])) if str(t).strip()
            ],
            operations=[
                str(op).strip().lower()
                for op in list(actor_dict.get("operations", []))
                if str(op).strip()
            ],
        )

    for actor_id, actor_cfg in actors.items():
        missing_roles = [role for role in actor_cfg.roles if role not in roles]
        if missing_roles:
            raise ValueError(
                f"capability_matrix actor '{actor_id}' references unknown roles: {missing_roles}"
            )

    return CapabilityMatrixConfig(
        enabled=enabled,
        default_allow=default_allow,
        roles=roles,
        actors=actors,
    )


def _load_confirmation(raw: dict[str, Any] | None) -> ConfirmationConfig:
    data = raw or {}

    require_raw = dict(data.get("require_for", {}))
    evidence_raw = dict(data.get("evidence", {}))
    signed_proof_raw = dict(evidence_raw.get("signed_proof", {}))

    min_risk_score = int(require_raw.get("min_risk_score", 0))
    if min_risk_score < 0:
        raise ValueError("confirmation.require_for.min_risk_score must be >= 0")

    require_for = ConfirmationRequireConfig(
        decisions=[
            str(d).strip().lower()
            for d in list(require_raw.get("decisions", ["require_confirm"]))
            if str(d).strip()
        ],
        tools=[
            str(t).strip().lower() for t in list(require_raw.get("tools", [])) if str(t).strip()
        ],
        operations=[
            str(op).strip().lower()
            for op in list(require_raw.get("operations", []))
            if str(op).strip()
        ],
        min_risk_score=min_risk_score,
    )

    token_param = str(evidence_raw.get("token_param", "confirm_token")).strip()
    context_param = str(evidence_raw.get("context_param", "confirm_context")).strip()
    min_context_length = int(evidence_raw.get("min_context_length", 12))

    if not token_param:
        raise ValueError("confirmation.evidence.token_param must be non-empty")
    if not context_param:
        raise ValueError("confirmation.evidence.context_param must be non-empty")
    if token_param == context_param:
        raise ValueError("confirmation evidence params must be distinct")
    if min_context_length < 0:
        raise ValueError("confirmation.evidence.min_context_length must be >= 0")

    proof_param = str(signed_proof_raw.get("proof_param", "confirm_proof")).strip()
    key_env = str(signed_proof_raw.get("key_env", "AETHERYA_CONFIRMATION_HMAC_KEY")).strip()
    keyring_env = str(
        signed_proof_raw.get("keyring_env", "AETHERYA_CONFIRMATION_HMAC_KEYRING")
    ).strip()
    active_kid = str(signed_proof_raw.get("active_kid", "k1")).strip().lower()
    max_valid_for_sec = int(signed_proof_raw.get("max_valid_for_sec", 900))
    clock_skew_sec = int(signed_proof_raw.get("clock_skew_sec", 5))
    replay_mode = str(signed_proof_raw.get("replay_mode", "single_use")).strip().lower()
    replay_store = str(signed_proof_raw.get("replay_store", "memory")).strip().lower()
    replay_redis_url_env = str(
        signed_proof_raw.get(
            "replay_redis_url_env",
            "AETHERYA_CONFIRMATION_REPLAY_REDIS_URL",
        )
    ).strip()
    replay_redis_prefix = str(signed_proof_raw.get("replay_redis_prefix", "aetherya:appr")).strip()

    if not proof_param:
        raise ValueError("confirmation.evidence.signed_proof.proof_param must be non-empty")
    if proof_param in {token_param, context_param}:
        raise ValueError(
            "confirmation signed_proof proof_param must be distinct from token/context"
        )
    if not key_env:
        raise ValueError("confirmation.evidence.signed_proof.key_env must be non-empty")
    if not keyring_env:
        raise ValueError("confirmation.evidence.signed_proof.keyring_env must be non-empty")
    if not active_kid:
        raise ValueError("confirmation.evidence.signed_proof.active_kid must be non-empty")
    if max_valid_for_sec <= 0:
        raise ValueError("confirmation.evidence.signed_proof.max_valid_for_sec must be > 0")
    if clock_skew_sec < 0:
        raise ValueError("confirmation.evidence.signed_proof.clock_skew_sec must be >= 0")
    if replay_mode not in {"single_use", "idempotent"}:
        raise ValueError(
            "confirmation.evidence.signed_proof.replay_mode must be one of: single_use, idempotent"
        )
    if replay_store not in {"memory", "redis"}:
        raise ValueError(
            "confirmation.evidence.signed_proof.replay_store must be one of: memory, redis"
        )
    if not replay_redis_url_env:
        raise ValueError(
            "confirmation.evidence.signed_proof.replay_redis_url_env must be non-empty"
        )
    if not replay_redis_prefix:
        raise ValueError("confirmation.evidence.signed_proof.replay_redis_prefix must be non-empty")

    signed_proof = ConfirmationSignedProofConfig(
        enabled=bool(signed_proof_raw.get("enabled", False)),
        proof_param=proof_param,
        key_env=key_env,
        keyring_env=keyring_env,
        active_kid=active_kid,
        max_valid_for_sec=max_valid_for_sec,
        clock_skew_sec=clock_skew_sec,
        replay_mode=replay_mode,
        replay_store=replay_store,
        replay_redis_url_env=replay_redis_url_env,
        replay_redis_prefix=replay_redis_prefix,
    )

    evidence = ConfirmationEvidenceConfig(
        token_param=token_param,
        context_param=context_param,
        token_pattern=str(evidence_raw.get("token_pattern", r"^ack:[a-z0-9_-]{8,}$")).strip(),
        min_context_length=min_context_length,
        signed_proof=signed_proof,
    )

    return ConfirmationConfig(
        enabled=bool(data.get("enabled", False)),
        on_confirmed=str(data.get("on_confirmed", "allow")).strip().lower(),
        require_for=require_for,
        evidence=evidence,
    )


def _load_llm_shadow(raw: dict[str, Any] | None) -> LLMShadowConfig:
    data = raw or {}

    provider = str(data.get("provider", "dry_run")).strip().lower()
    if provider not in {"dry_run", "openai"}:
        raise ValueError("llm_shadow.provider must be one of: dry_run, openai")

    model = str(data.get("model", "gpt-dry")).strip()
    if not model:
        raise ValueError("llm_shadow.model must be non-empty")

    temperature = float(data.get("temperature", 0.0))
    if temperature < 0.0 or temperature > 2.0:
        raise ValueError("llm_shadow.temperature must be between 0.0 and 2.0")

    max_tokens = int(data.get("max_tokens", 128))
    if max_tokens <= 0:
        raise ValueError("llm_shadow.max_tokens must be > 0")

    timeout_sec = float(data.get("timeout_sec", 10.0))
    if timeout_sec <= 0.0:
        raise ValueError("llm_shadow.timeout_sec must be > 0")

    return LLMShadowConfig(
        enabled=bool(data.get("enabled", False)),
        provider=provider,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout_sec=timeout_sec,
    )


def _load_policy_adapter_shadow(raw: dict[str, Any] | None) -> PolicyAdapterShadowConfig:
    data = raw or {}

    max_signals = int(data.get("max_signals", 3))
    if max_signals <= 0:
        raise ValueError("policy_adapter_shadow.max_signals must be > 0")

    return PolicyAdapterShadowConfig(
        enabled=bool(data.get("enabled", False)),
        max_signals=max_signals,
    )


def _load_output_gate(raw: dict[str, Any] | None) -> OutputGateConfig:
    data = raw or {}
    return OutputGateConfig(
        require_candidate_response=bool(data.get("require_candidate_response", False)),
    )


def _load_constitution_config(raw: dict[str, Any] | None) -> ConstitutionConfig:
    data = raw or {}

    violation_threshold = float(data.get("semantic_violation_threshold", 0.55))
    gray_zone_threshold = float(data.get("semantic_gray_zone_threshold", 0.35))

    if not (0.0 < violation_threshold <= 1.0):
        raise ValueError("constitution.semantic_violation_threshold must be in (0.0, 1.0]")
    if not (0.0 <= gray_zone_threshold < violation_threshold):
        raise ValueError(
            "constitution.semantic_gray_zone_threshold must be in [0.0, violation_threshold)"
        )

    return ConstitutionConfig(
        semantic_violation_threshold=violation_threshold,
        semantic_gray_zone_threshold=gray_zone_threshold,
    )


def load_policy_config(path: str | Path) -> PolicyConfig:
    path = Path(path)
    raw_text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw_text)

    version = int(_require(data, "version"))

    modes_raw = _require(data, "modes")
    modes: dict[str, ModeConfig] = {}
    for mode_name, m in modes_raw.items():
        thr = _require(m, "thresholds")
        modes[mode_name] = ModeConfig(
            default_state=str(_require(m, "default_state")),
            thresholds=ModeThresholds(
                deny_at=int(_require(thr, "deny_at")),
                confirm_at=int(_require(thr, "confirm_at")),
                log_only_at=int(thr.get("log_only_at", 0)),
            ),
        )

    agg = _require(data, "aggregator")
    aggregator = AggregatorConfig(
        weights=dict(_require(agg, "weights")),
        hard_deny_if=list(_require(agg, "hard_deny_if")),
    )

    pg = _require(data, "procedural_guard")
    procedural_guard = ProceduralGuardConfig(
        critical_tags=list(_require(pg, "critical_tags")),
        privileged_ops=list(_require(pg, "privileged_ops")),
    )
    execution_gate = _load_execution_gate(data.get("execution_gate"))
    capability_matrix = _load_capability_matrix(data.get("capability_matrix"))
    confirmation = _load_confirmation(data.get("confirmation"))
    llm_shadow = _load_llm_shadow(data.get("llm_shadow"))
    policy_adapter_shadow = _load_policy_adapter_shadow(data.get("policy_adapter_shadow"))
    output_gate_config = _load_output_gate(data.get("output_gate"))
    constitution_config = _load_constitution_config(data.get("constitution"))

    return PolicyConfig(
        version=version,
        modes=modes,
        aggregator=aggregator,
        procedural_guard=procedural_guard,
        execution_gate=execution_gate,
        capability_matrix=capability_matrix,
        confirmation=confirmation,
        llm_shadow=llm_shadow,
        policy_adapter_shadow=policy_adapter_shadow,
        policy_fingerprint=_policy_fingerprint(raw_text),
        output_gate_config=output_gate_config,
        constitution_config=constitution_config,
    )
