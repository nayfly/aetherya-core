from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ReleaseArtifactVerificationResult:
    passed: bool
    manifest_path: str
    expected_commit_sha: str
    observed_commit_sha: str
    expected_decision_count: int
    observed_decision_count: int
    phase1_audit_line_count: int
    signature_valid: bool
    errors: list[str]


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _resolve_attestation_key(explicit_key: str | None) -> str | None:
    raw = explicit_key if explicit_key is not None else os.getenv("AETHERYA_ATTESTATION_KEY", "")
    cleaned = raw.strip() if isinstance(raw, str) else ""
    return cleaned if cleaned else None


def _resolve_commit_sha(explicit_sha: str | None) -> str:
    raw = explicit_sha if explicit_sha is not None else os.getenv("GITHUB_SHA", "")
    cleaned = raw.strip() if isinstance(raw, str) else ""
    return cleaned if cleaned else ""


def _load_json_object(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ValueError(f"manifest file not found: {path}")
    raw_text = path.read_text(encoding="utf-8")
    if not raw_text.strip():
        raise ValueError(f"manifest is empty: {path}")

    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"manifest has invalid JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"manifest root must be JSON object: {path}")
    return payload


def _load_expected_decision_count(explicit_count: int | None, corpus_path: Path) -> int:
    if explicit_count is not None:
        if explicit_count <= 0:
            raise ValueError("expected_decision_count must be > 0")
        return explicit_count

    payload = json.loads(corpus_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"invalid corpus payload: {corpus_path}")
    raw_cases = payload.get("cases")
    if not isinstance(raw_cases, list):
        raise ValueError(f"corpus cases must be list: {corpus_path}")
    cases = [item for item in raw_cases if isinstance(item, dict)]
    if not cases:
        raise ValueError(f"corpus has no cases: {corpus_path}")
    return len(cases)


def _count_jsonl_events(path: Path) -> int:
    if not path.exists():
        raise ValueError(f"audit file not found: {path}")
    raw_text = path.read_text(encoding="utf-8")
    if not raw_text.strip():
        raise ValueError(f"audit file is empty: {path}")
    return sum(1 for line in raw_text.splitlines() if line.strip())


def _verify_manifest_signature(manifest: dict[str, Any], attestation_key: str) -> bool:
    signature_alg = str(manifest.get("signature_alg", "")).strip()
    signature_raw = str(manifest.get("signature", "")).strip()

    if signature_alg != "hmac-sha256":
        return False
    if not signature_raw.startswith("hmac-sha256:"):
        return False

    provided_digest = signature_raw.split(":", 1)[1].strip()
    if not provided_digest:
        return False

    signed_payload = {
        key: value for key, value in manifest.items() if key not in {"signature_alg", "signature"}
    }
    expected_digest = hmac.new(
        attestation_key.encode("utf-8"),
        _canonical_json(signed_payload).encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(provided_digest, expected_digest)


def run_release_artifact_verification(
    *,
    manifest_path: str | Path = "audit/security_gate/security_manifest.json",
    phase1_audit_path: str | Path | None = None,
    expected_commit_sha: str,
    expected_decision_count: int | None = None,
    corpus_path: str | Path = "tests/fixtures/security_corpus/v1/jailbreak_attacks.json",
    attestation_key: str | None = None,
) -> ReleaseArtifactVerificationResult:
    resolved_attestation_key = _resolve_attestation_key(attestation_key)
    if not resolved_attestation_key:
        raise ValueError("attestation key is required (arg or AETHERYA_ATTESTATION_KEY)")
    cleaned_expected_commit = expected_commit_sha.strip()
    if not cleaned_expected_commit:
        raise ValueError("expected_commit_sha must be non-empty")

    manifest_file = Path(manifest_path)
    expected_count = _load_expected_decision_count(
        expected_decision_count,
        Path(corpus_path),
    )

    errors: list[str] = []
    observed_commit = ""
    observed_decision_count = 0
    phase1_count = 0
    signature_valid = False

    try:
        manifest = _load_json_object(manifest_file)
    except ValueError as exc:
        errors.append(str(exc))
        manifest = {}

    if manifest:
        signature_valid = _verify_manifest_signature(manifest, resolved_attestation_key)
        if not signature_valid:
            errors.append("manifest signature is invalid")

        raw_commit = manifest.get("commit_sha")
        observed_commit = raw_commit.strip() if isinstance(raw_commit, str) else ""
        if observed_commit != cleaned_expected_commit:
            errors.append(
                f"commit_sha mismatch: expected={cleaned_expected_commit} observed={observed_commit or '-'}"
            )

        raw_count = manifest.get("decision_count")
        if isinstance(raw_count, int):
            observed_decision_count = raw_count
        else:
            errors.append("decision_count missing or invalid type")

        if observed_decision_count != expected_count:
            errors.append(
                f"decision_count mismatch: expected={expected_count} observed={observed_decision_count}"
            )

    if phase1_audit_path is not None:
        try:
            phase1_count = _count_jsonl_events(Path(phase1_audit_path))
        except ValueError as exc:
            errors.append(str(exc))
        else:
            if observed_decision_count and phase1_count != observed_decision_count:
                errors.append(
                    "phase1 audit event count mismatch: "
                    f"manifest={observed_decision_count} audit={phase1_count}"
                )

    return ReleaseArtifactVerificationResult(
        passed=not errors,
        manifest_path=str(manifest_file),
        expected_commit_sha=cleaned_expected_commit,
        observed_commit_sha=observed_commit,
        expected_decision_count=expected_count,
        observed_decision_count=observed_decision_count,
        phase1_audit_line_count=phase1_count,
        signature_valid=signature_valid,
        errors=errors,
    )


def _format_text_result(result: ReleaseArtifactVerificationResult) -> str:
    lines = [
        f"release_artifacts passed={result.passed}",
        f"- commit_sha: expected={result.expected_commit_sha} observed={result.observed_commit_sha or '-'}",
        (
            f"- decision_count: expected={result.expected_decision_count} "
            f"observed={result.observed_decision_count}"
        ),
        f"- phase1_audit_line_count: {result.phase1_audit_line_count}",
        f"- signature_valid: {result.signature_valid}",
    ]
    for error in result.errors:
        lines.append(f"- error: {error}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify AETHERYA release security artifacts.")
    parser.add_argument(
        "--manifest-path",
        default="audit/security_gate/security_manifest.json",
        help="Path to signed security manifest JSON.",
    )
    parser.add_argument(
        "--phase1-audit-path",
        default="",
        help="Optional path to phase1 corpus audit JSONL for count cross-check.",
    )
    parser.add_argument(
        "--expected-commit-sha",
        default=None,
        help="Expected commit SHA (or use env GITHUB_SHA).",
    )
    parser.add_argument(
        "--expected-decision-count",
        type=int,
        default=0,
        help="Expected decision count. If <=0, derive from corpus fixture.",
    )
    parser.add_argument(
        "--corpus-path",
        default="tests/fixtures/security_corpus/v1/jailbreak_attacks.json",
        help="Attack corpus used to derive expected decision count.",
    )
    parser.add_argument(
        "--attestation-key",
        default=None,
        help="HMAC key (or use env AETHERYA_ATTESTATION_KEY).",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output.")

    args = parser.parse_args(list(argv) if argv is not None else None)
    expected_commit_sha = _resolve_commit_sha(args.expected_commit_sha)
    if not expected_commit_sha:
        print("error: expected_commit_sha is required (arg or GITHUB_SHA)", file=sys.stderr)
        return 2

    explicit_expected_count = (
        args.expected_decision_count if args.expected_decision_count > 0 else None
    )
    try:
        result = run_release_artifact_verification(
            manifest_path=args.manifest_path,
            phase1_audit_path=(args.phase1_audit_path or None),
            expected_commit_sha=expected_commit_sha,
            expected_decision_count=explicit_expected_count,
            corpus_path=args.corpus_path,
            attestation_key=args.attestation_key,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(asdict(result), ensure_ascii=False, sort_keys=True))
    else:
        print(_format_text_result(result))

    return 0 if result.passed else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
