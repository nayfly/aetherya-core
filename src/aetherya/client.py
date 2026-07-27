from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from aetherya.actions import ActionRequest, Decision
from aetherya.enforcement import Enforcement, EnforcementPhase, apply_enforcement, resolve_phase

# ---------------------------------------------------------------------------
# Sidecar client.
#
# The agent runs in one process, the decision service in another. This is the
# whole integration surface: build an ActionRequest, ask, act on the answer.
#
#     gate = AetheryaClient("http://aetherya:8080", actor="deploy-bot", phase=1)
#     verdict = gate.check(action)
#     if verdict.execute:
#         result = run_the_tool()
#     else:
#         result = verdict.reason        # goes back to the model as tool output
#
# FAIL-CLOSED: an unreachable service refuses the action. A decision boundary
# that disappears when the network hiccups is not a boundary. Phase 1 is the one
# exception and it is explicit — see `fail_open_in_shadow`.
# ---------------------------------------------------------------------------


class AetheryaUnavailable(RuntimeError):
    """The decision service could not be reached or returned an unusable answer."""


@dataclass(frozen=True)
class Verdict:
    """What the caller should do, plus the decision it came from."""

    execute: bool
    requires_confirmation: bool
    reason: str
    state: str
    risk_score: int
    shadow_gap: bool
    decision: dict[str, Any]
    enforcement: Enforcement | None = None

    @property
    def refused(self) -> bool:
        return not self.execute


class AetheryaClient:
    """
    Minimal HTTP client for the decision service.

    Deliberately dependency-free (urllib, not requests): this sits in the hot
    path of every tool call an agent makes, and the fewer things that can break
    or need upgrading there, the better.
    """

    def __init__(
        self,
        base_url: str,
        *,
        actor: str,
        phase: int | EnforcementPhase = 1,
        timeout_sec: float = 5.0,
        fail_open_in_shadow: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.actor = actor
        self.phase: EnforcementPhase = (
            phase if isinstance(phase, EnforcementPhase) else resolve_phase(phase)
        )
        self.timeout_sec = float(timeout_sec)
        # Phase 1 is observation: the service being down must not stop the agent,
        # because nothing is being enforced anyway. From phase 2 on, an outage
        # refuses the action — that is the point of enforcing.
        self.fail_open_in_shadow = bool(fail_open_in_shadow)

    # -- transport ------------------------------------------------------------

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(  # noqa: S310 - operator-configured URL
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            opened = urllib.request.urlopen(request, timeout=self.timeout_sec)  # noqa: S310
            with opened as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "ignore")[:200]
            raise AetheryaUnavailable(f"HTTP {exc.code}: {detail}") from exc
        except Exception as exc:
            raise AetheryaUnavailable(f"{type(exc).__name__}: {exc}") from exc

        if not isinstance(body, dict):
            raise AetheryaUnavailable("response was not a JSON object")
        return body

    # -- public surface -------------------------------------------------------

    def health(self) -> dict[str, Any]:
        request = urllib.request.Request(f"{self.base_url}/health")  # noqa: S310
        try:
            opened = urllib.request.urlopen(request, timeout=self.timeout_sec)  # noqa: S310
            with opened as response:
                body = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            raise AetheryaUnavailable(f"{type(exc).__name__}: {exc}") from exc
        return dict(body) if isinstance(body, dict) else {}

    def check(
        self,
        action: ActionRequest,
        *,
        candidate_response: str | None = None,
    ) -> Verdict:
        """Ask the service about an action and apply the configured phase."""
        payload: dict[str, Any] = {
            "actor": self.actor,
            "wait_shadow": False,
            "action": {
                "raw_input": action.raw_input,
                "intent": action.intent,
                "mode_hint": action.mode_hint,
                "tool": action.tool,
                "target": action.target,
                "parameters": dict(action.parameters),
            },
        }
        if candidate_response is not None:
            payload["candidate_response"] = candidate_response

        try:
            body = self._post("/v1/decide", payload)
        except AetheryaUnavailable as exc:
            return self._unavailable_verdict(exc)

        decision = body.get("decision")
        if not isinstance(decision, dict) or "state" not in decision:
            return self._unavailable_verdict(
                AetheryaUnavailable("response did not contain a decision")
            )

        enforcement = apply_enforcement(
            Decision(
                allowed=bool(decision.get("allowed", False)),
                risk_score=int(decision.get("risk_score", 0)),
                reason=str(decision.get("reason", "")),
                violated_principle=decision.get("violated_principle"),
                mode=decision.get("mode"),
                state=str(decision["state"]),
            ),
            self.phase,
        )
        return Verdict(
            execute=enforcement.execute,
            requires_confirmation=enforcement.requires_confirmation,
            reason=(
                str(decision.get("reason", "")) if not enforcement.execute else enforcement.reason
            ),
            state=enforcement.state,
            risk_score=int(decision.get("risk_score", 0)),
            shadow_gap=enforcement.shadow_gap,
            decision=decision,
            enforcement=enforcement,
        )

    def _unavailable_verdict(self, exc: AetheryaUnavailable) -> Verdict:
        shadow = self.phase.number == 1 and self.fail_open_in_shadow
        reason = (
            f"aetherya unavailable ({exc}) — phase 1 observes only, action proceeds"
            if shadow
            else f"REFUSED: aetherya unavailable ({exc})"
        )
        return Verdict(
            execute=shadow,
            requires_confirmation=False,
            reason=reason,
            state="unavailable",
            risk_score=0,
            shadow_gap=False,
            decision={},
        )
