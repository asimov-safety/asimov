"""Low-friction onboarding and readiness diagnostics for Asimov adapters."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import importlib.util
import json
import platform
from pathlib import Path
from typing import Any

from .gate import catalog
from .probes import PROBE_CAPABILITIES, PROBES


PROFILE_REQUIREMENTS = {
    f"A{level}": tuple(r["id"] for r in catalog()["requirements"] if r["minimum_profile"] <= level)
    for level in range(1, 6)
}

COMMON_FRAMEWORKS = {
    "openai": "OpenAI Python package / Agents SDK may be present",
    "langchain": "LangChain may be present",
    "langgraph": "LangGraph may be present",
    "crewai": "CrewAI may be present",
    "autogen": "AutoGen may be present",
    "llama_index": "LlamaIndex may be present",
}


@dataclass(frozen=True)
class ReadinessFinding:
    requirement_id: str
    state: str
    missing_capabilities: tuple[str, ...]
    remediation: str


CAPABILITY_REMEDIATION = {
    "action_surface": "Add an action-surface discovery provider that inventories every consequential path.",
    "external_events": "Add an evidence oracle outside the acting principal's write/control authority.",
    "attempt": "Add an agent/action driver that can exercise the deployment with actor-equivalent privileges.",
    "observe": "Add a resource oracle that independently reads the protected resource or side effect.",
    "issue_grant": "Add an authority controller that can create scoped grants for the test fixture.",
    "issue_approval": "Add a trusted approval provider with action-bound approval artifacts.",
    "approval_view": "Add a trusted human approval view outside actor-controlled content.",
    "alternate_routes": "Expose direct/SDK/subprocess/delegated routes or explicitly disable them at the control boundary.",
    "dependency_health": "Expose required control dependencies and a safe fault-injection or simulation surface.",
    "revoke": "Add an external authority controller capable of resource-effective revocation.",
    "refresh_grant": "Expose credential/session refresh and renewal behavior for revocation testing.",
    "delegate": "Expose subagent/job delegation or prove those routes are technically disabled.",
    "budget_accounting": "Add aggregate resource/spend accounting tied to the root grant.",
    "control_plane_observation": "Expose control-plane state through an independent observer.",
    "stop": "Add an authenticated out-of-band human stop path.",
    "restart": "Add a lifecycle provider for actor/application/background-service restarts.",
    "fault_injection": "Add a bounded fault-injection provider or simulator for the required dependency/control.",
    "evidence_integrity": "Add an evidence integrity provider with an independent checkpoint/trust anchor.",
    "evidence_access": "Add evidence access-control/minimization hooks for routine and privileged views.",
    "assessment_binding": "Bind reports to a stable deployment/configuration digest and expose change invalidation.",
}


def doctor(adapter: Any, profile: str = "A2") -> dict[str, Any]:
    if profile not in PROFILE_REQUIREMENTS:
        raise ValueError(f"unsupported profile {profile!r}")
    available = set(adapter.capabilities())
    findings: list[ReadinessFinding] = []
    for rid in PROFILE_REQUIREMENTS[profile]:
        if rid not in PROBES:
            findings.append(ReadinessFinding(
                rid, "BLOCKED_PROBE_NOT_IMPLEMENTED", (),
                "The normative family exists, but this Asimov release does not yet ship an executable reference probe for it.",
            ))
            continue
        missing = tuple(sorted(PROBE_CAPABILITIES[rid] - available))
        if missing:
            remediation = " ".join(CAPABILITY_REMEDIATION.get(c, f"Provide capability: {c}.") for c in missing)
            findings.append(ReadinessFinding(rid, "BLOCKED_MISSING_CONTROL_SURFACE", missing, remediation))
        else:
            findings.append(ReadinessFinding(rid, "READY_TO_TEST", (), "No capability blocker detected; run the probe and review evidence."))
    blockers = [f for f in findings if f.state.startswith("BLOCKED")]
    return {
        "tool": "asimov-doctor",
        "profile": profile,
        "adapter_id": getattr(adapter, "adapter_id", "unknown"),
        "platform": platform.system(),
        "ready": not blockers,
        "requirements": len(findings),
        "blockers": len(blockers),
        "findings": [asdict(f) for f in findings],
        "rule": "Every mandatory requirement must be testable with an independent control/evidence surface. Coverage gaps block the profile; they are not averaged away.",
    }


def detect_environment() -> dict[str, Any]:
    frameworks = []
    for module, description in COMMON_FRAMEWORKS.items():
        if importlib.util.find_spec(module) is not None:
            frameworks.append({"module": module, "description": description})
    return {
        "platform": platform.system(),
        "platform_release": platform.release(),
        "python": platform.python_version(),
        "detected_framework_modules": frameworks,
    }


def init_project(path: Path) -> dict[str, Any]:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing file: {path}")
    env = detect_environment()
    lines = [
        "# Asimov deployment scaffold. Review every value before testing.",
        'spec = "0.2.0-draft.1"',
        'target_profile = "A2"',
        f'platform = {json.dumps(env["platform"])}',
        "",
        "[deployment]",
        'id = "replace-me"',
        'scope = "replace-me"',
        "",
        "[providers]",
        'action_driver = "replace-me"',
        'authority_controller = "replace-me"',
        'resource_oracle = "replace-me"',
        'lifecycle_controller = "replace-me"',
        'evidence_oracle = "replace-me"',
        "",
        "# Asimov does not treat unresolved provider/control surfaces as optional.",
        "# Run `asimov-draft doctor --level A2` after wiring an adapter.",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"path": str(path), "environment": env}
