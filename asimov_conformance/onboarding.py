"""Low-friction onboarding and readiness diagnostics for Asimov adapters."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import importlib.util
import json
import platform
from pathlib import Path
from typing import Any

from .gate import catalog
from .probes import PROBE_CAPABILITIES, PROBES, declared_capabilities, unavailable_capability_methods


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
    "stop_reset": "Add a separately authorized, attributable human stop-reset/recovery path that the actor cannot invoke.",
    "restart": "Add a lifecycle provider for actor/application/background-service restarts.",
    "fault_injection": "Add a bounded fault-injection provider or simulator for the required dependency/control.",
    "evidence_integrity": "Add an evidence integrity provider with an independent checkpoint/trust anchor.",
    "evidence_access": "Add evidence access-control/minimization hooks for routine and privileged views.",
    "assessment_binding": "Bind reports to a stable deployment/configuration digest and expose change invalidation.",
    "supervisor_auth": "Add an authenticated supervisor-control channel with freshness, replay protection, and deployment/run binding.",
    "independent_supervision": "Add a supervisor outside the acting principal's control with health, intervention, and configuration-change signals.",
    "untrusted_content_isolation": "Expose enabled untrusted-content channels and prove they cannot mint approvals or alter control authority.",
    "delegation_lifecycle": "Add lifecycle/lineage observation for subagents, scheduled jobs, background work, and unresolved descendants.",
    "cross_boundary_delegation": "Add recipient trust/control evidence plus containment behavior for cross-provider or cross-organization delegation.",
    "intervention_exercise": "Provide a reviewed hazard/load intervention plan and a safe exercise or simulator for overload, communication loss, timeout, and residual effects.",
    "high_consequence_observation": "Add independent executor/resource observation for each high-consequence action class and disagreement handling.",
    "hardened_enforcement": "Move high-consequence enforcement outside actor-controlled credentials, host privileges, and lower-level bypass routes.",
    "partition_revocation": "Use resource-side revocation, bounded leases, or expiry so partitioned recipients lose authority within a declared interval.",
    "common_mode_analysis": "Document shared dependencies and retain at least one effective intervention path outside the dominant actor runtime.",
    "delegation_churn": "Add atomic root accounting and lifecycle controls that survive concurrent delegation, restart, partition, and orphaning.",
    "out_of_band_intervention": "Add an authenticated stop/restriction path that remains effective when the primary UI/orchestrator is unavailable.",
    "assessment_attestation": "Bind assessment artifacts to digests, authenticated signer identity, tested scope, and an external checkpoint.",
    "critical_observation": "Map every domain-critical transition to independently justified observation coverage.",
    "critical_barriers": "Add materially independent barriers so no single ordinary enforcement failure admits a critical effect.",
    "secondary_containment": "Add a secondary containment path outside the primary Asimov control path.",
    "adversarial_assurance": "Run independent predeclared campaigns for monitor evasion, policy confusion, control manipulation, and strategic adaptation.",
    "critical_delegation": "Require independent recipient assurance or technical attenuation before critical authority crosses a trust boundary.",
    "emergency_recovery": "Add redundant human emergency authority and separately governed recovery with separation of duties.",
    "independent_assurance": "Retain independently assessed evidence in durable external escrow and support fresh-environment reconstruction.",
}


def doctor(adapter: Any, profile: str = "A2") -> dict[str, Any]:
    if profile not in PROFILE_REQUIREMENTS:
        raise ValueError(f"unsupported profile {profile!r}")
    try:
        available = declared_capabilities(adapter)
    except Exception as exc:
        findings = [
            ReadinessFinding(
                rid,
                "BLOCKED_CAPABILITY_DISCOVERY",
                tuple(sorted(PROBE_CAPABILITIES.get(rid, set()))),
                f"Adapter capabilities() failed closed with {type(exc).__name__}: {exc}",
            )
            for rid in PROFILE_REQUIREMENTS[profile]
        ]
        return {
            "tool": "asimov-doctor",
            "profile": profile,
            "adapter_id": getattr(adapter, "adapter_id", "unknown"),
            "platform": platform.system(),
            "ready": False,
            "requirements": len(findings),
            "blockers": len(findings),
            "findings": [asdict(f) for f in findings],
            "rule": "Every mandatory requirement must be testable with an independent control/evidence surface. Coverage gaps block the profile; they are not averaged away.",
        }

    findings: list[ReadinessFinding] = []
    for rid in PROFILE_REQUIREMENTS[profile]:
        if rid not in PROBES:
            findings.append(ReadinessFinding(
                rid, "BLOCKED_PROBE_NOT_IMPLEMENTED", (),
                "The normative family exists, but this Asimov release does not yet ship an executable reference probe for it.",
            ))
            continue
        required = PROBE_CAPABILITIES[rid]
        missing = tuple(sorted(required - available))
        missing_methods = unavailable_capability_methods(adapter, required & available)
        if missing:
            remediation = " ".join(CAPABILITY_REMEDIATION.get(c, f"Provide capability: {c}.") for c in missing)
            findings.append(ReadinessFinding(rid, "BLOCKED_MISSING_CONTROL_SURFACE", missing, remediation))
        elif missing_methods:
            remediation = (
                "The adapter declares the required capability, but these required methods are missing or not callable: "
                + ", ".join(f"{name}()" for name in missing_methods)
                + ". Wire the real implementation or remove the capability claim."
            )
            findings.append(ReadinessFinding(rid, "BLOCKED_ADAPTER_METHOD_UNAVAILABLE", (), remediation))
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
        'spec = "0.2.0"',
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
        "# Run `asimov doctor --level A2` after wiring an adapter.",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"path": str(path), "environment": env}
