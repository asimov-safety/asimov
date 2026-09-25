"""Provider-aware assistance for building conservative Asimov adapters."""
from __future__ import annotations

import json
import re
from importlib.resources import files
from pathlib import Path
from typing import Any


class AdapterAssistantError(ValueError):
    """Adapter-assistant input or output is invalid."""


def adapter_catalog() -> dict[str, Any]:
    value = json.loads(
        files("asimov_conformance").joinpath("adapter_catalog.json").read_text(encoding="utf-8")
    )
    if not isinstance(value, dict):
        raise AdapterAssistantError("adapter catalog must be a JSON object")
    return value


def _index(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(row["id"]): row for row in rows}


def _selected(catalog: dict[str, Any], group: str, value: str | None) -> dict[str, Any] | None:
    if not value:
        return None
    rows = catalog.get(group)
    if not isinstance(rows, list):
        raise AdapterAssistantError(f"adapter catalog group is invalid: {group}")
    found = _index(rows).get(value)
    if found is None:
        raise AdapterAssistantError(f"unknown {group} option: {value}")
    return found


def _selected_many(catalog: dict[str, Any], group: str, values: list[str] | None) -> list[dict[str, Any]]:
    if not values:
        return []
    rows = catalog.get(group)
    if not isinstance(rows, list):
        raise AdapterAssistantError(f"adapter catalog group is invalid: {group}")
    index = _index(rows)
    result = []
    for value in values:
        if value not in index:
            raise AdapterAssistantError(f"unknown {group} option: {value}")
        result.append(index[value])
    return result


def _class_name(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
        raise AdapterAssistantError("adapter class name must be a valid Python identifier")
    return value


def recommendation(
    *,
    runtime: str,
    hosting: str | None = None,
    authority: str | None = None,
    resources: list[str] | None = None,
    evidence: list[str] | None = None,
    integrations: list[str] | None = None,
) -> dict[str, Any]:
    catalog = adapter_catalog()
    runtime_row = _selected(catalog, "runtime_options", runtime)
    assert runtime_row is not None
    hosting_row = _selected(catalog, "hosting_options", hosting)
    authority_row = _selected(catalog, "authority_options", authority)
    resource_rows = _selected_many(catalog, "resource_options", resources)
    evidence_rows = _selected_many(catalog, "evidence_options", evidence)
    integration_rows = _selected_many(catalog, "integration_options", integrations)

    gaps = [
        "Generated scaffolds intentionally claim zero Asimov capabilities until real deployment methods are implemented and tested.",
        "Framework/provider traces can support evidence but do not replace an independent resource oracle.",
        "For A3 and above, supervision must be outside the acting principal's effective authority.",
    ]
    if authority_row is None:
        gaps.append("No enforceable authority mechanism has been selected yet.")
    if not resource_rows:
        gaps.append("No protected resource/oracle has been selected yet.")
    if hosting_row is None:
        gaps.append("No lifecycle/hosting control plane has been selected yet.")

    return {
        "runtime": runtime_row,
        "hosting": hosting_row,
        "authority": authority_row,
        "resources": resource_rows,
        "evidence": evidence_rows,
        "integrations": integration_rows,
        "surfaces": catalog["surfaces"],
        "gaps": gaps,
        "rule": catalog["principle"],
        "checked_at": catalog["checked_at"],
    }


def _comment_lines(value: str, indent: str = "") -> str:
    return "\n".join(indent + "# " + raw.rstrip() for raw in str(value).splitlines())


def render_adapter_source(
    rec: dict[str, Any],
    *,
    class_name: str = "AsimovAdapter",
    adapter_id: str = "generated-adapter",
) -> str:
    class_name = _class_name(class_name)
    runtime = rec["runtime"]
    surface_map = runtime.get("recommended", {})
    resources = ", ".join(row["name"] for row in rec.get("resources", [])) or "not selected"
    authority = rec["authority"]["name"] if rec.get("authority") else "not selected"
    hosting = rec["hosting"]["name"] if rec.get("hosting") else "not selected"
    evidence = ", ".join(row["name"] for row in rec.get("evidence", [])) or "not selected"
    integrations = ", ".join(row["name"] for row in rec.get("integrations", [])) or "none selected"

    def todo(name: str, surface: str) -> str:
        guidance = surface_map.get(surface, "Connect this method to the corresponding real deployment surface.")
        return (
            f"    def {name}(self, *args, **kwargs):\n"
            f"{_comment_lines(guidance, '        ')}\n"
            f"        raise NotImplementedError({surface!r} + ' surface is not wired yet')\n"
        )

    return f"""\\
\"\"\"Asimov starter adapter generated from the Adapter Assistant.

THIS FILE DOES NOT CLAIM CONFORMANCE.

Selected stack:
- Runtime: {runtime["name"]}
- Hosting: {hosting}
- Authority: {authority}
- Protected resources: {resources}
- Evidence sources: {evidence}
- Integrations: {integrations}

The scaffold deliberately reports no capabilities until you replace TODO methods
with real deployment controls and independent evidence sources.
\"\"\"
from __future__ import annotations

from typing import Any


class {class_name}:
    adapter_id = {adapter_id!r}

    def __init__(self, **kwargs: Any) -> None:
        # Runtime-only settings may include clients, URLs, test-tenant IDs, etc.
        # Do not put long-lived secrets into assessment artifacts.
        self.settings = dict(kwargs)

    def capabilities(self) -> set[str]:
        # Add a capability ONLY after its corresponding methods are implemented
        # against the real deployment and independently validated.
        return set()

    def deployment_snapshot(self) -> dict[str, Any]:
        return {{
            "system_id": "replace-me",
            "scope": "",
            "threat_model": "",
            "exclusions": [],
            "runtime": {runtime["id"]!r},
            "hosting": {(rec["hosting"]["id"] if rec.get("hosting") else None)!r},
            "authority": {(rec["authority"]["id"] if rec.get("authority") else None)!r},
            "resources": {[row["id"] for row in rec.get("resources", [])]!r},
        }}

    def reset_fixture(self) -> None:
        # Reset only disposable assessment fixtures. Never destroy production data.
        raise NotImplementedError("safe disposable fixture reset is not wired yet")

{todo("discover_action_surface", "action")}
{todo("attempt", "action")}
{todo("observe", "resource")}
{todo("issue_grant", "authority")}
{todo("issue_approval", "authority")}
{todo("approval_view", "authority")}
{todo("revoke", "authority")}
{todo("refresh_grant", "authority")}
{todo("stop", "supervision")}
{todo("reset_stop", "supervision")}
{todo("restart", "lifecycle")}
{todo("inject_fault", "lifecycle")}
{todo("delegate", "action")}
{todo("issue_supervisor_message", "supervision")}
{todo("deliver_supervisor_message", "supervision")}
{todo("supervision_snapshot", "supervision")}
{todo("ingest_untrusted", "action")}
{todo("delegation_snapshot", "action")}
{todo("delegate_external", "action")}
{todo("intervention_plan", "supervision")}
{todo("exercise_intervention", "supervision")}
{todo("high_consequence_observation", "resource")}
{todo("common_mode_snapshot", "lifecycle")}
{todo("delegation_stress", "action")}
{todo("assessment_attestation", "evidence")}
{todo("verify_assessment_attestation", "evidence")}
{todo("critical_transition_plan", "resource")}
{todo("exercise_critical_transition", "resource")}
{todo("critical_barrier_test", "authority")}
{todo("secondary_containment", "supervision")}
{todo("adversarial_assurance", "evidence")}
{todo("emergency_recovery", "supervision")}
{todo("independent_assurance_package", "evidence")}
{todo("verify_assurance_package", "evidence")}
{todo("evidence_snapshot", "evidence")}
{todo("evidence_report", "evidence")}
{todo("read_raw_evidence", "evidence")}
{todo("assessment_binding", "evidence")}
{todo("validate_assessment_binding", "evidence")}
{todo("verify_evidence_integrity", "evidence")}
"""


def render_readme(rec: dict[str, Any], *, class_name: str, adapter_filename: str = "adapter.py") -> str:
    runtime = rec["runtime"]
    rows = []
    for surface in rec["surfaces"]:
        sid = surface["id"]
        mapped = runtime.get("recommended", {}).get(sid, "Select and wire a real deployment surface.")
        rows.append(f"| {surface['name']} | {mapped} |")
    resource_rows = "\n".join(
        f"- **{row['name']}** — oracle: {row['oracle']}" for row in rec.get("resources", [])
    ) or "- No protected resource selected yet."
    warnings = "\n".join(f"- {item}" for item in runtime.get("not_enough", []))
    gaps = "\n".join(f"- {item}" for item in rec.get("gaps", []))
    table = "\n".join(rows)
    return f"""# Generated Asimov adapter starter

**Runtime:** {runtime['name']}  
**Catalog checked:** {rec['checked_at']}

This is a conservative starter, not a working conformance adapter. It reports zero
capabilities until real deployment controls are connected.

## Suggested surface mapping

| Asimov surface | Suggested mapping |
|---|---|
{table}

## Protected resources

{resource_rows}

## Important non-equivalences

{warnings}

## Gaps before testing

{gaps}

## Next steps

1. Open {adapter_filename} and implement only the surfaces your deployment really has.
2. Add capabilities one at a time only after the corresponding method is real.
3. Use a disposable target/tenant/namespace for destructive or fault-injection tests.
4. Run: asimov doctor --level A1
5. Raise the requested level only as the adapter earns the required surfaces.
6. Launch Studio and point the Adapter field to: {adapter_filename}:{class_name}

Provider documentation: {runtime['docs_url']}
"""


def generate_adapter(
    output_dir: Path,
    *,
    runtime: str,
    hosting: str | None = None,
    authority: str | None = None,
    resources: list[str] | None = None,
    evidence: list[str] | None = None,
    integrations: list[str] | None = None,
    class_name: str = "AsimovAdapter",
    adapter_id: str = "generated-adapter",
) -> dict[str, Any]:
    class_name = _class_name(class_name)
    output_dir = output_dir.expanduser().resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise AdapterAssistantError(f"refusing to overwrite nonempty adapter directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    rec = recommendation(
        runtime=runtime,
        hosting=hosting,
        authority=authority,
        resources=resources,
        evidence=evidence,
        integrations=integrations,
    )
    adapter_path = output_dir / "adapter.py"
    readme_path = output_dir / "README.md"
    manifest_path = output_dir / "asimov-adapter.json"
    adapter_path.write_text(
        render_adapter_source(rec, class_name=class_name, adapter_id=adapter_id),
        encoding="utf-8",
    )
    readme_path.write_text(render_readme(rec, class_name=class_name), encoding="utf-8")
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "runtime": runtime,
                "hosting": hosting,
                "authority": authority,
                "resources": resources or [],
                "evidence": evidence or [],
                "integrations": integrations or [],
                "adapter_class": class_name,
                "adapter_id": adapter_id,
                "catalog_checked_at": rec["checked_at"],
                "capability_claims": [],
                "warning": "Generated starter only. No Asimov capability is claimed until implemented.",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return {
        "output_dir": str(output_dir),
        "adapter_path": str(adapter_path),
        "adapter_spec": f"{adapter_path}:{class_name}",
        "readme_path": str(readme_path),
        "manifest_path": str(manifest_path),
        "recommendation": rec,
    }
