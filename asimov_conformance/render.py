"""Dependency-free HTML rendering for draft Asimov result summaries."""
from __future__ import annotations
from html import escape
from typing import Any


def render_html(result: dict[str, Any]) -> str:
    rows=[]
    for level in [f"A{i}" for i in range(1,6)]:
        p=result["profiles"][level]
        unmet="; ".join(f"{x['id']}={x['status']}" for x in p.get("unmet", [])[:12]) or "—"
        if len(p.get("unmet", [])) > 12:
            unmet += f"; +{len(p['unmet'])-12} more"
        rows.append(
            f"<tr><td>{level}</td><td>{escape(p['state'])}</td>"
            f"<td>{p['mandatory_families']}</td><td>{p['mandatory_preconditions']}</td><td>{escape(unmet)}</td></tr>"
        )
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Asimov draft result — {escape(result['system']['id'])}</title>
<style>
body{{font-family:system-ui,-apple-system,sans-serif;max-width:1100px;margin:40px auto;padding:0 20px;line-height:1.45}}
h1{{margin-bottom:.2rem}} .note{{border:1px solid #aaa;padding:12px 14px;border-radius:8px}}
table{{border-collapse:collapse;width:100%;margin-top:20px}} th,td{{border-bottom:1px solid #ddd;text-align:left;padding:10px;vertical-align:top}}
code{{background:#eee;padding:2px 5px;border-radius:4px}}
</style></head><body>
<h1>Asimov Conformance Draft Result</h1>
<p><strong>System:</strong> {escape(result['system']['id'])}<br>
<strong>Specification:</strong> {escape(result['spec_version'])}<br>
<strong>Requested profile:</strong> {escape(result['requested_profile'])}<br>
<strong>Reported outcome:</strong> {escape(result['reported_outcome'])}<br>
<strong>Assessment mode:</strong> {escape(result['assessment_mode'])}</p>
<div class="note"><strong>Not a certificate.</strong> This screen aggregates supplied findings. Unless separately verified, it does not prove evidence integrity, assessor identity, live deployment state, or safety.</div>
<table><thead><tr><th>Profile</th><th>State</th><th>Families</th><th>Preconditions</th><th>Unmet</th></tr></thead><tbody>
{''.join(rows)}
</tbody></table>
<h2>Scope binding</h2><p><code>{escape(result['scope_manifest_sha256'])}</code></p>
<h2>Limitations</h2><ul>{''.join('<li>'+escape(x)+'</li>' for x in result['limitations'])}</ul>
</body></html>'''


def render_probe_html(report: dict[str, Any]) -> str:
    """Render the A2 reference-harness result without implying conformance."""
    rows = []
    for row in report["results"]:
        details = escape(str(row.get("details", {})))
        rows.append(
            f"<tr><td><code>{escape(row['requirement_id'])}</code></td>"
            f"<td>{escape(row['status'])}</td><td>{escape(row['summary'])}</td>"
            f"<td><details><summary>details</summary><pre>{details}</pre></details></td></tr>"
        )
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Asimov A2 reference probes</title>
<style>
body{{font-family:system-ui,-apple-system,sans-serif;max-width:1150px;margin:40px auto;padding:0 20px;line-height:1.45}}
h1{{margin-bottom:.2rem}} .note{{border:1px solid #aaa;padding:12px 14px;border-radius:8px}}
table{{border-collapse:collapse;width:100%;margin-top:20px}} th,td{{border-bottom:1px solid #ddd;text-align:left;padding:10px;vertical-align:top}}
code,pre{{background:#eee;padding:2px 5px;border-radius:4px}} pre{{white-space:pre-wrap;overflow-wrap:anywhere}}
</style></head><body>
<h1>Asimov A2 Reference Probe Results</h1>
<p><strong>Adapter:</strong> {escape(report['adapter_id'])}<br>
<strong>Specification:</strong> {escape(report['spec_version'])}<br>
<strong>Selected probes passed:</strong> {sum(r['status']=='PASS' for r in report['results'])}/{len(report['results'])}</p>
<div class="note"><strong>Reference-harness validation only.</strong> This is not an A-profile conformance result and does not establish safety for an external deployment.</div>
<table><thead><tr><th>Requirement</th><th>Status</th><th>Finding</th><th>Evidence detail</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
</body></html>'''
