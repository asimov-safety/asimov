"""Styled HTML rendering for Asimov assessments and verification receipts."""
from __future__ import annotations
from html import escape
from typing import Any

from .gate import catalog

PROFILE_NAMES = {"A1": "Observable", "A2": "Controlled", "A3": "Supervised", "A4": "Hardened", "A5": "Critical"}
CONSTANTS = (
    ("I", "OBS", "Observable Agency"),
    ("II", "MED", "Mediated Action"),
    ("III", "REV", "Revocable Authority"),
    ("IV", "OVR", "Protected Oversight"),
    ("V", "DEL", "Bounded Delegation"),
    ("VI", "HUM", "Human Authority"),
    ("VII", "ACC", "Accountability"),
)

SEAL = """<svg viewBox="0 0 80 80" aria-hidden="true"><g fill="none" stroke="currentColor"><circle cx="40" cy="40" r="28" stroke-width="1.3"/><circle cx="40" cy="40" r="21" stroke-width=".8" opacity=".48"/><path d="M40 5v8M62.6 12.8l-4.9 6.3M75 32.2l-7.8 1.8M70.4 56.3l-7.2-3.5M51.3 73l-2.5-7.6M27.1 73l2.8-7.5M9.2 55.8l7.1-3.7" stroke-width="2" stroke-linecap="round"/></g><path d="M26.4 54 37.1 25.8h6L53.7 54h-5.2l-2.7-7.4H34.1L31.4 54h-5Zm9.3-11.9h8.5L40 30.3l-4.3 11.8Z" fill="currentColor"/></svg>"""

CSS = r"""
:root{--paper:#f4f0e6;--ink:#10251d;--green:#173c30;--muted:#68736d;--brass:#927c57;--line:rgba(16,37,29,.2);--cream:#fcfaf4}
*{box-sizing:border-box}html{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{margin:0;background:#d9d6ce;color:var(--ink);font:14px/1.55 "Helvetica Neue",Arial,sans-serif}
.report{max-width:1020px;margin:32px auto;background:var(--paper);box-shadow:0 20px 80px rgba(0,0,0,.13)}
.page{padding:54px 62px;position:relative}.cover{min-height:780px;background:var(--green);color:var(--cream);display:flex;flex-direction:column;justify-content:space-between}
.brand{display:flex;align-items:center;gap:12px;text-transform:uppercase;letter-spacing:.24em;font-size:11px;font-weight:700}.brand svg{width:40px;height:40px}
.eyebrow{font-size:10px;text-transform:uppercase;letter-spacing:.18em;color:#b9c9c0;margin-bottom:22px}
.cover h1,.serif{font-family:Baskerville,"Iowan Old Style",Georgia,serif;font-weight:400}
.cover h1{font-size:76px;line-height:.88;letter-spacing:-.045em;margin:0 0 30px;max-width:740px}.cover h1 em{color:#c8d7cf;font-weight:400}
.cover .system{font-family:Baskerville,"Iowan Old Style",Georgia,serif;font-size:25px;color:#d9e2dc}
.cover-grid{display:grid;grid-template-columns:1.2fr 1fr;gap:50px;border-top:1px solid rgba(255,255,255,.22);padding-top:22px}
.label{font-size:9px;text-transform:uppercase;letter-spacing:.15em;color:#9eb3a8}.cover .value{font-size:13px;margin-top:5px}
h2{font:400 42px/1.02 Baskerville,"Iowan Old Style",Georgia,serif;letter-spacing:-.025em;margin:0 0 24px}
h3{font:400 22px/1.15 Baskerville,"Iowan Old Style",Georgia,serif;margin:0}
.section{border-top:1px solid var(--line);padding-top:35px;margin-top:38px}
.result-line{display:grid;grid-template-columns:110px 1fr 180px;gap:24px;align-items:end;border-top:1px solid var(--line);border-bottom:1px solid var(--line);padding:25px 0}
.big-level{font:italic 52px/1 Baskerville,"Iowan Old Style",Georgia,serif;color:var(--green)}
.result-name{font:400 27px Baskerville,"Iowan Old Style",Georgia,serif}.result-state{text-align:right;font-size:11px;letter-spacing:.1em;text-transform:uppercase}
.constant-row{display:grid;grid-template-columns:65px 1fr 95px;gap:20px;border-top:1px solid var(--line);padding:19px 0}
.constant-row:last-child{border-bottom:1px solid var(--line)}.roman{font:italic 27px Baskerville,"Iowan Old Style",Georgia,serif;color:var(--brass)}
.constant-name{font:400 18px Baskerville,"Iowan Old Style",Georgia,serif}.status{text-align:right;font-size:10px;font-weight:700;letter-spacing:.09em}
.PASS,.REPORTED_PASS{color:#1e6a4e}.FAIL,.REPORTED_FAIL{color:#8b3028}.INCOMPLETE,.REPORTED_INCOMPLETE,.NOT_TESTED,.INCONCLUSIVE{color:#8b6a2f}
.meta{display:grid;grid-template-columns:repeat(3,1fr);gap:25px}.meta>div{border-top:1px solid var(--line);padding-top:11px}.meta .value{margin-top:5px;word-break:break-word}
.profile-table{width:100%;border-collapse:collapse}.profile-table td{border-top:1px solid var(--line);padding:12px 6px}.profile-table td:first-child{font:italic 20px Baskerville,Georgia,serif}.profile-table td:last-child{text-align:right}
.finding-group{page-break-inside:avoid;margin:30px 0}.finding-head{display:grid;grid-template-columns:65px 1fr;gap:18px;align-items:baseline;margin-bottom:12px}
.finding{display:grid;grid-template-columns:82px 92px minmax(0,1fr);gap:12px;padding:11px 0;border-top:1px solid var(--line)}
.finding>div{min-width:0}.finding-id{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:11px;overflow-wrap:anywhere}.finding-reason{color:var(--muted)}
.precondition{grid-template-columns:minmax(178px,1.15fr) 118px minmax(0,3fr);gap:22px}.precondition .status{text-align:left}
.evidence{font-size:10px;color:var(--muted);margin-top:4px;word-break:break-all}
.limits{padding-left:18px}.limits li{margin:8px 0}.hash{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:10px;word-break:break-all}
.footer{display:flex;justify-content:space-between;border-top:1px solid var(--line);padding-top:15px;margin-top:45px;font-size:9px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
.receipt-check{display:grid;grid-template-columns:180px 110px 1fr;gap:18px;border-top:1px solid var(--line);padding:16px 0}.receipt-check:last-child{border-bottom:1px solid var(--line)}
.summary{max-width:900px}.summary .page{min-height:700px}
@page{size:A4;margin:12mm}
@media print{body{background:white}.report{margin:0;max-width:none;box-shadow:none}.page{padding:8mm 10mm}.cover{min-height:260mm;page-break-after:always}.page-break{page-break-before:always}}
"""


def _highest_pass(result: dict[str, Any]) -> str | None:
    highest = None
    for profile in PROFILE_NAMES:
        if result["profiles"][profile]["state"] == "REPORTED_PASS":
            highest = profile
    return highest


def _constant_states(result: dict[str, Any]) -> list[tuple[str, str, str]]:
    findings = {row["requirement_id"]: row["status"] for row in result.get("findings", [])}
    requested_num = int(result["requested_profile"][1]) if result["requested_profile"] != "A0" else 0
    requirements = catalog()["requirements"]
    rows = []
    for roman, prefix, name in CONSTANTS:
        applicable = [
            r["id"] for r in requirements
            if r["id"].startswith(prefix + "-") and r["minimum_profile"] <= requested_num
        ]
        statuses = [findings.get(rid, "NOT_TESTED") for rid in applicable]
        if any(x == "FAIL" for x in statuses):
            state = "FAIL"
        elif statuses and all(x == "PASS" for x in statuses):
            state = "PASS"
        elif applicable:
            state = "INCOMPLETE"
        else:
            state = "—"
        rows.append((roman, name, state))
    return rows


def _head(title: str) -> str:
    return f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{escape(title)}</title><style>{CSS}</style></head><body>'


def render_html(result: dict[str, Any]) -> str:
    """Render a professional full Asimov assessment report."""
    cat = {r["id"]: r for r in catalog()["requirements"]}
    highest = _highest_pass(result)
    constant_rows = "".join(
        f'<div class="constant-row"><div class="roman">{roman}</div><div class="constant-name">{escape(name)}</div><div class="status {state}">{escape(state)}</div></div>'
        for roman, name, state in _constant_states(result)
    )
    profile_rows = "".join(
        f'<tr><td>{p}</td><td>{escape(PROFILE_NAMES[p])}</td><td>{result["profiles"][p]["mandatory_families"]}</td><td class="{result["profiles"][p]["state"]}">{escape(result["profiles"][p]["state"].replace("REPORTED_",""))}</td></tr>'
        for p in PROFILE_NAMES
    )

    groups = []
    for roman, prefix, name in CONSTANTS:
        items = [x for x in result.get("findings", []) if x["requirement_id"].startswith(prefix + "-")]
        if not items:
            continue
        findings_html = ""
        for item in items:
            rid = item["requirement_id"]
            title = cat.get(rid, {}).get("title", rid)
            refs = ", ".join(item.get("evidence_refs", [])) or "—"
            findings_html += (
                f'<div class="finding"><div class="finding-id">{escape(rid)}</div>'
                f'<div class="status {escape(item["status"])}">{escape(item["status"])}</div>'
                f'<div><strong>{escape(title)}</strong><div class="finding-reason">{escape(item["reason"])}</div>'
                f'<div class="evidence">Evidence: {escape(refs)}</div></div></div>'
            )
        groups.append(
            f'<section class="finding-group"><div class="finding-head"><div class="roman">{roman}</div><h3>{escape(name)}</h3></div>{findings_html}</section>'
        )

    preconditions = "".join(
        f'<div class="finding precondition"><div class="finding-id">{escape(name)}</div><div class="status {escape(row["status"])}">{escape(row["status"])}</div><div><div class="finding-reason">{escape(row["reason"])}</div><div class="evidence">Evidence: {escape(", ".join(row.get("evidence_refs", [])) or "—")}</div></div></div>'
        for name, row in result.get("preconditions", {}).items()
    )
    limitations = "".join(f"<li>{escape(x)}</li>" for x in result.get("limitations", [])) or "<li>None stated.</li>"
    achieved = f'{highest} · {PROFILE_NAMES[highest]}' if highest else "No assurance profile satisfied"
    created = result.get("created_at", "—")
    assessor = result.get("assessor", "—")
    mode = result.get("assessment_mode", "—").replace("_", " ").title()

    return _head(f'Asimov Assessment — {result["system"]["id"]}') + f'''
<div class="report">
<section class="page cover">
  <div class="brand">{SEAL}<span>Asimov</span></div>
  <div>
    <div class="eyebrow">Conformance assessment</div>
    <h1>Accountable<br><em>autonomy.</em></h1>
    <div class="system">{escape(result["system"]["id"])}</div>
  </div>
  <div class="cover-grid">
    <div><div class="label">Assessment result</div><div class="value">{escape(achieved)}</div></div>
    <div><div class="label">Requested assurance</div><div class="value">{escape(result["requested_profile"])} · {escape(PROFILE_NAMES.get(result["requested_profile"], "Classification"))}</div></div>
    <div><div class="label">Assessment mode</div><div class="value">{escape(mode)}</div></div>
    <div><div class="label">Report ID</div><div class="value">{escape(result["report_id"])}</div></div>
  </div>
</section>

<section class="page">
  <div class="eyebrow">Executive assessment</div>
  <h2>The Seven Constants</h2>
  <div class="result-line"><div class="big-level">{escape(highest or "—")}</div><div><div class="result-name">{escape(PROFILE_NAMES.get(highest or "", "No profile satisfied"))}</div><div class="finding-reason">Highest cumulative assurance level satisfied by the reported findings.</div></div><div class="result-state {escape(result["reported_outcome"])}">{escape(result["reported_outcome"].replace("REPORTED_",""))}</div></div>
  <div class="section">{constant_rows}</div>

  <div class="section">
    <div class="eyebrow">Assessment identity</div>
    <div class="meta">
      <div><div class="label">Assessor</div><div class="value">{escape(assessor)}</div></div>
      <div><div class="label">Created</div><div class="value">{escape(created)}</div></div>
      <div><div class="label">Mode</div><div class="value">{escape(mode)}</div></div>
      <div><div class="label">Configuration SHA-256</div><div class="value hash">{escape(result["system"]["configuration_sha256"])}</div></div>
      <div><div class="label">Scope manifest SHA-256</div><div class="value hash">{escape(result["scope_manifest_sha256"])}</div></div>
      <div><div class="label">Specification</div><div class="value">Asimov Core {escape(result["spec_version"])}</div></div>
    </div>
  </div>

  <div class="section">
    <div class="eyebrow">Assurance progression</div>
    <table class="profile-table"><tbody>{profile_rows}</tbody></table>
  </div>
  <div class="footer"><span>Asimov · Conformance Assessment</span><span>{escape(result["report_id"])}</span></div>
</section>

<section class="page page-break">
  <div class="eyebrow">Preconditions</div>
  <h2>Assessment foundation.</h2>
  {preconditions}
  <div class="footer"><span>Asimov · Preconditions</span><span>{escape(result["report_id"])}</span></div>
</section>

<section class="page page-break">
  <div class="eyebrow">Detailed findings</div>
  <h2>Evidence by Constant.</h2>
  {''.join(groups)}
  <div class="footer"><span>Asimov · Findings</span><span>{escape(result["report_id"])}</span></div>
</section>

<section class="page page-break">
  <div class="eyebrow">Public verification</div>
  <h2>Verify the report people actually share.</h2>
  <p>For public or media distribution, share this report together with <strong>public-verification.json</strong>. A reader can verify that the report bytes match the issued verification statement and inspect the exact assessment identity, scope/configuration binding, requested profile, and reported outcome bound to it.</p>
  <p><strong>Authenticated provenance:</strong> when the public verification record includes a valid Sigstore bundle, the reader can additionally verify the identity that signed the exact statement and its external transparency checkpoint.</p>
  <p><strong>What this does not prove:</strong> cryptography does not decide whether the underlying evidence or assessment judgment is substantively correct. Human/independent review remains separately visible in the assessment result.</p>
  <div class="section">
    <div class="label">Public verification</div><p>https://asimov-safety.github.io/verification.html</p>
    <div class="label">Report ID</div><p>{escape(result["report_id"])}</p>
  </div>
  <div class="section">
    <div class="label">Scope manifest SHA-256</div><p class="hash">{escape(result["scope_manifest_sha256"])}</p>
    <div class="label">Configuration SHA-256</div><p class="hash">{escape(result["system"]["configuration_sha256"])}</p>
  </div>
  <div class="section"><div class="eyebrow">Limitations</div><ul class="limits">{limitations}</ul></div>
  <div class="footer"><span>Asimov · Verification & Limitations</span><span>{escape(result["report_id"])}</span></div>
</section>
</div></body></html>'''


def render_summary_html(result: dict[str, Any]) -> str:
    """Render a concise shareable executive summary."""
    highest = _highest_pass(result)
    rows = "".join(
        f'<div class="constant-row"><div class="roman">{r}</div><div class="constant-name">{escape(n)}</div><div class="status {s}">{escape(s)}</div></div>'
        for r, n, s in _constant_states(result)
    )
    achieved = f'{highest} · {PROFILE_NAMES[highest]}' if highest else "No assurance profile satisfied"
    return _head(f'Asimov Summary — {result["system"]["id"]}') + f'''
<div class="report summary"><section class="page">
<div class="brand" style="color:var(--green)">{SEAL}<span>Asimov</span></div>
<div style="margin-top:90px"><div class="eyebrow">Assessment summary</div><h2 style="font-size:58px">{escape(result["system"]["id"])}</h2>
<div class="result-line"><div class="big-level">{escape(highest or "—")}</div><div><div class="result-name">{escape(achieved)}</div><div class="finding-reason">Highest cumulative assurance level satisfied.</div></div><div class="result-state {escape(result["reported_outcome"])}">{escape(result["reported_outcome"].replace("REPORTED_",""))}</div></div></div>
<div class="section">{rows}</div>
<div class="section meta"><div><div class="label">Assessor</div><div class="value">{escape(result.get("assessor","—"))}</div></div><div><div class="label">Report ID</div><div class="value">{escape(result["report_id"])}</div></div><div><div class="label">Specification</div><div class="value">Asimov Core {escape(result["spec_version"])}</div></div></div>
<div class="footer"><span>Asimov · Assessment Summary</span><span>Verify with the accompanying Asimov package</span></div>
</section></div></body></html>'''


def render_verification_receipt(receipt: dict[str, Any]) -> str:
    checks = receipt.get("checks", {})
    labels = {
        "evidence_integrity": "Evidence integrity",
        "artifact_and_scope_binding": "Artifact & scope binding",
        "sigstore_identity_and_transparency": "Identity & transparency",
        "semantic_assurance": "Semantic assurance",
    }
    rows = ""
    for key, label in labels.items():
        check = checks.get(key, {})
        state = str(check.get("state", "NOT_CHECKED"))
        detail = check.get("detail") or "; ".join(check.get("errors", [])) or "—"
        rows += f'<div class="receipt-check"><div>{escape(label)}</div><div class="status {escape(state)}">{escape(state)}</div><div class="finding-reason">{escape(str(detail))}</div></div>'
    return _head(f'Asimov Verification — {receipt.get("report_id","") }') + f'''
<div class="report summary"><section class="page">
<div class="brand" style="color:var(--green)">{SEAL}<span>Asimov</span></div>
<div style="margin-top:85px"><div class="eyebrow">Verification receipt</div><h2 style="font-size:54px">{escape(str(receipt.get("system_id","—")))}</h2>
<div class="result-line"><div class="big-level">{escape(str(receipt.get("requested_profile","—")))}</div><div><div class="result-name">{escape(str(receipt.get("overall","—")).replace("_"," ").title())}</div><div class="finding-reason">Verification state for the supplied assessment package.</div></div><div class="result-state">{escape(str(receipt.get("reported_outcome","—")).replace("REPORTED_",""))}</div></div></div>
<div class="section">{rows}</div>
<div class="footer"><span>Asimov · Verification Receipt</span><span>{escape(str(receipt.get("report_id","")))}</span></div>
</section></div></body></html>'''


def render_probe_html(report: dict[str, Any]) -> str:
    """Render the reference-harness result."""
    rows = []
    for row in report["results"]:
        details = escape(str(row.get("details", {})))
        rows.append(
            f"<tr><td><code>{escape(row['requirement_id'])}</code></td>"
            f"<td>{escape(row['status'])}</td><td>{escape(row['summary'])}</td>"
            f"<td><details><summary>details</summary><pre>{details}</pre></details></td></tr>"
        )
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Asimov Reference Harness</title></head><body>
<h1>Asimov A1-A5 Reference Harness</h1>
<p>Adapter: {escape(report['adapter_id'])} · Specification: {escape(report['spec_version'])} · Passed: {sum(r['status']=='PASS' for r in report['results'])}/{len(report['results'])}</p>
<table><thead><tr><th>Requirement</th><th>Status</th><th>Finding</th><th>Detail</th></tr></thead><tbody>{''.join(rows)}</tbody></table></body></html>'''
