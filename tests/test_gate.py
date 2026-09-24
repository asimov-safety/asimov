"""Tests of reporting logic, not tests of an AI deployment's safety."""
from __future__ import annotations
import contextlib
import io
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from asimov_conformance.__main__ import main
from asimov_conformance.gate import ReportError, catalog, evaluate_report, load_report, validate_report

ROOT=Path(__file__).resolve().parents[1]


class GateTests(unittest.TestCase):
    def setUp(self):
        self.report=json.loads((ROOT/'examples/report-illustrative-complete.json').read_text())

    def item(self,rid='MED-002'):
        return next(x for x in self.report['results'] if x['requirement_id']==rid)

    def test_complete_fixture_reports_a5_pass(self):
        result=evaluate_report(self.report)
        for p in ('A1','A2','A3','A4','A5'):
            self.assertEqual(result['profiles'][p]['state'],'REPORTED_PASS')
        self.assertEqual(result['reported_outcome'],'REPORTED_PASS')
        self.assertFalse(result['certificate_issued'])

    def test_a4_requires_advanced_preconditions(self):
        del self.report['preconditions']['common_mode_failure_analysis']
        result=evaluate_report(self.report)
        self.assertEqual(result['profiles']['A3']['state'],'REPORTED_PASS')
        self.assertEqual(result['profiles']['A4']['state'],'REPORTED_INCOMPLETE')

    def test_a5_requires_domain_preconditions(self):
        del self.report['preconditions']['domain_safety_case']
        result=evaluate_report(self.report)
        self.assertEqual(result['profiles']['A4']['state'],'REPORTED_PASS')
        self.assertEqual(result['profiles']['A5']['state'],'REPORTED_INCOMPLETE')

    def test_a5_requirement_failure_does_not_break_a4(self):
        self.item('MED-006')['status']='FAIL'
        result=evaluate_report(self.report)
        self.assertEqual(result['profiles']['A4']['state'],'REPORTED_PASS')
        self.assertEqual(result['profiles']['A5']['state'],'REPORTED_FAIL')

    def test_a4_requirement_failure_breaks_a4_and_a5(self):
        self.item('ACC-005')['status']='FAIL'
        result=evaluate_report(self.report)
        self.assertEqual(result['profiles']['A3']['state'],'REPORTED_PASS')
        self.assertEqual(result['profiles']['A4']['state'],'REPORTED_FAIL')
        self.assertEqual(result['profiles']['A5']['state'],'REPORTED_FAIL')

    def test_missing_requirement_is_incomplete(self):
        self.report['results'].remove(self.item('OVR-006'))
        result=evaluate_report(self.report)
        self.assertEqual(result['profiles']['A5']['state'],'REPORTED_INCOMPLETE')
        self.assertIn({'id':'OVR-006','status':'NOT_TESTED'},result['profiles']['A5']['unmet'])

    def test_nonpass_statuses_never_satisfy_mandatory_item(self):
        for status in ('ERROR','NOT_TESTED','INCONCLUSIVE','NOT_APPLICABLE'):
            with self.subTest(status=status):
                r=deepcopy(self.report); next(x for x in r['results'] if x['requirement_id']=='MED-002')['status']=status
                self.assertEqual(evaluate_report(r)['profiles']['A2']['state'],'REPORTED_INCOMPLETE')

    def test_failure_precedence(self):
        self.item('MED-002')['status']='FAIL'
        self.report['results'].remove(self.item('REV-004'))
        result=evaluate_report(self.report)
        self.assertEqual(result['reported_outcome'],'REPORTED_FAIL')
        self.assertIn({'id':'REV-004','status':'NOT_TESTED'},result['profiles']['A5']['unmet'])

    def test_a0_is_classification_only(self):
        self.report['requested_profile']='A0'
        self.assertEqual(evaluate_report(self.report)['reported_outcome'],'CLASSIFICATION_ONLY')

    def test_unknown_requirement_rejected(self):
        self.item()['requirement_id']='MAGIC-999'
        with self.assertRaises(ReportError): evaluate_report(self.report)

    def test_duplicate_requirement_rejected(self):
        self.report['results'].append(deepcopy(self.item()))
        with self.assertRaises(ReportError): evaluate_report(self.report)

    def test_pass_without_evidence_rejected(self):
        self.item()['evidence_refs']=[]
        with self.assertRaises(ReportError): evaluate_report(self.report)

    def test_unknown_assessment_mode_rejected(self):
        self.report['assessment']['mode']='trust_me'
        with self.assertRaises(ReportError): evaluate_report(self.report)

    def test_independence_field_is_not_cryptographically_verified(self):
        self.report['assessment']['mode']='independent_assessment'
        result=evaluate_report(self.report)
        self.assertEqual(result['claim_status'],'UNVERIFIED_REPORTED_RESULTS')
        self.assertFalse(result['evidence_verified_by_this_tool'])

    def test_timestamp_validation(self):
        self.report['created_at']='2026-09-24T13:52:00-04:00'; validate_report(self.report)
        self.report['created_at']='2026-09-24T13:52:00'
        with self.assertRaises(ReportError): validate_report(self.report)

    def test_input_not_mutated(self):
        before=deepcopy(self.report); evaluate_report(self.report); self.assertEqual(before,self.report)

    def test_duplicate_json_members_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'bad.json'; p.write_text('{"a":1,"a":2}')
            with self.assertRaises(ReportError): load_report(p)

    def test_cli_complete_html_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'report.html'; stream=io.StringIO()
            with contextlib.redirect_stdout(stream):
                code=main(['report',str(ROOT/'examples/report-illustrative-complete.json'),'--html-output',str(out)])
            self.assertEqual(code,0); self.assertTrue(out.exists())
            html=out.read_text(); self.assertIn('Asimov Conformance Result',html); self.assertIn('A5',html)
            self.assertIn('No deployment probed',stream.getvalue())

    def test_cli_failure_exit(self):
        with contextlib.redirect_stdout(io.StringIO()):
            code=main(['report',str(ROOT/'examples/report-illustrative-failure.json')])
        self.assertEqual(code,1)

    def test_cli_incomplete_exit(self):
        with contextlib.redirect_stdout(io.StringIO()):
            code=main(['report',str(ROOT/'examples/report-illustrative-missing.json')])
        self.assertEqual(code,2)


class RepositoryConsistencyTests(unittest.TestCase):
    def test_catalog_count_uniqueness_and_profile_counts(self):
        rows=catalog()['requirements']
        self.assertEqual(len(rows),42)
        self.assertEqual(len({r['id'] for r in rows}),42)
        self.assertEqual([sum(r['minimum_profile']<=n for r in rows) for n in (1,2,3,4,5)],[8,21,28,35,42])

    def test_all_seven_contracts_have_six_families(self):
        rows=catalog()['requirements']
        for c in ('I','II','III','IV','V','VI','VII'):
            self.assertEqual(sum(r['contract']==c for r in rows),6)

    def test_every_family_has_operational_metadata(self):
        for r in catalog()['requirements']:
            for key in ('requirement','setup','procedure','expected','evidence','limitation','methods','automation','implementation_status'):
                self.assertTrue(r.get(key),f"{r['id']} missing {key}")
            self.assertIn(r['automation'],{'ADAPTER_AUTOMATABLE','HYBRID','REVIEW_REQUIRED'})
            self.assertIn(r['implementation_status'],{'SPECIFIED_NOT_IMPLEMENTED','REFERENCE_PROBE_IMPLEMENTED'})

    def test_spec_and_catalog_doc_contain_exact_requirements(self):
        spec=(ROOT/'ASIMOV-CORE-0.2.md').read_text(); doc=(ROOT/'docs/TEST-CATALOG-0.2.md').read_text()
        for r in catalog()['requirements']:
            self.assertIn(r['requirement'],spec); self.assertIn(r['requirement'],doc)

    def test_schema_has_all_ids(self):
        s=json.loads((ROOT/'schemas/report.schema.json').read_text())
        ids=s['properties']['results']['items']['properties']['requirement_id']['enum']
        self.assertEqual(set(ids),{r['id'] for r in catalog()['requirements']})

    def test_manifest_digest_binds_examples(self):
        import hashlib
        d=hashlib.sha256((ROOT/'examples/manifest.example.json').read_bytes()).hexdigest()
        for p in (ROOT/'examples').glob('report-*.json'):
            self.assertEqual(json.loads(p.read_text())['scope_manifest_sha256'],d)


if __name__=='__main__': unittest.main()
