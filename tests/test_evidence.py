from __future__ import annotations
import json
import tempfile
import unittest
from pathlib import Path
from asimov_conformance.evidence import EvidenceError, build_evidence_manifest, verify_evidence_manifest
from asimov_conformance.__main__ import main


class EvidenceTests(unittest.TestCase):
    def test_manifest_round_trip_and_mutation_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'a.txt').write_text('alpha'); (root/'nested').mkdir(); (root/'nested/b.txt').write_text('beta')
            manifest=build_evidence_manifest(root)
            self.assertEqual(verify_evidence_manifest(manifest,root),[])
            (root/'a.txt').write_text('changed')
            self.assertTrue(any('a.txt' in e for e in verify_evidence_manifest(manifest,root)))

    def test_manifest_digest_detects_row_edit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'x').write_text('x'); m=build_evidence_manifest(root); m['files'][0]['size']=999
            errors=verify_evidence_manifest(m,root)
            self.assertIn('manifest digest mismatch',errors)

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); target=root/'target'; target.write_text('x'); link=root/'link'; link.symlink_to(target)
            with self.assertRaises(EvidenceError): build_evidence_manifest(root)

    def test_cli_integrity_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'e'; root.mkdir(); (root/'evidence.txt').write_text('evidence')
            mf=Path(tmp)/'manifest.json'
            self.assertEqual(main(['evidence-manifest',str(root),'--output',str(mf)]),0)
            self.assertEqual(main(['verify-evidence',str(mf),str(root)]),0)
            self.assertEqual(json.loads(mf.read_text())['algorithm'],'sha256')


if __name__=='__main__': unittest.main()
