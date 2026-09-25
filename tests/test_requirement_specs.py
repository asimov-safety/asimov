"""One generated Python definition test per normative family.

These tests ensure every family is machine-addressable and operationally
specified. They are NOT deployment conformance tests; live probes require an
adapter and independent observation oracle.
"""
from __future__ import annotations
import unittest
from asimov_conformance.gate import catalog


class RequirementDefinitionTests(unittest.TestCase):
    pass


def make_test(row):
    def test(self):
        self.assertRegex(row['id'],r'^[A-Z]{3}-\d{3}$')
        self.assertIn(row['minimum_profile'],range(1,6))
        self.assertTrue(row['methods'])
        self.assertIn(row['automation'],{'ADAPTER_AUTOMATABLE','HYBRID','REVIEW_REQUIRED'})
        self.assertIn(row['review_requirement'],{'NONE','HUMAN','ROLE_SEPARATED','THIRD_PARTY'})
        if row['automation'] == 'ADAPTER_AUTOMATABLE':
            self.assertEqual(row['review_requirement'], 'NONE')
        else:
            self.assertNotEqual(row['review_requirement'], 'NONE')
        for field in ('requirement','setup','procedure','expected','evidence','limitation'):
            self.assertGreater(len(row[field].strip()),20)
    return test


for _row in catalog()['requirements']:
    setattr(RequirementDefinitionTests,f"test_{_row['id'].lower().replace('-','_')}",make_test(_row))


if __name__=='__main__': unittest.main()
