# Contributing to Asimov

Begin with Core, the test catalog, and the conformance methodology.

For a requirement change, create an AEP describing the observable failure it addresses, proposed normative wording, affected profiles, test procedure, evidence/oracle, false-positive and bypass concerns, upstream overlap, and compatibility implications. AEP 0001 records the initial scope choices. Do not silently mark unspecified or unimplemented tests complete.

For code, add tests showing normal authorized behavior, the relevant failure, and incomplete/invalid evidence handling. The current regression command is:

```bash
python3 -m unittest discover -s tests -v
```

Run code only against systems you own or are authorized to assess, using synthetic data and disposable resources. Never submit production credentials, private conversations, undisclosed personal data, or live third-party exploit instructions as test fixtures. Review SECURITY.md before discussing a real vulnerability.

Contributions must be original or accompanied by compatible licensing and attribution. Referencing an upstream standard is not permission to copy its text or claim its endorsement. Submitting a change does not automatically make its author a maintainer or approved assessor.

Report results honestly: these unit tests exercise report logic, not control of a real agent. Include configuration, observer evidence and known limitations when an executable deployment test is eventually contributed.
