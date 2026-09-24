# Asimov Founding Charter

**Working draft — September 24, 2026**

## Mission

Make claims about human control of autonomous AI specific, testable and inspectable, without requiring adoption of a particular model, vendor or software stack.

## The public contribution

The Seven Safety Contracts provide a compact vocabulary. Versioned requirements translate that vocabulary into engineering properties. An open conformance suite is intended to probe those properties, preserve failures and uncertainty, and produce evidence-bound assessment reports. A reference implementation will demonstrate feasibility rather than become a required product.

The intended beneficiaries include AI providers, agent-framework builders, independent developers, deploying organizations, researchers, security teams and assessors. A vendor may implement the standard using its own infrastructure. A relying party decides whether the documented controls and threat model are sufficient for its use.

## Commitments for the founding draft

The specification, schemas, test definitions and reference code are freely accessible and permissively licensed. No paid account, hosted dashboard, blockchain or approved model is required. Mandatory failures cannot be averaged away. Unknown coverage remains unknown. Implementations and assessors must disclose the limits of their evidence.

No product may obtain an exemption by funding the project. Changes to requirements must be reviewable, versioned and accompanied by a rationale. The project should seek more than one independent implementation before promoting a stable interoperability claim.

## Boundaries

Asimov is not a universal theory of ethics, a proof of alignment, a certification of content quality, or a substitute for domain-specific risk management. It does not assert that controlling an agent prevents every harm, or that a designated human's goals are themselves acceptable. It specifies control mechanisms and evidence about their operation.

## Initial success criterion

A third party can read a requirement, implement it without depending on Asimov's runtime, run the associated observed test against a disposable deployment, understand a failure, and reproduce the relevant finding. A deliberately broken implementation must fail.

The first result worth publishing is not a grand certification claim. It is a reproducible finding such as: "Revoking this parent left its delegated child able to write to the protected resource; after the fix, independently observed access stopped within the reviewed bound."
