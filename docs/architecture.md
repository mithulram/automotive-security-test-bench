# Architecture and design notes

## Design goal

The project is deliberately small enough to inspect during an interview while still showing a complete engineering loop: validated inputs, domain rules, deterministic outputs, automated tests, CI, documentation, and a usable report.

## Boundaries

- The input is a synthetic JSON risk register, not a live vehicle or network feed.
- The 5x5 matrix is an explicit prioritisation rule, not a claim of compliance with ISO/SAE 21434 or a safety analysis method.
- Threat categories map to a small published control catalogue. Unknown categories are shown but never assigned invented controls.
- `existing_controls` are documented input context; the tool does not calculate a fabricated residual-risk reduction.

## Key decisions

### Standard-library-first implementation

The core package has no runtime dependencies. That keeps the project easy to clone, run, and audit, and places the security-relevant logic in a few visible files rather than behind framework abstractions.

### Typed immutable domain model

`Risk` is a frozen dataclass. Invalid identifiers, missing assets/vulnerabilities, missing threat categories, and scores outside 1-5 are rejected at the boundary.

### Deterministic prioritisation

Risks are sorted by descending score and then stable identifier. Reports are predictable enough for code review and testing.

### Two outputs for two audiences

The JSON report is useful for integration or audit review; the self-contained HTML report gives a non-technical reviewer a readable prioritised view without installing an application.

## Verification approach

- Unit tests cover scoring boundaries, input rejection, control mapping, stable ordering, policy-gate behavior, and HTML escaping.
- The CI workflow compiles the source, runs tests on Python 3.11 and 3.13, and builds a sample assessment.
- The example data is synthetic and safe to publish.
