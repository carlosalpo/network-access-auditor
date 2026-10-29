# Network Access Auditor

[![CI](https://github.com/carlosalpo/network-access-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/carlosalpo/network-access-auditor/actions/workflows/ci.yml)

**Explain which NAC authorization rule permits a risky outcome—and which earlier rules prevent another from ever running.**

An offline Python auditor for a bounded, explicitly normalized network-access policy model. It evaluates ordered rules across every modeled group, method and posture combination, records the winning decision, and ties review findings to concrete witness states.

Created by **Carlos Alvarado** as a public security engineering portfolio project. Examples are synthetic. The model is designed to support NAC/Cisco ISE policy reviews, but **v0.1 does not connect to ISE, import native ISE exports or emulate its complete policy engine**.

## Why it exists

A permissive rule may be reachable, partially covered or completely hidden by earlier rules. Searching configuration text for broad permits does not distinguish those cases. Separately, a documented MAB exception can expire while the modeled access path remains available.

This tool makes both questions reviewable: it enumerates effective authorization outcomes, reports rule coverage, checks owned/dated MAB exceptions for declared endpoint observations, and compares results with explicit intent checks. Every result is reproducible from the supplied model and assessment date.

## Quick start

Python 3.11 or newer. No runtime dependencies or network access after installation.

```sh
git clone https://github.com/carlosalpo/network-access-auditor.git
cd network-access-auditor
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
naa validate --input examples/baseline.json
naa audit --input examples/baseline.json --output baseline-review
naa audit --input examples/risky-first-match.json --output risky-review
# The final command returns 1 because the default severity gate fails.
```

Open `risky-review/report.md`. The broad first rule produces **15 findings across 30 modeled states**: effective baseline violations, five shadowed rules, four intent mismatches and two missing MAB exception records. These are model findings, not observed attacks or confirmed exploitable paths.

`validate` checks the input contract only. `audit` reports findings and applies a severity gate. Exit **0** means the configured gate passed, **1** means it failed, and **2** means invalid input, a file error or incorrect command usage. The default gate is `--fail-on medium`; `--fail-on none` preserves every finding while returning 0. Always read the report's `status`, findings and gate together.

## What it reviews

- Effective standard/privileged access lacking the required identity trust, authentication-method declaration or posture.
- Unclassified identities receiving internal access and an effective permissive default.
- Rules fully shadowed by one **or several** earlier rules; partial coverage appears in the rule table.
- Missing or expired MAB exception ownership records for declared endpoints receiving internal access.
- Exact profile mismatches against expected authorization outcomes.

Risk checks apply to effective first-match outcomes. A fully shadowed broad permit is reported as a shadowed rule, not as reachable exposure. Disabled rules neither win nor block later rules. An exception record does not waive policy baseline findings.

## Deliverables

Each accepted input produces nine files in a new output directory:

| File | Purpose |
| --- | --- |
| `model.json` | Canonical input; policy rule order preserved |
| `audit.json` | Complete findings, witnesses, state outcomes, rule coverage and checks |
| `states.csv` | Every modeled state and its first winning rule/profile |
| `rule-coverage.csv` | Potential/effective/shadowed state counts and earlier winners |
| `endpoints.csv` | Declared observations and dated MAB exception status |
| `checks.csv` | Expected versus actual profile and winning rule |
| `findings.csv` | Review findings, severity and remediation guidance |
| `report.md` | Human-readable review with assumptions, evidence and limits |
| `manifest.json` | Input/canonical hashes, gate, counts and artifact hashes |

Existing output directories are never overwritten. Invalid or unsupported input produces no audit package. An I/O failure can leave partial output; require a parseable manifest and matching hashes before consuming a package.

## Reproducible scenarios

| Input | Expected result at default gate |
| --- | --- |
| `baseline.json` | No findings under the declared baseline; exit 0 |
| `risky-first-match.json` | Broad first rule; 15 findings; exit 1 |
| `shadowed-rule.json` | One fully shadowed rule; exit 1 |
| `expired-mab.json` | One expired exception; exit 1 |
| `current-mab.json` | Same-day expiry remains current; explicit relaxed standard-method baseline; exit 0 |
| `intent-mismatch.json` | One expected-profile mismatch; exit 1 |
| `permissive-default.json` | Effective internal-access default; exit 1 |
| `invalid-reference.json` | Unknown profile; exit 2 and no output directory |

The reference domain has four declared groups plus `unclassified`, two methods and three postures: **30 exhaustive modeled states**. This is not a count of actual sessions. State coverage is exhaustive only within those declared dimensions.

## Documentation

- [Input contract and baseline definitions](docs/input-model.md)
- [Evaluation, findings and engineering decisions](docs/engineering.md)
- [Cisco ISE normalization guide and exclusions](docs/ise-normalization.md)
- [Security and privacy boundaries](SECURITY.md)
- [Concept illustrations](docs/illustrations/README.md) — artwork, not execution evidence

```sh
python -m pip install '.[dev]'
ruff check src tests scripts
ruff format --check src tests scripts
pytest -q
python scripts/check_examples.py --output reports/example-matrix
```

Tests cover first-match semantics, shadowing by unions of prior rules, partial coverage, disabled rules, immutable privileged controls, exception date boundaries, exact intent checks, strict input rejection, deterministic projections and file safety. The eight-case runner invokes the installed CLI, checks expected exits/findings, verifies all artifact hashes and reconciles state coverage. CI runs on Python 3.11, 3.12 and 3.13.

## Limits that affect interpretation

Group trust and profile tiers are supplied by the reviewer; the tool does not interpret dACL contents or prove that a restricted profile enforces restrictions. `dot1x` is a declared method, not proof of successful authentication or certificate validation. Unknown posture is an explicit state, not a wildcard.

Policy-set selection, local/global exceptions, multiple authorization results, additional RADIUS attributes, real-time profiling, user/machine chaining, CoA, device enforcement and packet forwarding are outside this model. Do not silently drop such conditions from a real policy. A clean report cannot establish that the network is secure.

MIT licensed. Use synthetic reproductions for contributions; never submit real endpoint inventories, credentials or client policy exports.
