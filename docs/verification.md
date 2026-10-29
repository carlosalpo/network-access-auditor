# Verification record — v0.1.0

Tested implementation: [`bf76b4bf12d0c08422ed98ca05e024d9557f737b`](https://github.com/carlosalpo/network-access-auditor/commit/bf76b4bf12d0c08422ed98ca05e024d9557f737b).

On 2026-10-29, **124 tests and eight installed-CLI scenarios passed**, with Ruff lint and formatting checks, on local Python 3.12 and GitHub Actions Python 3.11, 3.12 and 3.13. [CI execution](https://github.com/carlosalpo/network-access-auditor/actions/runs/40957313860).

## Observed scenario results

| Scenario | Exit | Findings | Artifacts |
| --- | ---: | ---: | ---: |
| Baseline | 0 | 0 | 9 |
| Risky first match | 1 | 15 | 9 |
| Shadowed rule | 1 | 1 | 9 |
| Expired MAB exception | 1 | 1 | 9 |
| Current MAB exception | 0 | 0 | 9 |
| Intent mismatch | 1 | 1 | 9 |
| Permissive default | 1 | 8 | 9 |
| Invalid profile reference | 2 | Not audited | 0 |

Each accepted scenario evaluated 30 modeled states. The eight-case runner verified exit behavior, expected findings, all artifact byte lengths/hashes and reconciliation of effective rules plus default outcomes against the entire state count. A passing scenario means the expected behavior occurred, including deliberate audit failures.

The broad-first example has four effective-risk findings, five shadowed-rule findings, four intent mismatches and two missing MAB exception findings. These categories can overlap in underlying states; 15 is not a count of exploited or distinct real endpoints.

## Tested properties

- Exact first-enabled-match decisions, partial shadowing, and full shadowing by the union of earlier rules.
- Disabled rules do not win or block later rules; an unused permissive default does not create effective exposure findings.
- Risk witnesses agree with recorded winners; privileged requirements remain mandatory when standard controls are relaxed.
- Exception expiry is inclusive through its date, evaluated against the explicit assessment date. Current exceptions do not waive baseline findings.
- Intent checks compare exact profile IDs. A passed severity gate preserves review findings below its threshold.
- Maximum domain size, input bounds, duplicate/unknown data rejection, canonical stability with rule-order preservation, and no mutation of input.
- CSV/Markdown escaping, manifest consistency, offline execution with socket/DNS entry points disabled, exclusive output creation, restrictive POSIX permissions and incomplete writes without a completed manifest.

## Practical limits

The evidence comes from public synthetic models. No live Cisco ISE, RADIUS authentication, certificate validation, native export import or endpoint enforcement was tested. Group trust, profile tiers and exception approval remain declarations. Model findings are review leads; no findings cannot establish network security or compliance.

The release ZIP contains three complete generated review packages: baseline, risky first match and expired MAB, with nine files each. Each canonical `model.json` can be used as input for a fresh run. The ZIP checksum and per-package manifests are unsigned content-integrity records.
