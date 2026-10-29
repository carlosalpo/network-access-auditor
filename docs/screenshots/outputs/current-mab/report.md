# Synthetic NAC authorization review

Result: **no_findings** · assessment 2026-10-29

Gate: **PASS** at medium.

Scope: offline review of an explicitly normalized NAC authorization model. No Cisco ISE connection, authentication validation, policy import, device enforcement or live connectivity test. No findings is not a security certification.

## Declared assumptions

Provenance: synthetic — Public hand\-authored example; no Cisco ISE export

Standard access requires dot1x: False; requires compliant posture: True.

Privileged access always requires a managed group, dot1x and compliant posture. Standard access requires a managed group. Unclassified internal access is flagged. Profile access tiers and group trust are reviewer declarations, not interpreted ACLs.

## Coverage

30 exhaustive modeled states; 6 rules; 6 declared observations; 5 intent checks.

The domain is each declared group plus unclassified, two methods and three postures. States need not be observed or reachable in the real environment. Rule order is preserved; only the first enabled match applies. Unmatched states use the explicit default profile.

## Findings

No findings under this model and baseline. Review omitted conditions and enforcement separately.

## Rule coverage

| Order | Rule | Enabled | Potential states | Effective states | Shadowed states |
| ---: | --- | --- | ---: | ---: | ---: |
| 1 | admins\-compliant | True | 1 | 1 | 0 |
| 2 | employees\-compliant | True | 1 | 1 | 0 |
| 3 | managed\-remediation | True | 8 | 8 | 0 |
| 4 | printer\-mab | True | 3 | 3 | 0 |
| 5 | guest\-restricted | True | 6 | 6 | 0 |
| 6 | legacy\-managed | True | 1 | 1 | 0 |

## Review boundaries

- `states.csv` gives every first-match outcome; findings include up to three witnesses.
- `rule-coverage.csv` identifies earlier winners. Disabled rules are not shadow findings.
- `endpoints.csv` contains declared observations, not live sessions. MAB exception dates are inclusive through expires_on; review is against assessment_date, not the system clock.
- A current exception does not waive baseline risks. Restricted/deny access does not require a MAB exception in this baseline.
- `checks.csv` compares exact profile IDs, even when their tiers are the same.
- ISE policy-set selection, global/local exceptions, authentication results, compound attributes, profiling, certificates, VLAN/dACL/SGT enforcement, CoA and temporal state are excluded.
- The input and outputs are not anonymized. Hashes are unsigned content checks, not authentication.

The JSON model is the source of truth. Review proposed rule changes separately; this tool never modifies a network or generates remediation commands.
