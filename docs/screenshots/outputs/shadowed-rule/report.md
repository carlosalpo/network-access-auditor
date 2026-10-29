# Synthetic NAC authorization review

Result: **review_required** · assessment 2026-10-29

Gate: **FAIL** at medium.

Scope: offline review of an explicitly normalized NAC authorization model. No Cisco ISE connection, authentication validation, policy import, device enforcement or live connectivity test. No findings is not a security certification.

## Declared assumptions

Provenance: synthetic — Public hand\-authored example; no Cisco ISE export

Standard access requires dot1x: True; requires compliant posture: True.

Privileged access always requires a managed group, dot1x and compliant posture. Standard access requires a managed group. Unclassified internal access is flagged. Profile access tiers and group trust are reviewer declarations, not interpreted ACLs.

## Coverage

30 exhaustive modeled states; 6 rules; 5 declared observations; 5 intent checks.

The domain is each declared group plus unclassified, two methods and three postures. States need not be observed or reachable in the real environment. Rule order is preserved; only the first enabled match applies. Unmatched states use the explicit default profile.

## Findings

### MEDIUM — RULE_SHADOWED

Location: `rule/unreachable-admin`

Earlier rules cover every matching state in the modeled domain\.

Review prior winners; remove or reorder only after checking intended behavior\.

```json
{
  "potential_states": 1,
  "shadowed_by": [
    "admins-compliant"
  ],
  "witnesses": [
    {
      "access": "privileged",
      "decision": "admins-compliant",
      "group": "admins",
      "method": "dot1x",
      "posture": "compliant",
      "profile": "admin",
      "trust": "managed"
    }
  ]
}
```


## Rule coverage

| Order | Rule | Enabled | Potential states | Effective states | Shadowed states |
| ---: | --- | --- | ---: | ---: | ---: |
| 1 | admins\-compliant | True | 1 | 1 | 0 |
| 2 | employees\-compliant | True | 1 | 1 | 0 |
| 3 | managed\-remediation | True | 8 | 8 | 0 |
| 4 | printer\-mab | True | 3 | 3 | 0 |
| 5 | guest\-restricted | True | 6 | 6 | 0 |
| 6 | unreachable\-admin | True | 1 | 0 | 1 |

## Review boundaries

- `states.csv` gives every first-match outcome; findings include up to three witnesses.
- `rule-coverage.csv` identifies earlier winners. Disabled rules are not shadow findings.
- `endpoints.csv` contains declared observations, not live sessions. MAB exception dates are inclusive through expires_on; review is against assessment_date, not the system clock.
- A current exception does not waive baseline risks. Restricted/deny access does not require a MAB exception in this baseline.
- `checks.csv` compares exact profile IDs, even when their tiers are the same.
- ISE policy-set selection, global/local exceptions, authentication results, compound attributes, profiling, certificates, VLAN/dACL/SGT enforcement, CoA and temporal state are excluded.
- The input and outputs are not anonymized. Hashes are unsigned content checks, not authentication.

The JSON model is the source of truth. Review proposed rule changes separately; this tool never modifies a network or generates remediation commands.
