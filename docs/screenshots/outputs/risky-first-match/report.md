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

### CRITICAL — UNCLASSIFIED_INTERNAL_ACCESS

Location: `decision/broad-first`

Effective modeled access violates the declared review baseline\.

Keep unclassified identities out of internal access profiles\.

```json
{
  "affected_states": 6,
  "profile": "staff",
  "witnesses": [
    {
      "access": "standard",
      "decision": "broad-first",
      "group": "unclassified",
      "method": "dot1x",
      "posture": "compliant",
      "profile": "staff",
      "trust": "unclassified"
    },
    {
      "access": "standard",
      "decision": "broad-first",
      "group": "unclassified",
      "method": "dot1x",
      "posture": "noncompliant",
      "profile": "staff",
      "trust": "unclassified"
    },
    {
      "access": "standard",
      "decision": "broad-first",
      "group": "unclassified",
      "method": "dot1x",
      "posture": "unknown",
      "profile": "staff",
      "trust": "unclassified"
    }
  ]
}
```

### HIGH — INTENT_MISMATCH

Location: `check/admin-mab-denied`

First\-match result differs from the declared expected profile\.

Review the first winning rule against the expected profile\.

```json
{
  "actual_profile": "staff",
  "context": {
    "group": "admins",
    "method": "mab",
    "posture": "compliant"
  },
  "decision": "broad-first",
  "expected_profile": "deny"
}
```

### HIGH — INTENT_MISMATCH

Location: `check/noncompliant-restricted`

First\-match result differs from the declared expected profile\.

Review the first winning rule against the expected profile\.

```json
{
  "actual_profile": "staff",
  "context": {
    "group": "employees",
    "method": "dot1x",
    "posture": "noncompliant"
  },
  "decision": "broad-first",
  "expected_profile": "quarantine"
}
```

### HIGH — INTENT_MISMATCH

Location: `check/printer-restricted`

First\-match result differs from the declared expected profile\.

Review the first winning rule against the expected profile\.

```json
{
  "actual_profile": "staff",
  "context": {
    "group": "printers",
    "method": "mab",
    "posture": "unknown"
  },
  "decision": "broad-first",
  "expected_profile": "print-only"
}
```

### HIGH — INTENT_MISMATCH

Location: `check/unknown-denied`

First\-match result differs from the declared expected profile\.

Review the first winning rule against the expected profile\.

```json
{
  "actual_profile": "staff",
  "context": {
    "group": "unclassified",
    "method": "dot1x",
    "posture": "compliant"
  },
  "decision": "broad-first",
  "expected_profile": "deny"
}
```

### HIGH — MAB_EXCEPTION_MISSING

Location: `endpoint/sample-2`

MAB internal access lacks a current accountable exception\.

Record accountable owner, reason and expiration for this MAB exception\.

```json
{
  "assessment_date": "2026-10-29",
  "decision": "broad-first",
  "expires_on": null,
  "profile": "staff"
}
```

### HIGH — MAB_EXCEPTION_MISSING

Location: `endpoint/sample-5`

MAB internal access lacks a current accountable exception\.

Record accountable owner, reason and expiration for this MAB exception\.

```json
{
  "assessment_date": "2026-10-29",
  "decision": "broad-first",
  "expires_on": null,
  "profile": "staff"
}
```

### HIGH — STANDARD_UNTRUSTED_GROUP

Location: `decision/broad-first`

Effective modeled access violates the declared review baseline\.

Use a reviewed restricted profile for unmanaged/guest groups\.

```json
{
  "affected_states": 18,
  "profile": "staff",
  "witnesses": [
    {
      "access": "standard",
      "decision": "broad-first",
      "group": "guests",
      "method": "dot1x",
      "posture": "compliant",
      "profile": "staff",
      "trust": "guest"
    },
    {
      "access": "standard",
      "decision": "broad-first",
      "group": "guests",
      "method": "dot1x",
      "posture": "noncompliant",
      "profile": "staff",
      "trust": "guest"
    },
    {
      "access": "standard",
      "decision": "broad-first",
      "group": "guests",
      "method": "dot1x",
      "posture": "unknown",
      "profile": "staff",
      "trust": "guest"
    }
  ]
}
```

### HIGH — STANDARD_WITHOUT_COMPLIANCE

Location: `decision/broad-first`

Effective modeled access violates the declared review baseline\.

Require compliant posture or explicitly revise the baseline\.

```json
{
  "affected_states": 20,
  "profile": "staff",
  "witnesses": [
    {
      "access": "standard",
      "decision": "broad-first",
      "group": "admins",
      "method": "dot1x",
      "posture": "noncompliant",
      "profile": "staff",
      "trust": "managed"
    },
    {
      "access": "standard",
      "decision": "broad-first",
      "group": "admins",
      "method": "dot1x",
      "posture": "unknown",
      "profile": "staff",
      "trust": "managed"
    },
    {
      "access": "standard",
      "decision": "broad-first",
      "group": "admins",
      "method": "mab",
      "posture": "noncompliant",
      "profile": "staff",
      "trust": "managed"
    }
  ]
}
```

### HIGH — STANDARD_WITHOUT_DOT1X

Location: `decision/broad-first`

Effective modeled access violates the declared review baseline\.

Require dot1x or explicitly revise the declared baseline after review\.

```json
{
  "affected_states": 15,
  "profile": "staff",
  "witnesses": [
    {
      "access": "standard",
      "decision": "broad-first",
      "group": "admins",
      "method": "mab",
      "posture": "compliant",
      "profile": "staff",
      "trust": "managed"
    },
    {
      "access": "standard",
      "decision": "broad-first",
      "group": "admins",
      "method": "mab",
      "posture": "noncompliant",
      "profile": "staff",
      "trust": "managed"
    },
    {
      "access": "standard",
      "decision": "broad-first",
      "group": "admins",
      "method": "mab",
      "posture": "unknown",
      "profile": "staff",
      "trust": "managed"
    }
  ]
}
```

### MEDIUM — RULE_SHADOWED

Location: `rule/admins-compliant`

Earlier rules cover every matching state in the modeled domain\.

Review prior winners; remove or reorder only after checking intended behavior\.

```json
{
  "potential_states": 1,
  "shadowed_by": [
    "broad-first"
  ],
  "witnesses": [
    {
      "access": "standard",
      "decision": "broad-first",
      "group": "admins",
      "method": "dot1x",
      "posture": "compliant",
      "profile": "staff",
      "trust": "managed"
    }
  ]
}
```

### MEDIUM — RULE_SHADOWED

Location: `rule/employees-compliant`

Earlier rules cover every matching state in the modeled domain\.

Review prior winners; remove or reorder only after checking intended behavior\.

```json
{
  "potential_states": 1,
  "shadowed_by": [
    "broad-first"
  ],
  "witnesses": [
    {
      "access": "standard",
      "decision": "broad-first",
      "group": "employees",
      "method": "dot1x",
      "posture": "compliant",
      "profile": "staff",
      "trust": "managed"
    }
  ]
}
```

### MEDIUM — RULE_SHADOWED

Location: `rule/guest-restricted`

Earlier rules cover every matching state in the modeled domain\.

Review prior winners; remove or reorder only after checking intended behavior\.

```json
{
  "potential_states": 6,
  "shadowed_by": [
    "broad-first"
  ],
  "witnesses": [
    {
      "access": "standard",
      "decision": "broad-first",
      "group": "guests",
      "method": "dot1x",
      "posture": "compliant",
      "profile": "staff",
      "trust": "guest"
    },
    {
      "access": "standard",
      "decision": "broad-first",
      "group": "guests",
      "method": "dot1x",
      "posture": "noncompliant",
      "profile": "staff",
      "trust": "guest"
    },
    {
      "access": "standard",
      "decision": "broad-first",
      "group": "guests",
      "method": "dot1x",
      "posture": "unknown",
      "profile": "staff",
      "trust": "guest"
    }
  ]
}
```

### MEDIUM — RULE_SHADOWED

Location: `rule/managed-remediation`

Earlier rules cover every matching state in the modeled domain\.

Review prior winners; remove or reorder only after checking intended behavior\.

```json
{
  "potential_states": 8,
  "shadowed_by": [
    "broad-first"
  ],
  "witnesses": [
    {
      "access": "standard",
      "decision": "broad-first",
      "group": "admins",
      "method": "dot1x",
      "posture": "noncompliant",
      "profile": "staff",
      "trust": "managed"
    },
    {
      "access": "standard",
      "decision": "broad-first",
      "group": "admins",
      "method": "dot1x",
      "posture": "unknown",
      "profile": "staff",
      "trust": "managed"
    },
    {
      "access": "standard",
      "decision": "broad-first",
      "group": "admins",
      "method": "mab",
      "posture": "noncompliant",
      "profile": "staff",
      "trust": "managed"
    }
  ]
}
```

### MEDIUM — RULE_SHADOWED

Location: `rule/printer-mab`

Earlier rules cover every matching state in the modeled domain\.

Review prior winners; remove or reorder only after checking intended behavior\.

```json
{
  "potential_states": 3,
  "shadowed_by": [
    "broad-first"
  ],
  "witnesses": [
    {
      "access": "standard",
      "decision": "broad-first",
      "group": "printers",
      "method": "mab",
      "posture": "compliant",
      "profile": "staff",
      "trust": "unmanaged"
    },
    {
      "access": "standard",
      "decision": "broad-first",
      "group": "printers",
      "method": "mab",
      "posture": "noncompliant",
      "profile": "staff",
      "trust": "unmanaged"
    },
    {
      "access": "standard",
      "decision": "broad-first",
      "group": "printers",
      "method": "mab",
      "posture": "unknown",
      "profile": "staff",
      "trust": "unmanaged"
    }
  ]
}
```


## Rule coverage

| Order | Rule | Enabled | Potential states | Effective states | Shadowed states |
| ---: | --- | --- | ---: | ---: | ---: |
| 1 | broad\-first | True | 30 | 30 | 0 |
| 2 | admins\-compliant | True | 1 | 0 | 1 |
| 3 | employees\-compliant | True | 1 | 0 | 1 |
| 4 | managed\-remediation | True | 8 | 0 | 8 |
| 5 | printer\-mab | True | 3 | 0 | 3 |
| 6 | guest\-restricted | True | 6 | 0 | 6 |

## Review boundaries

- `states.csv` gives every first-match outcome; findings include up to three witnesses.
- `rule-coverage.csv` identifies earlier winners. Disabled rules are not shadow findings.
- `endpoints.csv` contains declared observations, not live sessions. MAB exception dates are inclusive through expires_on; review is against assessment_date, not the system clock.
- A current exception does not waive baseline risks. Restricted/deny access does not require a MAB exception in this baseline.
- `checks.csv` compares exact profile IDs, even when their tiers are the same.
- ISE policy-set selection, global/local exceptions, authentication results, compound attributes, profiling, certificates, VLAN/dACL/SGT enforcement, CoA and temporal state are excluded.
- The input and outputs are not anonymized. Hashes are unsigned content checks, not authentication.

The JSON model is the source of truth. Review proposed rule changes separately; this tool never modifies a network or generates remediation commands.
