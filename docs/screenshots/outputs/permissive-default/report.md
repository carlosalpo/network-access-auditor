# Synthetic NAC authorization review

Result: **review_required** · assessment 2026-10-29

Gate: **FAIL** at medium.

Scope: offline review of an explicitly normalized NAC authorization model. No Cisco ISE connection, authentication validation, policy import, device enforcement or live connectivity test. No findings is not a security certification.

## Declared assumptions

Provenance: synthetic — Public hand\-authored example; no Cisco ISE export

Standard access requires dot1x: True; requires compliant posture: True.

Privileged access always requires a managed group, dot1x and compliant posture. Standard access requires a managed group. Unclassified internal access is flagged. Profile access tiers and group trust are reviewer declarations, not interpreted ACLs.

## Coverage

30 exhaustive modeled states; 5 rules; 5 declared observations; 5 intent checks.

The domain is each declared group plus unclassified, two methods and three postures. States need not be observed or reachable in the real environment. Rule order is preserved; only the first enabled match applies. Unmatched states use the explicit default profile.

## Findings

### CRITICAL — UNCLASSIFIED_INTERNAL_ACCESS

Location: `decision/@default`

Effective modeled access violates the declared review baseline\.

Keep unclassified identities out of internal access profiles\.

```json
{
  "affected_states": 6,
  "profile": "staff",
  "witnesses": [
    {
      "access": "standard",
      "decision": "@default",
      "group": "unclassified",
      "method": "dot1x",
      "posture": "compliant",
      "profile": "staff",
      "trust": "unclassified"
    },
    {
      "access": "standard",
      "decision": "@default",
      "group": "unclassified",
      "method": "dot1x",
      "posture": "noncompliant",
      "profile": "staff",
      "trust": "unclassified"
    },
    {
      "access": "standard",
      "decision": "@default",
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
  "decision": "@default",
  "expected_profile": "deny"
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
  "decision": "@default",
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
  "decision": "@default",
  "expires_on": null,
  "profile": "staff"
}
```

### HIGH — PERMISSIVE_DEFAULT

Location: `decision/@default`

Effective modeled access violates the declared review baseline\.

Use deny/restricted default and explicit rules for internal access\.

```json
{
  "affected_states": 11,
  "profile": "staff",
  "witnesses": [
    {
      "access": "standard",
      "decision": "@default",
      "group": "admins",
      "method": "mab",
      "posture": "compliant",
      "profile": "staff",
      "trust": "managed"
    },
    {
      "access": "standard",
      "decision": "@default",
      "group": "employees",
      "method": "mab",
      "posture": "compliant",
      "profile": "staff",
      "trust": "managed"
    },
    {
      "access": "standard",
      "decision": "@default",
      "group": "printers",
      "method": "dot1x",
      "posture": "compliant",
      "profile": "staff",
      "trust": "unmanaged"
    }
  ]
}
```

### HIGH — STANDARD_UNTRUSTED_GROUP

Location: `decision/@default`

Effective modeled access violates the declared review baseline\.

Use a reviewed restricted profile for unmanaged/guest groups\.

```json
{
  "affected_states": 9,
  "profile": "staff",
  "witnesses": [
    {
      "access": "standard",
      "decision": "@default",
      "group": "printers",
      "method": "dot1x",
      "posture": "compliant",
      "profile": "staff",
      "trust": "unmanaged"
    },
    {
      "access": "standard",
      "decision": "@default",
      "group": "printers",
      "method": "dot1x",
      "posture": "noncompliant",
      "profile": "staff",
      "trust": "unmanaged"
    },
    {
      "access": "standard",
      "decision": "@default",
      "group": "printers",
      "method": "dot1x",
      "posture": "unknown",
      "profile": "staff",
      "trust": "unmanaged"
    }
  ]
}
```

### HIGH — STANDARD_WITHOUT_COMPLIANCE

Location: `decision/@default`

Effective modeled access violates the declared review baseline\.

Require compliant posture or explicitly revise the baseline\.

```json
{
  "affected_states": 6,
  "profile": "staff",
  "witnesses": [
    {
      "access": "standard",
      "decision": "@default",
      "group": "printers",
      "method": "dot1x",
      "posture": "noncompliant",
      "profile": "staff",
      "trust": "unmanaged"
    },
    {
      "access": "standard",
      "decision": "@default",
      "group": "printers",
      "method": "dot1x",
      "posture": "unknown",
      "profile": "staff",
      "trust": "unmanaged"
    },
    {
      "access": "standard",
      "decision": "@default",
      "group": "unclassified",
      "method": "dot1x",
      "posture": "noncompliant",
      "profile": "staff",
      "trust": "unclassified"
    }
  ]
}
```

### HIGH — STANDARD_WITHOUT_DOT1X

Location: `decision/@default`

Effective modeled access violates the declared review baseline\.

Require dot1x or explicitly revise the declared baseline after review\.

```json
{
  "affected_states": 5,
  "profile": "staff",
  "witnesses": [
    {
      "access": "standard",
      "decision": "@default",
      "group": "admins",
      "method": "mab",
      "posture": "compliant",
      "profile": "staff",
      "trust": "managed"
    },
    {
      "access": "standard",
      "decision": "@default",
      "group": "employees",
      "method": "mab",
      "posture": "compliant",
      "profile": "staff",
      "trust": "managed"
    },
    {
      "access": "standard",
      "decision": "@default",
      "group": "unclassified",
      "method": "mab",
      "posture": "compliant",
      "profile": "staff",
      "trust": "unclassified"
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

## Review boundaries

- `states.csv` gives every first-match outcome; findings include up to three witnesses.
- `rule-coverage.csv` identifies earlier winners. Disabled rules are not shadow findings.
- `endpoints.csv` contains declared observations, not live sessions. MAB exception dates are inclusive through expires_on; review is against assessment_date, not the system clock.
- A current exception does not waive baseline risks. Restricted/deny access does not require a MAB exception in this baseline.
- `checks.csv` compares exact profile IDs, even when their tiers are the same.
- ISE policy-set selection, global/local exceptions, authentication results, compound attributes, profiling, certificates, VLAN/dACL/SGT enforcement, CoA and temporal state are excluded.
- The input and outputs are not anonymized. Hashes are unsigned content checks, not authentication.

The JSON model is the source of truth. Review proposed rule changes separately; this tool never modifies a network or generates remediation commands.
