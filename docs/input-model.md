# Input contract v1

[baseline.json](../examples/baseline.json) is a complete working model. Input is strict UTF-8 JSON, at most 1,000,000 bytes. Each object requires exactly the fields below. Unknown/missing keys, duplicate JSON keys, duplicate IDs, unsupported enum values and broken references are rejected before audit output is created.

| Object | Required fields | Bounds |
| --- | --- | --- |
| Root | `schema_version`, `id`, `title`, `assessment_date`, `provenance`, `baseline`, `groups`, `profiles`, `rules`, `default_profile`, `endpoints`, `checks` | Integer version 1; title 1–160 printable characters |
| Provenance | `kind`, `reference` | Kind `synthetic` or `manual-normalization`; reference 1–160 printable characters |
| Baseline | `standard_requires_dot1x`, `standard_requires_compliant` | JSON booleans |
| Group | `id`, `label`, `trust` | 0–32 groups; trust `managed`, `unmanaged` or `guest` |
| Profile | `id`, `label`, `access` | 1–64 profiles; access `deny`, `restricted`, `standard` or `privileged` |
| Rule | `id`, `enabled`, `match`, `profile` | 0–128 ordered rules; enabled is a JSON boolean |
| Match | `groups`, `methods`, `postures` | Each is string `any` or a nonempty list of distinct supported values |
| Endpoint observation | `id`, `group`, `method`, `posture`, `mab_exception` | 0–1000 observations; exception object or null |
| MAB exception | `owner`, `reason`, `expires_on` | Owner 1–120, reason 1–240 printable characters; valid date |
| Intent check | `id`, `group`, `method`, `posture`, `expected_profile` | 0–256 checks |

All dates are calendar dates in exact `YYYY-MM-DD` format. IDs begin with a lowercase ASCII letter and contain at most 48 lowercase letters, digits or hyphens. IDs are unique within each collection. Labels and other text fields are printable single-line strings, cannot be whitespace-only, and default to a 120-character bound unless specified above.

## Identity and profile classifications

`managed` means the reviewer has classified a group as eligible for internal access; it is not discovered or verified. `unmanaged` and `guest` do not qualify for standard/privileged access under this project's baseline. These categories are a review convention, not Cisco ISE native attributes.

`unclassified` is an implicit reserved group that cannot be redefined. Include it explicitly in a selector list when needed, or match it through `any`. All group references must otherwise name a declared group. A typo never silently becomes an unclassified identity.

Profile tiers are reviewer-assigned:

- `deny`: declared refusal of authorization.
- `restricted`: declared limited guest, printer or remediation access; actual enforcement remains unverified.
- `standard`: internal access that requires a managed group and the enabled standard baseline controls.
- `privileged`: sensitive internal access, always requiring a managed group, `dot1x` and `compliant` posture.

The two baseline booleans affect only standard access. Relaxing them is explicit in both input and reports. They do not weaken privileged controls, waive trust requirements or suppress missing/expired MAB exception findings.

## Match semantics

Methods are `dot1x` and `mab`; postures are `compliant`, `noncompliant` and `unknown`. Each selector list is OR within one dimension; the three dimensions are ANDed. `any` includes every modeled value for that dimension. `unknown` posture matches only that posture. Empty lists, list item `any`, repeated values, nested expressions and native ISE dictionaries are unsupported.

For example:

```json
{
  "id": "managed-compliant",
  "enabled": true,
  "match": {
    "groups": ["employees", "admins"],
    "methods": ["dot1x"],
    "postures": ["compliant"]
  },
  "profile": "staff"
}
```

Rules are evaluated in their JSON array order; the first enabled match returns one profile. Unmatched states use `default_profile`, recorded as decision `@default`. Disabled rules are still schema/reference-validated but do not participate in decisions or shadowing. Profile IDs, including the default, must exist.

## Observations, exceptions and intent

Endpoint entries are pseudonymous declared observations. They do not contain MAC addresses and are not authentication logs. Multiple entries may represent the same group/method/posture; the tool evaluates each record without inferring a real device population.

MAB exception metadata is required by the audit baseline only when an observed `mab` endpoint receives standard or privileged access. An exception is current through its `expires_on` date, compared against the explicitly supplied `assessment_date`. Ownership/reason are declarations; the tool cannot establish who approved them. Exceptions for deny/restricted or dot1x outcomes are shown but not assessed as required. A current exception does not change rule matching or waive other findings.

Intent checks compare exact profile IDs. Two profiles with the same access tier may still differ operationally, so a different ID is a mismatch. A model with no checks or observations still receives exhaustive state analysis, but has no observation/intent evidence; counts make that absence visible.
