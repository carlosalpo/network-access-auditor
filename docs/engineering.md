# Evaluation and engineering decisions

## Finite-domain analysis

The auditor constructs `(declared groups + unclassified) × {dot1x, mab} × {compliant, noncompliant, unknown}`. There are at most 198 states. For every state it records the first enabled rule that matches, or `@default`, and the profile's declared access tier. These states are possible combinations in the abstraction, not necessarily reachable combinations in a real deployment.

For each enabled rule, potential states match its condition, effective states actually select it, and shadowed states select an earlier rule. Earlier rules may jointly cover a later rule even when no single earlier rule does. A fully shadowed rule is a medium-severity finding; partial coverage is a table entry rather than an automatic defect. A disabled rule has potential coverage for review but zero effective/shadowed states and no shadow finding.

Risk findings are grouped by code and winning decision, with an exact affected-state count and at most three deterministic witnesses. `states.csv` and `audit.json` retain the complete domain, so the witness limit does not discard coverage. Findings may overlap; their counts must not be summed into a unique endpoint or state total.

## Baseline rules

These severities and controls are project-defined review judgments, not vendor certification or universal NAC requirements.

| Code | Severity | Effective condition |
| --- | --- | --- |
| `PRIVILEGED_WITHOUT_DOT1X` | Critical | Privileged access with MAB |
| `PRIVILEGED_UNTRUSTED_GROUP` | Critical | Privileged access outside a managed group |
| `PRIVILEGED_WITHOUT_COMPLIANCE` | High | Privileged access with unknown/noncompliant posture |
| `STANDARD_WITHOUT_DOT1X` | High | Standard MAB access while that baseline control is enabled |
| `STANDARD_WITHOUT_COMPLIANCE` | High | Standard unknown/noncompliant access while that control is enabled |
| `STANDARD_UNTRUSTED_GROUP` | High | Standard access outside a managed group |
| `UNCLASSIFIED_INTERNAL_ACCESS` | Critical | Unclassified group receives standard/privileged access |
| `PERMISSIVE_DEFAULT` | High | At least one unmatched state receives standard/privileged access |
| `RULE_SHADOWED` | Medium | An enabled rule has matching states but none can select it |
| `MAB_EXCEPTION_MISSING` | High | Declared MAB observation receives internal access without an exception |
| `MAB_EXCEPTION_EXPIRED` | High | Required observation exception expired before the assessment date |
| `INTENT_MISMATCH` | High | Actual winning profile ID differs from the declared expected ID |

A default profile that never applies is not an effective permissive-default finding. A fully shadowed privileged rule is not counted as reachable privileged exposure. Restricted profiles are assumed correctly classified; their contents/enforcement are outside the tool. The baseline intentionally does not validate exception ownership for all guest/printer/remediation uses of MAB.

## Status and exit codes

The report status is `review_required` when any finding exists and `no_findings` otherwise. Separately, `gate.failed` compares finding severity with `--fail-on low|medium|high|critical|none`; default is medium. Low is accepted as a threshold even though v0.1 currently emits only medium/high/critical findings. `none` disables only exit-code gating, not analysis.

The `audit` exit code is 0 for a passed gate, 1 for a failed gate, 2 for invalid input/usage or file errors. `validate` returning 0 means input contract validity only. It does not run risk checks. Automation should not label either a valid input or a passed configured gate as a secure network.

## Determinism and artifact integrity

Groups, profiles, observations and checks are sorted by ID; selector lists are sorted. Rule order is preserved because it changes policy meaning. There are no generated timestamps, automatic current-date reads, absolute input paths or network lookups in report generation. The exact input bytes and canonical input have separate SHA-256 hashes.

CSV projections use a leading apostrophe for values whose first non-whitespace character is `=`, `+`, `-` or `@`. Thus decision `@default` appears as `'@default` in CSV for spreadsheet safety. JSON retains exact values and is the recommended machine-readable source. Markdown escapes user text; JSON witnesses contain only validated IDs/enums/dates and generated strings.

The manifest hashes all other output files, not itself. It is unsigned. Matching hashes establish consistency against that manifest; they do not authenticate origin or prevent replacement of both files and hashes.

## Filesystem behavior

The output parent must exist and the requested directory must be new. Directory/file creation is exclusive. On POSIX, requested permissions are 0700 for the directory and 0600 for files, subject to stricter umask settings. The manifest is written last, but writes are not an atomic transaction. A full disk or permission error may leave partial output. Require a complete parseable manifest, expected files, sizes and hashes before consuming a package; retry into a fresh directory.

The runtime assumes a trusted local filesystem. It does not defend against concurrent hostile replacement of output paths. No model content chooses output filenames or executes commands.

## Verification approach

Tests exercise coverage and winners, union shadowing, disabled and partially covered rules, witness consistency, non-waivable privileged requirements, date boundaries, thresholds, deterministic ordering, input rejection and filesystem behavior. The installed-CLI scenario runner verifies both successful review execution and expected failure exits. A scenario marked PASS can intentionally contain security findings or invalid input; PASS means its expected behavior was observed.

No live Cisco ISE, RADIUS authenticator or network-device validation was performed for this release. Separate comparison against actual authorization logs, policy-set/exceptions configuration and endpoint enforcement is necessary before applying a real-world conclusion.
