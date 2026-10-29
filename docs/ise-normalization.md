# Using the model in a Cisco ISE review

This project supplies a transparent authorization-review abstraction, not a native Cisco ISE import format. Its JSON fields and access tiers are project-defined. Do not rename an ISE export to `.json` or treat a successful model audit as validation of an ISE deployment.

Cisco's ISE 3.4 guide describes authorization profiles, policy sets, exceptions and network-device-specific handling of MAB. It also discusses additional restrictions for MAB endpoints such as printers. These concepts motivate reviewing the resulting access, not only the authentication-method label. [Cisco ISE 3.4 Segmentation](https://www.cisco.com/c/en/us/td/docs/security/ise/3-4/admin_guide/b_ise_admin_3_4/b_ISE_admin_segmentation.html).

Cisco's Linux posture example distinguishes unknown, noncompliant and compliant posture and uses different authorization outcomes during the process. This project retains those three labels but does not reproduce remediation, reauthorization or the temporal posture lifecycle. [Cisco ISE posture example](https://www.cisco.com/c/en/us/support/docs/security/identity-services-engine/217818-configure-cisco-ise-3-1-posture-with-lin.html).

## Prepare an explicit review model

1. Select a narrow authorization scenario that can be faithfully represented by one ordered first-match rule list. Record a sanitized evidence reference and set provenance kind to `manual-normalization`.
2. Define mutually exclusive review groups. If real identity memberships overlap, do not simply choose one: explicitly create reviewed combinations or stop when the bounded abstraction is insufficient.
3. Classify each resulting profile as deny, restricted, standard or privileged after reviewing its real effects. Record the operational review separately. A name containing “restricted” is not evidence that its ACL or enforcement actually restricts traffic.
4. Preserve rule order. Map only the supported group/method/posture predicates. Expand compatible OR conditions into selector lists; preserve AND across the three dimensions. Do not drop unsupported attributes or exceptions to make the model fit.
5. Declare the unmatched default explicitly. Include unclassified identities in review and capture intended outcomes as checks, including denied and remediation paths.
6. Add pseudonymous endpoint observations and owned, dated MAB exception records where applicable. Choose an explicit assessment date and review baseline.
7. Compare the normalized model against source evidence with a second review, then run the auditor. Resolve model findings and validate actual outcomes separately in an authorized lab or deployment process.

This checklist is a manual normalization workflow. v0.1 provides no ERS/OpenAPI/XML/CSV ingestion adapter, no credential handling and no proof that an export was translated correctly.

## Mapping and exclusions

| Review concept | Model representation | Material limitation |
| --- | --- | --- |
| Identity/endpoint classification | One group per state/observation | No identity-store lookup, overlapping memberships or dynamic profiling |
| Authentication method | `dot1x` or `mab` | No EAP-method, certificate, authentication-success or RADIUS validation |
| Posture | Three explicit labels | No posture assessment, remediation timers or state transitions |
| Authorization result | One profile ID with declared tier | No ACL/VLAN/SGT interpretation, combined profiles or enforcement proof |
| Policy conditions | Group/method/posture selectors | No arbitrary dictionaries, expressions, device/port/time conditions |
| Exception governance | Owner/reason/expiry on a declared observation | Not ISE global/local authorization exceptions; does not change rule matching |
| Policy ordering | First enabled match in one list | No policy-set selection or full ISE evaluation semantics |

If the source relies on excluded behavior, keep that behavior visible as a limitation of the assessment or use a more capable model. The tool cannot detect an omitted real-world condition that was never supplied.
