"""Exhaustive first-match analysis within an explicit, finite NAC abstraction."""

from collections import defaultdict
from itertools import product

from .model import METHODS, POSTURES, canonical, iso_date, validate_model

SEVERITIES = {"low": 1, "medium": 2, "high": 3, "critical": 4}
REMEDIATION = {
    "PRIVILEGED_WITHOUT_DOT1X": "Require dot1x for privileged access; review the effective rule.",
    "PRIVILEGED_UNTRUSTED_GROUP": "Limit privileged access to explicitly managed groups.",
    "PRIVILEGED_WITHOUT_COMPLIANCE": "Require compliant posture for privileged access.",
    "STANDARD_WITHOUT_DOT1X": (
        "Require dot1x or explicitly revise the declared baseline after review."
    ),
    "STANDARD_WITHOUT_COMPLIANCE": "Require compliant posture or explicitly revise the baseline.",
    "STANDARD_UNTRUSTED_GROUP": "Use a reviewed restricted profile for unmanaged/guest groups.",
    "UNCLASSIFIED_INTERNAL_ACCESS": "Keep unclassified identities out of internal access profiles.",
    "PERMISSIVE_DEFAULT": "Use deny/restricted default and explicit rules for internal access.",
    "RULE_SHADOWED": (
        "Review prior winners; remove or reorder only after checking intended behavior."
    ),
    "MAB_EXCEPTION_MISSING": (
        "Record accountable owner, reason and expiration for this MAB exception."
    ),
    "MAB_EXCEPTION_EXPIRED": "Renew after review or remove the exception and its access path.",
    "INTENT_MISMATCH": "Review the first winning rule against the expected profile.",
}


def matches(rule, state):
    return all(
        rule["match"][plural] == "any" or state[singular] in rule["match"][plural]
        for plural, singular in (
            ("groups", "group"),
            ("methods", "method"),
            ("postures", "posture"),
        )
    )


def decision(data, state):
    for rule in data["rules"]:
        if rule["enabled"] and matches(rule, state):
            return rule["id"], rule["profile"]
    return "@default", data["default_profile"]


def gate_failed(findings, threshold):
    return threshold != "none" and any(
        SEVERITIES[f["severity"]] >= SEVERITIES[threshold] for f in findings
    )


def audit(data):
    validate_model(data)
    data = canonical(data)
    trust = {g["id"]: g["trust"] for g in data["groups"]} | {"unclassified": "unclassified"}
    profiles = {p["id"]: p for p in data["profiles"]}
    states = []
    for group, method, posture in product(sorted(trust), METHODS, POSTURES):
        context = dict(group=group, method=method, posture=posture)
        winner, profile = decision(data, context)
        states.append(
            context
            | dict(
                trust=trust[group],
                decision=winner,
                profile=profile,
                access=profiles[profile]["access"],
            )
        )
    findings = []

    def finding(code, severity, location, message, evidence):
        findings.append(
            dict(
                id=code + ":" + location,
                code=code,
                severity=severity,
                location=location,
                message=message,
                remediation=REMEDIATION[code],
                evidence=evidence,
            )
        )

    coverage = []
    for order, rule in enumerate(data["rules"], 1):
        potential = [s for s in states if matches(rule, s)]
        effective = [s for s in potential if s["decision"] == rule["id"]]
        blocked = [s for s in potential if s["decision"] != rule["id"]] if rule["enabled"] else []
        row = dict(
            order=order,
            rule=rule["id"],
            enabled=rule["enabled"],
            profile=rule["profile"],
            potential_states=len(potential),
            effective_states=len(effective),
            shadowed_states=len(blocked),
            shadowed_by=sorted({s["decision"] for s in blocked}),
        )
        coverage.append(row)
        if rule["enabled"] and potential and not effective:
            finding(
                "RULE_SHADOWED",
                "medium",
                "rule/" + rule["id"],
                "Earlier rules cover every matching state in the modeled domain.",
                dict(
                    potential_states=len(potential),
                    shadowed_by=row["shadowed_by"],
                    witnesses=blocked[:3],
                ),
            )

    violations = defaultdict(list)
    for state in states:
        access = state["access"]
        if access == "privileged":
            if state["method"] != "dot1x":
                violations[("PRIVILEGED_WITHOUT_DOT1X", "critical", state["decision"])].append(
                    state
                )
            if state["trust"] != "managed":
                violations[("PRIVILEGED_UNTRUSTED_GROUP", "critical", state["decision"])].append(
                    state
                )
            if state["posture"] != "compliant":
                violations[("PRIVILEGED_WITHOUT_COMPLIANCE", "high", state["decision"])].append(
                    state
                )
        if access == "standard":
            if data["baseline"]["standard_requires_dot1x"] and state["method"] != "dot1x":
                violations[("STANDARD_WITHOUT_DOT1X", "high", state["decision"])].append(state)
            if data["baseline"]["standard_requires_compliant"] and state["posture"] != "compliant":
                violations[("STANDARD_WITHOUT_COMPLIANCE", "high", state["decision"])].append(state)
            if state["trust"] != "managed":
                violations[("STANDARD_UNTRUSTED_GROUP", "high", state["decision"])].append(state)
        if access in ("standard", "privileged"):
            if state["group"] == "unclassified":
                violations[("UNCLASSIFIED_INTERNAL_ACCESS", "critical", state["decision"])].append(
                    state
                )
            if state["decision"] == "@default":
                violations[("PERMISSIVE_DEFAULT", "high", state["decision"])].append(state)
    for (code, severity, winner), affected in sorted(violations.items()):
        finding(
            code,
            severity,
            "decision/" + winner,
            "Effective modeled access violates the declared review baseline.",
            dict(
                affected_states=len(affected),
                profile=affected[0]["profile"],
                witnesses=affected[:3],
            ),
        )

    endpoint_results = []
    assessment = iso_date(data["assessment_date"])
    for endpoint in data["endpoints"]:
        winner, profile = decision(data, endpoint)
        access = profiles[profile]["access"]
        required = endpoint["method"] == "mab" and access in ("standard", "privileged")
        exception = endpoint["mab_exception"]
        status = "not-required"
        if required:
            status = (
                "missing"
                if exception is None
                else "expired"
                if iso_date(exception["expires_on"]) < assessment
                else "current"
            )
            if status in ("missing", "expired"):
                code = "MAB_EXCEPTION_" + status.upper()
                finding(
                    code,
                    "high",
                    "endpoint/" + endpoint["id"],
                    "MAB internal access lacks a current accountable exception.",
                    dict(
                        decision=winner,
                        profile=profile,
                        assessment_date=data["assessment_date"],
                        expires_on=exception["expires_on"] if exception else None,
                    ),
                )
        endpoint_results.append(
            {k: endpoint[k] for k in ("id", "group", "method", "posture")}
            | dict(
                decision=winner,
                profile=profile,
                access=access,
                exception_status=status,
                exception_owner=exception["owner"] if exception else "",
                expires_on=exception["expires_on"] if exception else "",
            )
        )

    check_results = []
    for check in data["checks"]:
        winner, profile = decision(data, check)
        passed = profile == check["expected_profile"]
        check_results.append(check | dict(decision=winner, actual_profile=profile, passed=passed))
        if not passed:
            finding(
                "INTENT_MISMATCH",
                "high",
                "check/" + check["id"],
                "First-match result differs from the declared expected profile.",
                dict(
                    decision=winner,
                    expected_profile=check["expected_profile"],
                    actual_profile=profile,
                    context={k: check[k] for k in ("group", "method", "posture")},
                ),
            )
    findings.sort(key=lambda f: (-SEVERITIES[f["severity"]], f["id"]))
    return dict(
        schema_version=1,
        scope="offline-normalized-nac-model",
        status="review_required" if findings else "no_findings",
        assessment_date=data["assessment_date"],
        baseline=data["baseline"],
        counts=dict(
            groups=len(data["groups"]),
            profiles=len(profiles),
            rules=len(data["rules"]),
            enabled_rules=sum(r["enabled"] for r in data["rules"]),
            states=len(states),
            endpoints=len(endpoint_results),
            checks=len(check_results),
            failed_checks=sum(not c["passed"] for c in check_results),
            findings=len(findings),
        ),
        findings=findings,
        states=states,
        rule_coverage=coverage,
        endpoints=endpoint_results,
        checks=check_results,
    )
