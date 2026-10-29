"""Deterministic report projections with explicit audit limitations."""

import csv
import html
import io
import re

from . import __version__
from .engine import audit, gate_failed
from .model import canonical, digest, json_bytes


def csv_bytes(rows, headers):
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=headers, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        values = {}
        for key in headers:
            value = row[key]
            value = ";".join(value) if isinstance(value, list) else str(value)
            values[key] = "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value
        writer.writerow(values)
    return output.getvalue().encode()


def md(value):
    return re.sub(r"([\\`*{}\[\]()#+.!_|-])", r"\\\1", html.escape(str(value), quote=False))


def markdown(data, result):
    lines = [
        f"# {md(data['title'])}",
        "",
        f"Result: **{result['status']}** · assessment {data['assessment_date']}",
        "",
        f"Gate: **{'FAIL' if result['gate']['failed'] else 'PASS'}** "
        f"at {result['gate']['fail_on']}.",
        "",
        "Scope: offline review of an explicitly normalized NAC authorization model. "
        "No Cisco ISE connection, authentication validation, policy import, device enforcement "
        "or live connectivity test. No findings is not a security certification.",
        "",
        "## Declared assumptions",
        "",
        f"Provenance: {md(data['provenance']['kind'])} — {md(data['provenance']['reference'])}",
        "",
        f"Standard access requires dot1x: {data['baseline']['standard_requires_dot1x']}; "
        f"requires compliant posture: {data['baseline']['standard_requires_compliant']}.",
        "",
        "Privileged access always requires a managed group, dot1x and compliant posture. "
        "Standard access requires a managed group. Unclassified internal access is flagged. "
        "Profile access tiers and group trust are reviewer declarations, not interpreted ACLs.",
        "",
        "## Coverage",
        "",
        f"{result['counts']['states']} exhaustive modeled states; "
        f"{result['counts']['rules']} rules; "
        f"{result['counts']['endpoints']} declared observations; "
        f"{result['counts']['checks']} intent checks.",
        "",
        "The domain is each declared group plus unclassified, two methods and three postures. "
        "States need not be observed or reachable in the real environment. Rule "
        "order is preserved; "
        "only the first enabled match applies. Unmatched states use the explicit default profile.",
        "",
        "## Findings",
        "",
    ]
    if not result["findings"]:
        lines.append(
            "No findings under this model and baseline. Review omitted conditions and "
            "enforcement separately."
        )
    for finding in result["findings"]:
        lines.extend(
            [
                f"### {finding['severity'].upper()} — {finding['code']}",
                "",
                f"Location: `{finding['location']}`",
                "",
                md(finding["message"]),
                "",
                md(finding["remediation"]),
                "",
                "```json",
                json_bytes(finding["evidence"]).decode().rstrip(),
                "```",
                "",
            ]
        )
    lines += [
        "",
        "## Rule coverage",
        "",
        "| Order | Rule | Enabled | Potential states | Effective states | Shadowed states |",
        "| ---: | --- | --- | ---: | ---: | ---: |",
    ]
    for row in result["rule_coverage"]:
        lines.append(
            "| "
            + " | ".join(
                md(row[k])
                for k in (
                    "order",
                    "rule",
                    "enabled",
                    "potential_states",
                    "effective_states",
                    "shadowed_states",
                )
            )
            + " |"
        )
    lines += [
        "",
        "## Review boundaries",
        "",
        "- `states.csv` gives every first-match outcome; findings include up to three witnesses.",
        "- `rule-coverage.csv` identifies earlier winners. Disabled rules are not shadow findings.",
        "- `endpoints.csv` contains declared observations, not live sessions. MAB exception dates "
        "are inclusive through expires_on; review is against assessment_date, not "
        "the system clock.",
        "- A current exception does not waive baseline risks. Restricted/deny "
        "access does not require "
        "a MAB exception in this baseline.",
        "- `checks.csv` compares exact profile IDs, even when their tiers are the same.",
        "- ISE policy-set selection, global/local exceptions, authentication results, compound "
        "attributes, profiling, certificates, VLAN/dACL/SGT enforcement, CoA and "
        "temporal state are excluded.",
        "- The input and outputs are not anonymized. Hashes are unsigned content "
        "checks, not authentication.",
        "",
        "The JSON model is the source of truth. Review proposed rule changes separately; this "
        "tool never modifies a network or generates remediation commands.",
        "",
    ]
    return "\n".join(lines).encode()


def compile_report(data, input_hash, threshold="medium"):
    result = audit(data)
    data = canonical(data)
    result["gate"] = {"fail_on": threshold, "failed": gate_failed(result["findings"], threshold)}
    files = {
        "model.json": json_bytes(data),
        "audit.json": json_bytes(result),
        "states.csv": csv_bytes(
            result["states"],
            ["group", "trust", "method", "posture", "decision", "profile", "access"],
        ),
        "rule-coverage.csv": csv_bytes(
            result["rule_coverage"],
            [
                "order",
                "rule",
                "enabled",
                "profile",
                "potential_states",
                "effective_states",
                "shadowed_states",
                "shadowed_by",
            ],
        ),
        "endpoints.csv": csv_bytes(
            result["endpoints"],
            [
                "id",
                "group",
                "method",
                "posture",
                "decision",
                "profile",
                "access",
                "exception_status",
                "exception_owner",
                "expires_on",
            ],
        ),
        "checks.csv": csv_bytes(
            result["checks"],
            [
                "id",
                "group",
                "method",
                "posture",
                "expected_profile",
                "decision",
                "actual_profile",
                "passed",
            ],
        ),
        "findings.csv": csv_bytes(
            result["findings"], ["id", "severity", "code", "location", "message", "remediation"]
        ),
        "report.md": markdown(data, result),
    }
    files["manifest.json"] = json_bytes(
        dict(
            schema_version=1,
            tool="network-access-auditor",
            version=__version__,
            scope=result["scope"],
            status=result["status"],
            gate=result["gate"],
            counts=result["counts"],
            input_sha256=input_hash,
            canonical_model_sha256=digest(json_bytes(data)),
            files={
                name: dict(sha256=digest(raw), bytes=len(raw))
                for name, raw in sorted(files.items())
            },
        )
    )
    return files, result
