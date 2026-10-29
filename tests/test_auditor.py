import copy
import csv
import io
import json
import os
import socket
from pathlib import Path

import pytest

from accessaudit.cli import main
from accessaudit.engine import audit, gate_failed
from accessaudit.model import (
    MAX_BYTES,
    InputError,
    canonical,
    digest,
    load,
    validate_model,
)
from accessaudit.report import compile_report

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def model():
    return json.loads((ROOT / "examples/baseline.json").read_text())


def example(name):
    return json.loads((ROOT / f"examples/{name}.json").read_text())


def codes(result):
    return {f["code"] for f in result["findings"]}


def any_rule(identifier, profile, enabled=True):
    return dict(
        id=identifier,
        enabled=enabled,
        match=dict(groups="any", methods="any", postures="any"),
        profile=profile,
    )


@pytest.mark.parametrize(
    "name,count,code",
    [
        ("baseline", 0, None),
        ("current-mab", 0, None),
        ("expired-mab", 1, "MAB_EXCEPTION_EXPIRED"),
        ("intent-mismatch", 1, "INTENT_MISMATCH"),
        ("shadowed-rule", 1, "RULE_SHADOWED"),
        ("risky-first-match", 15, "UNCLASSIFIED_INTERNAL_ACCESS"),
        ("permissive-default", 8, "PERMISSIVE_DEFAULT"),
    ],
)
def test_examples(name, count, code):
    result = audit(example(name))
    assert result["counts"]["findings"] == count
    assert result["counts"]["states"] == 30
    if code:
        assert code in codes(result)
    assert result["status"] == ("review_required" if count else "no_findings")


def test_reference_outcomes_and_exhaustive_coverage(model):
    result = audit(model)
    rows = {(s["group"], s["method"], s["posture"]): s for s in result["states"]}
    assert len(rows) == 30
    assert rows["admins", "dot1x", "compliant"]["profile"] == "admin"
    assert rows["admins", "mab", "compliant"]["profile"] == "deny"
    assert rows["employees", "dot1x", "unknown"]["profile"] == "quarantine"
    assert rows["printers", "mab", "unknown"]["profile"] == "print-only"
    assert rows["printers", "dot1x", "compliant"]["profile"] == "deny"
    assert all(s["profile"] == "deny" for s in result["states"] if s["group"] == "unclassified")
    assert (
        sum(r["effective_states"] for r in result["rule_coverage"])
        + sum(s["decision"] == "@default" for s in result["states"])
        == 30
    )
    assert all(c["passed"] for c in result["checks"])


def test_risk_uses_effective_access_not_unreachable_allow(model):
    model["rules"] = [any_rule("deny-first", "deny"), any_rule("unreachable-privileged", "admin")]
    model["checks"] = []
    result = audit(model)
    assert codes(result) == {"RULE_SHADOWED"}
    assert all(s["access"] == "deny" for s in result["states"])
    finding = result["findings"][0]
    assert finding["evidence"]["shadowed_by"] == ["deny-first"]
    assert finding["evidence"]["potential_states"] == 30


def test_union_of_prior_rules_can_shadow(model):
    first = any_rule("dot1x-deny", "deny")
    first["match"]["methods"] = ["dot1x"]
    second = any_rule("mab-deny", "deny")
    second["match"]["methods"] = ["mab"]
    model["rules"] = [first, second, any_rule("later", "admin")]
    model["checks"] = []
    result = audit(model)
    assert codes(result) == {"RULE_SHADOWED"}
    assert result["findings"][0]["evidence"]["shadowed_by"] == ["dot1x-deny", "mab-deny"]
    assert [r["effective_states"] for r in result["rule_coverage"]] == [15, 15, 0]


def test_partial_shadow_preserves_uncovered_states(model):
    first = any_rule("dot1x-deny", "deny")
    first["match"]["methods"] = ["dot1x"]
    model["rules"] = [first, any_rule("remaining", "quarantine")]
    model["checks"] = []
    result = audit(model)
    assert not result["findings"]
    assert result["rule_coverage"][1]["shadowed_states"] == 15
    assert result["rule_coverage"][1]["effective_states"] == 15
    assert result["rule_coverage"][1]["shadowed_by"] == ["dot1x-deny"]


def test_disabled_rules_neither_win_nor_block(model):
    model["rules"].insert(0, any_rule("disabled-risk", "admin", False))
    result = audit(model)
    assert not result["findings"]
    assert result["rule_coverage"][0]["potential_states"] == 30
    assert result["rule_coverage"][0]["effective_states"] == 0
    assert result["rule_coverage"][0]["shadowed_states"] == 0


@pytest.mark.parametrize(
    "dot1x,compliant", [(True, True), (True, False), (False, True), (False, False)]
)
def test_privileged_baseline_cannot_be_relaxed(model, dot1x, compliant):
    model["baseline"] = dict(standard_requires_dot1x=dot1x, standard_requires_compliant=compliant)
    model["rules"] = [any_rule("privileged-all", "admin")]
    model["checks"] = []
    result = audit(model)
    assert {
        "PRIVILEGED_WITHOUT_DOT1X",
        "PRIVILEGED_UNTRUSTED_GROUP",
        "PRIVILEGED_WITHOUT_COMPLIANCE",
        "UNCLASSIFIED_INTERNAL_ACCESS",
    } <= codes(result)
    bycode = {f["code"]: f for f in result["findings"]}
    assert bycode["PRIVILEGED_WITHOUT_DOT1X"]["evidence"]["affected_states"] == 15
    assert bycode["PRIVILEGED_UNTRUSTED_GROUP"]["evidence"]["affected_states"] == 18
    assert bycode["PRIVILEGED_WITHOUT_COMPLIANCE"]["evidence"]["affected_states"] == 20
    assert all(len(f["evidence"].get("witnesses", [])) <= 3 for f in result["findings"])


def test_standard_switches_are_reported_and_do_not_relax_trust(model):
    model["baseline"] = dict(standard_requires_dot1x=False, standard_requires_compliant=False)
    model["rules"] = [any_rule("standard-all", "staff")]
    model["checks"] = []
    result = audit(model)
    assert "STANDARD_WITHOUT_DOT1X" not in codes(result)
    assert "STANDARD_WITHOUT_COMPLIANCE" not in codes(result)
    assert {"STANDARD_UNTRUSTED_GROUP", "UNCLASSIFIED_INTERNAL_ACCESS"} <= codes(result)
    assert result["baseline"] == model["baseline"]


def test_each_risk_witness_matches_recorded_winner(model):
    model["rules"] = [any_rule("privileged-all", "admin")]
    result = audit(model)
    states = {(s["group"], s["method"], s["posture"]): s for s in result["states"]}
    for finding in result["findings"]:
        for witness in finding["evidence"].get("witnesses", []):
            assert witness == states[witness["group"], witness["method"], witness["posture"]]


@pytest.mark.parametrize(
    "expires,status,code",
    [
        ("2026-10-28", "expired", "MAB_EXCEPTION_EXPIRED"),
        ("2026-10-29", "current", None),
        ("2026-10-30", "current", None),
    ],
)
def test_exception_date_is_inclusive(expires, status, code):
    model = example("current-mab")
    model["endpoints"][-1]["mab_exception"]["expires_on"] = expires
    result = audit(model)
    endpoint = next(e for e in result["endpoints"] if e["id"] == "legacy-device")
    assert endpoint["exception_status"] == status
    assert codes(result) == ({code} if code else set())


def test_exception_does_not_waive_policy_risk():
    model = example("current-mab")
    model["baseline"]["standard_requires_dot1x"] = True
    result = audit(model)
    assert "STANDARD_WITHOUT_DOT1X" in codes(result)
    assert "MAB_EXCEPTION_EXPIRED" not in codes(result)


def test_missing_exception_and_non_required_records():
    model = example("current-mab")
    model["endpoints"][-1]["mab_exception"] = None
    assert codes(audit(model)) == {"MAB_EXCEPTION_MISSING"}
    model["rules"][-1]["profile"] = "quarantine"
    assert not audit(model)["findings"]
    model["endpoints"][-1]["mab_exception"] = dict(
        owner="team", reason="old", expires_on="2000-01-01"
    )
    assert not audit(model)["findings"]


def test_expected_profile_identity_not_just_tier(model):
    model["checks"] = [
        dict(
            id="distinct-profile",
            group="guests",
            method="mab",
            posture="unknown",
            expected_profile="print-only",
        )
    ]
    result = audit(model)
    assert codes(result) == {"INTENT_MISMATCH"}
    assert result["checks"][0]["actual_profile"] == "guest-only"


def test_empty_groups_rules_and_observations(model):
    model.update(groups=[], rules=[], endpoints=[], checks=[])
    result = audit(model)
    assert result["counts"]["states"] == 6 and not result["findings"]
    assert all(s["decision"] == "@default" for s in result["states"])


def test_maximum_group_domain(model):
    model.update(
        groups=[dict(id=f"g{i}", label="Synthetic", trust="managed") for i in range(32)],
        rules=[],
        checks=[],
        endpoints=[],
    )
    assert audit(model)["counts"]["states"] == 198


@pytest.mark.parametrize(
    "threshold,failed",
    [("low", True), ("medium", True), ("high", False), ("critical", False), ("none", False)],
)
def test_severity_gate_is_distinct_from_report_status(threshold, failed):
    files, result = compile_report(example("shadowed-rule"), "source", threshold)
    assert result["status"] == "review_required"
    assert result["gate"] == {"fail_on": threshold, "failed": failed}
    assert gate_failed(result["findings"], threshold) == failed
    assert json.loads(files["manifest.json"])["gate"] == result["gate"]


@pytest.mark.parametrize("value", [True, False, 1.0, "1", None, 2])
def test_schema_strict(model, value):
    model["schema_version"] = value
    with pytest.raises(InputError):
        validate_model(model)


@pytest.mark.parametrize(
    "value", ["20261029", "2026-1-1", "2026-02-30", "2026-10-29T00:00:00", "invalid", None, True]
)
def test_date_contract(model, value):
    model["assessment_date"] = value
    with pytest.raises(InputError):
        validate_model(model)


@pytest.mark.parametrize("value", ["", " ", "line\nbreak", "\x1b[31m", "x" * 161, True, None])
def test_printable_title(model, value):
    model["title"] = value
    with pytest.raises(InputError):
        validate_model(model)


@pytest.mark.parametrize(
    "value", [[], ["any"], ["missing"], ["admins", "admins"], {}, True, None, [{}]]
)
def test_bad_selectors(model, value):
    model["rules"][0]["match"]["groups"] = value
    with pytest.raises(InputError):
        validate_model(model)


@pytest.mark.parametrize("value", [1, "true", None, [], {}])
def test_boolean_fields_are_strict(model, value):
    model["baseline"]["standard_requires_dot1x"] = value
    with pytest.raises(InputError):
        validate_model(model)
    model["baseline"]["standard_requires_dot1x"] = True
    model["rules"][0]["enabled"] = value
    with pytest.raises(InputError):
        validate_model(model)


@pytest.mark.parametrize(
    "collection,maximum",
    [("groups", 32), ("profiles", 64), ("rules", 128), ("endpoints", 1000), ("checks", 256)],
)
def test_collection_limits(model, collection, maximum):
    model[collection] = [model[collection][0]] * (maximum + 1)
    with pytest.raises(InputError):
        validate_model(model)


@pytest.mark.parametrize("collection", ["groups", "profiles", "rules", "endpoints", "checks"])
def test_duplicate_ids(model, collection):
    model[collection].append(copy.deepcopy(model[collection][0]))
    with pytest.raises(InputError):
        validate_model(model)


@pytest.mark.parametrize(
    "where",
    ["top", "group", "profile", "rule", "match", "endpoint", "check", "baseline", "provenance"],
)
def test_unknown_fields_rejected(model, where):
    obj = {
        "top": model,
        "group": model["groups"][0],
        "profile": model["profiles"][0],
        "rule": model["rules"][0],
        "match": model["rules"][0]["match"],
        "endpoint": model["endpoints"][0],
        "check": model["checks"][0],
        "baseline": model["baseline"],
        "provenance": model["provenance"],
    }[where]
    obj["unknown"] = 1
    with pytest.raises(InputError):
        validate_model(model)


@pytest.mark.parametrize(
    "where",
    ["default", "rule-profile", "rule-group", "endpoint-group", "check-group", "check-profile"],
)
def test_broken_references_fail_closed(model, where):
    if where == "default":
        model["default_profile"] = "absent"
    if where == "rule-profile":
        model["rules"][0]["profile"] = "absent"
    if where == "rule-group":
        model["rules"][0]["match"]["groups"] = ["absent"]
    if where == "endpoint-group":
        model["endpoints"][0]["group"] = "absent"
    if where == "check-group":
        model["checks"][0]["group"] = "absent"
    if where == "check-profile":
        model["checks"][0]["expected_profile"] = "absent"
    with pytest.raises(InputError):
        validate_model(model)


def test_reserved_group_and_default_rule_id(model):
    model["groups"][0]["id"] = "unclassified"
    with pytest.raises(InputError):
        validate_model(model)
    model = example("baseline")
    model["rules"][0]["id"] = "@default"
    with pytest.raises(InputError):
        validate_model(model)


@pytest.mark.parametrize("value", ["radius", "any", "DOT1X", 1, None])
def test_unknown_method_rejected(model, value):
    model["endpoints"][0]["method"] = value
    with pytest.raises(InputError):
        validate_model(model)


@pytest.mark.parametrize("value", ["unknown-state", "any", 1, None])
def test_unknown_posture_rejected(model, value):
    model["endpoints"][0]["posture"] = value
    with pytest.raises(InputError):
        validate_model(model)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"a":2}',
        b"NaN",
        b"{",
        b"\xff",
        b"\xef\xbb\xbf{}",
        b" " * (MAX_BYTES + 1),
        b"[" * 2000 + b"]" * 2000,
    ],
)
def test_loader_rejects_ambiguous_or_unbounded_input(tmp_path, raw):
    p = tmp_path / "input.json"
    p.write_bytes(raw)
    with pytest.raises(InputError):
        load(p)


def test_source_hash_and_canonical_stability(model, tmp_path):
    raw = json.dumps(model).encode()
    p = tmp_path / "input.json"
    p.write_bytes(raw)
    loaded, source_hash = load(p)
    assert source_hash == digest(raw) and loaded == canonical(model)
    changed = copy.deepcopy(model)
    for key in ("groups", "profiles", "endpoints", "checks"):
        changed[key].reverse()
    for rule in changed["rules"]:
        for value in rule["match"].values():
            if isinstance(value, list):
                value.reverse()
    assert compile_report(model, "same") == compile_report(changed, "same")
    changed["rules"].insert(0, any_rule("broad-first", "staff"))
    forward = canonical(changed)
    changed["rules"].reverse()
    assert forward["rules"] != canonical(changed)["rules"]
    assert audit(forward) != audit(changed)


def test_no_network_dependency(model, monkeypatch):
    def fail(*args, **kwargs):
        pytest.fail("Unexpected network access")

    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(socket, "getaddrinfo", fail)
    assert not audit(model)["findings"]


def test_manifest_and_tabular_consistency(model):
    files, result = compile_report(model, "source")
    assert len(files) == 9 and list(files)[-1] == "manifest.json"
    manifest = json.loads(files["manifest.json"])
    assert set(manifest["files"]) == set(files) - {"manifest.json"}
    for name, item in manifest["files"].items():
        assert item == dict(bytes=len(files[name]), sha256=digest(files[name]))
    for name, key in [
        ("states.csv", "states"),
        ("rule-coverage.csv", "rule_coverage"),
        ("endpoints.csv", "endpoints"),
        ("checks.csv", "checks"),
        ("findings.csv", "findings"),
    ]:
        assert len(list(csv.DictReader(io.StringIO(files[name].decode())))) == len(result[key])
    assert manifest["canonical_model_sha256"] == digest(files["model.json"])


def test_untrusted_text_and_formula_escaping():
    model = example("current-mab")
    model["title"] = "<script>alert(1)</script> [click](x)"
    model["endpoints"][-1]["mab_exception"]["owner"] = " =1+1"
    files, _ = compile_report(model, "source")
    assert b"<script>" not in files["report.md"]
    rows = list(csv.DictReader(io.StringIO(files["endpoints.csv"].decode())))
    assert next(r for r in rows if r["id"] == "legacy-device")["exception_owner"] == "' =1+1"
    states = list(csv.DictReader(io.StringIO(files["states.csv"].decode())))
    assert any(s["decision"] == "'@default" for s in states)


@pytest.mark.parametrize(
    "name,exit_code", [("baseline", 0), ("risky-first-match", 1), ("invalid-reference", 2)]
)
def test_cli_audit(tmp_path, name, exit_code, capsys):
    output = tmp_path / "out"
    assert (
        main(["audit", "--input", str(ROOT / f"examples/{name}.json"), "--output", str(output)])
        == exit_code
    )
    captured = capsys.readouterr()
    if exit_code == 2:
        assert not output.exists() and "Input error" in captured.err
    else:
        assert len(list(output.iterdir())) == 9
        assert "offline-normalized-nac-model" in captured.out
        if os.name == "posix":
            assert output.stat().st_mode & 0o077 == 0
            assert all(p.stat().st_mode & 0o077 == 0 for p in output.iterdir())


def test_cli_validate_does_not_claim_security(capsys):
    assert main(["validate", "--input", str(ROOT / "examples/risky-first-match.json")]) == 0
    assert json.loads(capsys.readouterr().out) == dict(
        input_valid=True, scope="input-contract-only"
    )


def test_cli_gate_none_preserves_findings(tmp_path):
    output = tmp_path / "out"
    assert (
        main(
            [
                "audit",
                "--input",
                str(ROOT / "examples/risky-first-match.json"),
                "--output",
                str(output),
                "--fail-on",
                "none",
            ]
        )
        == 0
    )
    assert json.loads((output / "audit.json").read_text())["counts"]["findings"] == 15


def test_existing_output_preserved(tmp_path):
    marker = tmp_path / "keep"
    marker.write_text("keep")
    assert (
        main(["audit", "--input", str(ROOT / "examples/baseline.json"), "--output", str(tmp_path)])
        == 2
    )
    assert list(tmp_path.iterdir()) == [marker] and marker.read_text() == "keep"


def test_partial_write_no_manifest(tmp_path, monkeypatch):
    original = os.open

    def fail(path, *args, **kwargs):
        if Path(path).name == "states.csv":
            raise OSError("simulated full disk")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", fail)
    output = tmp_path / "out"
    assert (
        main(["audit", "--input", str(ROOT / "examples/baseline.json"), "--output", str(output)])
        == 2
    )
    assert output.exists() and not (output / "manifest.json").exists()


def test_missing_input(tmp_path):
    assert main(["validate", "--input", str(tmp_path / "missing")]) == 2


def test_unused_permissive_default_is_not_effective_risk(model):
    model["default_profile"] = "admin"
    model["rules"] = [any_rule("deny-all", "deny")]
    model["checks"] = []
    assert not audit(model)["findings"]


def test_audit_does_not_mutate_input(model):
    before = copy.deepcopy(model)
    compile_report(model, "source")
    assert model == before


@pytest.mark.parametrize(
    "field,value", [("owner", ""), ("reason", " "), ("expires_on", "2026-02-30")]
)
def test_exception_metadata_contract(field, value):
    model = example("current-mab")
    model["endpoints"][-1]["mab_exception"][field] = value
    with pytest.raises(InputError):
        validate_model(model)


def test_empty_profile_collection_rejected(model):
    model["profiles"] = []
    with pytest.raises(InputError):
        validate_model(model)
