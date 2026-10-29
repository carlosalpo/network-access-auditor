"""Strict input contract with explicit assumptions and bounded state space."""

import hashlib
import json
import re
from datetime import date
from pathlib import Path

MAX_BYTES = 1_000_000
IDENTIFIER = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
METHODS = ("dot1x", "mab")
POSTURES = ("compliant", "noncompliant", "unknown")
ACCESS = ("deny", "restricted", "standard", "privileged")


class InputError(ValueError):
    """Model is unsupported or ambiguous; no audit should be produced."""


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fields(obj, names, where):
    if not isinstance(obj, dict) or set(obj) != set(names.split()):
        raise InputError(f"{where}: fields must match the specification exactly.")


def text(value, where, maximum=120):
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or not value.isprintable()
        or not value.strip()
    ):
        raise InputError(f"{where}: expected 1..{maximum} printable characters on one line.")


def identifier(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise InputError("IDs require a lowercase letter and up to 47 letters, digits or hyphens.")


def choice(value, options, where):
    if not isinstance(value, str) or value not in options:
        raise InputError(f"{where}: unsupported value.")


def iso_date(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise InputError("Dates must be YYYY-MM-DD.")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise InputError("Invalid calendar date.") from exc
    return parsed


def collection(value, maximum, minimum=0):
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise InputError(f"Collection requires {minimum}..{maximum} items.")
    return value


def unique_ids(values):
    ids = set()
    for obj in values:
        identifier(obj["id"])
        if obj["id"] in ids:
            raise InputError("IDs must be unique within each collection.")
        ids.add(obj["id"])
    return ids


def reference(value, options, where):
    if not isinstance(value, str) or value not in options:
        raise InputError(f"{where}: unknown reference.")


def selector(value, options, where):
    if value == "any":
        return
    collection(value, len(options), 1)
    for item in value:
        choice(item, options, where)
    if len(value) != len(set(value)):
        raise InputError(f"{where}: duplicate selector values.")


def validate_model(data):
    fields(
        data,
        "schema_version id title assessment_date provenance baseline groups profiles rules "
        "default_profile endpoints checks",
        "model",
    )
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise InputError("schema_version must be integer 1.")
    identifier(data["id"])
    text(data["title"], "title", 160)
    iso_date(data["assessment_date"])
    fields(data["provenance"], "kind reference", "provenance")
    choice(data["provenance"]["kind"], ("synthetic", "manual-normalization"), "provenance.kind")
    text(data["provenance"]["reference"], "provenance.reference", 160)
    fields(data["baseline"], "standard_requires_dot1x standard_requires_compliant", "baseline")
    if any(type(v) is not bool for v in data["baseline"].values()):
        raise InputError("Baseline switches must be JSON booleans.")
    for obj in collection(data["groups"], 32):
        fields(obj, "id label trust", "group")
        text(obj["label"], "group.label")
        choice(obj["trust"], ("managed", "unmanaged", "guest"), "group.trust")
    groups = unique_ids(data["groups"])
    if "unclassified" in groups:
        raise InputError("unclassified is reserved for the implicit unknown group.")
    groups.add("unclassified")
    for obj in collection(data["profiles"], 64, 1):
        fields(obj, "id label access", "profile")
        text(obj["label"], "profile.label")
        choice(obj["access"], ACCESS, "profile.access")
    profiles = unique_ids(data["profiles"])
    reference(data["default_profile"], profiles, "default_profile")
    for obj in collection(data["rules"], 128):
        fields(obj, "id enabled match profile", "rule")
        if type(obj["enabled"]) is not bool:
            raise InputError("rule.enabled must be a JSON boolean.")
        reference(obj["profile"], profiles, "rule.profile")
        fields(obj["match"], "groups methods postures", "rule.match")
        for key, options in (("groups", groups), ("methods", METHODS), ("postures", POSTURES)):
            selector(obj["match"][key], options, "rule.match." + key)
    unique_ids(data["rules"])
    for obj in collection(data["endpoints"], 1000):
        fields(obj, "id group method posture mab_exception", "endpoint")
        context(obj, groups)
        exception = obj["mab_exception"]
        if exception is not None:
            fields(exception, "owner reason expires_on", "mab_exception")
            text(exception["owner"], "mab_exception.owner")
            text(exception["reason"], "mab_exception.reason", 240)
            iso_date(exception["expires_on"])
    unique_ids(data["endpoints"])
    for obj in collection(data["checks"], 256):
        fields(obj, "id group method posture expected_profile", "check")
        context(obj, groups)
        reference(obj["expected_profile"], profiles, "check.expected_profile")
    unique_ids(data["checks"])


def context(obj, groups):
    reference(obj["group"], groups, "context.group")
    choice(obj["method"], METHODS, "context.method")
    choice(obj["posture"], POSTURES, "context.posture")


def canonical(data):
    normalized = json.loads(json_bytes(data))
    for key in ("groups", "profiles", "endpoints", "checks"):
        normalized[key].sort(key=lambda obj: obj["id"])
    # Rule order is policy semantics. NEVER sort the rule list.
    for rule in normalized["rules"]:
        for key, value in rule["match"].items():
            if isinstance(value, list):
                rule["match"][key] = sorted(value)
    return normalized


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("Duplicate JSON keys are not accepted.")
        result[key] = value
    return result


def _constant(value):
    raise InputError("Non-finite JSON numbers are not accepted.")


def load(path: Path):
    with path.open("rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise InputError("Input exceeds 1,000,000 bytes.")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InputError("Expected bounded UTF-8 JSON with unique keys and finite values.") from exc
    validate_model(data)
    return canonical(data), digest(raw)
