"""Run the installed CLI against eight public scenarios and verify its artifacts."""

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

CASES = {
    "baseline": (0, None),
    "risky-first-match": (1, "UNCLASSIFIED_INTERNAL_ACCESS"),
    "shadowed-rule": (1, "RULE_SHADOWED"),
    "expired-mab": (1, "MAB_EXCEPTION_EXPIRED"),
    "current-mab": (0, None),
    "intent-mismatch": (1, "INTENT_MISMATCH"),
    "permissive-default": (1, "PERMISSIVE_DEFAULT"),
    "invalid-reference": (2, None),
}


def run(output):
    cli = shutil.which("naa")
    if not cli:
        raise SystemExit("Install this package and activate its environment first.")
    output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[1]
    summary = []
    for name, (expected, code) in CASES.items():
        destination = output / name
        result = subprocess.run(
            [
                cli,
                "audit",
                "--input",
                str(root / f"examples/{name}.json"),
                "--output",
                str(destination),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        (output / (name + ".log")).write_text(
            f"case={name}\nexit={result.returncode}\n" + result.stdout + result.stderr,
            encoding="utf-8",
        )
        assert result.returncode == expected, name
        item = dict(case=name, exit_code=result.returncode, expected_code=code)
        if expected == 2:
            assert not destination.exists(), name
            item.update(status="input_error", artifacts=0)
        else:
            audit = json.loads((destination / "audit.json").read_text())
            assert audit["gate"]["failed"] == (expected == 1), name
            if code:
                assert code in {f["code"] for f in audit["findings"]}, name
            else:
                assert not audit["findings"], name
            manifest = json.loads((destination / "manifest.json").read_text())
            assert set(manifest["files"]) == {p.name for p in destination.iterdir()} - {
                "manifest.json"
            }
            for filename, metadata in manifest["files"].items():
                raw = (destination / filename).read_bytes()
                assert len(raw) == metadata["bytes"], (name, filename)
                assert hashlib.sha256(raw).hexdigest() == metadata["sha256"], (name, filename)
            assert len(audit["states"]) == (audit["counts"]["groups"] + 1) * 6
            assert (
                sum(r["effective_states"] for r in audit["rule_coverage"])
                + sum(s["decision"] == "@default" for s in audit["states"])
                == audit["counts"]["states"]
            )
            item.update(
                status=audit["status"],
                states=audit["counts"]["states"],
                findings=len(audit["findings"]),
                artifacts=len(manifest["files"]) + 1,
                hashes_verified=True,
            )
        summary.append(item)
        print(f"PASS {name}: exit={result.returncode}, artifacts={item['artifacts']}")
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(
        f"{len(summary)} CLI scenarios passed; artifact hashes and modeled-state coverage verified."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    run(parser.parse_args().output)
