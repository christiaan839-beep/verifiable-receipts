"""Tests for normalize_sbom.py: python -m pytest .github/release"""

import hashlib
import json
import pathlib
import subprocess
import sys

import pytest

SCRIPT = pathlib.Path(__file__).with_name("normalize_sbom.py")
GO = "pkg:golang/github.com/christiaan839-beep/verifiable-receipts/packages/verifiable-receipts-go"
MOD = "pkg:golang/golang.org/x/mod@v0.30.0?type=module"


def run(tmp_path, bom, purl, artifact=b"zip bytes"):
    (tmp_path / "in.json").write_text(json.dumps(bom))
    (tmp_path / "file.zip").write_bytes(artifact)
    result = subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "--sbom", str(tmp_path / "in.json"),
         "--artifact", str(tmp_path / "file.zip"), "--purl", purl,
         "--epoch", "1700000000", "--out", str(tmp_path / "out.json")],
        capture_output=True, text=True, check=False,
    )
    out = tmp_path / "out.json"
    return result, json.loads(out.read_text()) if result.returncode == 0 else None


def go_bom():
    """What cyclonedx-gomod v1.12.0 writes: the root's bom-ref has no version."""
    stale = GO + "?type=module"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "component": {"bom-ref": stale, "type": "library", "name": "verifiable-receipts-go",
                          "purl": GO + "?goarch=arm64&goos=darwin&type=module"},
            "tools": {"components": [{"name": "cyclonedx-gomod",
                                      "hashes": [{"alg": "SHA-256", "content": "x"}]}]},
        },
        "components": [{"bom-ref": MOD, "name": "mod"}],
        "dependencies": [
            {"ref": stale, "dependsOn": [MOD]},
            {"ref": MOD, "dependsOn": []},
        ],
    }


def test_root_bom_ref_and_dependency_refs_follow_the_purl(tmp_path):
    purl = GO + "@v0.2.0?type=module"
    result, bom = run(tmp_path, go_bom(), purl)
    assert result.returncode == 0, result.stderr
    root = bom["metadata"]["component"]
    assert root["purl"] == purl
    assert root["version"] == "v0.2.0"
    assert root["bom-ref"] == purl
    assert bom["dependencies"][0]["ref"] == purl
    assert bom["dependencies"][1]["ref"] == MOD
    refs = {d["ref"] for d in bom["dependencies"]}
    refs |= {r for d in bom["dependencies"] for r in d.get("dependsOn", [])}
    known = {root["bom-ref"]} | {c["bom-ref"] for c in bom["components"]}
    assert refs <= known, refs - known


def test_dependson_pointing_at_the_root_is_rewritten(tmp_path):
    bom = go_bom()
    stale = bom["metadata"]["component"]["bom-ref"]
    bom["dependencies"][1]["dependsOn"] = [stale]
    purl = GO + "@v0.2.0?type=module"
    result, out = run(tmp_path, bom, purl)
    assert result.returncode == 0, result.stderr
    assert out["dependencies"][1]["dependsOn"] == [purl]


def test_a_root_without_bom_ref_gets_one(tmp_path):
    bom = go_bom()
    del bom["metadata"]["component"]["bom-ref"]
    bom["dependencies"] = []
    purl = GO + "@v0.2.0?type=module"
    result, out = run(tmp_path, bom, purl)
    assert result.returncode == 0, result.stderr
    assert out["metadata"]["component"]["bom-ref"] == purl


def test_a_new_bom_ref_that_collides_with_a_component_is_refused(tmp_path):
    result, _ = run(tmp_path, go_bom(), MOD)
    assert result.returncode != 0
    assert "bom-ref" in result.stderr


def test_serial_timestamp_hashes_and_tools(tmp_path):
    result, bom = run(tmp_path, go_bom(), GO + "@v0.2.0?type=module", artifact=b"abc")
    assert result.returncode == 0, result.stderr
    digest = hashlib.sha256(b"abc").hexdigest()
    assert bom["metadata"]["component"]["hashes"] == [{"alg": "SHA-256", "content": digest}]
    assert bom["metadata"]["timestamp"] == "2023-11-14T22:13:20Z"
    assert bom["serialNumber"].startswith("urn:uuid:")
    assert "hashes" not in bom["metadata"]["tools"]["components"][0]


def test_rebuild_is_identical(tmp_path):
    _, first = run(tmp_path, go_bom(), GO + "@v0.2.0?type=module")
    _, second = run(tmp_path, go_bom(), GO + "@v0.2.0?type=module")
    assert first == second


@pytest.mark.parametrize("purl", ["pkg:npm/x", "pkg:npm/x@"])
def test_a_purl_without_a_version_is_refused(tmp_path, purl):
    result, _ = run(tmp_path, go_bom(), purl)
    assert result.returncode != 0


def test_the_version_is_the_purls_decoded(tmp_path):
    purl = "pkg:pypi/sovereign-matrix-verifiable-receipts@0.3.0%2Bdryrun.gabc"
    result, bom = run(tmp_path, go_bom(), purl)
    assert result.returncode == 0, result.stderr
    assert bom["metadata"]["component"]["version"] == "0.3.0+dryrun.gabc"
    assert bom["metadata"]["component"]["purl"] == purl
