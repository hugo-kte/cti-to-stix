"""Command line, dataset manifest, and report rendering (no network, no datasets)."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from gleaner import datasets, plots, report
from gleaner.cli import app
from gleaner.evaluate import attack_id_from_url, name_baseline

ROOT = Path(__file__).parents[1]
EXAMPLE = ROOT / "examples" / "glass-heron.md"
runner = CliRunner()


def test_iocs_command():
    result = runner.invoke(app, ["iocs", str(EXAMPLE)])
    assert result.exit_code == 0, result.output
    assert "ipv4-addr\t198[.]51[.]100[.]23\tindicator" in result.output
    assert "10[.]20[.]30[.]40" not in result.output  # internal address: not exported
    assert (
        "10[.]20[.]30[.]40\tinternal" in runner.invoke(app, ["iocs", str(EXAMPLE), "--all"]).output
    )
    assert "\t198.51.100.23\t" in runner.invoke(app, ["iocs", str(EXAMPLE), "--raw"]).output


def test_extract_stix_then_validate(tmp_path: Path, models_dir: Path):
    out = tmp_path / "bundle.json"
    result = runner.invoke(
        app, ["extract", str(EXAMPLE), "-f", "stix", "-o", str(out), "--models", str(models_dir)]
    )
    assert result.exit_code == 0, result.output
    bundle = json.loads(out.read_text())
    assert bundle["type"] == "bundle"
    assert runner.invoke(app, ["validate", str(out)]).exit_code == 0


def test_extract_json_and_markdown(models_dir: Path):
    result = runner.invoke(
        app, ["extract", str(EXAMPLE), "-f", "json", "--models", str(models_dir)]
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["components"] == ["iocs", "gazetteer", "technique-classifier"]
    assert {e["name"] for e in data["entities"]} >= {"QakBot", "Mimikatz", "PsExec"}
    assert any("classifier" in t["sources"] for t in data["techniques"])
    md = runner.invoke(app, ["extract", str(EXAMPLE), "--models", str(models_dir)])
    assert md.exit_code == 0 and md.stdout.startswith("# GLASS HERON")


def test_validate_rejects_a_broken_bundle(tmp_path: Path):
    broken = tmp_path / "broken.json"
    broken.write_text(
        json.dumps({"type": "bundle", "id": "bundle--1", "objects": [{"type": "indicator"}]})
    )
    assert runner.invoke(app, ["validate", str(broken)]).exit_code == 1


def test_bad_inputs_give_one_line_errors(tmp_path: Path):
    binary = tmp_path / "report.txt"
    binary.write_bytes(b"\xff\xfe\x00 not text")
    result = runner.invoke(app, ["iocs", str(binary)])
    assert result.exit_code == 1 and "not UTF-8 text" in result.output
    assert "type\tvalue" not in result.output  # nothing written before the error
    result = runner.invoke(app, ["extract", str(EXAMPLE), "--models", str(tmp_path / "none")])
    assert result.exit_code == 1 and "run from the repository root" in result.output
    not_json = tmp_path / "bundle.json"
    not_json.write_text("{not json")
    result = runner.invoke(app, ["validate", str(not_json)])
    assert result.exit_code == 1 and "is not JSON" in result.output
    result = runner.invoke(app, ["evaluate", "--only", "iocs,bogus", "--raw", str(tmp_path)])
    assert result.exit_code == 1 and "unknown section(s) bogus" in result.output
    result = runner.invoke(app, ["evaluate", "--only", "iocs", "--raw", str(tmp_path)])
    assert result.exit_code == 1 and "gleaner download" in result.output


def test_byte_order_mark_is_ignored(tmp_path: Path, models_dir: Path):
    report = tmp_path / "bom.md"
    report.write_text("﻿# Synthetic advisory\n\nNothing to see.\n", encoding="utf-8")
    result = runner.invoke(app, ["extract", str(report), "-f", "json", "--models", str(models_dir)])
    assert result.exit_code == 0 and json.loads(result.stdout)["title"] == "Synthetic advisory"


def test_module_entry_point():
    result = subprocess.run(
        [sys.executable, "-m", "gleaner", "--help"],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(ROOT / "src"), "PATH": ""},
        check=False,
    )
    assert result.returncode == 0 and "extract" in result.stdout


# --------------------------------------------------------------------------- datasets


def test_manifest_and_checksums_are_consistent():
    sources = datasets.load_sources(ROOT / "datasets.toml")
    pairs = datasets.read_checksums(ROOT / "checksums.sha256")
    assert (
        {rel.split("/", 1)[0] for _, rel in pairs} == set(sources) == {"tram", "attack", "annoctr"}
    )
    assert all(len(digest) == 64 for digest, _ in pairs)
    url = sources["annoctr"].url("annoctr/ner_json/test.json")
    assert url.startswith(
        "https://raw.githubusercontent.com/boschresearch/anno-ctr-lrec-coling-2024/"
    )
    assert url.endswith("/AnnoCTR/ner_json/test.json")


def test_download_verifies_checksums(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    payload = b"synthetic dataset file\n"
    manifest = tmp_path / "datasets.toml"
    manifest.write_text(
        '[sources.demo]\nrepo = "example/repo"\ncommit = "abc"\nremote = "data"\nlicense = "MIT"\n'
    )
    checksums = tmp_path / "checksums.sha256"
    checksums.write_text(f"{hashlib.sha256(payload).hexdigest()}  demo/file.txt\n")
    fetched = []

    def fake_fetch(url: str, dest: Path, retries: int = 3) -> None:
        fetched.append(url)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(payload)

    monkeypatch.setattr(datasets, "_fetch", fake_fetch)
    raw = tmp_path / "raw"
    assert datasets.download(raw, manifest, checksums) == {"present": 0, "downloaded": 1}
    assert fetched == ["https://raw.githubusercontent.com/example/repo/abc/data/file.txt"]
    assert datasets.download(raw, manifest, checksums) == {"present": 1, "downloaded": 0}
    assert datasets.verify(raw, checksums) == []
    (raw / "demo" / "file.txt").write_bytes(b"tampered")
    assert datasets.verify(raw, checksums) == ["demo/file.txt"]
    monkeypatch.setattr(datasets, "_fetch", lambda url, dest, retries=3: dest.write_bytes(b"bad"))
    with pytest.raises(ValueError, match="checksum mismatch"):
        datasets.download(raw, manifest, checksums)


# --------------------------------------------------------------------------- evaluation helpers


def test_attack_id_from_url():
    assert attack_id_from_url("https://attack.mitre.org/techniques/T1566/001") == "T1566.001"
    assert attack_id_from_url("https://attack.mitre.org/groups/G0032") == "G0032"
    assert attack_id_from_url("http://www.bosch.com#node1") is None


def test_name_baseline(catalog):
    pred = name_baseline(["Classic phishing email.", "Nothing here."], ["T1566", "T1105"], catalog)
    assert pred.tolist() == [[True, False], [False, False]]


def test_report_and_figures_render_from_published_metrics(tmp_path: Path):
    metrics = json.loads((ROOT / "reports" / "metrics.json").read_text(encoding="utf-8"))
    text = report.render(metrics)
    assert text.startswith("# Gleaner evaluation report")
    for heading in (
        "Indicators of compromise",
        "Named entities",
        "ATT&CK technique classification",
    ):
        assert heading in text
    paths = plots.all_figures(metrics, tmp_path)
    assert len(paths) == 5 and all(p.stat().st_size > 10_000 for p in paths)
