"""STIX 2.1 export: patterns, relationships, determinism and validation."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
import stix2patterns.validator

from gleaner.attack import Catalog
from gleaner.iocs import IOC
from gleaner.pipeline import Extractor
from gleaner.render import markdown
from gleaner.stix import pattern, to_bundle, validate

ROOT = Path(__file__).parents[1]
NOW = datetime(2026, 1, 1, tzinfo=UTC)


def ioc(kind: str, value: str, status: str = "indicator") -> IOC:
    return IOC(kind, value, status, (0,))


@pytest.mark.parametrize(
    ("kind", "value", "expected"),
    [
        ("ipv4-addr", "198.51.100.7", "[ipv4-addr:value = '198.51.100.7']"),
        ("url", "https://example.com/a'b", "[url:value = 'https://example.com/a\\'b']"),
        ("sha256", "ab" * 32, f"[file:hashes.'SHA-256' = '{'ab' * 32}']"),
        ("md5", "cd" * 16, f"[file:hashes.MD5 = '{'cd' * 16}']"),
        (
            "registry-key",
            r"HKEY_CURRENT_USER\Software\Run",
            r"[windows-registry-key:key = 'HKEY_CURRENT_USER\\Software\\Run']",
        ),
        (
            "file-path",
            r"C:\ProgramData\x.dll",
            r"[file:name = 'x.dll' AND file:parent_directory_ref.path = 'C:\\ProgramData']",
        ),
    ],
)
def test_patterns_are_escaped_and_valid(kind, value, expected):
    built = pattern(ioc(kind, value))
    assert built == expected
    assert stix2patterns.validator.run_validator(built) == []


def test_pattern_rejects_non_indicators():
    with pytest.raises(ValueError):
        pattern(ioc("cve", "CVE-2021-44228", "vulnerability"))


@pytest.fixture()
def extraction(catalog: Catalog, gazetteer):
    text = (ROOT / "examples" / "glass-heron.md").read_text(encoding="utf-8")
    return Extractor(catalog, gazetteer).extract(text, "examples/glass-heron.md")


def test_bundle_is_valid_and_complete(extraction, catalog: Catalog):
    bundle = json.loads(to_bundle(extraction, catalog, now=NOW).serialize())
    valid, errors, warnings = validate(bundle)
    assert valid and errors == [] and warnings == []
    types = {o["type"] for o in bundle["objects"]}
    assert {"identity", "marking-definition", "report", "indicator", "malware", "tool"} <= types
    assert {"vulnerability", "attack-pattern", "relationship"} <= types
    report = next(o for o in bundle["objects"] if o["type"] == "report")
    ids = {o["id"] for o in bundle["objects"]}
    assert set(report["object_refs"]) <= ids
    assert report["object_marking_refs"] == [
        o["id"] for o in bundle["objects"] if o["type"] == "marking-definition"
    ]


def test_attack_references_and_relationships(extraction, catalog: Catalog):
    objects = json.loads(to_bundle(extraction, catalog, now=NOW).serialize())["objects"]
    qakbot = next(o for o in objects if o["type"] == "malware" and o["name"] == "QakBot")
    assert qakbot["external_references"][0]["external_id"] == "S9003"
    ap = next(o for o in objects if o["type"] == "attack-pattern" and o["name"] == "LSASS Memory")
    assert ap["external_references"][0]["external_id"] == "T1003.001"
    assert ap["kill_chain_phases"] == [
        {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
    ]
    rels = [
        (o["relationship_type"], o["source_ref"].split("--")[0], o["target_ref"])
        for o in objects
        if o["type"] == "relationship"
    ]
    # one malware family in the report: indicators indicate it, it uses the techniques
    assert ("indicates", "indicator", qakbot["id"]) in rels
    assert ("uses", "malware", ap["id"]) in rels
    indicator = next(
        o for o in objects if o["type"] == "indicator" and o["name"] == "198.51.100.23"
    )
    assert (
        indicator["indicator_types"] == ["malicious-activity"]
        and indicator["pattern_type"] == "stix"
    )
    artifact = next(o for o in objects if o["type"] == "indicator" and "svcupdate.dll" in o["name"])
    assert artifact["indicator_types"] == ["unknown"]


def test_non_exported_values_stay_out(extraction, catalog: Catalog):
    names = {
        o.get("name")
        for o in json.loads(to_bundle(extraction, catalog, now=NOW).serialize())["objects"]
    }
    assert "10.20.30.40" not in names and "8.8.8.8" not in names  # internal, public resolver
    assert "https://attack.mitre.org/" not in names  # reference link


@pytest.mark.parametrize(
    "source", ["/home/analyst/cases/acme/glass-heron.md", r"C:\Users\analyst\glass-heron.md"]
)
def test_bundle_names_the_source_file_without_its_directory(catalog: Catalog, gazetteer, source):
    text = (ROOT / "examples" / "glass-heron.md").read_text(encoding="utf-8")
    result = Extractor(catalog, gazetteer).extract(text, source)
    objects = json.loads(to_bundle(result, catalog, now=NOW).serialize())["objects"]
    report = next(o for o in objects if o["type"] == "report")
    assert report["external_references"][0]["description"] == "glass-heron.md"


def test_bundle_is_deterministic(extraction, catalog: Catalog):
    first = to_bundle(extraction, catalog, now=NOW).serialize()
    second = to_bundle(extraction, catalog, now=NOW).serialize()
    assert json.loads(first)["objects"] == json.loads(second)["objects"]


@pytest.mark.parametrize("tlp", ["clear", "green", "amber", "red"])
def test_tlp_markings(extraction, catalog: Catalog, tlp: str):
    bundle = json.loads(to_bundle(extraction, catalog, tlp=tlp, now=NOW).serialize())
    marking = next(o for o in bundle["objects"] if o["type"] == "marking-definition")
    assert marking["definition"]["tlp"] == ("white" if tlp == "clear" else tlp)
    assert validate(bundle)[0]


def test_validator_catches_a_broken_bundle(extraction, catalog: Catalog):
    bundle = json.loads(to_bundle(extraction, catalog, now=NOW).serialize())
    next(o for o in bundle["objects"] if o["type"] == "indicator")["pattern"] = (
        "[ipv4-addr:value = ]"
    )
    valid, errors, _ = validate(bundle)
    assert not valid and errors


def test_markdown_summary(extraction, catalog: Catalog):
    text = markdown(extraction, catalog)
    assert text.startswith("# GLASS HERON")
    assert "hxxps://cdn-update[.]example[.]net/gate.php" in text  # shown defanged
    assert "[S9003](https://attack.mitre.org/software/S9003)" in text
    assert "Not exported" in text


def test_markdown_defangs_live_values_in_title_and_evidence(
    catalog: Catalog, gazetteer, technique_model
):
    text = (
        "# Payloads served from https://cdn.example.com/x\n\n"
        "The loader downloads additional payloads over HTTPS from https://cdn.example.com/x.\n"
    )
    result = Extractor(catalog, gazetteer, techniques=technique_model).extract(text)
    assert any(t.attack_id == "T1105" for t in result.techniques)
    text = markdown(result, catalog)
    assert "https://cdn.example.com" not in text
    assert text.startswith("# Payloads served from hxxps://cdn[.]example[.]com/x")


def test_cited_attack_ids_become_techniques(catalog: Catalog, gazetteer):
    text = "Mapping: | T1059.001 | PowerShell |\nThe actor later used T1574.002 again."
    result = Extractor(catalog, gazetteer).extract(text)
    found = {t.attack_id: t for t in result.techniques}
    assert found["T1059.001"].sources == ["attack-id"] and found["T1059.001"].score == 1.0
    assert found["T1574.001"].original_ids == ["T1574.002"]  # revoked ID resolved
