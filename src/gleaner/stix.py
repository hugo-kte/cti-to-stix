"""STIX 2.1 export of an :class:`~gleaner.pipeline.Extraction` (``stix2``), and validation.

Mapping:

* indicators and host artifacts -> ``indicator`` with a STIX pattern
* CVE identifiers -> ``vulnerability``
* GROUP / MALWARE / TOOL -> ``intrusion-set`` / ``malware`` / ``tool``
* techniques -> ``attack-pattern`` referencing the ATT&CK ID, with kill-chain phases
* everything -> one ``report``, created by a ``system`` identity, under a TLP marking

Relationships are inferred conservatively from the report: when it names exactly one
intrusion set, the set ``uses`` every malware, tool and technique and ``targets`` the CVEs;
when it names exactly one malware family, the family ``uses`` the techniques, ``exploits`` the
CVEs and every indicator ``indicates`` it. With several families, an indicator only
indicates a family named in the same sentence.

Identifiers are derived from the objects' content, so the same report gives the same object
identifiers (only the timestamps and the bundle id change). The source document is referenced by
its file name only: a shared bundle should not reveal the analyst's directory layout.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import PureWindowsPath

import stix2
from stix2validator import ValidationOptions, validate_instance

from gleaner import __version__
from gleaner.attack import Catalog
from gleaner.iocs import IOC
from gleaner.pipeline import EntityHit, Extraction

NAMESPACE = uuid.UUID("5b7f0c3e-6a39-4f4e-9d2c-7a1f3b9e2d10")
TLP = {
    "clear": stix2.TLP_WHITE,
    "green": stix2.TLP_GREEN,
    "amber": stix2.TLP_AMBER,
    "red": stix2.TLP_RED,
}
_HASH_KEYS = {"md5": "MD5", "sha1": "'SHA-1'", "sha256": "'SHA-256'", "sha512": "'SHA-512'"}
_INFERRED = "Inferred from co-occurrence in the source report."


def _id(stix_type: str, *parts: str) -> str:
    """Deterministic identifier with UUIDv4 layout (the spec's SHOULD for SDOs and SROs).

    The 122 "random" bits come from a SHA-256 of the object's key, so re-running on the same
    report yields the same bundle and the same objects merge across reports.
    """
    key = "|".join((str(NAMESPACE), stix_type, *parts)).encode("utf-8")
    return f"{stix_type}--{uuid.UUID(bytes=hashlib.sha256(key).digest()[:16], version=4)}"


def _quote(value: str) -> str:
    """A STIX pattern string literal: backslashes and quotes escaped."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def pattern(ioc: IOC) -> str:
    """STIX pattern for an indicator (raises ValueError for non-indicator types)."""
    if ioc.type in ("ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr"):
        return f"[{ioc.type}:value = {_quote(ioc.value)}]"
    if ioc.type in _HASH_KEYS:
        return f"[file:hashes.{_HASH_KEYS[ioc.type]} = {_quote(ioc.value)}]"
    if ioc.type == "registry-key":
        return f"[windows-registry-key:key = {_quote(ioc.value)}]"
    if ioc.type == "file-path":
        path = PureWindowsPath(ioc.value)
        directory = str(path.parent)
        if directory in ("", "."):
            return f"[file:name = {_quote(path.name)}]"
        return (
            f"[file:name = {_quote(path.name)} AND "
            f"file:parent_directory_ref.path = {_quote(directory)}]"
        )
    raise ValueError(f"no STIX pattern for {ioc.type}")


def producer_identity() -> stix2.Identity:
    return stix2.Identity(
        id=_id("identity", "gleaner"),
        created="2026-01-01T00:00:00.000Z",
        modified="2026-01-01T00:00:00.000Z",
        name="Gleaner",
        identity_class="system",
        description="Automated extraction of threat intelligence from unstructured reports.",
    )


def _attack_ref(attack_id: str, url: str) -> stix2.ExternalReference:
    return stix2.ExternalReference(source_name="mitre-attack", external_id=attack_id, url=url)


def to_bundle(
    extraction: Extraction,
    catalog: Catalog,
    *,
    tlp: str = "amber",
    now: datetime | None = None,
) -> stix2.Bundle:
    now = now or datetime.now(UTC)
    identity = producer_identity()
    marking = TLP[tlp]
    common = {
        "created": now,
        "modified": now,
        "created_by_ref": identity.id,
        "object_marking_refs": [marking.id],
    }
    objects: list = []

    # ------------------------------------------------------------------ entities
    sdo_for: dict[int, object] = {}
    by_label: dict[str, list[tuple[EntityHit, object]]] = {"GROUP": [], "MALWARE": [], "TOOL": []}
    for k, hit in enumerate(extraction.entities):
        obj = catalog.get(hit.attack_id) if hit.attack_id else None
        refs = [_attack_ref(obj.attack_id, obj.url)] if obj else []
        aliases = sorted(
            {*hit.surfaces, *(obj.aliases if obj else ())} - {hit.name}, key=str.casefold
        )
        key = hit.attack_id or hit.name.casefold()
        kwargs = {"name": hit.name, "external_references": refs or None, **common}
        if hit.label == "GROUP":
            sdo = stix2.IntrusionSet(
                id=_id("intrusion-set", key), aliases=aliases or None, **kwargs
            )
        elif hit.label == "MALWARE":
            sdo = stix2.Malware(
                id=_id("malware", key), is_family=True, aliases=aliases or None, **kwargs
            )
        else:
            sdo = stix2.Tool(id=_id("tool", key), aliases=aliases or None, **kwargs)
        sdo_for[k] = sdo
        by_label[hit.label].append((hit, sdo))
        objects.append(sdo)

    # ------------------------------------------------------------------ techniques
    patterns = []
    for tech in extraction.techniques:
        obj = catalog.get(tech.attack_id)
        if obj is None:
            continue
        sdo = stix2.AttackPattern(
            id=_id("attack-pattern", obj.attack_id),
            name=obj.name,
            external_references=[_attack_ref(obj.attack_id, obj.url)],
            kill_chain_phases=[
                stix2.KillChainPhase(kill_chain_name="mitre-attack", phase_name=t)
                for t in obj.tactics
            ]
            or None,
            **common,
        )
        patterns.append(sdo)
        objects.append(sdo)

    # ------------------------------------------------------------------ indicators
    indicators: list[tuple[IOC, stix2.Indicator]] = []
    vulnerabilities = []
    for ioc in extraction.iocs:
        if ioc.status == "vulnerability":
            vuln = stix2.Vulnerability(
                id=_id("vulnerability", ioc.value),
                name=ioc.value,
                external_references=[
                    stix2.ExternalReference(source_name="cve", external_id=ioc.value)
                ],
                **common,
            )
            vulnerabilities.append(vuln)
            objects.append(vuln)
        elif ioc.status in ("indicator", "artifact"):
            artifact = ioc.status == "artifact"
            indicator = stix2.Indicator(
                id=_id("indicator", pattern(ioc)),
                name=ioc.value,
                description=(
                    "Host artifact mentioned in the report; review before use."
                    if artifact
                    else f"{ioc.type} extracted from the report ({ioc.count} mention(s))."
                ),
                indicator_types=["unknown" if artifact else "malicious-activity"],
                pattern=pattern(ioc),
                pattern_type="stix",
                valid_from=now,
                **common,
            )
            indicators.append((ioc, indicator))
            objects.append(indicator)

    # ------------------------------------------------------------------ relationships
    relationships = []

    def relate(source, kind: str, target) -> None:
        relationships.append(
            stix2.Relationship(
                id=_id("relationship", source.id, kind, target.id),
                relationship_type=kind,
                source_ref=source.id,
                target_ref=target.id,
                description=_INFERRED,
                **common,
            )
        )

    groups, families, tools = by_label["GROUP"], by_label["MALWARE"], by_label["TOOL"]
    if len(groups) == 1:
        actor = groups[0][1]
        for _, sdo in (*families, *tools):
            relate(actor, "uses", sdo)
        for ap in patterns:
            relate(actor, "uses", ap)
        for vuln in vulnerabilities:
            relate(actor, "targets", vuln)
    if len(families) == 1:
        family = families[0][1]
        for ap in patterns:
            relate(family, "uses", ap)
        for vuln in vulnerabilities:
            relate(family, "exploits", vuln)
    for ioc, indicator in indicators:
        if ioc.status != "indicator":
            continue
        if len(families) == 1:
            relate(indicator, "indicates", families[0][1])
            continue
        where = set(extraction.ioc_sentences.get(f"{ioc.type}|{ioc.value}", ()))
        for hit, sdo in families:
            if where & set(hit.sentences):
                relate(indicator, "indicates", sdo)
    objects.extend(relationships)

    report = stix2.Report(
        id=_id("report", extraction.sha256),
        name=extraction.title,
        description=_summary(extraction),
        published=now,
        report_types=["threat-report"],
        object_refs=[o.id for o in objects] or [identity.id],
        external_references=[
            stix2.ExternalReference(
                source_name="source-document", description=PureWindowsPath(extraction.source).name
            )
        ]
        if extraction.source
        else None,
        **common,
    )
    return stix2.Bundle(objects=[identity, marking, report, *objects], allow_custom=False)


def _summary(extraction: Extraction) -> str:
    n_ind = sum(i.status in ("indicator", "artifact") for i in extraction.iocs)
    return (
        f"Extracted by Gleaner {__version__} ({', '.join(extraction.components)}): "
        f"{n_ind} indicator(s), {len(extraction.entities)} named entit(ies), "
        f"{len(extraction.techniques)} ATT&CK technique(s). Machine-generated; review before use."
    )


# Best-practice check 302 asks for a hash next to every external-reference URL; MITRE's own
# ATT&CK bundle references attack.mitre.org pages by URL alone, and so do we.
SKIPPED_CHECKS = "302"


def validate(bundle: dict | str, strict: bool = True) -> tuple[bool, list[str], list[str]]:
    """Validate with the OASIS ``stix2-validator``: (valid, errors, warnings).

    ``strict`` turns best-practice warnings into errors (only check 302 is skipped).
    """
    instance = json.loads(bundle) if isinstance(bundle, str) else bundle
    options = ValidationOptions(version="2.1", strict=strict, disabled=SKIPPED_CHECKS)
    results = validate_instance(instance, options)
    errors, warnings = [], []
    for obj in _iter_results(results):
        errors += [str(e) for e in obj.errors]
        warnings += [str(w) for w in obj.warnings]
    return results.is_valid, errors, warnings


def _iter_results(results) -> Iterable:
    if hasattr(results, "object_results"):
        yield from results.object_results
    else:
        yield results
