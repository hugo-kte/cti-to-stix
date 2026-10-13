"""A compact MITRE ATT&CK catalog built from the Enterprise STIX bundle.

It keeps what extraction and export need: techniques (with their tactics), tactics, groups and
software with their aliases, plus the revocation map (``T1574.002`` was revoked by
``T1574.001`` in v19), so identifiers from older datasets resolve to current objects.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

KINDS = ("technique", "tactic", "group", "malware", "tool")
# ATT&CK object kind -> entity label used by AnnoCTR and by the extractors
LABEL_OF_KIND = {
    "group": "GROUP",
    "malware": "MALWARE",
    "tool": "TOOL",
    "technique": "TECHNIQUE",
    "tactic": "TACTIC",
}
_URL_PATH = {
    "technique": "techniques",
    "tactic": "tactics",
    "group": "groups",
    "malware": "software",
    "tool": "software",
}
_STIX_KIND = {
    "attack-pattern": "technique",
    "x-mitre-tactic": "tactic",
    "intrusion-set": "group",
    "malware": "malware",
    "tool": "tool",
}
# Names that ATT&CK retired but reports still use. v19 renamed "Defense Evasion" to "Stealth".
LEGACY_ALIASES = {"TA0005": ("Defense Evasion",)}
NOTICE = (
    "Derived from MITRE ATT&CK Enterprise. © 2026 The MITRE Corporation. This work is "
    "reproduced and distributed with the permission of The MITRE Corporation. "
    "License: The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free "
    "license to use ATT&CK® for research, development, and commercial purposes. Any copy you "
    "make for such purposes is authorized provided that you reproduce MITRE's copyright "
    "designation and this license in any such copy. "
    "Terms of use: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/"
)


@dataclass(frozen=True, slots=True)
class AttackObject:
    attack_id: str  # T1059.003, TA0002, G0007, S0154
    name: str
    kind: str  # technique | tactic | group | malware | tool
    aliases: tuple[str, ...] = ()
    tactics: tuple[str, ...] = ()  # kill-chain phase names, techniques only

    @property
    def label(self) -> str:
        return LABEL_OF_KIND[self.kind]

    @property
    def url(self) -> str:
        return f"https://attack.mitre.org/{_URL_PATH[self.kind]}/{self.attack_id.replace('.', '/')}"

    @property
    def names(self) -> tuple[str, ...]:
        """Canonical name first, then aliases (deduplicated, case-insensitively)."""
        seen: dict[str, str] = {}
        for name in (self.name, *self.aliases):
            seen.setdefault(name.casefold(), name)
        return tuple(seen.values())


@dataclass(slots=True)
class Catalog:
    version: str
    objects: dict[str, AttackObject]
    redirects: dict[str, str] = field(default_factory=dict)  # revoked ID -> replacement ID
    notice: str = NOTICE

    def get(self, attack_id: str) -> AttackObject | None:
        """Look an identifier up, following revocations (``T1574.002`` -> ``T1574.001``)."""
        seen = set()
        while attack_id in self.redirects and attack_id not in seen:
            seen.add(attack_id)
            attack_id = self.redirects[attack_id]
        return self.objects.get(attack_id)

    def of_kind(self, *kinds: str) -> list[AttackObject]:
        return [o for o in self.objects.values() if o.kind in kinds]

    # ------------------------------------------------------------------ building and I/O

    @classmethod
    def from_bundle(cls, path: Path) -> Catalog:
        bundle = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_stix_objects(bundle["objects"])

    @classmethod
    def from_stix_objects(cls, stix_objects: Iterable[dict]) -> Catalog:
        stix_objects = list(stix_objects)
        by_stix_id = {o["id"]: o for o in stix_objects}
        version = next(
            (
                o.get("x_mitre_version", "")
                for o in stix_objects
                if o["type"] == "x-mitre-collection"
            ),
            "",
        )
        objects: dict[str, AttackObject] = {}
        for o in stix_objects:
            kind = _STIX_KIND.get(o["type"])
            attack_id = external_id(o)
            if not kind or not attack_id or o.get("revoked") or o.get("x_mitre_deprecated"):
                continue
            aliases = o.get("aliases") or o.get("x_mitre_aliases") or []
            aliases = [a for a in aliases if a != o["name"]] + list(
                LEGACY_ALIASES.get(attack_id, ())
            )
            tactics = tuple(
                p["phase_name"]
                for p in o.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            )
            objects[attack_id] = AttackObject(attack_id, o["name"], kind, tuple(aliases), tactics)
        redirects = {}
        for rel in stix_objects:
            if rel["type"] == "relationship" and rel["relationship_type"] == "revoked-by":
                old, new = by_stix_id.get(rel["source_ref"]), by_stix_id.get(rel["target_ref"])
                if old and new and external_id(old) and external_id(new):
                    redirects[external_id(old)] = external_id(new)
        return cls(version, objects, redirects)

    def save(self, path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "attack_version": self.version,
            "notice": self.notice,
            "objects": [
                {
                    "id": o.attack_id,
                    "name": o.name,
                    "kind": o.kind,
                    **({"aliases": list(o.aliases)} if o.aliases else {}),
                    **({"tactics": list(o.tactics)} if o.tactics else {}),
                }
                for o in sorted(self.objects.values(), key=lambda o: (o.kind, o.attack_id))
            ],
            "redirects": dict(sorted(self.redirects.items())),
        }
        path.write_text(json.dumps(data, indent=0, ensure_ascii=False) + "\n", encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: Path) -> Catalog:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        objects = {
            o["id"]: AttackObject(
                o["id"],
                o["name"],
                o["kind"],
                tuple(o.get("aliases", ())),
                tuple(o.get("tactics", ())),
            )
            for o in data["objects"]
        }
        return cls(
            data["attack_version"], objects, data.get("redirects", {}), data.get("notice", NOTICE)
        )


def external_id(stix_object: dict) -> str | None:
    """The ATT&CK identifier (``T1059``, ``G0007``...) of a STIX object from the bundle."""
    for ref in stix_object.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def parent(technique_id: str) -> str:
    """``T1059.003`` -> ``T1059``."""
    return technique_id.split(".", 1)[0]
