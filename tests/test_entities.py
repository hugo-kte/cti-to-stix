"""ATT&CK catalog, gazetteer, spans, tokenisation and the CRF tagger (fixture data only)."""

from __future__ import annotations

from pathlib import Path

from gleaner.attack import Catalog, external_id, parent
from gleaner.gazetteer import Gazetteer, GazetteerRules, common_words, fit_rules
from gleaner.metrics import span_scores
from gleaner.ner import CrfTagger, sentence_features, shape
from gleaner.spans import Mention, bio_to_spans, merge, spans_to_bio
from gleaner.text import split_sentences, tokenize


def words(text: str) -> list[str]:
    return [t.text for t in tokenize(text)]


# --------------------------------------------------------------------------- catalog


def test_catalog_skips_revoked_and_deprecated(catalog: Catalog):
    assert catalog.version == "0.1"
    assert "T1574.002" not in catalog.objects and "T1086" not in catalog.objects
    assert catalog.get("T1574.002").attack_id == "T1574.001"  # revoked-by is followed
    assert catalog.get("T9999") is None


def test_catalog_objects(catalog: Catalog):
    group = catalog.get("G9001")
    assert group.kind == "group" and group.label == "GROUP"
    assert group.names == ("Glass Heron", "Example Spider")  # case-insensitive dedup
    tech = catalog.get("T1059.001")
    assert tech.tactics == ("execution",)
    assert tech.url == "https://attack.mitre.org/techniques/T1059/001"
    assert catalog.get("S9101").url == "https://attack.mitre.org/software/S9101"
    assert catalog.get("TA0005").aliases == ("Defense Evasion",)  # legacy name kept
    assert parent("T1059.001") == "T1059"
    assert external_id({"external_references": [{"source_name": "x"}]}) is None


def test_catalog_round_trip(catalog: Catalog, tmp_path: Path):
    loaded = Catalog.load(catalog.save(tmp_path / "catalog.json"))
    assert loaded.objects == catalog.objects
    assert loaded.redirects == catalog.redirects
    assert "MITRE" in loaded.notice


# --------------------------------------------------------------------------- gazetteer


def labels_of(gazetteer: Gazetteer, text: str) -> list[tuple[str, str, str | None]]:
    ws = words(text)
    return [(" ".join(ws[m.start : m.end]), m.label, m.attack_id) for m in gazetteer.match(ws)]


def test_gazetteer_matches_names_and_aliases(gazetteer: Gazetteer):
    found = labels_of(gazetteer, "Example Spider used InkPot RAT, Mimikatz and PsExec.")
    assert ("Example Spider", "GROUP", "G9001") in found
    assert ("InkPot RAT", "MALWARE", "S9001") in found  # longest match wins
    assert ("Mimikatz", "TOOL", "S9103") in found and ("PsExec", "TOOL", "S9101") in found


def test_gazetteer_variants(gazetteer: Gazetteer):
    found = labels_of(gazetteer, "We saw InkPotRAT, psexec.exe and Copper Kite activity.")
    assert ("InkPotRAT", "MALWARE", "S9001") in found  # RAT suffix glued to the name
    assert ("psexec.exe", "TOOL", "S9101") in found  # executable name
    assert ("Copper Kite", "GROUP", "G9002") in found  # "Group" dropped from the name


def test_gazetteer_technique_names(gazetteer: Gazetteer):
    found = labels_of(gazetteer, "Phishing led to LSASS Memory dumps and Spearphishing Attachment.")
    assert ("Phishing", "TECHNIQUE", "T1566") in found
    assert ("LSASS Memory", "TECHNIQUE", "T1003.001") in found
    # single-word sub-technique names are too generic to match on their own
    assert labels_of(gazetteer, "The DLL was loaded by PowerShell.") == []


def test_case_and_common_word_rules(catalog: Catalog):
    rules = GazetteerRules(common_words=frozenset({"royal", "net"}))
    gaz = Gazetteer(catalog, rules=rules)
    assert labels_of(gaz, "A royal decree was published.") == []
    assert labels_of(gaz, "Royal decrees were published.") == []  # sentence-initial
    assert labels_of(gaz, "Operators deployed Royal on servers.") == [("Royal", "MALWARE", "S9002")]
    assert labels_of(gaz, "They used net user to list accounts.") == []
    assert labels_of(gaz, "Then they ran net.exe to list accounts.") == [
        ("net.exe", "TOOL", "S9102")
    ]
    assert labels_of(gaz, "the inkpot file") == []  # capitalised alias, lower-case token


def test_blocklist_and_relabel(catalog: Catalog):
    rules = GazetteerRules(
        blocklist=frozenset({("phishing", "TECHNIQUE")}),
        relabel={("mimikatz", "TOOL"): "MALWARE"},
    )
    gaz = Gazetteer(catalog, rules=rules)
    assert labels_of(gaz, "Phishing emails delivered Mimikatz.") == [
        ("Mimikatz", "MALWARE", "S9103")
    ]


def test_fit_rules_learns_from_training_labels(catalog: Catalog):
    sentences = [
        (["Phishing", "is", "common", "."], ["O", "O", "O", "O"]),
        (["Phishing", "again", "."], ["O", "O", "O"]),
        (["More", "Phishing", "."], ["O", "O", "O"]),
        (["They", "used", "Mimikatz", "."], ["O", "O", "B-MALWARE", "O"]),
        (["Then", "Mimikatz", "ran", "."], ["O", "B-MALWARE", "O", "O"]),
    ]
    rules = fit_rules(catalog, sentences, [["royal", "royal", "royal", "net"]])
    assert ("phishing", "TECHNIQUE") in rules.blocklist
    assert rules.relabel[("mimikatz", "TOOL")] == "MALWARE"
    assert rules.common_words == frozenset({"royal"})


def test_rules_round_trip(tmp_path: Path):
    rules = GazetteerRules(
        frozenset({"net"}), frozenset({("dll", "TECHNIQUE")}), {("remcos", "TOOL"): "MALWARE"}
    )
    assert GazetteerRules.load(rules.save(tmp_path / "rules.json")) == rules


def test_link(gazetteer: Gazetteer):
    assert gazetteer.link("Glass Heron").attack_id == "G9001"
    assert gazetteer.link("InkPot RAT", "MALWARE").attack_id == "S9001"
    assert gazetteer.link("Unknown Thing") is None


def test_common_words():
    corpus = [["the", "net", "Net", "net", "net", "Turla", "Turla"]]
    assert common_words(corpus, min_count=3) == frozenset({"net"})


# --------------------------------------------------------------------------- spans and text


def test_bio_round_trip():
    tags = ["B-GROUP", "I-GROUP", "O", "I-MALWARE", "B-TOOL", "B-TOOL"]
    spans = bio_to_spans(tags)
    assert spans == {(0, 2, "GROUP"), (3, 4, "MALWARE"), (4, 5, "TOOL"), (5, 6, "TOOL")}
    assert bio_to_spans(spans_to_bio(len(tags), spans)) == spans
    assert spans_to_bio(3, [(0, 2, "A"), (1, 3, "B")]) == ["B-A", "I-A", "O"]


def test_merge_prefers_primary():
    primary = [Mention(0, 2, "GROUP")]
    secondary = [Mention(1, 2, "MALWARE"), Mention(3, 4, "TOOL")]
    assert [m.label for m in merge(primary, secondary)] == ["GROUP", "TOOL"]


def test_span_scores_strict_and_lenient():
    gold = [{(0, 2, "GROUP"), (5, 6, "TOOL")}]
    pred = [{(0, 1, "GROUP"), (5, 6, "TOOL"), (7, 8, "TOOL")}]
    strict = span_scores(gold, pred, ["GROUP", "TOOL"])
    assert strict["per_label"]["TOOL"]["tp"] == 1 and strict["per_label"]["GROUP"]["tp"] == 0
    lenient = span_scores(gold, pred, ["GROUP", "TOOL"], lenient=True)
    assert lenient["per_label"]["GROUP"]["f1"] == 1.0
    assert round(strict["micro"]["precision"], 3) == round(1 / 3, 3)


def test_lenient_recall_counts_gold_spans():
    # one prediction covering two gold spans finds both; two predictions inside one gold span
    # are both correct but find it once
    gold = [{(0, 1, "TOOL"), (1, 2, "TOOL")}, {(0, 4, "GROUP")}]
    pred = [{(0, 2, "TOOL")}, {(0, 1, "GROUP"), (2, 3, "GROUP")}]
    lenient = span_scores(gold, pred, ["GROUP", "TOOL"], lenient=True)
    tool, group = lenient["per_label"]["TOOL"], lenient["per_label"]["GROUP"]
    assert (tool["precision"], tool["recall"], tool["support"]) == (1.0, 1.0, 2)
    assert (group["precision"], group["recall"], group["support"]) == (1.0, 1.0, 1)
    assert lenient["micro"]["support"] == 3 and lenient["micro"]["tp"] == 3


def test_tokenizer_and_sentences():
    assert words("APT28 used cmd.exe, third-party tools and the victim's account.") == [
        "APT28", "used", "cmd.exe", ",", "third-party", "tools", "and", "the", "victim's",
        "account", ".",
    ]  # fmt: skip
    text = (
        "First sentence, e.g. with an abbreviation. Second one!\n\n# Heading\nU.S. agencies agree."
    )
    sentences = split_sentences(text)
    assert [s.text for s in sentences] == [
        "First sentence, e.g. with an abbreviation.",
        "Second one!",
        "# Heading",
        "U.S. agencies agree.",
    ]
    assert text[sentences[1].start :].startswith("Second")
    assert sentences[1].tokens[0].start == sentences[1].start
    wrapped = "The loader beacons to\nexample[.]com every hour. Done.\n| a | b |\n- item"
    assert [s.text for s in split_sentences(wrapped)] == [
        "The loader beacons to\nexample[.]com every hour.",  # one sentence over two lines
        "Done.",
        "| a | b |",
        "- item",
    ]


# --------------------------------------------------------------------------- CRF


def test_features():
    assert shape("APT28") == "XXXdd"
    feats = sentence_features(["Glass", "Heron", "struck"], ["B-GROUP", "I-GROUP", "O"])
    assert feats[0]["lower"] == "glass" and feats[0]["BOS"] == 1.0 and feats[-1]["EOS"] == 1.0
    assert feats[1]["gaz"] == "I-GROUP" and feats[1]["-1:lower"] == "glass"


def test_crf_learns_a_toy_task(tmp_path: Path, gazetteer: Gazetteer):
    train = []
    for name in ("Glass Heron", "Copper Kite", "Night Owl", "Red Fox", "Blue Jay"):
        a, b = name.split()
        for verb in ("attacked", "targeted", "phished", "breached"):
            train.append(
                ([a, b, verb, "the", "bank", "."], ["B-GROUP", "I-GROUP", "O", "O", "O", "O"])
            )
            train.append(
                (["Analysts", "tracked", a, b, "."], ["O", "O", "B-GROUP", "I-GROUP", "O"])
            )
    tagger = CrfTagger.train(train, tmp_path / "toy.crfsuite", c1=0.0, c2=0.01, max_iterations=50)
    assert tagger.labels == ["GROUP"]
    assert [
        (m.start, m.end, m.label)
        for m in tagger.mentions(["Grey", "Wolf", "attacked", "the", "bank", "."])
    ] == [(0, 2, "GROUP")]
    assert tagger.tag([]) == []
    with_gaz = CrfTagger.train(
        train, tmp_path / "gaz.crfsuite", gazetteer=gazetteer, max_iterations=20
    )
    assert with_gaz.mentions(["Glass", "Heron", "attacked", "the", "bank", "."])[0].label == "GROUP"
