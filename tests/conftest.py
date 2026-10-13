from __future__ import annotations

from pathlib import Path

import pytest

from gleaner.attack import Catalog
from gleaner.gazetteer import Gazetteer
from gleaner.techniques import ModelConfig, binarize, fit

ROOT = Path(__file__).parents[1]
FIXTURES = Path(__file__).parent / "fixtures"

# A toy corpus: three techniques plus unlabelled sentences, spread over six "reports".
TECHNIQUE_SENTENCES = [
    ("The attachment was sent in a spearphishing email to finance staff.", ["T1566.001"]),
    ("Victims received phishing emails with a malicious Word attachment.", ["T1566.001"]),
    ("The lure email carried an ISO attachment that users opened.", ["T1566.001"]),
    ("Operators dumped credentials from LSASS memory with a custom tool.", ["T1003.001"]),
    ("The tool reads lsass.exe memory to extract password hashes.", ["T1003.001"]),
    ("Credential dumping from the LSASS process was observed on servers.", ["T1003.001"]),
    ("A PowerShell script downloaded the second stage from the server.", ["T1105"]),
    ("The loader downloads additional payloads over HTTPS.", ["T1105"]),
    ("Further tools were transferred to the host with certutil.", ["T1105"]),
    ("The company published its quarterly results on Monday.", []),
    ("Researchers shared the findings with the community.", []),
    ("This blog post describes the campaign timeline.", []),
]


@pytest.fixture(scope="session")
def catalog() -> Catalog:
    return Catalog.from_bundle(FIXTURES / "mini-attack.json")


@pytest.fixture(scope="session")
def gazetteer(catalog: Catalog) -> Gazetteer:
    return Gazetteer(catalog)


@pytest.fixture(scope="session")
def technique_data():
    texts, label_sets, docs = [], [], []
    for repeat in range(6):
        for k, (text, labels) in enumerate(TECHNIQUE_SENTENCES):
            texts.append(f"{text} (report {repeat}, item {k})")
            label_sets.append(labels)
            docs.append(f"report-{repeat}")
    labels = sorted({lab for ls in label_sets for lab in ls})
    return texts, binarize(label_sets, labels), labels, docs


@pytest.fixture(scope="session")
def technique_model(technique_data):
    texts, y, labels, _ = technique_data
    return fit(
        texts, y, labels, ModelConfig("word", 4.0, min_df=1, top_k=50), threshold=0.3, n_jobs=1
    )


@pytest.fixture()
def models_dir(tmp_path: Path, catalog: Catalog, technique_model) -> Path:
    """A models/ directory with the fixture catalog and the toy technique model (no CRF)."""
    catalog.save(tmp_path / "attack-catalog.json")
    technique_model.save(tmp_path / "techniques")
    return tmp_path
