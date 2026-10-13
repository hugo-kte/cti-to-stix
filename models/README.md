# Model files: licences and attribution

The code of this repository is MIT-licensed. The files in this directory are derived from public
datasets and keep their terms.

* **`gazetteer-rules.json`** is an adaptation of the AnnoCTR corpus, licensed under the
  [Creative Commons Attribution-ShareAlike 4.0 International licence](https://creativecommons.org/licenses/by-sa/4.0/)
  (CC BY-SA 4.0).
  * Source: Lukas Lange, Marc Müller, Ghazaleh Haratinezhad Torbati, Dragan Milchevski, Patrick
    Grau, Subhash Pujari, Annemarie Friedrich. *AnnoCTR: A Dataset for Detecting and Linking
    Entities, Tactics, and Techniques in Cyber Threat Reports.* LREC-COLING 2024. Corpus
    © 2023 Robert Bosch GmbH and its subsidiaries, CC BY-SA 4.0,
    <https://github.com/boschresearch/anno-ctr-lrec-coling-2024> (commit `d510b69`).
  * Changes: no text or annotation is copied. `gleaner.gazetteer.fit_rules` computed the file
    from the AnnoCTR train and dev splits: the words written mostly in lower case (counted on
    that text and on TRAM, Apache-2.0), the ATT&CK aliases whose matches were mostly wrong
    (`blocklist`) and the aliases whose matches mostly carried another annotated type
    (`relabel`). The ATT&CK names it lists remain subject to MITRE's terms below.
  * Provided as is, without warranties of any kind; see the licence.
* **`attack-catalog.json`** is derived from MITRE ATT&CK Enterprise v19.2 and carries MITRE's
  copyright designation and licence in its `notice` field. © 2026 The MITRE Corporation. This
  work is reproduced and distributed with the permission of The MITRE Corporation.
  [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
* **`techniques/`** holds logistic-regression weights learned from MITRE CTID's
  [TRAM](https://github.com/center-for-threat-informed-defense/tram) training data
  (Apache-2.0).
* **`training.json`** holds model-selection scores.

The CRF taggers (`ner.crfsuite`, `ner-gazetteer.crfsuite`) are not committed: `make train`
rebuilds them from the pinned data. Trained on AnnoCTR, they would be CC BY-SA 4.0 adaptations
too if shared.
