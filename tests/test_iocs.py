"""IOC extraction. Every indicator here is neutral: documentation ranges (RFC 5737/3849),
reserved names (RFC 2606/6761) and digests of placeholder strings."""

from __future__ import annotations

import hashlib

import pytest

from gleaner.iocs import (
    defang,
    defang_text,
    domain_status,
    extract_iocs,
    ip_scope,
    refang,
    registrable_domain,
)

MD5 = hashlib.md5(b"gleaner test sample").hexdigest()
SHA1 = hashlib.sha1(b"gleaner test sample").hexdigest()
SHA256 = hashlib.sha256(b"gleaner test sample").hexdigest()


def found(text: str, **kw) -> dict[tuple[str, str], str]:
    return {(i.type, i.value): i.status for i in extract_iocs(text, **kw)}


@pytest.mark.parametrize(
    ("defanged", "expected"),
    [
        ("hxxps://cdn[.]example[.]com/a", "https://cdn.example.com/a"),
        ("hXXp://198.51.100[.]7/x", "http://198.51.100.7/x"),
        ("example(.)org and example{.}net", "example.org and example.net"),
        ("example[dot]com", "example.com"),
        ("billing[@]example[.]org", "billing@example.org"),
        ("hxxps[:]//example[.]com", "https://example.com"),
        ("hxxps[://]cdn[.]example[.]com/a", "https://cdn.example.com/a"),
        ("hXXp(://)198.51.100[.]7/x", "http://198.51.100.7/x"),
        ("fxp://203.0.113.5/file", "ftp://203.0.113.5/file"),
        ("evil.example [.] com", "evil.example.com"),
        ("host64\\_sh.bin", "host64_sh.bin"),
    ],
)
def test_refang(defanged, expected):
    assert refang(defanged).text == expected


def test_bracketed_scheme_separator_is_extracted():
    statuses = found("C2: hxxps[://]update[.]example[.]com/gate.php")
    assert statuses == {("url", "https://update.example.com/gate.php"): "indicator"}


def test_refang_keeps_offsets():
    text = "see hxxp://example[.]com now"
    ref = refang(text)
    start = ref.text.index("example")
    assert text[ref.source_offsets[start] :].startswith("example")
    assert ref.replaced  # the replaced characters are tracked


def test_defang_for_display():
    assert defang("https://cdn.example.com/a.php") == "hxxps://cdn[.]example[.]com/a.php"
    assert defang("198.51.100.7") == "198[.]51[.]100[.]7"
    assert defang("user@example.org") == "user[@]example[.]org"
    assert defang("example.com/path/x.php") == "example[.]com/path/x.php"


def test_defang_text_neutralises_live_values_only():
    text = (
        r"Beacons to https://cdn.example.com/a and 198.51.100.7 from ops@example.org, "
        r"drops C:\ProgramData\x.dll; already safe: hxxp://bad[.]example[.]net/b."
    )
    assert defang_text(text) == (
        r"Beacons to hxxps://cdn[.]example[.]com/a and 198[.]51[.]100[.]7 from "
        r"ops[@]example[.]org, drops C:\ProgramData\x.dll; already safe: "
        r"hxxp://bad[.]example[.]net/b."
    )


def test_network_indicators_and_scopes():
    text = (
        "C2 at hxxps://update.example[.]com/gate.php and 198.51.100[.]23, "
        "fallback 2001:db8::7; sender billing[@]example[.]org."
    )
    iocs = {i.value: i for i in extract_iocs(text)}
    assert iocs["https://update.example.com/gate.php"].type == "url"
    assert iocs["198.51.100.23"].scope == "documentation"
    assert iocs["2001:db8::7"].type == "ipv6-addr"
    assert iocs["billing@example.org"].type == "email-addr"
    assert all(
        i.status == "indicator" and i.defanged for i in iocs.values() if i.type != "ipv6-addr"
    )


def test_private_and_special_addresses_are_not_exported():
    statuses = found("Hosts 10.1.2.3, 192.168.0.10, 127.0.0.1, 169.254.1.1 and 100.64.0.9.")
    assert set(statuses.values()) == {"internal"}
    assert ip_scope("203.0.113.0/24") == "documentation"
    assert ip_scope("8.8.8.8") == "public"
    assert found("Resolver 8.8.8.8 was queried.")[("ipv4-addr", "8.8.8.8")] == "benign"


def test_versions_and_oids_are_not_addresses():
    assert found("version 1.2.3.4, Version: 1.2.2.0, OID 1.3.6.1.4.1.311, build 10.0.19041.1") == {}


def test_cidr_blocks():
    assert ("ipv4-addr", "198.51.100.0/24") in found("The range 198.51.100.0/24 was used.")


def test_hashes():
    text = f"MD5 {MD5.upper()}, SHA-1 {SHA1} and SHA-256 {SHA256}."
    types = {k[0] for k in found(text)}
    assert types == {"md5", "sha1", "sha256"}
    assert ("md5", MD5) in found(text)  # normalised to lower case


@pytest.mark.parametrize(
    "text",
    [
        "Wallet 0x52908400098527886E0F7030069857D2E4169EE7 received funds.",  # 0x prefix
        "Padding deadbeefdeadbeefdeadbeefdeadbeef here.",  # no digit, repeated pattern
        "Numbers 12345678901234567890123456789012 only.",  # all digits
        "Mixed AbCdEf0123456789aBcDeF0123456789 case.",  # mixed case
        f"License: {MD5}",  # a key, not a digest
    ],
)
def test_hex_strings_that_are_not_digests(text):
    assert not any(k[0] in ("md5", "sha1") for k in found(text))


def test_digest_in_url_path_is_not_a_sample_hash():
    url_with_hex = f"hxxps://cdn.example[.]com/{MD5}/app.js"
    assert ("md5", MD5) not in found(url_with_hex)
    sandbox = f"[report](https://www.virustotal.com/gui/file/{SHA256})"
    assert found(sandbox)[("sha256", SHA256)] == "indicator"


def test_cve_identifiers():
    statuses = found("Exploits CVE-2021-44228 and cve-2017-0144, but not CVE-21-1.")
    assert statuses == {
        ("cve", "CVE-2021-44228"): "vulnerability",
        ("cve", "CVE-2017-0144"): "vulnerability",
    }


def test_filenames_are_not_domains():
    text = "It drops invoice.zip, setup.py, run.sh, report.pdf and payload.exe; see README.md."
    assert not any(k[0] == "domain-name" for k in found(text))
    # ...unless the author defanged them: then they are hosts
    assert ("domain-name", "invoice.zip") in found("It beacons to invoice[.]zip every hour.")


def test_code_identifiers_are_not_domains():
    text = "It calls System.Net.WebClient, WScript.Shell and file.read() then document.write(x)."
    assert not any(k[0] == "domain-name" for k in found(text))


def test_reference_and_benign_classification():
    text = (
        "See [the analysis](https://blog.example.net/post) and https://www.proofpoint.com/x. "
        "Payload at https://github.com/someone/tool/raw/main/x.dll; github.com itself is benign; "
        "dynamic DNS provider duckdns.org."
    )
    statuses = found(text)
    assert statuses[("url", "https://blog.example.net/post")] == "reference"
    assert statuses[("url", "https://www.proofpoint.com/x")] == "reference"
    assert statuses[("url", "https://github.com/someone/tool/raw/main/x.dll")] == "indicator"
    assert statuses[("domain-name", "github.com")] == "benign"
    assert statuses[("domain-name", "duckdns.org")] == "benign"


def test_defang_consistency_marks_live_urls_as_references():
    # documentation names are exempt (they keep synthetic reports useful): use IANA's page
    live = "https://www.iana.org/domains/reserved"
    text = f"C2: hxxps://bad.example[.]com/a. Background: {live}."
    assert found(text)[("url", live)] == "reference"
    assert found(text, defang_consistency=False)[("url", live)] == "indicator"


def test_schemeless_url():
    statuses = found("Payload hosted at files.example[.]com/drop/x.bin today.")
    assert statuses[("url", "files.example.com/drop/x.bin")] == "indicator"


def test_windows_paths_and_registry_keys():
    text = (
        r"Dropped to C:\ProgramData\Updates\svc.dll and %APPDATA%\Microsoft\x.exe; "
        r"persistence in HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater, "
        r"and HKLM\SYSTEM\CurrentControlSet\Services\evil."
    )
    statuses = found(text)
    assert statuses[("file-path", r"C:\ProgramData\Updates\svc.dll")] == "artifact"
    assert ("file-path", r"%APPDATA%\Microsoft\x.exe") in statuses
    assert (
        "registry-key",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
    ) in statuses
    assert (
        "registry-key",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\evil",
    ) in statuses


def test_duplicates_are_merged_with_offsets():
    text = "Contact 203.0.113.9 then 203.0.113[.]9 again."
    (ioc,) = extract_iocs(text)
    assert ioc.count == 2 and ioc.defanged
    assert text[ioc.offsets[0] :].startswith("203.0.113.9")


def test_psl_helpers():
    assert registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert registrable_domain("host.test") == "host.test"
    assert registrable_domain("not-a-tld.zzzz") is None
    assert domain_status("cdn.example.com") == ("indicator", "documentation")
