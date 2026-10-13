"""Indicator-of-compromise extraction: refanging, candidate patterns and validation.

Extraction is precision-oriented. Every candidate goes through a type-specific validator and
then gets a *status* that decides what it becomes in the STIX bundle:

* ``indicator``      network or file-hash observable (STIX indicator, ``malicious-activity``)
* ``artifact``       host artifact: Windows file path or registry key (indicator, ``unknown``)
* ``vulnerability``  CVE identifier (STIX vulnerability)
* ``reference``      citation: Markdown link target, URL on a security-vendor or news site, or a
                     non-defanged URL or e-mail address in a report that defangs its indicators
* ``benign``         bare mention of a legitimate service, hosting or dynamic-DNS platform
                     (``github.com``, ``duckdns.org``) or public resolver (``8.8.8.8``)
* ``internal``       private, loopback, link-local or otherwise non-routable address

Only the first three statuses are exported.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from functools import cache

from publicsuffixlist import PublicSuffixList

NETWORK_TYPES = ("url", "domain-name", "ipv4-addr", "ipv6-addr", "email-addr")
HASH_TYPES = ("md5", "sha1", "sha256", "sha512")
HOST_TYPES = ("file-path", "registry-key")
IOC_TYPES = (*NETWORK_TYPES, *HASH_TYPES, "cve", *HOST_TYPES)
EXPORTED_STATUSES = frozenset({"indicator", "artifact", "vulnerability"})


def _words(text: str) -> frozenset[str]:
    """A frozenset from a whitespace-separated list (keeps long lists readable)."""
    return frozenset(text.split())


# File extensions that are also ICANN top-level domains. A bare ``invoice.zip`` or ``setup.py``
# is far more often a file than a host, so it only counts as a domain when defanged or in a URL.
AMBIGUOUS_TLDS = frozenset(
    {"ai", "app", "cab", "md", "mov", "one", "pl", "ps", "py", "rs", "sh", "so", "zip"}
)
# Well-known legitimate services: a bare mention is not an indicator. URLs *with a path* on
# these hosts are kept, since attackers routinely stage payloads on them.
BENIGN_DOMAINS = _words(
    """
    amazon.com amazonaws.com aol.com apple.com azure.com baidu.com bing.com bit.ly
    bitbucket.org cloudflare-dns.com cloudflare.com discord.com discordapp.com dropbox.com
    facebook.com github.com githubusercontent.com gitlab.com gmail.com google.com
    googleapis.com gstatic.com icloud.com instagram.com live.com mail.ru mediafire.com mega.nz
    microsoftonline.com mozilla.org office.com office365.com onedrive.com opendns.com
    outlook.com pastebin.com proton.me protonmail.com python.org qq.com quad9.net reddit.com
    sharepoint.com skype.com slack.com telegram.org tinyurl.com tuta.io tutanota.com vk.com
    we.tl wetransfer.com whatsapp.com windows.com windowsupdate.com wordpress.com yahoo.com
    yandex.ru youtube.com zoom.us
    """
)
BENIGN_IPS = frozenset(
    {"1.0.0.1", "1.1.1.1", "8.8.4.4", "8.8.8.8", "9.9.9.9", "208.67.220.220", "208.67.222.222"}
)
# Sites cited as sources (vendors, news, knowledge bases): their URLs are references.
REFERENCE_DOMAINS = _words(
    """
    abuse.ch any.run bleepingcomputer.com checkpoint.com cisa.gov cisco.com crowdstrike.com
    cve.org eset.com fireeye.com fortinet.com hybrid-analysis.com intel471.com joesandbox.com
    kaspersky.com krebsonsecurity.com lab52.io linkedin.com mandiant.com mcafee.com medium.com
    microsoft.com mitre.org nist.gov nytimes.com paloaltonetworks.com proofpoint.com
    quointelligence.eu recordedfuture.com reuters.com s2grupo.es securelist.com sentinelone.com
    sophos.com symantec.com talosintelligence.com thehackernews.com tria.ge trellix.com
    trendmicro.com twitter.com urlscan.io us-cert.gov virustotal.com washingtonpost.com
    welivesecurity.com wikipedia.org x.com zdnet.com zscaler.com
    """
)
# Analysis services whose URLs embed the digest of the sample they describe.
SANDBOX_DOMAINS = frozenset(
    {"abuse.ch", "any.run", "hybrid-analysis.com", "joesandbox.com", "tria.ge", "virustotal.com"}
)
# Reserved for documentation (RFC 2606/6761 names, RFC 5737/3849/9637 address blocks). They are
# kept as indicators so that sanitised or synthetic reports still produce a complete bundle.
DOCUMENTATION_DOMAINS = frozenset({"example.com", "example.net", "example.org"})
DOCUMENTATION_TLDS = frozenset({"example", "test", "invalid"})
DOCUMENTATION_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "3fff::/20")
)
ROUTABLE_SCOPES = frozenset({"public", "documentation"})

# --------------------------------------------------------------------------- refanging

_DEFANG_RE = re.compile(
    r"""
    (?P<scheme>\b(?:h[x*]{2}p|h[x*]tp|ht[x*]p|f[x*]p)(?P<s>s?)(?=\s*[\[({]?:))
  | (?P<sep>\[://\]|\(://\))
  | (?P<colon>\[:\]|\(:\)|\{:\})
  | (?P<slash>\[/\])
  | (?P<dot>[ ]?\[\.\][ ]?|[ ]?\(\.\)[ ]?|[ ]?\{\.\}[ ]?|\[dot\]|\(dot\)|\{dot\}|(?<=\w)\\\.(?=\w))
  | (?P<at>\[@\]|\(@\)|\{@\}|\[at\]|\(at\)|\{at\})
  | (?P<escape>(?<=\w)\\{1,2}(?=[_*]))   # Markdown escape inside a token: host64\_x.bin
    """,
    re.IGNORECASE | re.VERBOSE,
)
_REPLACEMENTS = {"sep": "://", "colon": ":", "slash": "/", "dot": ".", "at": "@", "escape": ""}


@dataclass(frozen=True, slots=True)
class Refanged:
    """Refanged text with a map back to the source offsets."""

    text: str
    source_offsets: tuple[int, ...]  # one per character of ``text``, plus an end sentinel
    replaced: frozenset[int]  # positions in ``text`` produced by undoing a defang


def refang(text: str) -> Refanged:
    """Undo common defanging (``hxxp``, ``[.]``, ``(dot)``, ``[://]``, ``[@]``, ``\\.``...)."""
    out: list[str] = []
    offsets: list[int] = []
    replaced: set[int] = set()
    pos = 0
    for m in _DEFANG_RE.finditer(text):
        out.append(text[pos : m.start()])
        offsets.extend(range(pos, m.start()))
        if m.group("scheme"):
            rep = ("ftp" if m.group("scheme")[0] in "fF" else "http") + m.group("s").lower()
        else:
            rep = _REPLACEMENTS[m.lastgroup or "escape"]
        replaced.update(range(len(offsets), len(offsets) + len(rep)))
        out.append(rep)
        offsets.extend([m.start()] * len(rep))
        pos = m.end()
    out.append(text[pos:])
    offsets.extend(range(pos, len(text) + 1))
    return Refanged("".join(out), tuple(offsets), frozenset(replaced))


def defang(value: str) -> str:
    """Make an indicator safe to display: ``http`` -> ``hxxp``, dots in hosts -> ``[.]``."""
    if "://" in value:
        scheme, rest = value.split("://", 1)
        scheme = re.sub("^http", "hxxp", re.sub("^ftp", "fxp", scheme, flags=re.I), flags=re.I)
        host, sep, path = rest.partition("/")
        return f"{scheme}://{host.replace('.', '[.]')}{sep}{path}"
    if "/" in value:  # scheme-less URL
        host, sep, path = value.partition("/")
        return f"{host.replace('.', '[.]')}{sep}{path}"
    return value.replace("@", "[@]").replace(".", "[.]")


# --------------------------------------------------------------------------- patterns

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4_RE = re.compile(
    rf"(?<![\w.])(?:{_OCTET}\.){{3}}{_OCTET}(?:/(?:3[0-2]|[12]?\d))?(?![\w-]|\.\d)"
)
_IPV6_RE = re.compile(r"(?<![\w:.])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])", re.IGNORECASE)
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN = rf"(?:{_LABEL}\.)+(?:[a-z]{{2,63}}|xn--[a-z0-9-]{{1,59}})"
_DOMAIN_RE = re.compile(rf"(?<![\w@.\\/-]){_DOMAIN}(?![\w-]|\.[a-z0-9])", re.IGNORECASE)
_EMAIL_RE = re.compile(
    rf"(?<![\w.+-])[a-z0-9][a-z0-9._%+-]{{0,63}}@{_DOMAIN}(?![\w-]|\.[a-z0-9])", re.IGNORECASE
)
_URL_CHARS = r"[^\s<>\"'`|\\^{}]"
_URL_RE = re.compile(rf"\b(?:https?|ftp)://{_URL_CHARS}+", re.IGNORECASE)
_URL_PATH_RE = re.compile(rf"/{_URL_CHARS}*")
# Markdown link target, possibly wrapped onto the next line, or link title: [t](url "url")
_LINK_BEFORE_RE = re.compile(r"(?:\]\s*\(|\]\(\S+\s+\")\s*$")
_HASH_RE = re.compile(r"(?<![0-9a-z])[0-9a-f]{32,128}(?![0-9a-z])", re.IGNORECASE)
_NOT_A_DIGEST_BEFORE_RE = re.compile(
    r"(?:license|serial|key|mutex|guid|uuid|clsid|token|password|passwd|secret|session|\bid)"
    r"\w{0,8}\W{0,3}$",
    re.IGNORECASE,
)
_CVE_RE = re.compile(r"\bCVE-((?:19|20)\d\d)-(\d{4,7})\b", re.IGNORECASE)
# Inner path component: up to four words (``Program Files (x86)``, ``Start Menu``); no ``%``,
# so a second path on the same line (``... and %APPDATA%\\x.exe``) starts a new match.
_WORD = r"[^\\/:*?\"<>|\s,;%]+"
_SEGMENT = rf"{_WORD}(?: {_WORD}){{0,3}}(?=\\)"
_LAST = r"[^\\/:*?\"<>|\s,;()\[\]`“”‘’]{1,128}"  # last component: no spaces
_PATH_RE = re.compile(
    rf"(?<![\w%])(?:[a-z]:|%[a-z_]{{2,32}}%|\\\\[\w.$-]+)(?:\\{_SEGMENT})*\\{_LAST}",
    re.IGNORECASE,
)
_HIVES = {
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKCU": "HKEY_CURRENT_USER",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKU": "HKEY_USERS",
    "HKCC": "HKEY_CURRENT_CONFIG",
}
_REGISTRY_RE = re.compile(
    rf"(?<![\w\\])(?P<hive>{'|'.join([*_HIVES.values(), *_HIVES])}):?"
    rf"(?P<key>(?:\\{_SEGMENT})*\\{_LAST})",
    re.IGNORECASE,
)
_VERSION_BEFORE_RE = re.compile(
    r"(?:\bversion|\bver\.?|\bv|\bbuild|\brelease|\bfirmware)\s*[:=]?\s*$", re.IGNORECASE
)
_TRAILING = ".,;:!?'\"*_`“”‘’"
_HASH_KINDS = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}


@cache
def _psl(icann_only: bool = True) -> PublicSuffixList:
    return PublicSuffixList(only_icann=icann_only, accept_unknown=False)


# --------------------------------------------------------------------------- data model


@dataclass(frozen=True, slots=True)
class IOC:
    """One unique indicator value found in a document."""

    type: str
    value: str
    status: str
    offsets: tuple[int, ...]  # start offset of every occurrence in the source text
    defanged: bool = False
    scope: str = "public"  # public | documentation | private | loopback | link_local | ...

    @property
    def exported(self) -> bool:
        return self.status in EXPORTED_STATUSES

    @property
    def count(self) -> int:
        return len(self.offsets)


@dataclass(slots=True)
class _Hit:
    type: str
    value: str
    start: int  # offsets in the refanged text
    end: int
    status: str = "indicator"
    scope: str = "public"


# --------------------------------------------------------------------------- validators


def registrable_domain(domain: str) -> str | None:
    """Registrable part of ``domain`` under the ICANN public-suffix list (None if invalid)."""
    domain = domain.lower().rstrip(".")
    labels = domain.split(".")
    if len(labels) >= 2 and labels[-1] in DOCUMENTATION_TLDS:
        return ".".join(labels[-2:])
    return _psl().privatesuffix(domain)


def ip_scope(value: str) -> str:
    """Routing scope of an address or CIDR block (raises ValueError if not an IP)."""
    net = ipaddress.ip_network(value, strict=False)
    if any(net.version == d.version and net.subnet_of(d) for d in DOCUMENTATION_NETS):
        return "documentation"
    addr = net.network_address
    for scope in ("loopback", "link_local", "multicast", "unspecified"):
        if getattr(addr, f"is_{scope}"):
            return scope
    if addr.version == 4 and addr in ipaddress.ip_network("100.64.0.0/10"):
        return "shared"
    if addr.is_private:
        return "private"
    return "public" if addr.is_global else "reserved"


def _ip_status(value: str) -> tuple[str, str]:
    scope = ip_scope(value)
    if scope not in ROUTABLE_SCOPES:
        return "internal", scope
    return ("benign" if value in BENIGN_IPS else "indicator"), scope


def domain_status(domain: str) -> tuple[str, str]:
    """(status, scope) of a syntactically valid domain."""
    reg = registrable_domain(domain)
    if reg in DOCUMENTATION_DOMAINS or domain.rsplit(".", 1)[-1] in DOCUMENTATION_TLDS:
        return "indicator", "documentation"
    if reg in REFERENCE_DOMAINS:
        return "reference", "public"
    if reg in BENIGN_DOMAINS or _psl(icann_only=False).is_public(domain):
        return "benign", "public"  # a service, or a hosting/dynamic-DNS platform (duckdns.org)
    return "indicator", "public"


def valid_domain(candidate: str, *, bare: bool = False) -> bool:
    """Plausible domain under the PSL. ``bare`` adds the heuristics for free-text mentions."""
    if len(candidate) > 253 or registrable_domain(candidate) is None:
        return False
    if not bare:
        return True
    if any(c.isupper() for c in candidate):  # System.Net, WScript.Shell, README.md
        return False
    return candidate.rsplit(".", 1)[-1] not in AMBIGUOUS_TLDS


def _strip_url(url: str) -> str:
    url = url.split("**", 1)[0].rstrip(_TRAILING)  # Markdown bold glued to the URL
    for opener, closer in ("()", "[]"):
        while url.endswith(closer) and url.count(closer) > url.count(opener):
            url = url[:-1].rstrip(_TRAILING)
    return url


def _url_host(url: str) -> str:
    rest = url.split("://", 1)[1] if "://" in url else url
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0].rsplit("@", 1)[-1]
    if authority.startswith("["):
        return authority[1 : authority.find("]")]
    return authority.rsplit(":", 1)[0] if authority.count(":") == 1 else authority


def _url_status(url: str, host: str) -> tuple[str, str]:
    try:
        return _ip_status(host)
    except ValueError:
        status, scope = domain_status(host)
        rest = url.split("://", 1)[1] if "://" in url else url
        if status == "benign" and rest.rstrip("/").lower() != host:
            status = "indicator"  # a path on a legitimate service: hosted payload
        return status, scope


# --------------------------------------------------------------------------- finders


def _find_urls(text: str) -> list[_Hit]:
    hits = []
    pos = 0
    while m := _URL_RE.search(text, pos):
        url = _strip_url(m.group())
        host = _url_host(url).lower()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not host or not valid_domain(host):
                pos = m.start() + 1  # keep looking inside: a nested URL may follow
                continue
        status, scope = _url_status(url, host)
        before = text[max(0, m.start() - 300) : m.start()]
        if before.endswith("<") or _LINK_BEFORE_RE.search(before):
            status = "reference"  # Markdown link target, autolink or link title
        hits.append(_Hit("url", url, m.start(), m.start() + len(url), status, scope))
        pos = m.start() + len(url)
    return hits


def _find_emails(text: str) -> list[_Hit]:
    hits = []
    for m in _EMAIL_RE.finditer(text):
        value = m.group().rstrip(".")
        if valid_domain(domain := value.rsplit("@", 1)[1]):
            scope = domain_status(domain)[1]
            end = m.start() + len(value)
            hits.append(_Hit("email-addr", value.lower(), m.start(), end, "indicator", scope))
    return hits


def _find_host_artifacts(text: str) -> list[_Hit]:
    hits = []
    for m in _PATH_RE.finditer(text):
        value = m.group().rstrip(_TRAILING)
        hits.append(_Hit("file-path", value, m.start(), m.start() + len(value), "artifact"))
    for m in _REGISTRY_RE.finditer(text):
        key = m.group("key").rstrip(_TRAILING)
        hive = m.group("hive").upper()
        end = m.start("key") + len(key)
        hits.append(_Hit("registry-key", _HIVES.get(hive, hive) + key, m.start(), end, "artifact"))
    return hits


def _find_ips(text: str) -> list[_Hit]:
    hits = []
    for m in _IPV4_RE.finditer(text):
        if _VERSION_BEFORE_RE.search(text[max(0, m.start() - 12) : m.start()]):
            continue  # "version 1.2.3.4", "Version: 1.2.2.0"
        status, scope = _ip_status(m.group())
        hits.append(_Hit("ipv4-addr", m.group(), m.start(), m.end(), status, scope))
    for m in _IPV6_RE.finditer(text):
        if not re.search(r"\d", m.group()):
            continue
        try:
            addr = ipaddress.IPv6Address(m.group())
        except ValueError:
            continue
        status, scope = _ip_status(addr.compressed)
        hits.append(_Hit("ipv6-addr", addr.compressed, m.start(), m.end(), status, scope))
    return hits


def _find_domains(text: str, replaced: frozenset[int]) -> list[_Hit]:
    """Bare domains, and scheme-less URLs such as ``example[.]com/gate.php``."""
    hits = []
    for m in _DOMAIN_RE.finditer(text):
        defanged = any(i in replaced for i in range(m.start(), m.end()))
        if not valid_domain(m.group(), bare=not defanged):
            continue
        if text[m.end() : m.end() + 1] == "(":
            continue  # file.read(), document.write(): a method call
        domain = m.group().lower()
        path = _URL_PATH_RE.match(text, m.end())
        url = _strip_url(m.group() + path.group()) if path else ""
        if len(url) > len(domain) + 1:
            status, scope = _url_status(url, domain)
            hits.append(_Hit("url", url, m.start(), m.start() + len(url), status, scope))
        else:
            status, scope = domain_status(domain)
            hits.append(_Hit("domain-name", domain, m.start(), m.end(), status, scope))
    return hits


def _find_hashes(text: str, urls: list[_Hit]) -> list[_Hit]:
    hits = []
    for m in _HASH_RE.finditer(text):
        value = m.group()
        kind = _HASH_KINDS.get(len(value))
        if kind is None or text[max(0, m.start() - 2) : m.start()].lower() == "0x":
            continue
        if value not in (value.lower(), value.upper()):  # mixed case: not a hex digest
            continue
        lower = value.lower()
        # a digest has digits *and* letters; IDs, padding and repeated patterns do not
        if not re.search(r"\d", lower) or lower.isdigit() or len(set(lower)) < 6:
            continue
        if _NOT_A_DIGEST_BEFORE_RE.search(text[max(0, m.start() - 25) : m.start()]):
            continue  # "License: 4E78...", "RC4 key 6b3c..."
        container = next((u for u in urls if u.start <= m.start() and m.end() <= u.end), None)
        if container and registrable_domain(_url_host(container.value)) not in SANDBOX_DOMAINS:
            continue  # a path component of a URL, not the digest of a sample
        hits.append(_Hit(kind, lower, m.start(), m.end()))
    return hits


def _find_cves(text: str) -> list[_Hit]:
    return [
        _Hit("cve", f"CVE-{m.group(1)}-{m.group(2)}", m.start(), m.end(), "vulnerability")
        for m in _CVE_RE.finditer(text)
    ]


# --------------------------------------------------------------------------- extraction


def _claimed_hits(ref: Refanged) -> list[_Hit]:
    """URLs, e-mails, host artifacts, addresses and domains, in that priority order.

    A span claimed by one finder (a URL) is not re-used by the next (the domain inside it).
    """
    clean = ref.text
    hits: list[_Hit] = []
    claimed: list[tuple[int, int]] = []
    for found in (
        _find_urls(clean),
        _find_emails(clean),
        _find_host_artifacts(clean),
        _find_ips(clean),
        _find_domains(clean, ref.replaced),
    ):
        for hit in found:
            if not any(hit.start < end and start < hit.end for start, end in claimed):
                hits.append(hit)
                claimed.append((hit.start, hit.end))
    return hits


def defang_text(text: str) -> str:
    """``text`` with every live URL, domain, address and e-mail defanged, for display.

    Values the text already defangs are left as written.
    """
    ref = refang(text)
    out: list[str] = []
    pos = 0
    for hit in sorted(_claimed_hits(ref), key=lambda h: h.start):
        already_defanged = any(i in ref.replaced for i in range(hit.start, hit.end))
        if hit.type not in NETWORK_TYPES or already_defanged:
            continue
        start, end = ref.source_offsets[hit.start], ref.source_offsets[hit.end]
        out += [text[pos:start], defang(text[start:end])]
        pos = end
    return "".join(out) + text[pos:]


def extract_iocs(text: str, *, defang_consistency: bool = True) -> list[IOC]:
    """Extract unique indicators from a report (raw or defanged text).

    Finders run in priority order and a span claimed by one (a URL) is not re-used by the
    next (the domain inside it). Digests and CVE identifiers are searched everywhere: a sandbox
    or NVD link still carries a valid digest or CVE.

    ``defang_consistency``: when a report defangs at least one network indicator, its
    non-defanged URLs and e-mail addresses are treated as references (vendor links, contact
    addresses). Bare domains are exempt: on the development split they were as often attacker
    infrastructure listed in a table as citations.
    """
    ref = refang(text)
    clean = ref.text
    hits = _claimed_hits(ref)
    hits += _find_hashes(clean, [h for h in hits if h.type == "url"]) + _find_cves(clean)

    def is_defanged(hit: _Hit) -> bool:
        return any(i in ref.replaced for i in range(hit.start, hit.end))

    report_defangs = any(is_defanged(h) for h in hits if h.type in NETWORK_TYPES)
    occurrences: dict[tuple[str, str], list[tuple[_Hit, str, bool]]] = {}
    for hit in sorted(hits, key=lambda h: h.start):
        defanged = is_defanged(hit)
        status = hit.status
        if (
            defang_consistency
            and report_defangs
            and not defanged
            and status == "indicator"
            and hit.type in ("url", "email-addr")
            and hit.scope != "documentation"
        ):
            status = "reference"
        occurrences.setdefault((hit.type, hit.value), []).append((hit, status, defanged))

    iocs = []
    for (kind, value), occ in occurrences.items():
        statuses = [status for _, status, _ in occ]
        if any(status == "indicator" and defanged for _, status, defanged in occ):
            status = "indicator"  # one deliberate, defanged mention settles it
        elif "reference" in statuses:
            status = "reference"
        else:
            status = statuses[0]
        offsets = tuple(ref.source_offsets[hit.start] for hit, _, _ in occ)
        defanged = any(d for _, _, d in occ)
        iocs.append(IOC(kind, value, status, offsets, defanged, occ[0][0].scope))
    return iocs
