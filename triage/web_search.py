"""Web search for chat, through the Brave Search API (owner-approved, 2026-10-10).

Off until an admin stores a key (python -m triage.brave_key set). Then a chat
question about one alert also gets a few web results, so the AI can investigate
like a tier-one analyst: what the activity is, who is behind it, how it works.

What may leave this computer are two search queries, and code alone writes them:
1. The alert's kind, from public identifiers only: a Windows event id from
   LightHouse's own event tables, a Suricata rule's number and name from the
   public ruleset, MITRE ATT&CK technique ids (search_query).
2. The outside party (owner-approved, 2026-10-11): the one public IP address in the
   alert, or a domain from the record's DNS, TLS or HTTP fields (outside_indicator).
   This tells Brave which address this network dealt with, which the owner accepted
   for better "who is this" answers. Never a private, loopback, link-local, CGNAT or
   other non-global address; when both ends are public, neither (one of them is
   this network's own); never an internal-looking name (.local, .lan, single
   labels).
Never a device or user name, file path or command line; never anything the AI
wrote. A query that fails its allowlist is not sent at all.

General chats (owner-approved, 2026-10-12) also search every question, from the
owner's own words (question_query), so the AI can look up what the owner asks about.
Code cleans them first: private, loopback and link-local addresses, e-mail
addresses, file paths, document file names, internal names, Windows-style host
names and names LightHouse knows are this network's (devices, LightHouse users,
this computer) are dropped word by word. Free text cannot be cleaned perfectly:
anything else the owner types, such as a client's name, can reach Brave, and the
dashboard footer says so. If the question points at one alert, that alert's two
code-built searches run too (results_for_question).

The outside indicator is attacker-chosen (an attacker can pick what gets searched)
and the results are attacker-reachable text (anyone can publish a page that ranks
for a rule name or an address), so results are cleaned, capped and quoted inside
the evidence fence, where the AI is told to treat them as data. The severity floor
and the fixed reminders do not depend on them. Any failure means no results; chat
answers without them.
"""
from __future__ import annotations

import html
import ipaddress
import logging
import re
import threading
import time
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

import httpx

from .schema import AlertDetail, Source

logger = logging.getLogger(__name__)

BRAVE_SEARCH_URL = "https://api.search.brave.com/res/v1/web/search"
BRAVE_HOST = "api.search.brave.com"
SEARCH_TIMEOUT = httpx.Timeout(6.0, connect=4.0)
RESULT_COUNT = 3
INDICATOR_RESULT_COUNT = 2
QUESTION_RESULT_COUNT = 3
QUESTION_MAX_WORDS = 16
QUESTION_MAX_CHARS = 400
# Brave's entry plans allow about one request a second; the two searches of a
# question are spaced so the second is not refused (which would pause search).
MIN_REQUEST_GAP_SECONDS = 1.1
TITLE_MAX_CHARS = 100
SNIPPET_MAX_CHARS = 280
URL_MAX_CHARS = 200
QUERY_MAX_CHARS = 160
CACHE_SECONDS = 60 * 60
CACHE_MAX_ENTRIES = 128
COOLDOWN_SECONDS = 60.0

# The query's last line of defence: plain words, numbers and a little punctuation,
# and never anything shaped like an address.
_QUERY_ALLOWED = re.compile(r"[A-Za-z0-9 .,:_()/&'+-]{3,%d}" % QUERY_MAX_CHARS)
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_IPV6 = re.compile(r"\b[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){2,}\b")
_MITRE = re.compile(r"T\d{4}(?:\.\d{3})?")
_SID = re.compile(r"\d{1,10}")
_WINDOWS_RULE = re.compile(r"(Microsoft-Windows-(?:Security-Auditing|Sysmon|Eventlog)):(\d{1,5})")
_TAGS = re.compile(r"<[^>]{0,200}>")
_DOMAIN = re.compile(r"(?=.{4,100}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,6}[a-z]{2,24}")
# Names that only mean something inside a business network: searching them would
# describe this network, not the outside party.
_INTERNAL_SUFFIXES = (".local", ".lan", ".home", ".internal", ".intranet", ".corp", ".private",
                      ".localdomain", ".home.arpa", ".arpa", ".test", ".example", ".invalid", ".localhost")
# A question's word is kept only if it looks like this: letters and digits with a
# little inner punctuation, so no paths, e-mail addresses, ports or markup.
_QUESTION_WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9.&'+-]{0,62}")
# Default Windows computer names (DESKTOP-4F2K9QZ, WIN-…, LAPTOP-…).
_HOST_LIKE = re.compile(r"(?:desktop|laptop|win|pc|srv|server|dc|nas|ws)-[a-z0-9-]+")
# The owner's own files: their names describe the business, not the threat. Program
# and script names (.exe, .ps1) stay, since those are what gets looked up.
_DOCUMENT_SUFFIXES = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".txt", ".csv", ".rtf",
                      ".odt", ".ods", ".jpg", ".jpeg", ".png", ".heic", ".zip", ".pst", ".ost", ".msg", ".eml", ".qbw")
_CHIT_CHAT = frozenset({"hi", "hello", "hey", "thanks", "thank", "you", "thx", "ok", "okay", "yes", "no", "cool",
                        "great", "nice", "sure", "got", "it", "bye", "good", "please"})

_lock = threading.Lock()
_cache: dict[str, tuple[float, list[dict[str, str]]]] = {}
_paused_until = 0.0
_last_request = 0.0


def search_query(alert: AlertDetail) -> str | None:
    """The web query for an alert, built from public identifiers only; None when
    the alert has none worth searching (then nothing is sent)."""
    parts: list[str] = []
    rule = alert.rule_id or ""
    windows = _WINDOWS_RULE.fullmatch(rule) if alert.source == Source.WAZUH else None
    if windows:
        provider, event_id = windows.groups()
        parts.append(f"Sysmon event ID {event_id}" if provider.endswith("Sysmon")
                     else f"Windows Security event ID {event_id}")
    elif alert.source == Source.SURICATA and _SID.fullmatch(rule):
        # A ruleset signature: its name comes from the published rule, not from
        # traffic, but is still filtered word by word below.
        parts.append(f"Suricata rule sid {rule} {_public_words(alert.title)}")
    techniques = [item for item in alert.mitre if isinstance(item, str) and _MITRE.fullmatch(item)][:2]
    if techniques:
        parts.append("MITRE ATT&CK " + " ".join(techniques))
    if not parts:
        return None
    query = " ".join(" ".join(parts).split())[:QUERY_MAX_CHARS].strip()
    if not _QUERY_ALLOWED.fullmatch(query) or _IPV4.search(query) or _IPV6.search(query):
        return None
    return query


def _public_words(text: str) -> str:
    """Words of a rule name that cannot carry an address or path: letters, digits
    and dashes only, nothing shaped like an IP or a host name."""
    words = []
    for word in text.split():
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,30}", word):
            words.append(word)
        if len(words) == 12:
            break
    return " ".join(words)


def outside_indicator(alert: AlertDetail) -> str | None:
    """The outside party of an alert, to search for: its one public IP address, else
    a public domain from the record's structured DNS/TLS/HTTP fields. None when
    there is none, or when it cannot be told apart from this network's own."""
    found = []
    for value in (alert.source_ip, alert.destination_ip):
        try:
            address = ipaddress.ip_address(str(value).strip())
        except ValueError:
            continue
        # is_global excludes private, loopback, link-local, CGNAT and reserved ranges.
        if address.is_global and not address.is_multicast and str(address) not in found:
            found.append(str(address))
    if len(found) == 1:
        return found[0]
    if found:
        # Both ends public: one is this network's own address; search neither.
        return None
    raw = alert.raw if isinstance(alert.raw, dict) else {}
    for path in (("dns", "rrname"), ("dns", "queries", 0, "rrname"), ("tls", "sni"), ("http", "hostname"),
                 ("data", "win", "eventdata", "QueryName")):
        name = _dig(raw, path)
        if isinstance(name, str):
            name = name.strip().rstrip(".").lower()
            if _DOMAIN.fullmatch(name) and not name.endswith(_INTERNAL_SUFFIXES):
                return name
    return None


def _dig(node: Any, path: tuple) -> Any:
    for step in path:
        if isinstance(step, int):
            node = node[step] if isinstance(node, list) and len(node) > step else None
        else:
            node = node.get(step) if isinstance(node, dict) else None
    return node


def indicator_query(indicator: str) -> str:
    """Quoted, so Brave matches the address itself rather than similar numbers."""
    return f'"{indicator}" abuse OR malware OR threat'


def question_query(question: str, private_names: Iterable[str] = ()) -> str | None:
    """The web query for a general chat question: the owner's own words, minus
    anything that names or addresses this network. None when nothing worth
    searching is left (a greeting, a thank-you), and then nothing is sent.

    `private_names` are names LightHouse knows belong here (device names, LightHouse
    user names, this computer's name); a word matching one is dropped, as is the
    first label of a dotted name (office-pc-7.example.com)."""
    blocked = {name.strip().lower() for name in private_names if isinstance(name, str) and name.strip()}
    words: list[str] = []
    for token in question[:QUESTION_MAX_CHARS].split():
        word = token.strip("\"'`()[]{}<>,;:!?*").rstrip(".")
        if "://" in word:
            # A pasted link: only its host may go, and only if it is a public name.
            word = (urlsplit(word).hostname or "").rstrip(".")
        lower = word.lower()
        if (not word or lower in blocked or lower.split(".")[0] in blocked or "@" in word or "\\" in word
                or "/" in word or _HOST_LIKE.fullmatch(lower) or lower.endswith(_DOCUMENT_SUFFIXES)):
            continue
        try:
            address = ipaddress.ip_address(word)
        except ValueError:
            address = None
        if address is not None:
            # An outside address the owner asks about may go; this network's never.
            if address.is_global and not address.is_multicast:
                words.append(str(address))
            continue
        if _DOMAIN.fullmatch(lower) and lower.endswith(_INTERNAL_SUFFIXES):
            continue
        if not _QUESTION_WORD.fullmatch(word):
            continue
        words.append(word)
        if len(words) == QUESTION_MAX_WORDS:
            break
    if not words or all(word.lower() in _CHIT_CHAT for word in words):
        return None
    query = ""
    for word in words:
        if len(query) + len(word) + 1 > QUERY_MAX_CHARS:
            break
        query = f"{query} {word}".strip()
    if not _QUERY_ALLOWED.fullmatch(query):
        return None
    # Last line of defence: every address left must be a public one.
    for match in _IPV4.findall(query):
        try:
            if not ipaddress.ip_address(match).is_global:
                return None
        except ValueError:
            return None
    return query


def search(query: str, key: str, transport: httpx.BaseTransport | None = None,
           count: int = RESULT_COUNT) -> list[dict[str, str]]:
    """Up to `count` cleaned results; [] on any failure. Never raises, never logs the
    key or the query's results. Cached, so a warm-up and the question that follows
    it see the same results (and the same prompt prefix)."""
    global _paused_until, _last_request
    now = time.monotonic()
    with _lock:
        hit = _cache.get(query)
        if hit and now - hit[0] < CACHE_SECONDS:
            return hit[1]
        if now < _paused_until:
            return []
        wait = _last_request + MIN_REQUEST_GAP_SECONDS - now
        _last_request = max(now, _last_request + MIN_REQUEST_GAP_SECONDS)
    if wait > 0:
        time.sleep(wait)
    try:
        with httpx.Client(timeout=SEARCH_TIMEOUT, follow_redirects=False, transport=transport) as client:
            response = client.get(BRAVE_SEARCH_URL, params={
                "q": query, "count": count, "safesearch": "strict", "text_decorations": "false"},
                headers={"Accept": "application/json", "X-Subscription-Token": key})
        if response.status_code != 200:
            raise RuntimeError(f"HTTP {response.status_code}")
        results = clean_results(response.json(), count)
    except Exception as error:
        # Type and status only: never the key, and the query is in the fixed shape.
        logger.warning("Brave web search unavailable (%s); chat answers without it for %.0f s",
                       str(error) if isinstance(error, RuntimeError) else type(error).__name__, COOLDOWN_SECONDS)
        with _lock:
            _paused_until = time.monotonic() + COOLDOWN_SECONDS
        return []
    with _lock:
        if len(_cache) >= CACHE_MAX_ENTRIES:
            _cache.pop(next(iter(_cache)))
        _cache[query] = (now, results)
    return results


def clean_results(body: Any, count: int = RESULT_COUNT) -> list[dict[str, str]]:
    """Brave's JSON is untrusted: keep only https links' title, address and snippet,
    as short plain text."""
    items = (((body or {}).get("web") or {}).get("results") or []) if isinstance(body, dict) else []
    results = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        if not isinstance(url, str) or len(url) > URL_MAX_CHARS:
            continue
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
            continue
        title, snippet = _plain(item.get("title"), TITLE_MAX_CHARS), _plain(item.get("description"), SNIPPET_MAX_CHARS)
        if not title and not snippet:
            continue
        results.append({"title": title, "url": url, "snippet": snippet})
        if len(results) == count:
            break
    return results


def _plain(value: object, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    text = " ".join(html.unescape(_TAGS.sub("", value)).split())
    return text[:limit]


def results_for(alert: AlertDetail) -> list[dict[str, str]]:
    """Web results for the alert a chat question is about, each tagged with what it
    is `about` ("this kind of alert" or the outside indicator); [] when web search
    is off (no key), there is nothing to search for, or the searches failed."""
    query, indicator = search_query(alert), outside_indicator(alert)
    if query is None and indicator is None:
        return []
    from .brave_key import load
    key = load()
    if not key:
        return []
    results: list[dict[str, str]] = []
    if query is not None:
        results += [item | {"about": "this kind of alert"} for item in search(query, key)]
    if indicator is not None:
        seen = {item["url"] for item in results}
        results += [item | {"about": indicator} for item in search(indicator_query(indicator), key,
                                                                    count=INDICATOR_RESULT_COUNT)
                    if item["url"] not in seen]
    return results


def results_for_question(question: str, alert: AlertDetail | None,
                         private_names: Iterable[str] = ()) -> list[dict[str, str]]:
    """Web results for a general chat question: its cleaned words (tagged "your
    question"), plus results_for the alert the question points at, if any. Taken in
    turn from each search, so a capped prompt keeps some of every kind. [] when web
    search is off or nothing could be searched."""
    query = question_query(question, private_names)
    if query is None and alert is None:
        return []
    from .brave_key import load
    key = load()
    if not key:
        return []
    groups: list[list[dict[str, str]]] = []
    if query is not None:
        groups.append([item | {"about": "your question"}
                       for item in search(query, key, count=QUESTION_RESULT_COUNT)])
    if alert is not None:
        found = results_for(alert)
        for about in dict.fromkeys(item["about"] for item in found):
            groups.append([item for item in found if item["about"] == about])
    merged: list[dict[str, str]] = []
    seen: set[str] = set()
    for rank in range(max((len(group) for group in groups), default=0)):
        for group in groups:
            if rank < len(group) and group[rank]["url"] not in seen:
                seen.add(group[rank]["url"])
                merged.append(group[rank])
    return merged


def enabled() -> bool:
    """Whether a Brave key is stored and decrypts (for the dashboard footer)."""
    from .brave_key import load
    return load() is not None
