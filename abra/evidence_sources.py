"""Shared ABRA event-source and security-evidence classification."""

from __future__ import annotations

from urllib.parse import urlparse


SECURITY_REPORT_SOURCES = {
    "blocksec_phalcon": ("phalcon.blocksec.com", "app.blocksec.com"),
    "metasleuth": ("metasleuth.io",),
    "eigenphi": ("eigenphi.io",),
    "defihacklabs": ("github.com/sunweb3sec/defihacklabs",),
    "slowmist": ("slowmist.io", "slowmist_team"),
    "certik": ("certik.com",),
    "peckshield": ("peckshield", "peckshield.com"),
    "blocksec": ("blocksec", "blocksec.com"),
    "beosin": ("beosin", "beosin.com"),
    "rekt": ("rekt.news",),
    "immunefi": ("immunefi.com",),
    "chainsecurity": ("chainsecurity.com",),
    "openzeppelin": ("openzeppelin.com",),
}

SECURITY_ALERT_SOCIAL_HANDLES = {
    "certikalert": "certik",
    "peckshieldalert": "peckshield",
    "peckshield": "peckshield",
    "phalcon_xyz": "blocksec",
    "slowmist_team": "slowmist",
    "defimonalerts": "defimon",
    "blockaid_": "blockaid",
    "defi_nerd_sec": "defi_nerd",
    "exvulsec": "exvul",
}

DIRECT_CANDIDATE_SOURCE_URLS = {
    "defihacklabs_replay": ("github.com/sunweb3sec/defihacklabs",),
    "blocksec_phalcon_incidents": ("phalcon.blocksec.com", "app.blocksec.com"),
    "metasleuth_trace": ("metasleuth.io",),
    "eigenphi": ("eigenphi.io",),
}

EXPLORER_TX_DOMAINS = (
    "etherscan.io",
    "basescan.org",
    "bscscan.com",
    "arbiscan.io",
    "polygonscan.com",
    "snowtrace.io",
    "celoscan.io",
    "era.zksync.network",
    "zkevm.polygonscan.com",
    "skylens.certik.com",
)


def candidate_discovery_sources(row: dict[str, str]) -> list[dict[str, str]]:
    """Return public candidate feeds only; these are not security anchors."""

    source_url = str(row.get("source_url") or "").strip()
    source_lower = source_url.lower()
    sources: list[dict[str, str]] = []
    direct_source = direct_candidate_source(row)
    if direct_source:
        sources.append({"source": direct_source, "url": source_url, "role": "candidate_discovery"})
    if "hacked.slowmist.io" in source_lower:
        sources.append({"source": "slowmist_hacked", "url": source_url, "role": "candidate_discovery"})
    if "defillama.com/hacks" in source_lower or "api.llama.fi/hacks" in source_lower:
        sources.append({"source": "defillama_hacks", "url": source_url, "role": "candidate_discovery"})
    return sources


def security_report_sources(row: dict[str, str], card: dict[str, str] | None = None) -> list[dict[str, str]]:
    """Return URL-host anchored security/public reports, never text-only mentions."""

    card = card or {}
    reference_urls = [
        str(row.get("reference_url") or "").strip(),
        str(card.get("reference_url") or "").strip(),
    ]
    usable_reference_urls = [url for url in reference_urls if is_security_reference_url(url)]
    sources: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for url in usable_reference_urls:
        social_source = security_alert_social_source(url)
        if social_source:
            key = (social_source, url)
            if key not in seen:
                sources.append({"source": social_source, "url": url})
                seen.add(key)
            continue
        direct_tx_source = direct_tx_security_source(url)
        if direct_tx_source:
            key = (direct_tx_source, url)
            if key not in seen:
                sources.append({"source": direct_tx_source, "url": url})
                seen.add(key)
            continue
        host = url_host(url)
        for name, markers in SECURITY_REPORT_SOURCES.items():
            if any(marker_matches_host(marker, host) for marker in markers):
                key = (name, url)
                if key not in seen:
                    sources.append({"source": name, "url": url})
                    seen.add(key)
    return sources


def security_alert_social_source(url: str) -> str:
    parsed = urlparse(url.strip())
    host = (parsed.netloc or parsed.path.split("/", 1)[0]).lower().removeprefix("www.")
    if host not in {"x.com", "twitter.com"}:
        return ""
    handle = parsed.path.strip("/").split("/", 1)[0].lower()
    return SECURITY_ALERT_SOCIAL_HANDLES.get(handle, "")


def direct_tx_security_source(url: str) -> str:
    text = url.strip().lower()
    parsed = urlparse(url.strip())
    host = (parsed.netloc or parsed.path.split("/", 1)[0]).lower().removeprefix("www.")
    path = parsed.path.lower()
    if host.endswith("phalcon.blocksec.com") or host == "app.blocksec.com":
        return "blocksec_phalcon"
    if host.endswith("metasleuth.io"):
        return "metasleuth"
    if host.endswith("eigenphi.io"):
        return "eigenphi"
    if host == "skylens.certik.com":
        return "certik"
    if host == "github.com" and "sunweb3sec/defihacklabs" in path:
        return "defihacklabs"
    if "github.com/sunweb3sec/defihacklabs" in text:
        return "defihacklabs"
    return ""


def direct_candidate_source(row: dict[str, str]) -> str:
    category = str(row.get("category_filter") or "").strip().lower()
    source_url = str(row.get("source_url") or "").strip()
    if category == "defihacklabs_replay":
        return "defihacklabs_replay"
    if not source_url:
        return ""
    parsed = urlparse(source_url)
    host = (parsed.netloc or parsed.path.split("/", 1)[0]).lower().removeprefix("www.")
    path = parsed.path.lower()
    for name, markers in DIRECT_CANDIDATE_SOURCE_URLS.items():
        if any(marker_matches_host(marker, host) for marker in markers):
            return name
    if any(host == domain or host.endswith(f".{domain}") for domain in EXPLORER_TX_DOMAINS) and "/tx/" in path:
        return "explorer_tx"
    return ""


def text_only_security_mentions_ignored(row: dict[str, str], card: dict[str, str] | None = None) -> bool:
    """Detect cases where security firms are mentioned without an anchored source URL."""

    if security_report_sources(row, card):
        return False
    haystack = " ".join(
        [
            str(row.get("description") or ""),
            str(row.get("target") or ""),
            str(row.get("attack_method_raw") or ""),
        ]
    ).lower()
    for name, markers in SECURITY_REPORT_SOURCES.items():
        if name in haystack:
            return True
        for marker in markers:
            if "." not in marker and marker.lower() in haystack:
                return True
    return False


def is_security_reference_url(url: str) -> bool:
    text = url.strip().lower()
    if not text:
        return False
    if "hacked.slowmist.io" in text and ("?c=" in text or "page=" in text):
        return False
    return True


def url_host(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path.split("/", 1)[0]
    return host.lower().removeprefix("www.")


def marker_matches_host(marker: str, host: str) -> bool:
    marker_text = marker.lower().removeprefix("www.")
    if "/" in marker_text:
        return host == marker_text.split("/", 1)[0]
    if "." in marker_text:
        return host == marker_text or host.endswith(f".{marker_text}")
    return host == marker_text or host.startswith(f"{marker_text}.")
