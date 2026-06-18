"""Shared blockchain chain and Alchemy capability helpers."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any


EVM_CHAIN_IDS = {
    "ethereum": 1,
    "eth": 1,
    "mainnet": 1,
    "polygon": 137,
    "arbitrum": 42161,
    "arbitrum_nova": 42170,
    "optimism": 10,
    "op_mainnet": 10,
    "base": 8453,
    "bnb": 56,
    "bsc": 56,
    "avalanche": 43114,
    "avalanche_c_chain": 43114,
    "blast": 81457,
    "sonic": 146,
    "mantle": 5000,
    "linea": 59144,
    "celo": 42220,
    "polygon_zkevm": 1101,
    "zksync": 324,
    "berachain": 80094,
    "scroll": 534352,
    "gnosis": 100,
    "opbnb": 204,
    "unichain": 130,
    "worldchain": 480,
    "world_chain": 480,
    "monad": 143,
    "sei": 1329,
    "abstract": 2741,
    "ink": 57073,
    "soneium": 1868,
    "zora": 7777777,
    "multi_evm": None,
}

NON_EVM_MARKERS = {
    "sui": "sui",
    "aptos": "aptos",
    "starknet": "starknet",
    "terra": "terra",
    "cosmos": "cosmos",
    "eos": "eos",
    "stellar": "stellar",
    "algorand": "algorand",
    "near": "near",
    "solana": "solana",
    "bitcoin": "bitcoin",
    "flow": "flow",
    "tron": "tron",
}

ALCHEMY_ADDITIONAL_EVM_CHAINS = {
    "adi",
    "alchemy",
    "alchemy_arbitrum",
    "alterscope",
    "apechain",
    "anime",
    "arc",
    "astar",
    "boba",
    "bob",
    "botanix",
    "celestiabridge",
    "citrea",
    "clankermon",
    "commons",
    "crossfi",
    "degen",
    "earnm",
    "edge",
    "frax",
    "galactica",
    "gensyn",
    "geist",
    "humanity",
    "hyperevm",
    "hyperliquid",
    "lens",
    "megaeth",
    "metis",
    "mode",
    "moonbeam",
    "mythos",
    "openloot",
    "plasma",
    "polynomial",
    "race",
    "risa",
    "rise",
    "ronin",
    "rootstock",
    "settlus",
    "shape",
    "stable",
    "standard",
    "story",
    "syndicate",
    "superseed",
    "tea",
    "tempo",
    "tron",
    "unite",
    "worldl3",
    "worldmobile",
    "worldmobilechain",
    "x_protocol",
    "xmtp",
    "zetachain",
}

ALCHEMY_SUPPORTED_CHAINS = {
    "ethereum",
    "polygon",
    "arbitrum",
    "arbitrum_nova",
    "optimism",
    "op_mainnet",
    "base",
    "bsc",
    "bnb",
    "avalanche",
    "avalanche_c_chain",
    "blast",
    "sonic",
    "mantle",
    "linea",
    "celo",
    "polygon_zkevm",
    "zksync",
    "berachain",
    "scroll",
    "gnosis",
    "opbnb",
    "unichain",
    "worldchain",
    "world_chain",
    "monad",
    "sei",
    "abstract",
    "ink",
    "soneium",
    "zora",
    "solana",
    "sui",
    "aptos",
    "starknet",
    "bitcoin",
    "flow",
    "multi_evm",
} | ALCHEMY_ADDITIONAL_EVM_CHAINS

CHAIN_RPC_ENV = {
    "ethereum": "ETH_RPC_URL",
    "eth": "ETH_RPC_URL",
    "mainnet": "ETH_RPC_URL",
    "polygon": "POLYGON_RPC_URL",
    "bsc": "BSC_RPC_URL",
    "bnb": "BSC_RPC_URL",
    "arbitrum": "ARBITRUM_RPC_URL",
    "arbitrum_nova": "ARBITRUM_NOVA_RPC_URL",
    "optimism": "OPTIMISM_RPC_URL",
    "op_mainnet": "OPTIMISM_RPC_URL",
    "base": "BASE_RPC_URL",
    "avalanche": "AVALANCHE_RPC_URL",
    "avalanche_c_chain": "AVALANCHE_RPC_URL",
    "blast": "BLAST_RPC_URL",
    "sonic": "SONIC_RPC_URL",
    "mantle": "MANTLE_RPC_URL",
    "linea": "LINEA_RPC_URL",
    "celo": "CELO_RPC_URL",
    "polygon_zkevm": "POLYGON_ZKEVM_RPC_URL",
    "zksync": "ZKSYNC_RPC_URL",
    "berachain": "BERACHAIN_RPC_URL",
    "scroll": "SCROLL_RPC_URL",
    "gnosis": "GNOSIS_RPC_URL",
    "opbnb": "OPBNB_RPC_URL",
    "unichain": "UNICHAIN_RPC_URL",
    "worldchain": "WORLDCHAIN_RPC_URL",
    "world_chain": "WORLDCHAIN_RPC_URL",
    "monad": "MONAD_RPC_URL",
    "sei": "SEI_RPC_URL",
    "abstract": "ABSTRACT_RPC_URL",
    "ink": "INK_RPC_URL",
    "soneium": "SONEIUM_RPC_URL",
    "zora": "ZORA_RPC_URL",
    "solana": "SOLANA_RPC_URL",
    "sui": "SUI_RPC_URL",
    "aptos": "APTOS_RPC_URL",
    "starknet": "STARKNET_RPC_URL",
    "bitcoin": "BITCOIN_RPC_URL",
    "flow": "FLOW_RPC_URL",
    "adi": "ADI_RPC_URL",
    "alchemy": "ALCHEMY_RPC_URL",
    "alchemy_arbitrum": "ALCHEMY_ARBITRUM_RPC_URL",
    "alterscope": "ALTERSCOPE_RPC_URL",
    "apechain": "APECHAIN_RPC_URL",
    "anime": "ANIME_RPC_URL",
    "arc": "ARC_RPC_URL",
    "astar": "ASTAR_RPC_URL",
    "boba": "BOBA_RPC_URL",
    "bob": "BOB_RPC_URL",
    "botanix": "BOTANIX_RPC_URL",
    "celestiabridge": "CELESTIABRIDGE_RPC_URL",
    "citrea": "CITREA_RPC_URL",
    "clankermon": "CLANKERMON_RPC_URL",
    "commons": "COMMONS_RPC_URL",
    "crossfi": "CROSSFI_RPC_URL",
    "degen": "DEGEN_RPC_URL",
    "earnm": "EARNM_RPC_URL",
    "edge": "EDGE_RPC_URL",
    "frax": "FRAX_RPC_URL",
    "galactica": "GALACTICA_RPC_URL",
    "gensyn": "GENSYN_RPC_URL",
    "geist": "GEIST_RPC_URL",
    "humanity": "HUMANITY_RPC_URL",
    "hyperevm": "HYPEREVM_RPC_URL",
    "hyperliquid": "HYPERLIQUID_RPC_URL",
    "lens": "LENS_RPC_URL",
    "megaeth": "MEGAETH_RPC_URL",
    "metis": "METIS_RPC_URL",
    "mode": "MODE_RPC_URL",
    "moonbeam": "MOONBEAM_RPC_URL",
    "mythos": "MYTHOS_RPC_URL",
    "openloot": "OPENLOOT_RPC_URL",
    "plasma": "PLASMA_RPC_URL",
    "polynomial": "POLYNOMIAL_RPC_URL",
    "race": "RACE_RPC_URL",
    "risa": "RISA_RPC_URL",
    "rise": "RISE_RPC_URL",
    "ronin": "RONIN_RPC_URL",
    "rootstock": "ROOTSTOCK_RPC_URL",
    "settlus": "SETTLUS_RPC_URL",
    "shape": "SHAPE_RPC_URL",
    "stable": "STABLE_RPC_URL",
    "standard": "STANDARD_RPC_URL",
    "story": "STORY_RPC_URL",
    "syndicate": "SYNDICATE_RPC_URL",
    "superseed": "SUPERSEED_RPC_URL",
    "tea": "TEA_RPC_URL",
    "tempo": "TEMPO_RPC_URL",
    "tron": "TRON_RPC_URL",
    "unite": "UNITE_RPC_URL",
    "worldl3": "WORLDL3_RPC_URL",
    "worldmobile": "WORLDMOBILE_RPC_URL",
    "worldmobilechain": "WORLDMOBILECHAIN_RPC_URL",
    "x_protocol": "X_PROTOCOL_RPC_URL",
    "xmtp": "XMTP_RPC_URL",
    "zetachain": "ZETACHAIN_RPC_URL",
    "multi_evm": "ETH_RPC_URL",
}

ALCHEMY_NETWORK_SLUGS = {
    "ethereum": "eth-mainnet",
    "polygon": "polygon-mainnet",
    "bsc": "bnb-mainnet",
    "bnb": "bnb-mainnet",
    "arbitrum": "arb-mainnet",
    "optimism": "opt-mainnet",
    "op_mainnet": "opt-mainnet",
    "base": "base-mainnet",
    "avalanche": "avax-mainnet",
    "avalanche_c_chain": "avax-mainnet",
    "blast": "blast-mainnet",
    "sonic": "sonic-mainnet",
    "mantle": "mantle-mainnet",
    "linea": "linea-mainnet",
    "celo": "celo-mainnet",
    "polygon_zkevm": "polygonzkevm-mainnet",
    "zksync": "zksync-mainnet",
    "berachain": "berachain-mainnet",
    "solana": "solana-mainnet",
    "sui": "sui-mainnet",
    "aptos": "aptos-mainnet",
}


def load_local_environment(root: Path) -> None:
    """Load local ABRA env files without overwriting process variables."""

    if os.environ.get("ABRA_DISABLE_LOCAL_ENV"):
        return
    for path in (root / ".env", root / ".env.local"):
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            key, value = parse_env_line(line)
            if key and value and key not in os.environ:
                os.environ[key] = value


def parse_env_line(line: str) -> tuple[str, str]:
    text = line.strip()
    if not text or text.startswith("#") or "=" not in text:
        return "", ""
    key, value = text.split("=", 1)
    key = key.strip()
    value = value.strip().strip('"').strip("'")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        return "", ""
    return key, value


def infer_chain(row: dict[str, str], replay: dict[str, str] | None = None) -> str:
    replay = replay or {}
    chain = (replay.get("chain") or row.get("chain") or "").strip().lower()
    if chain:
        return normalize_chain(chain)
    text = " ".join(
        [
            row.get("target", ""),
            row.get("protocol_slug_guess", ""),
            row.get("description", ""),
            row.get("reference_url", ""),
        ]
    ).lower()
    for marker, normalized in NON_EVM_MARKERS.items():
        if marker in text:
            return normalized
    if "polygon zkevm" in text or "polygon-zkevm" in text or "polygon_zkevm" in text:
        return "polygon_zkevm"
    if "zk sync" in text or "zksync" in text:
        return "zksync"
    if "bnb chain" in text or "pancake" in text:
        return "bsc"
    for marker in EVM_CHAIN_IDS:
        if marker != "base" and marker in text:
            return normalize_chain(marker)
    if "base" in text:
        return "base"
    return "ethereum"


def normalize_chain(chain: str) -> str:
    normalized = chain.strip().lower().replace(" ", "_").replace("-", "_")
    if normalized in {"eth", "mainnet"}:
        return "ethereum"
    if normalized in {"op", "optimism_mainnet"}:
        return "optimism"
    if normalized in {"bnb_chain", "binance", "bnb_smart_chain"}:
        return "bsc"
    if normalized in {"polygon_zkevm", "polygonzkevm"}:
        return "polygon_zkevm"
    if normalized in {"zk_sync", "zk_sync_era", "zksync_era"}:
        return "zksync"
    if normalized in {"avalanche_c_chain", "avax"}:
        return "avalanche"
    if normalized in {"world_chain"}:
        return "worldchain"
    if normalized in {"world_mobile", "world_mobile_chain"}:
        return "worldmobilechain"
    if normalized in {"xprotocol", "x_protocol"}:
        return "x_protocol"
    if normalized in {"celestia_bridge"}:
        return "celestiabridge"
    if normalized in {"flow_evm"}:
        return "flow"
    if normalized in {"hyper_evm", "hyperliquid"}:
        return "hyperevm"
    return normalized


def chain_id(chain: str) -> int | None:
    return EVM_CHAIN_IDS.get(normalize_chain(chain))


def rpc_env_for_chain(chain: str, replay: dict[str, str] | None = None) -> str:
    replay = replay or {}
    rpc_env = str(replay.get("rpc_env") or "").strip()
    if rpc_env:
        return rpc_env
    return CHAIN_RPC_ENV.get(normalize_chain(chain), "ARCHIVE_RPC_URL")


def rpc_url_for_chain(chain: str) -> str:
    """Resolve a read-only RPC URL for ABRA evidence backfill.

    The unified Alchemy key is the provider contract for automatic evidence
    production. Legacy per-chain RPC env vars are retained only as a fallback
    when no Alchemy key is configured.
    """

    normalized = normalize_chain(chain)
    for env_name in ("ALCHEMY_RPC_URL", "ALCHEMY_MAINNET_RPC_URL", "ALCHEMY_HTTP_URL"):
        value = os.environ.get(env_name)
        if value:
            return value
    api_key = os.environ.get("ALCHEMY_API_KEY")
    network_slug = ALCHEMY_NETWORK_SLUGS.get(normalized)
    if api_key and network_slug:
        return f"https://{network_slug}.g.alchemy.com/v2/{api_key}"
    value = os.environ.get(rpc_env_for_chain(normalized))
    if value:
        return value
    return ""


def rpc_capability_state(*, provider: str, explicit_chains: list[str] | None) -> dict[str, Any]:
    normalized_provider = str(provider or "alchemy").strip().lower()
    if explicit_chains is not None:
        return {
            "provider": normalized_provider,
            "configured": True,
            "configuration_sources": ["explicit_rpc_supported_chain"],
            "supported_chains": {normalize_chain(str(chain)) for chain in explicit_chains if str(chain).strip()},
            "missing_configuration_error": "",
        }
    if normalized_provider != "alchemy":
        return {
            "provider": normalized_provider,
            "configured": False,
            "configuration_sources": [],
            "supported_chains": set(),
            "missing_configuration_error": f"unsupported_rpc_provider:{normalized_provider}",
        }
    sources = alchemy_configuration_sources()
    configured = bool(sources)
    return {
        "provider": "alchemy",
        "configured": configured,
        "configuration_sources": sources,
        "supported_chains": set(ALCHEMY_SUPPORTED_CHAINS) if configured else set(),
        "missing_configuration_error": "" if configured else "alchemy_rpc_not_configured",
    }


def alchemy_configuration_sources() -> list[str]:
    names = ("ALCHEMY_API_KEY", "ALCHEMY_RPC_URL", "ALCHEMY_MAINNET_RPC_URL", "ALCHEMY_HTTP_URL")
    return [name for name in names if os.environ.get(name)]


def chain_rpc_supported(chain: str, rpc_supported_chains: set[str]) -> bool:
    if not rpc_supported_chains:
        return False
    normalized = normalize_chain(chain)
    if normalized == "multi_evm":
        return any(chain in rpc_supported_chains for chain in EVM_CHAIN_IDS if chain != "multi_evm")
    return normalized in rpc_supported_chains
