#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "httpx>=0.25.0",
#     "x402>=2.0.0",
#     "solana>=0.35.0",
#     "solders>=0.21.0",
# ]
# ///
"""
MCP tool caller with x402 payment support (EVM and Solana).

Usage:
    uv run mcp_x402_call.py <base_url> --list-tools
    uv run mcp_x402_call.py <base_url> <tool_name> '<json_arguments>'
    uv run mcp_x402_call.py <base_url> <tool_name> '<json_arguments>' --pay
    uv run mcp_x402_call.py <base_url> <tool_name> '<json_arguments>' --pay --network base
    uv run mcp_x402_call.py <base_url> <tool_name> '<json_arguments>' --pay --network solana
    uv run mcp_x402_call.py <base_url> --list-tools --stateless

Examples:
    uv run mcp_x402_call.py https://prod.mcp-lurky.xyber.inc/mcp-server/mcp/ --list-tools
    uv run mcp_x402_call.py https://prod.mcp-lurky.xyber.inc/mcp-server/mcp/ search_tweets '{"query": "AI"}' --pay
    uv run mcp_x402_call.py http://localhost:8113/mcp/ search_token_address '{"query": "ETH"}' --pay --network avalanche
    uv run mcp_x402_call.py http://localhost:8101/mcp/ arxiv_search '{"query": "AI"}' --pay --network solana
    uv run mcp_x402_call.py http://localhost:8101/mcp/ --list-tools --stateless  # For stateless servers

Environment variables:
    EVM_WALLET_PRIVATE_KEY - Ethereum private key (hex) for EVM payments
    SOLANA_WALLET_PRIVATE_KEY - Solana keypair (base58) for Solana payments

Flags:
    --stateless, -s: Use stateless mode for servers configured with stateless_http=True.
                     Skips session negotiation (GET request) and sends requests directly.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import json
import os
import sys
from typing import Any
from urllib.parse import urlparse

import httpx
from eth_account import Account
from solders.keypair import Keypair
from x402 import prefer_network
from x402.client import x402Client
from x402.http.clients import x402HttpxClient
from x402.mechanisms.evm.exact import register_exact_evm_client
from x402.mechanisms.evm.signers import EthAccountSigner
from x402.mechanisms.evm.utils import NETWORK_CONFIGS
from x402.mechanisms.svm.exact import register_exact_svm_client
from x402.mechanisms.svm.signers import KeypairSigner

# =============================================================================
# CUSTOM NETWORK CONFIGURATIONS (not in x402 library by default)
# =============================================================================
# These networks need to be registered with x402 before payments can be made.
# The config must include chain_id and default_asset with address, name, version, decimals.

CUSTOM_EVM_NETWORKS = {
    # SKALE Base (L3 on Base) - Custom network
    "eip155:1187947933": {
        "chain_id": 1187947933,
        "default_asset": {
            "address": "0x85889c8c714505E0c94b30fcfcF64fE3Ac8FCb20",
            "name": "Bridged USDC (SKALE Bridge)",
            "version": "2",
            "decimals": 6,
        },
    },
    # BNB Chain (BSC) Mainnet - Using wrapped USDC for EIP-3009 support
    "eip155:56": {
        "chain_id": 56,
        "default_asset": {
            "address": "0xf3A3E4D9c163251124229Da6DC9C98D889647804",
            "name": "Wrapped USDC",
            "version": "2",
            "decimals": 6,
        },
    },
    # Sei Network Mainnet - Native USDC (Circle)
    # See: https://docs.sei.io/evm/usdc-on-sei
    "eip155:1329": {
        "chain_id": 1329,
        "default_asset": {
            "address": "0xe15fC38F6D8c56aF07bbCBe3BAf5708A2Bf42392",
            "name": "USDC",  # EIP-712 domain name from contract's name()
            "version": "2",
            "decimals": 6,
        },
    },
}


def register_custom_networks() -> None:
    """Register custom EVM networks with x402 library."""
    for network, config in CUSTOM_EVM_NETWORKS.items():
        if network not in NETWORK_CONFIGS:
            NETWORK_CONFIGS[network] = config


# Register custom networks at module load time
register_custom_networks()

# EVM network aliases (eip155:*)
EVM_NETWORK_ALIASES = {
    "base": "eip155:8453",
    "avalanche": "eip155:43114",
    "avax": "eip155:43114",
    "skale": "eip155:1187947933",
    "skale-base": "eip155:1187947933",
    "ethereum": "eip155:1",
    "eth": "eip155:1",
    "optimism": "eip155:10",
    "arbitrum": "eip155:42161",
    "polygon": "eip155:137",
    "bsc": "eip155:56",
    "bnb": "eip155:56",
    "sei": "eip155:1329",
}

# Solana network aliases (solana:*)
SOLANA_NETWORK_ALIASES = {
    "solana": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    "sol": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
}

# Combined network aliases for lookup
NETWORK_ALIASES = {**EVM_NETWORK_ALIASES, **SOLANA_NETWORK_ALIASES}


def is_solana_network(network: str) -> bool:
    """Check if a network alias or CAIP-2 identifier is a Solana network."""
    if network.startswith("solana:"):
        return True
    return network.lower() in SOLANA_NETWORK_ALIASES


def parse_mcp_response(response: httpx.Response) -> dict:
    """Parse MCP response, handling both JSON and SSE formats."""
    content_type = response.headers.get("content-type", "")
    text = response.text

    # Try to parse as JSON first
    if "application/json" in content_type:
        try:
            return response.json()
        except json.JSONDecodeError:
            pass

    # Parse SSE format: look for "data:" lines
    if "text/event-stream" in content_type or text.startswith("event:") or "data:" in text:
        for line in text.split("\n"):
            if line.startswith("data:"):
                data_str = line[5:].strip()
                if data_str:
                    try:
                        return json.loads(data_str)
                    except json.JSONDecodeError:
                        continue

    # Fallback: try to parse the whole text as JSON
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        print(f"[Warning] Could not parse response: {text[:500]}")
        return {"result": {"tools": []}}


class NetworkMismatchError(Exception):
    """Raised when payment goes to a different network than requested."""
    pass


def normalize_network(network: str) -> str:
    """Normalize network identifier to CAIP-2 format for comparison."""
    # If it's already CAIP-2 format, return as-is
    if network.startswith("eip155:") or network.startswith("solana:"):
        return network
    # Otherwise, look up the alias
    return NETWORK_ALIASES.get(network.lower(), network)


def print_payment_info(response: httpx.Response, requested_network: str | None = None) -> str | None:
    """Print decoded payment info from response headers. Returns actual network used.

    Raises:
        NetworkMismatchError: If payment went to a different network than requested.
    """
    if "payment-response" in response.headers:
        data = json.loads(base64.b64decode(response.headers["payment-response"]))
        actual_network = data.get("network")
        print(f"\n[Payment] tx={data.get('transaction')} network={actual_network}")

        # FAIL if payment went to a different network than requested
        if requested_network and actual_network:
            requested_caip2 = normalize_network(requested_network)
            actual_caip2 = normalize_network(actual_network)
            if actual_caip2 != requested_caip2:
                raise NetworkMismatchError(
                    f"Payment used {actual_network} ({actual_caip2}) instead of requested {requested_network} ({requested_caip2})!\n"
                    f"    Your {requested_caip2} balance was NOT charged.\n"
                    f"    Your {actual_caip2} balance WAS charged instead.\n"
                    f"    The server does not support payments on {requested_caip2}."
                )
        return actual_network
    return None


async def get_mcp_session(client: httpx.AsyncClient, mcp_path: str) -> str:
    """Negotiate MCP session ID via GET request."""
    headers = {"Accept": "text/event-stream"}
    response = await client.get(mcp_path, headers=headers)
    session_id = response.headers.get("mcp-session-id")
    if not session_id:
        raise RuntimeError(f"Failed to get session ID: {response.status_code} {response.text}")
    return session_id


async def initialize_session(client: httpx.AsyncClient, mcp_path: str, session_id: str | None) -> None:
    """Send MCP initialize request."""
    payload = {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {"sampling": {}, "roots": {}},
            "clientInfo": {"name": "mcp_x402_cli", "version": "1.0.0"},
        },
    }
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    if session_id:
        headers["mcp-session-id"] = session_id
    response = await client.post(mcp_path, json=payload, headers=headers)
    if response.status_code >= 400:
        print(f"[Warning] Initialize returned {response.status_code}: {response.text[:500]}")
    # Don't raise - some servers may have issues but still work for tool listing


async def list_tools(client: httpx.AsyncClient, mcp_path: str, session_id: str | None) -> dict:
    """List available MCP tools."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {},
    }
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    if session_id:
        headers["mcp-session-id"] = session_id
    response = await client.post(mcp_path, json=payload, headers=headers)
    if response.status_code >= 400:
        print(f"[Error] tools/list returned {response.status_code}: {response.text[:1000]}")
        return {"result": {"tools": []}}
    return parse_mcp_response(response)


async def call_tool(
    client: httpx.AsyncClient,
    mcp_path: str,
    session_id: str | None,
    tool_name: str,
    arguments: dict[str, Any]
) -> httpx.Response:
    """Call an MCP tool."""
    payload = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    if session_id:
        headers["mcp-session-id"] = session_id
    return await client.post(mcp_path, json=payload, headers=headers)


def create_x402_client(
    evm_private_key: str | None,
    solana_private_key: str | None,
    preferred_network: str | None = None
) -> x402Client:
    """Create x402 client with EVM and/or Solana signers based on available keys."""
    x402_client = x402Client()

    # Register EVM mechanism if key provided
    if evm_private_key:
        account = Account.from_key(evm_private_key)
        evm_signer = EthAccountSigner(account)
        register_exact_evm_client(x402_client, evm_signer)
        print(f"[EVM] Registered wallet: {account.address}")

    # Register Solana mechanism if key provided (base58 or 64-char hex seed)
    if solana_private_key:
        if len(solana_private_key) == 64 and all(c in '0123456789abcdefABCDEF' for c in solana_private_key):
            keypair = Keypair.from_seed(bytes.fromhex(solana_private_key))
        else:
            keypair = Keypair.from_base58_string(solana_private_key)
        register_exact_svm_client(x402_client, KeypairSigner(keypair))
        print(f"[Solana] Registered wallet: {keypair.pubkey()}")

    # Register network preference policy if specified
    if preferred_network:
        caip2_network = NETWORK_ALIASES.get(preferred_network.lower(), preferred_network)
        x402_client.register_policy(prefer_network(caip2_network))
        print(f"[Network] Preferred: {caip2_network}")

    return x402_client


@contextlib.asynccontextmanager
async def create_client(
    base: str,
    x402_client: x402Client | None = None,
):
    """Create HTTP client, with or without x402 payment support."""
    if x402_client:
        async with x402HttpxClient(x402_client, base_url=base, timeout=120, follow_redirects=True) as client:
            yield client
    else:
        async with httpx.AsyncClient(base_url=base, timeout=60) as client:
            yield client


async def run(
    base_url: str,
    tool_name: str | None,
    arguments: dict[str, Any],
    x402_client: x402Client | None = None,
    preferred_network: str | None = None,
    stateless: bool = False,
) -> None:
    """Run MCP call with optional x402 payment support."""
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    mcp_path = parsed.path or "/mcp/"

    async with create_client(base, x402_client) as client:
        # Get session (skip for stateless mode)
        session_id = None
        if not stateless:
            session_id = await get_mcp_session(client, mcp_path)
            print(f"[Session] {session_id}")
            await initialize_session(client, mcp_path, session_id)
            print("[Initialized]")
        else:
            print("[Stateless] Skipping session negotiation")

        if tool_name is None:
            result = await list_tools(client, mcp_path, session_id)
            print("\n[Available Tools]")
            for t in result.get("result", {}).get("tools", []):
                print(f"  - {t['name']}: {t.get('description', 'No description')}")
                if t.get("inputSchema", {}).get("properties"):
                    print(f"    Args: {list(t['inputSchema']['properties'].keys())}")
        else:
            print(f"\n[Calling] {tool_name} with {arguments}")
            response = await call_tool(client, mcp_path, session_id, tool_name, arguments)

            if x402_client:
                try:
                    print_payment_info(response, preferred_network)
                except NetworkMismatchError as e:
                    print(f"\n[NETWORK MISMATCH ERROR] {e}", file=sys.stderr)
                    sys.exit(2)

            print(f"\n[Response] Status: {response.status_code}")
            if response.status_code == 402:
                print("\n[402 Payment Required] - Use --pay flag with wallet env vars")
            try:
                print(json.dumps(response.json(), indent=2))
            except Exception:
                print(response.text)


def main():
    # All supported network choices
    all_networks = list(NETWORK_ALIASES.keys())

    parser = argparse.ArgumentParser(description="MCP tool caller with x402 payment support (EVM and Solana)")
    parser.add_argument("base_url", help="MCP server URL (e.g., https://prod.mcp-lurky.xyber.inc/mcp-server/mcp/)")
    parser.add_argument("tool_name", nargs="?", help="Tool name to call (omit to list tools)")
    parser.add_argument("arguments", nargs="?", default="{}", help="JSON arguments for the tool")
    parser.add_argument("--list-tools", "-l", action="store_true", help="List available tools")
    parser.add_argument("--pay", "-p", action="store_true", help="Enable x402 payment")
    parser.add_argument(
        "--network", "-n",
        choices=all_networks,
        help=f"Preferred network for payment. Choices: {', '.join(all_networks)}"
    )
    parser.add_argument(
        "--stateless", "-s",
        action="store_true",
        help="Use stateless mode (skip session negotiation). Use for servers with stateless_http=True"
    )

    args = parser.parse_args()

    # Validate --network requires --pay
    if args.network and not args.pay:
        print(f"Error: --network requires --pay flag", file=sys.stderr)
        sys.exit(1)

    # Parse tool name
    tool_name = None if args.list_tools or args.tool_name is None else args.tool_name

    # Parse arguments
    try:
        arguments = json.loads(args.arguments)
    except json.JSONDecodeError as e:
        print(f"Error parsing arguments JSON: {e}", file=sys.stderr)
        sys.exit(1)

    # Run
    if args.pay:
        evm_private_key = os.environ.get("EVM_WALLET_PRIVATE_KEY")
        solana_private_key = os.environ.get("SOLANA_WALLET_PRIVATE_KEY")

        # Validate required keys based on network preference
        if args.network:
            if is_solana_network(args.network):
                if not solana_private_key:
                    print(
                        f"Error: SOLANA_WALLET_PRIVATE_KEY environment variable required "
                        f"for --network {args.network}",
                        file=sys.stderr
                    )
                    sys.exit(1)
            else:
                if not evm_private_key:
                    print(
                        f"Error: EVM_WALLET_PRIVATE_KEY environment variable required "
                        f"for --network {args.network}",
                        file=sys.stderr
                    )
                    sys.exit(1)
        else:
            # No specific network - require at least one key
            if not evm_private_key and not solana_private_key:
                print(
                    "Error: At least one of EVM_WALLET_PRIVATE_KEY or SOLANA_WALLET_PRIVATE_KEY "
                    "environment variable required for --pay",
                    file=sys.stderr
                )
                sys.exit(1)

        # Only pass the relevant key based on network selection
        if args.network and is_solana_network(args.network):
            x402_client = create_x402_client(None, solana_private_key, args.network)
        elif args.network:
            x402_client = create_x402_client(evm_private_key, None, args.network)
        else:
            x402_client = create_x402_client(evm_private_key, solana_private_key, args.network)
        asyncio.run(run(args.base_url, tool_name, arguments, x402_client, args.network, args.stateless))
    else:
        asyncio.run(run(args.base_url, tool_name, arguments, stateless=args.stateless))


if __name__ == "__main__":
    main()
