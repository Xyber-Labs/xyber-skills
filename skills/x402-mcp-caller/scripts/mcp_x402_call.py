#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "httpx>=0.25.0",
#     "x402[evm]>=2.0.0",
# ]
# ///
"""
MCP tool caller with x402 payment support.

Usage:
    uv run mcp_x402_call.py <base_url> --list-tools
    uv run mcp_x402_call.py <base_url> <tool_name> '<json_arguments>'
    uv run mcp_x402_call.py <base_url> <tool_name> '<json_arguments>' --pay
    uv run mcp_x402_call.py <base_url> <tool_name> '<json_arguments>' --pay --network base
    uv run mcp_x402_call.py <base_url> <tool_name> '<json_arguments>' --pay --network avalanche
    uv run mcp_x402_call.py <base_url> <tool_name> '<json_arguments>' --pay --network skale

Examples:
    uv run mcp_x402_call.py https://prod.mcp-lurky.xyber.inc/mcp-server/mcp/ --list-tools
    uv run mcp_x402_call.py https://prod.mcp-lurky.xyber.inc/mcp-server/mcp/ search_tweets '{"query": "AI"}' --pay
    uv run mcp_x402_call.py http://localhost:8113/mcp/ search_token_address '{"query": "ETH"}' --pay --network avalanche

Environment variables:
    EVM_WALLET_PRIVATE_KEY - Ethereum private key for x402 payments (required with --pay)
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import sys
from typing import Any

import httpx
from eth_account import Account
from x402 import prefer_network
from x402.client import x402Client
from x402.http.clients import x402HttpxClient
from x402.mechanisms.evm.exact import register_exact_evm_client
from x402.mechanisms.evm.signers import EthAccountSigner

# Network aliases to CAIP-2 identifiers
NETWORK_ALIASES = {
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
}


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


def print_payment_info(response: httpx.Response) -> None:
    """Print decoded payment info from response headers."""
    if "payment-response" in response.headers:
        data = json.loads(base64.b64decode(response.headers["payment-response"]))
        print(f"\n[Payment] tx={data.get('transaction')} network={data.get('network')}")


async def get_mcp_session(client: httpx.AsyncClient, mcp_path: str) -> str:
    """Negotiate MCP session ID via GET request."""
    headers = {"Accept": "text/event-stream"}
    response = await client.get(mcp_path, headers=headers)
    session_id = response.headers.get("mcp-session-id")
    if not session_id:
        raise RuntimeError(f"Failed to get session ID: {response.status_code} {response.text}")
    return session_id


async def initialize_session(client: httpx.AsyncClient, mcp_path: str, session_id: str) -> None:
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
        "mcp-session-id": session_id,
    }
    response = await client.post(mcp_path, json=payload, headers=headers)
    if response.status_code >= 400:
        print(f"[Warning] Initialize returned {response.status_code}: {response.text[:500]}")
    # Don't raise - some servers may have issues but still work for tool listing


async def list_tools(client: httpx.AsyncClient, mcp_path: str, session_id: str) -> dict:
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
        "mcp-session-id": session_id,
    }
    response = await client.post(mcp_path, json=payload, headers=headers)
    if response.status_code >= 400:
        print(f"[Error] tools/list returned {response.status_code}: {response.text[:1000]}")
        return {"result": {"tools": []}}
    return parse_mcp_response(response)


async def call_tool(
    client: httpx.AsyncClient,
    mcp_path: str,
    session_id: str,
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
        "mcp-session-id": session_id,
    }
    return await client.post(mcp_path, json=payload, headers=headers)


def create_x402_client(private_key: str, preferred_network: str | None = None) -> tuple[x402Client, EthAccountSigner]:
    """Create x402 client with EVM signer and optional network preference."""
    account = Account.from_key(private_key)
    signer = EthAccountSigner(account)
    x402_client = x402Client()

    # Register EVM mechanism
    register_exact_evm_client(x402_client, signer)

    # Register network preference policy if specified
    if preferred_network:
        caip2_network = NETWORK_ALIASES.get(preferred_network.lower(), preferred_network)
        x402_client.register_policy(prefer_network(caip2_network))
        print(f"[Network] Preferred: {caip2_network}")

    return x402_client, signer


async def run_with_payment(
    base_url: str,
    tool_name: str | None,
    arguments: dict[str, Any],
    private_key: str,
    preferred_network: str | None = None
) -> None:
    """Run MCP call with x402 payment support."""
    x402_client, _ = create_x402_client(private_key, preferred_network)

    # Parse base URL to extract the MCP path
    from urllib.parse import urlparse
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    mcp_path = parsed.path or "/mcp/"

    async with x402HttpxClient(
        x402_client,
        base_url=base,
        timeout=120,
        follow_redirects=True,
    ) as client:
        # Get session
        session_id = await get_mcp_session(client, mcp_path)
        print(f"[Session] {session_id}")

        # Initialize
        await initialize_session(client, mcp_path, session_id)
        print("[Initialized]")

        if tool_name is None:
            # List tools
            result = await list_tools(client, mcp_path, session_id)
            print("\n[Available Tools]")
            tools = result.get("result", {}).get("tools", [])
            for t in tools:
                print(f"  - {t['name']}: {t.get('description', 'No description')}")
                if t.get("inputSchema", {}).get("properties"):
                    print(f"    Args: {list(t['inputSchema']['properties'].keys())}")
        else:
            # Call tool
            print(f"\n[Calling] {tool_name} with {arguments}")
            response = await call_tool(client, mcp_path, session_id, tool_name, arguments)
            print_payment_info(response)
            print(f"\n[Response] Status: {response.status_code}")
            try:
                print(json.dumps(response.json(), indent=2))
            except Exception:
                print(response.text)


async def run_without_payment(base_url: str, tool_name: str | None, arguments: dict[str, Any]) -> None:
    """Run MCP call without payment (for free tools or inspection)."""
    from urllib.parse import urlparse
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    mcp_path = parsed.path or "/mcp/"

    async with httpx.AsyncClient(base_url=base, timeout=60) as client:
        # Get session
        session_id = await get_mcp_session(client, mcp_path)
        print(f"[Session] {session_id}")

        # Initialize
        await initialize_session(client, mcp_path, session_id)
        print("[Initialized]")

        if tool_name is None:
            # List tools
            result = await list_tools(client, mcp_path, session_id)
            print("\n[Available Tools]")
            tools = result.get("result", {}).get("tools", [])
            for t in tools:
                print(f"  - {t['name']}: {t.get('description', 'No description')}")
                if t.get("inputSchema", {}).get("properties"):
                    print(f"    Args: {list(t['inputSchema']['properties'].keys())}")
        else:
            # Call tool
            print(f"\n[Calling] {tool_name} with {arguments}")
            response = await call_tool(client, mcp_path, session_id, tool_name, arguments)
            print(f"\n[Response] Status: {response.status_code}")

            if response.status_code == 402:
                print("\n[402 Payment Required] - Use --pay flag with EVM_WALLET_PRIVATE_KEY env var")
                body = response.json()
                print(json.dumps(body, indent=2))
            else:
                try:
                    print(json.dumps(response.json(), indent=2))
                except Exception:
                    print(response.text)


def main():
    parser = argparse.ArgumentParser(description="MCP tool caller with x402 payment support")
    parser.add_argument("base_url", help="MCP server URL (e.g., https://prod.mcp-lurky.xyber.inc/mcp-server/mcp/)")
    parser.add_argument("tool_name", nargs="?", help="Tool name to call (omit to list tools)")
    parser.add_argument("arguments", nargs="?", default="{}", help="JSON arguments for the tool")
    parser.add_argument("--list-tools", "-l", action="store_true", help="List available tools")
    parser.add_argument("--pay", "-p", action="store_true", help="Enable x402 payment (requires EVM_WALLET_PRIVATE_KEY)")
    parser.add_argument(
        "--network", "-n",
        choices=["base", "avalanche", "avax", "skale", "skale-base", "ethereum", "eth", "optimism", "arbitrum", "polygon"],
        help="Preferred network for payment (default: first available)"
    )

    args = parser.parse_args()

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
        private_key = os.environ.get("EVM_WALLET_PRIVATE_KEY")
        if not private_key:
            print("Error: EVM_WALLET_PRIVATE_KEY environment variable required for --pay", file=sys.stderr)
            sys.exit(1)
        asyncio.run(run_with_payment(args.base_url, tool_name, arguments, private_key, args.network))
    else:
        asyncio.run(run_without_payment(args.base_url, tool_name, arguments))


if __name__ == "__main__":
    main()
