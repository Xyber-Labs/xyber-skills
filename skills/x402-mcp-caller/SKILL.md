---
name: x402-mcp-caller
description: Use this skill to call MCP server tools with x402 crypto payment support. Enables testing and interacting with paid MCP services across multiple EVM blockchain networks (Base, Avalanche, SKALE, Ethereum, Optimism, Arbitrum, Polygon). Invoke when user wants to test MCP servers, make paid API calls, or interact with x402-enabled services.
---

# X402 MCP Tool Caller

This skill enables calling MCP (Model Context Protocol) server tools with automatic x402 payment handling. It supports paid services that require cryptocurrency payments on EVM-compatible blockchains.

## When to Use

- Testing MCP servers that implement x402 payment protocol
- Making paid API calls to MCP services
- Listing available tools on an MCP server
- Interacting with x402-enabled services across different blockchain networks

## Prerequisites

- `EVM_WALLET_PRIVATE_KEY` environment variable must be set for paid calls
- The wallet must have sufficient funds on the target network

## Usage

The skill uses the script at `scripts/mcp_x402_call.py`.

### List Available Tools

```bash
uv run scripts/mcp_x402_call.py <server_url> --list-tools
```

### Call a Tool (Free)

```bash
uv run scripts/mcp_x402_call.py <server_url> <tool_name> '<json_arguments>'
```

### Call a Tool (With Payment)

```bash
uv run scripts/mcp_x402_call.py <server_url> <tool_name> '<json_arguments>' --pay
```

### Specify Network

```bash
uv run scripts/mcp_x402_call.py <server_url> <tool_name> '<json_arguments>' --pay --network <network>
```

Available networks: `base`, `avalanche`, `skale`, `ethereum`, `optimism`, `arbitrum`, `polygon`

## Examples

```bash
# List tools on a server
uv run scripts/mcp_x402_call.py https://prod.mcp-lurky.xyber.inc/mcp-server/mcp/ --list-tools

# Search tweets with payment on Base network (default)
uv run scripts/mcp_x402_call.py https://prod.mcp-lurky.xyber.inc/mcp-server/mcp/ search_tweets '{"query": "AI"}' --pay

# Call tool with payment on Avalanche
uv run scripts/mcp_x402_call.py http://localhost:8113/mcp/ search_token_address '{"query": "ETH"}' --pay --network avalanche

# Call tool on SKALE network
uv run scripts/mcp_x402_call.py https://example.com/mcp/ some_tool '{"param": "value"}' --pay --network skale
```

## Arguments Reference

| Argument | Required | Description |
|----------|----------|-------------|
| `base_url` | Yes | MCP server URL (e.g., `https://server.com/mcp/`) |
| `tool_name` | No | Tool to call (omit to list tools) |
| `arguments` | No | JSON string with tool arguments (default: `{}`) |
| `--list-tools`, `-l` | No | List available tools |
| `--pay`, `-p` | No | Enable x402 payment |
| `--network`, `-n` | No | Preferred payment network |

## Response Handling

- On success: Returns JSON response from the tool
- On 402 Payment Required: Shows payment details (use `--pay` flag)
- Payment transactions are logged with tx hash and network

## See Also

- `references/x402-protocol.md` - X402 payment protocol specification
