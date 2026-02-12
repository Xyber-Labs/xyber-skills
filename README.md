# Xyber Skills

A collection of [Agent Skills](https://agentskills.io) for Web3, crypto payments, and MCP integrations.

## What are Agent Skills?

Agent Skills are a standardized format for giving AI agents new capabilities. They consist of instructions, scripts, and resources packaged in a simple folder structure with a `SKILL.md` file.

Learn more:
- [Agent Skills Specification](https://agentskills.io/specification)
- [Anthropic Skills Repository](https://github.com/anthropics/skills)

## Available Skills

### x402-mcp-caller

Call MCP (Model Context Protocol) server tools with x402 crypto payment support across multiple EVM blockchain networks.

**Features:**
- Automatic x402 payment handling
- Support for Base, Avalanche, SKALE, Ethereum, Optimism, Arbitrum, Polygon
- List and call MCP tools
- Built-in payment verification

**Usage:**
```bash
# List available tools
uv run scripts/mcp_x402_call.py <server_url> --list-tools

# Call a tool with payment
uv run scripts/mcp_x402_call.py <server_url> <tool_name> '<json_args>' --pay --network base
```

**Requirements:**
- `EVM_WALLET_PRIVATE_KEY` environment variable for paid calls
- Python 3.12+
- uv package manager

## Installation

For Claude Code users:

```bash
/plugin marketplace add <your-username>/xyber-skills
/plugin install web3-skills@xyber-skills
```

## Structure

This repository follows the [Agent Skills specification](https://agentskills.io):

```
xyber-skills/
├── .claude-plugin/
│   └── marketplace.json    # Claude Code marketplace config
├── skills/
│   └── x402-mcp-caller/
│       ├── SKILL.md        # Skill definition
│       ├── scripts/        # Executable code
│       └── references/     # Additional documentation
└── LICENSE
```

## Protocol References

- [X402 Payment Protocol](https://x402.org)
- [Model Context Protocol (MCP)](https://modelcontextprotocol.io)

## License

MIT
