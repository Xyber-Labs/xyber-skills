# X402 Payment Protocol Reference

X402 is a payment protocol that enables HTTP-based micropayments using cryptocurrency. It leverages the HTTP 402 "Payment Required" status code to facilitate machine-to-machine payments.

## Protocol Overview

### How It Works

1. **Client Request**: Client makes an HTTP request to a paid endpoint
2. **402 Response**: Server responds with HTTP 402 and payment requirements in headers
3. **Payment**: Client signs and submits payment transaction on-chain
4. **Retry with Proof**: Client retries request with payment proof in headers
5. **Service Delivery**: Server verifies payment and delivers the service

### HTTP Headers

#### Request Headers (with payment)

| Header | Description |
|--------|-------------|
| `X-Payment` | Base64-encoded payment proof containing signed transaction |

#### Response Headers (402 Payment Required)

| Header | Description |
|--------|-------------|
| `X-Payment-Required` | Base64-encoded JSON with payment requirements |

Payment requirements include:
- `amount`: Required payment amount (in smallest unit, e.g., wei)
- `currency`: Token contract address or native currency identifier
- `network`: CAIP-2 network identifier (e.g., `eip155:8453` for Base)
- `recipient`: Payment recipient address
- `facilitator`: Optional payment facilitator URL

#### Response Headers (successful payment)

| Header | Description |
|--------|-------------|
| `Payment-Response` | Base64-encoded JSON with transaction details |

## Supported Networks

The x402 protocol supports multiple EVM-compatible networks:

| Network | CAIP-2 Identifier | Chain ID |
|---------|-------------------|----------|
| Ethereum Mainnet | `eip155:1` | 1 |
| Base | `eip155:8453` | 8453 |
| Avalanche C-Chain | `eip155:43114` | 43114 |
| SKALE | `eip155:1187947933` | 1187947933 |
| Optimism | `eip155:10` | 10 |
| Arbitrum One | `eip155:42161` | 42161 |
| Polygon | `eip155:137` | 137 |

## Payment Mechanisms

### EVM Exact Payment

The primary payment mechanism for EVM chains. Supports:

- **Native currency** (ETH, AVAX, etc.)
- **ERC-20 tokens** (USDC, USDT, etc.)

### Payment Flow

```
┌────────┐     1. Request      ┌────────┐
│ Client │ ─────────────────▶  │ Server │
│        │                     │        │
│        │  ◀───────────────── │        │
│        │  2. 402 + Payment   │        │
│        │     Requirements    │        │
│        │                     │        │
│        │  3. Sign & Submit   │        │
│        │     Transaction     │        │
│        │         │           │        │
│        │         ▼           │        │
│        │    ┌─────────┐      │        │
│        │    │Blockchain│     │        │
│        │    └─────────┘      │        │
│        │                     │        │
│        │  4. Retry with      │        │
│        │     Payment Proof   │        │
│        │ ─────────────────▶  │        │
│        │                     │        │
│        │  ◀───────────────── │        │
│        │  5. Service         │        │
└────────┘     Response        └────────┘
```

## Python Client Library

The `x402` Python library provides client-side implementation:

```python
from x402.client import x402Client
from x402.http.clients import x402HttpxClient
from x402.mechanisms.evm.exact import register_exact_evm_client
from x402.mechanisms.evm.signers import EthAccountSigner
from eth_account import Account

# Create signer from private key
account = Account.from_key(private_key)
signer = EthAccountSigner(account)

# Create x402 client
client = x402Client()
register_exact_evm_client(client, signer)

# Use with httpx
async with x402HttpxClient(client, base_url="https://api.example.com") as http:
    response = await http.post("/paid-endpoint", json=data)
```

### Network Preference

```python
from x402 import prefer_network

# Prefer Base network for payments
client.register_policy(prefer_network("eip155:8453"))
```

## MCP Integration

When integrated with MCP (Model Context Protocol) servers:

1. MCP server exposes tools via JSON-RPC
2. Some tools require x402 payment
3. Client wraps MCP calls with x402 payment handling
4. Payment is automatic when server returns 402

### MCP Session Flow

```
1. GET /mcp/ → Receive mcp-session-id header
2. POST initialize → Establish protocol version
3. POST tools/list → Get available tools
4. POST tools/call → Call tool (may require payment)
```

## Security Considerations

- **Private keys**: Never expose in code, use environment variables
- **Transaction signing**: All signing happens client-side
- **Payment verification**: Servers verify on-chain transactions
- **Facilitators**: Optional trusted third parties for payment processing

## Resources

- [X402 Protocol Specification](https://x402.org)
- [x402 Python Library](https://pypi.org/project/x402/)
- [MCP Protocol](https://modelcontextprotocol.io)
- [CAIP-2 Chain IDs](https://chainagnostic.org/CAIPs/caip-2)
