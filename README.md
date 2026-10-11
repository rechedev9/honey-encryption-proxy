# Honey Encryption Proxy 🍯: Stand-in names for Claude Code prompts

[![version](https://img.shields.io/github/package-json/v/rechedev9/honey-encryption-proxy?style=flat-square)](package.json)
[![runtime](https://img.shields.io/badge/runtime-Bun-f9f1e1?style=flat-square&logo=bun&logoColor=black)](https://bun.sh)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6?style=flat-square&logo=typescript&logoColor=white)](tsconfig.json)

A local proxy that sits in front of Claude Code. Before a request leaves your machine it swaps the proprietary names and constants in the code you send for stand-ins of the same shape, strips `//` and `/* */` comments, and then puts your original names back into the streamed reply. It is for developers who want Claude's help on code whose class names, function names and domain numbers they would rather not send to a third party. It renames; it does not encrypt, and it only looks for names in fenced code in message text (see [Limits](#limits-and-threat-model)).

You write, inside a fenced block in a prompt:

```typescript
// VAT rate: confidential
class InvoiceProcessor {
  calculateTax(amount: number): number { return amount * 0.21 }
}
const paymentTerms = 365
```

The model receives:

```typescript

class WorkerGlobal {
  prepareOpen(attach: number): number { return attach * 0.14 }
}
const clonePublic = 842
```

When the reply mentions `WorkerGlobal.prepareOpen`, you see `InvoiceProcessor.calculateTax`. This is the output of `obfuscateText` in this repo with a fixed test salt. A real session picks a new random salt on every start, so the stand-ins differ each time.

## Install

You need [Bun](https://bun.sh). Run the proxy from a clone:

```bash
git clone https://github.com/rechedev9/honey-encryption-proxy
cd honey-encryption-proxy
bun install
```

## Quick start

Start the proxy with your Anthropic API key and a passphrase:

```bash
ANTHROPIC_API_KEY=sk-ant-... HONEY_PASSPHRASE=choose-a-passphrase bun run src/proxy.ts
```

It listens on `127.0.0.1:8080` and logs `Honey proxy ready` when it is up. In another shell, point Claude Code at it and use it as usual:

```bash
export ANTHROPIC_BASE_URL=http://localhost:8080
claude
```

The proxy sends its own `ANTHROPIC_API_KEY` upstream and drops the `authorization` header from the client, so requests are billed to that key and not to a Claude subscription login.

## What gets replaced

Inside fenced code blocks (lines starting with three backticks or tildes) of message text:

| Kind | What happens |
|---|---|
| Identifiers: classes, functions, variables, properties, types | Replaced by words from a fixed 267-word list, keeping camelCase, PascalCase, snake_case or SCREAMING_SNAKE |
| Numbers | Floats are scaled by 0.5 to 1.5 and keep their decimals; integers keep their digit count |
| String literals | Replaced only when the whole value is a renamed identifier, such as `"invoiceId"` |
| `//` and `/* */` comments | Removed |
| The same names in the prose around the fence | Replaced with the same stand-ins |

Not replaced: keywords, common builtins, names under 3 characters, small numbers (0 to 5, 8, 10, 16, 32, 64, 100, 128, 256), common HTTP status codes and years 1900 to 2100.

## How the reply is restored

The proxy reads the streamed reply, splits it into server-sent events, swaps each stand-in back to your original name, and forwards each event as soon as it is complete. A stand-in cut in half by a network chunk is held until the rest arrives. Details are in [docs/design.md](docs/design.md#streaming).

## Configuration

All settings are environment variables.

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | yes | none | Key the proxy sends upstream. Removed from the process environment after startup. |
| `HONEY_PASSPHRASE` | yes | none | Seeds the key that drives the name mapping. A fresh random salt is added on every start. |
| `PROXY_PORT` | no | `8080` | Listen port, on `127.0.0.1` only. |
| `ANTHROPIC_BASE_URL_UPSTREAM` | no | `https://api.anthropic.com` | Upstream base URL. Must start with `https://`. |
| `LOG_LEVEL` | no | `info` | `debug`, `info`, `warn` or `error`. |
| `HONEY_KYBER_CAPSULE` | no | none | Base64url ML-KEM-768 ciphertext. Has no useful effect today, see [docs/crypto.md](docs/crypto.md). |

## Limits and threat model

Treat anything the proxy does not rewrite as sent to Anthropic in clear text.

- **Tool results are not rewritten.** Only message strings and `text` blocks are processed. The `system` field, `tool_result` blocks (where Claude Code returns the files it reads) and `tool_use` blocks pass through unchanged. In an agentic session most code reaches Claude that way.
- **Code outside a fenced block is not discovered.** A name that appears only in prose, a path or an unfenced paste is not mapped.
- **Other routes are untouched.** Only `POST /v1/messages` is rewritten; everything else, such as `/v1/messages/count_tokens`, is forwarded as received.
- **Structure stays visible.** Control flow, types, call graph, libraries, string literals other than exact identifier values, `#` comments and the numbers listed above are sent as written.
- **Restoring is text replacement.** A stand-in split across two streamed events is not restored. A stand-in that equals a protocol word such as `data` can corrupt the stream. See [docs/threat-model.md](docs/threat-model.md).
- **The honey encryption engine is not used.** `src/honey/engine.ts` is exercised by tests only. Claude receives renamed code, never ciphertext.
- **No client authentication.** Any local process can use `127.0.0.1:8080` with your API key.

## Documentation

- [Design](docs/design.md): request flow, rewrite pipeline, numbers, streaming
- [Threat model](docs/threat-model.md): what is protected, what is not, what can go wrong when restoring
- [Cryptography](docs/crypto.md): key derivation, the honey encryption engine, post-quantum components
- [Operations](docs/operations.md): logging, shutdown, audit trail
- [Development](docs/development.md): source layout, tests, roadmap
