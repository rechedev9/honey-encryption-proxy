# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

A Honey Encryption proxy for Claude Code. It sits between the Claude Code CLI and the Anthropic API (`localhost:8080`), applying Format-Preserving Encryption (FPE) to obfuscate proprietary identifiers in code before they reach Anthropic's servers. Responses are deobfuscated transparently before reaching the user.

## Commands

| Task | Command |
|---|---|
| Run proxy | `ANTHROPIC_API_KEY=sk-ant-... HONEY_PASSPHRASE=secret bun run src/proxy.ts` |
| Type check | `bun run typecheck` |
| Tests (all 147) | `bun test` |
| Single test file | `bun test tests/honey.test.ts` |
| CI (typecheck + tests) | `bun run ci` |
| Build | `bun build src/proxy.ts --outdir dist --target bun` |

Always run `bun run typecheck` after TypeScript changes.

## Architecture

### Request flow (POST /v1/messages only; everything else is passthrough)

```
Claude Code → Proxy → [obfuscate messages] → Anthropic
Claude Code ← Proxy ← [deobfuscate response] ← Anthropic
```

### Three-layer crypto stack

1. **Key derivation** (`src/honey/key-manager.ts`) — scrypt(N=65536, r=8, p=1) + HKDF produces three independent 32-byte sub-keys (`fpeKey`, `key`, `macKey`) from a single passphrase. Optional ML-KEM-768 hybrid key strengthening via `HONEY_KYBER_CAPSULE` env var. Fresh 32-byte random salt per proxy start (forward secrecy).

2. **FPE** (`src/honey/fpe.ts`) — HMAC-SHA256 maps each identifier word to a 267-word vocabulary. Convention-preserving (camelCase→camelCase, snake_case→snake_case). Numeric literals get HMAC-derived scale factors. String literals with identifier values get exact-match replacement. Collision avoidance via up to 16 retry offsets.

3. **Honey Encryption engine** (`src/honey/engine.ts` + `src/honey/lwe-dte.ts` + `src/honey/dte-corpus.ts`) — v2 LWE-DTE + HMAC (default), with v1/v0 AES-256-CTR backward compat. LWE params: n=128, q=7681, B=5 (demo-grade; production uses n≥512). Rejection sampling eliminates modular bias in vector derivation. The DTE maps code→corpus index via HMAC. **Not used in the proxy pipeline** — exists to demonstrate/test the honey property and for future secure storage of mappings. Claude receives FPE'd code, not ciphertext.

### Obfuscation pipeline (`src/ast/mapper.ts` orchestrates)

`obfuscateText`: extract code blocks → strip comments → extract identifiers → build FPE mappings (identifiers + numbers) → apply mappings → obfuscate string literals.

`deobfuscateText`: reverse-map fake→real across the full response text (both code and prose, since Claude echoes identifiers in explanations).

### Streaming

`StreamDeobfuscator` (`src/stream-deobfuscator.ts`) buffers SSE chunks on `\n\n` boundaries so identifiers split across TCP chunks are deobfuscated correctly.

### Config

All via env vars. Required: `ANTHROPIC_API_KEY`, `HONEY_PASSPHRASE`. Optional: `PROXY_PORT` (default 8080), `ANTHROPIC_BASE_URL_UPSTREAM`, `LOG_LEVEL`, `HONEY_KYBER_CAPSULE` (base64url ML-KEM-768 ciphertext for hybrid key strengthening). Config is loaded as `Result<Config>` — forced error handling.

## Key Patterns

- **`Result<T, E>`** in `src/types.ts` — used for all fallible operations (`ok(value)` / `err(error)`). Check `.ok` before accessing `.value`. Propagated through `buildIdentifierMapping` → `obfuscateText` / `buildGlobalMapping` → `obfuscateMessages`; proxy returns HTTP 413 when the identifier cap (5 000) is exceeded.
- **Structured JSON logger** (`src/logger.ts`) — use `logger.debug/info/warn/error()`, never `console.log`.
- **Audit trail** (`src/audit.ts`) — fire-and-forget JSONL to `~/.honey-proxy/audit.jsonl`. Metadata only, never real/fake names. Signed with SLH-DSA-SHA2-128s (SPHINCS+) over a canonical JSON representation (alphabetical field order, signature fields excluded) for deterministic tamper evidence.
- **ML-KEM-768 public key** — logged at startup for external encapsulation; hybrid key strengthening via `HONEY_KYBER_CAPSULE`.
- **`ReadonlyMap` / `ReadonlySet`** everywhere for identifier mappings — mutations happen only during construction.

## Gotchas

- **Template literals in `src/corpus/data.ts`**: When adding corpus entries, escape `${expr}` as `\${expr}` and nested backticks as `` \` `` since entries are template literals.
- **Regex `lastIndex` reset**: All module-level RegExp objects with the `g` flag need `lastIndex = 0` before use (already done, but maintain this pattern).
- **Identifier skip-list** in `fpe.ts`: JS/TS keywords and builtins are excluded from obfuscation. Update `SKIP_WORDS` if adding support for new languages.
- **Numeric FPE skip rules**: Trivial numbers (0–256), HTTP status codes (explicit set), and calendar years (1900–2100) are never obfuscated.
- **`decryptHoneyUnsafe`** in `engine.ts`: skips HMAC — test/demo only, never in request path.
- **Passthrough body limit**: Non-GET/HEAD passthrough routes reject `Content-Length` > 10 MiB with 413.

## Phase Roadmap

1. ✅ scrypt/HKDF, ML-KEM-768 hybrid, FPE + proxy with SSE streaming
2. ✅ Comment/numeric/string FPE, LWE-DTE v2 engine, SPHINCS+ audit signing, pentest hardening (done; `web-tree-sitter` AST and larger corpus pending)
3. Planned — Arithmetic Coding DTE with Ollama (local LLM distribution)
4. Planned — TEE deployment
