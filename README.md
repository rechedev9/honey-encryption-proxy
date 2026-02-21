# Honey Encryption Proxy for Claude Code

A local proxy that sits between [Claude Code](https://claude.ai/code) and the Anthropic API. It intercepts every outgoing request, applies cryptographic obfuscation to proprietary source-code content, forwards the sanitised request to Anthropic, then reverses the mapping on the response before handing it back to the IDE — all transparently.

**Core guarantee:** Anthropic's servers never see your real identifier names, numeric domain constants, business-logic comments, or exact string values. Claude still receives syntactically valid, structurally intact code so its suggestions remain accurate and useful.

---

## Table of Contents

- [Why this exists](#why-this-exists)
- [What gets obfuscated](#what-gets-obfuscated)
- [How it works](#how-it-works)
  - [Request flow](#request-flow)
  - [Obfuscation pipeline detail](#obfuscation-pipeline-detail)
  - [Cryptographic layers](#cryptographic-layers)
  - [Honey Encryption property](#honey-encryption-property)
  - [Post-Quantum Cryptography](#post-quantum-cryptography)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Project structure](#project-structure)
- [Security properties](#security-properties)
- [Development](#development)
- [Operational features](#operational-features)
- [Phase roadmap](#phase-roadmap)
- [Theoretical background](#theoretical-background)

---

## Why this exists

Enterprise adoption of AI coding assistants stalls at a single objection: every prompt containing proprietary code — class names that reveal business logic, constants that expose pricing or domain models, comments that explain confidential algorithms — travels in plain text through a third-party server.

Standard mitigations (VPN, contractual DPA, on-premise models) either don't address the problem or require significant infrastructure changes. This proxy provides a **drop-in cryptographic layer** that works with the existing Claude Code CLI and requires no changes to Anthropic's infrastructure.

---

## What gets obfuscated

| Content type | Example (real → sent to Anthropic) |
|---|---|
| Identifiers (classes, functions, variables) | `InvoiceProcessor` → `ScheduleProcessor` |
| Naming-convention–aware | `calculateTax` → `computeCache`, `fraud_model` → `batch_stream` |
| Numeric domain constants | `0.21` (VAT rate) → `0.15`, `365` (payment terms) → `412` |
| String literals with identifier values | `"invoiceId"` → `"processResult"` |
| Inline comments | `// VAT rate — confidential` → stripped entirely |
| Block comments | `/* payment logic */` → replaced with whitespace |
| Multi-turn history | Fake names are consistent across user **and** assistant turns |

What Anthropic sees is syntactically valid code with a different vocabulary. Every identifier maps to a plausible word from a 267-entry programming vocabulary; numeric fakes stay in the same order of magnitude with the same number of decimal places. Round-trip accuracy is 100%: Claude's response is deobfuscated before being displayed.

---

## How it works

### Request flow

```
Claude Code (IDE)
    │  ANTHROPIC_BASE_URL=http://localhost:8080
    ▼
┌─────────────────────────────────────────────────────────────┐
│  HONEY PROXY  (localhost:8080)                              │
│                                                             │
│  For every POST /v1/messages:                               │
│                                                             │
│  1. Parse JSON body                                         │
│  2. For EACH message (user and assistant):                  │
│     a. Extract fenced code blocks                           │
│     b. Strip comments from code                             │
│     c. Collect identifiers + numeric constants              │
│     d. Build deterministic FPE mappings                     │
│     e. Apply: strip comments → remap identifiers/numbers    │
│              → obfuscate exact-match string literals        │
│  3. Forward obfuscated request to Anthropic                 │
│                                                             │
│  On response:                                               │
│  4. Reverse all fake → real mappings                        │
│  5. Return corrected response to Claude Code                │
└─────────────────────────────────────────────────────────────┘
    │  HTTPS → api.anthropic.com
    ▼
Anthropic sees: structurally valid code, wrong names,
                wrong numbers, no comments, no real strings
```

All other routes (e.g. `GET /v1/models`) are forwarded transparently without modification.

### Obfuscation pipeline detail

`obfuscateText` in `src/ast/mapper.ts` runs the following steps in order:

```
1. extractCodeBlocks(text)
   → finds all ``` ... ``` fenced blocks

2. stripComments(block.content) for each block
   → removes // and /* */ without altering string literals
   → replaces block-comment chars with spaces (preserves line numbers)

3. extractIdentifiers(strippedCode)
   → regex token scan; skips JS/TS keywords, builtins, short tokens

4. buildIdentifierMapping(identifiers, fpeKey)
   → HMAC-SHA256(fpeKey, word) → VOCAB index → fake word
   → convention-preserving: PascalCase→PascalCase, snake_case→snake_case
   → collision-free: up to 16 retry offsets per identifier

5. buildNumericMapping(strippedCode, fpeKey)
   → scans /\b\d+\.?\d*\b/
   → skips: trivial (0,1,2,…,256), HTTP status codes, years 1900–2100
   → floats: scaled by factor in [0.5, 1.5), same decimal precision
   → integers: different value in same order of magnitude

6. merge(identifierMapping, numericMapping) → fullMapping

7. transformCodeBlocks(text, block =>
     stripped = stripComments(block.content)
     applied  = applyMapping(stripped, fullMapping)      // identifiers + numbers
     return   obfuscateStringLiterals(applied, identifierMapping)  // string literals
   )
```

`deobfuscateText` simply applies `reverseMapping` to the full response text (both inside and outside code fences, since Claude often echoes identifier names in prose).

### Cryptographic layers

**Layer 1 — Key derivation (`src/honey/key-manager.ts`)**

A single passphrase produces three independent 32-byte keys via scrypt + HKDF, with an optional ML-KEM-768 hybrid strengthening step:

```
masterKey = scrypt(passphrase, salt, N=65536, r=8, p=1)   # 64 MB RAM, ~300 ms

# Optional ML-KEM-768 hybrid (post-quantum key strengthening)
kyberSeed  = HKDF(masterKey, salt, "honey:kyber:seed:v1", 64)
(pk, sk)   = ml_kem768.keygen(kyberSeed)                  # pk logged on startup
if HONEY_KYBER_CAPSULE:
  ss        = ml_kem768.decapsulate(capsule, sk)
  masterKey = masterKey XOR HKDF(ss, salt, "honey:kyber:hybrid:v1", 32)

# Three independent sub-keys via HKDF-SHA256
fpeKey = HKDF(masterKey, salt, "honey:fpe:v1")        ← identifier + numeric FPE
key    = HKDF(masterKey, salt, "honey:aes-ctr:v1")    ← AES-256-CTR (HE engine)
macKey = HKDF(masterKey, salt, "honey:hmac:v1")        ← HMAC-SHA-256 (HE + audit)
```

A fresh 32-byte random salt is generated each time the proxy starts, providing **forward secrecy**: compromising one session's key material does not expose past or future sessions.

**Why scrypt instead of PBKDF2:** scrypt is memory-hard (64 MB per derivation), making GPU/ASIC brute-force attacks orders of magnitude more expensive than the equivalent PBKDF2 iteration count. This follows the recommendation in Khan et al. (2025) for honey encryption systems.

**ML-KEM-768 operational flow:**

1. Start the proxy normally — it logs the ephemeral ML-KEM public key at startup
2. An external party encapsulates a shared secret using the public key
3. Restart the proxy with `HONEY_KYBER_CAPSULE=<base64url>` — the master key is now hybrid-strengthened against both classical and quantum brute-force

**Layer 2 — Format-Preserving Encryption (`src/honey/fpe.ts`)**

Each user-defined identifier is mapped to a fake name using HMAC-SHA-256 against a 267-word vocabulary:

```
words      = split(identifier)           # by casing or underscores
fakeWords  = [VOCAB[HMAC(fpeKey, w) mod 267]  for w in words]
fakeId     = reassemble(fakeWords, original_convention)
```

Convention mapping examples:

| Convention | Original | Fake |
|---|---|---|
| PascalCase | `InvoiceProcessor` | `ScheduleProcessor` |
| camelCase | `calculateTax` | `computeCache` |
| snake_case | `fraud_detection_model` | `batch_stream_handler` |
| SCREAMING_SNAKE | `MAX_RETRY_COUNT` | `DEFAULT_QUEUE_SIZE` |

Numeric literals use a similar HMAC derivation:

```
hash   = HMAC-SHA256(fpeKey, "num:<numStr>:<offset>")
factor = 0.5 + readUInt32BE(hash) / 2^32       # in [0.5, 1.5)
fake   = (originalValue * factor).toFixed(decimals)   # float
fake   = min + (u32 mod (max - min + 1))               # integer
```

**Layer 3 — Honey Encryption engine (`src/honey/engine.ts` + `src/honey/lwe-dte.ts`)**

The engine encrypts a corpus index derived from a code string. The default format (v2) uses **LWE-DTE** — a lattice-based encoder that provides the honey property from the hardness of the Learning With Errors problem:

```
LWE parameters: n=128, q=7681, B=5, M=53 (corpus size)

Note: deriveSecretVector and derivePublicVector use rejection sampling
(REJECTION_LIMIT = floor(2^32 / q) * q) to eliminate modular bias.

Encrypt(code, sessionKey):
  index     = DTE.encode(code, key)                # HMAC(key, code) mod M
  nonce     = random(16 bytes)
  a         = expand(nonce)                        # PRG → vector in Z_q^n
  s         = HKDF(key, nonce, n) mod q            # secret vector
  e         = sampleError(nonce, key, B)           # |e_i| ≤ B
  b         = (a·s + e + ⌊q/M⌋·index) mod q       # LWE scalar
  tag       = HMAC-SHA-256(nonce ‖ b, macKey)
  payload   = 0x02 ‖ tag(32) ‖ nonce(16) ‖ b_uint16BE(2)   # 51 bytes

Decrypt(payload, sessionKey):
  parse tag, nonce, b from payload[1:]
  assert HMAC-SHA-256(nonce ‖ b, macKey) == tag    # timing-safe compare
  a, s, e   = regenerate from nonce + key
  diff      = (b - a·s - e) mod q
  index     = round(diff · M / q) mod M
  return DTE.decode(index)                         # corpus snippet
```

**Backward-compatible formats** (v1/v0) use AES-256-CTR + HMAC for decrypting legacy payloads:

```
v1 Decrypt(payload):  # payload[0] == 0x01, 53 bytes
  parse nonce(16), tag(32), cipher(4) from payload[1:]
  assert HMAC-SHA-256(nonce ‖ cipher, macKey) == tag
  index = AES-256-CTR.decrypt(cipher, key, nonce)
  return DTE.decode(index)

v0 Decrypt(payload):  # no version byte, 52 bytes
  parse nonce(16), tag(32), cipher(4)
  (same as v1)
```

> **Architectural note:** The proxy sends FPE-obfuscated code (not LWE/AES ciphertext) to Claude so that Claude can read and improve it. The HE engine is used for (a) encrypting the identifier mapping for secure local storage, and (b) demonstrating/testing the honey encryption security property against brute-force.

### Honey Encryption property

The "honey" property (Juels & Ristenpart, EUROCRYPT 2014) means that an adversary brute-forcing the passphrase cannot distinguish the real code from decoys:

- **Correct passphrase** → correct `fpeKey` → real identifier names
- **Wrong passphrase P′** → different `fpeKey K′` → different but plausible identifier mapping → syntactically valid code that looks like a completely different project

**LWE-DTE honey property (v2):** With a wrong key s', the decryption computes `diff' = a·(s−s') + e + ⌊q/M⌋·m`. Because `a·(s−s')` is computationally indistinguishable from uniform over Z_q (by the LWE assumption), `diff'` is effectively uniform, and the recovered index is uniformly distributed over the corpus. The attacker cannot distinguish the real decryption from any other corpus entry — the honey property follows from lattice hardness rather than the stream-cipher property of AES.

**AES-CTR honey property (v1/v0):** AES-CTR decryption never "fails" (it always produces output bytes), so every candidate passphrase yields a plausible-looking code snippet drawn from the embedded corpus. This provides the classical honey guarantee.

In both cases, the attacker sees many valid-seeming decryptions from the corpus of ~53 real-world OSS snippets and has no way to identify the real one.

### Post-Quantum Cryptography

The proxy implements four layers of post-quantum protection following the "harvest now, decrypt later" threat model — an adversary recording today's traffic to break it with a future quantum computer:

| Layer | Component | Standard | Purpose |
|---|---|---|---|
| Key derivation | scrypt(N=65536) | — | Memory-hard (64 MB), resistant to GPU/ASIC brute-force |
| Key strengthening | ML-KEM-768 hybrid | FIPS 203 | Quantum-resistant key encapsulation; master key XOR'd with lattice-based shared secret |
| HE engine | LWE-DTE (n=128, q=7681) | Lattice-based | Honey property from LWE hardness, not just stream-cipher indistinguishability |
| Audit integrity | SLH-DSA-SHA2-128s | FIPS 205 | Hash-based post-quantum signatures; tamper-evident audit trail survives quantum adversaries |

**Dependency:** [`@noble/post-quantum`](https://github.com/nicklaus/noble-post-quantum) v0.2.x — pure TypeScript, no native bindings. Imports: `ml_kem768` from `@noble/post-quantum/ml-kem`, `slh_dsa_sha2_128s` from `@noble/post-quantum/slh-dsa`.

---

## Quick start

**Prerequisites:** [Bun](https://bun.sh) ≥ 1.0

```bash
# 1. Clone and install
git clone https://github.com/rechedev9/honey-encryption-proxy
cd honey-encryption-proxy
bun install

# 2. Start the proxy
ANTHROPIC_API_KEY="sk-ant-your-real-key" \
HONEY_PASSPHRASE="choose-a-strong-passphrase" \
bun run src/proxy.ts

# 3. Point Claude Code at the proxy (in a separate shell or your shell config)
export ANTHROPIC_BASE_URL="http://localhost:8080"

# That's it — use Claude Code normally.
```

The proxy logs every request as structured JSON to stdout. Log verbosity is controlled by `LOG_LEVEL` (default `info`):

```json
{"level":"info","msg":"Honey proxy starting","port":8080,"sessionId":"a3f1...","upstream":"https://api.anthropic.com"}
{"level":"info","msg":"Honey proxy ready","url":"http://127.0.0.1:8080"}
{"level":"info","msg":"Obfuscated identifiers","requestId":"...","count":17}
{"level":"info","msg":"Stream complete","requestId":"...","ms":1823}
```

Press `Ctrl-C` to stop — the proxy shuts down gracefully, completing in-flight requests before exiting.

Each request also appends an audit entry (metadata only — never real code or identifiers) to `~/.honey-proxy/audit.jsonl`.

---

## Configuration

All configuration is via environment variables.

| Variable | Required | Default | Description |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | **Yes** | — | Your real Anthropic API key. Forwarded to `api.anthropic.com` on every request. Never logged. |
| `HONEY_PASSPHRASE` | **Yes** | — | Passphrase for session key derivation. Use a random string of ≥ 20 characters. |
| `PROXY_PORT` | No | `8080` | TCP port the proxy listens on (`127.0.0.1` only). |
| `ANTHROPIC_BASE_URL_UPSTREAM` | No | `https://api.anthropic.com` | Override the upstream endpoint (useful for testing against a stub). |
| `HONEY_KYBER_CAPSULE` | No | — | Base64url-encoded ML-KEM-768 ciphertext for hybrid key strengthening. Obtain by encapsulating against the public key logged at startup. |
| `LOG_LEVEL` | No | `info` | Verbosity: `debug`, `info`, `warn`, or `error`. Messages below this threshold are suppressed. |

---

## Project structure

```
honey-encryption-proxy/
├── src/
│   ├── proxy.ts              # Bun HTTP server — main entry point
│   ├── config.ts             # Environment variable loader + validator
│   ├── logger.ts             # Structured JSON logger with level filtering
│   ├── types.ts              # Result<T,E>, SessionKey, CodeBlock, IdentifierMapping, AuditEntry
│   ├── audit.ts              # JSONL audit trail writer (~/.honey-proxy/audit.jsonl), SPHINCS+ signed
│   ├── stream-deobfuscator.ts # Chunk-boundary-safe SSE deobfuscation
│   │
│   ├── honey/
│   │   ├── key-manager.ts    # scrypt + HKDF + ML-KEM-768 hybrid → three 32-byte sub-keys
│   │   ├── fpe.ts            # Format-Preserving Encryption: identifiers, numbers,
│   │   │                     #   string literals; 267-word vocabulary; collision avoidance
│   │   ├── dte-corpus.ts     # Distribution-Transforming Encoder (corpus variant)
│   │   ├── lwe-dte.ts        # LWE-based DTE: n=128, q=7681, B=5; rejection sampling;
│   │   │                     #   honey via lattice hardness
│   │   └── engine.ts         # LWE-DTE + AES-CTR HE pipeline (v2/v1/v0 wire formats)
│   │
│   ├── ast/
│   │   ├── extractor.ts      # Comment stripping; fenced code block extraction;
│   │   │                     #   user-defined identifier token scan
│   │   ├── tree-sitter.ts    # web-tree-sitter AST extraction (initTreeSitter,
│   │   │                     #   extractIdentifiersAST); regex fallback in extractor
│   │   └── mapper.ts         # obfuscateText / deobfuscateText high-level API;
│   │                         #   returns Result<MapResult>
│   │
│   └── corpus/
│       ├── index.ts          # Indexed access layer with safe modular wrapping
│       └── data.ts           # ~53 embedded OSS code snippets (TypeScript, Python,
│                             #   Rust, Go) used as Honey Encryption decoys
│
├── tests/
│   ├── honey.test.ts         # HE engine + key derivation + LWE-DTE + versioned format (16 tests)
│   ├── dte.test.ts           # DTE, FPE, extractor, mapper end-to-end (52 tests)
│   ├── proxy.test.ts         # Full pipeline integration (11 tests)
│   ├── logger.test.ts        # Log-level filtering (7 tests)
│   ├── audit.test.ts         # JSONL audit writer + SPHINCS+ signatures (9 tests)
│   ├── stream-deobfuscator.test.ts  # SSE chunk-boundary handling (7 tests)
│   ├── tree-sitter.test.ts   # AST extraction via web-tree-sitter (45 tests)
│   ├── config.test.ts        # Env var loading + validation (7 tests — added Phase 2)
│   └── setup.ts              # Test preload: initializes tree-sitter WASM
│
├── package.json
└── tsconfig.json
```

### Module responsibilities

| Module | Responsibility |
|---|---|
| `proxy.ts` | Bun HTTP server; intercepts `POST /v1/messages`; passes everything else transparently; handles streaming (SSE); graceful shutdown on SIGINT/SIGTERM |
| `config.ts` | Loads and validates env vars; returns `Result<Config>` to force explicit error handling |
| `logger.ts` | Structured JSON logger with level-based filtering (`setLogLevel`/`getLogLevel`); errors go to `stderr`, all others to `stdout` |
| `types.ts` | All shared interfaces (`Result<T,E>`, `SessionKey`, `IdentifierMapping`, `AuditEntry`) for type-safe error propagation |
| `audit.ts` | Fire-and-forget JSONL audit writer with SLH-DSA-SHA2-128s (SPHINCS+) tamper-evident signatures; canonical JSON field ordering for deterministic signing; appends metadata-only entries to `~/.honey-proxy/audit.jsonl` |
| `stream-deobfuscator.ts` | Buffers SSE chunks on `\n\n` boundaries so identifiers split across TCP chunks are deobfuscated correctly |
| `key-manager.ts` | scrypt(N=65536) + HKDF key derivation with optional ML-KEM-768 hybrid strengthening; derives three 32-byte sub-keys; zeroes sensitive material after use |
| `fpe.ts` | Identifier FPE (HMAC→267-word vocabulary), numeric FPE (HMAC→scaled value), string-literal FPE (exact-match replacement), collision avoidance, reverse mapping |
| `dte-corpus.ts` | Maps code strings to corpus indices via HMAC; maps corpus indices back to code |
| `lwe-dte.ts` | LWE-based Distribution-Transforming Encoder (n=128, q=7681, B=5); rejection sampling eliminates modular bias; honey property via lattice hardness |
| `engine.ts` | Combines DTE + LWE/AES-CTR + HMAC-SHA256 into a versioned Honey Encryption envelope (v2 LWE-DTE default, v1/v0 AES-CTR backward compat) |
| `extractor.ts` | Single-pass regex to strip comments (preserving strings), extract fenced code blocks, extract identifier tokens |
| `mapper.ts` | Orchestrates the full obfuscation pipeline: strip → extract → map → transform; returns `Result<MapResult>` with `ObfuscationStats` for audit |
| `tree-sitter.ts` | web-tree-sitter AST extraction (`initTreeSitter`, `extractIdentifiersAST`); used by `extractor.ts` with regex fallback |
| `corpus/data.ts` | 53 real-world OSS snippets across TypeScript, Python, Rust, Go used as plausible HE decoys |

---

## Security properties

### What is protected

| Asset | Mechanism |
|---|---|
| Class, function, and variable names | FPE: deterministic HMAC → vocabulary word mapping |
| Naming conventions (PascalCase, camelCase, …) | Preserved by convention-aware split + reassemble |
| Numeric domain constants (VAT rates, timeouts, limits) | FPE: HMAC-derived scale factor, same decimal precision |
| String literals whose content is an identifier | Exact-match replacement inside `"..."`, `'...'`, `` `...` `` |
| Inline comments (`// VAT rate — confidential`) | Stripped entirely before forwarding |
| Block comments (`/* internal pricing logic */`) | Replaced with whitespace (line numbers preserved) |
| Multi-turn conversation history | Consistent fake names across user **and** assistant messages |
| Passphrase | scrypt(N=65536, r=8, p=1) — 64 MB RAM per derivation; brute-force cost ~300 ms per guess |
| Session key material | Forward secrecy: fresh 32-byte random salt per proxy start |
| Key separation | Three independent sub-keys (fpe, aes, hmac) via HKDF |
| Quantum resistance (key derivation) | ML-KEM-768 hybrid: master key XOR'd with lattice-based shared secret (FIPS 203) |
| Quantum resistance (HE engine) | LWE-DTE: honey property from lattice hardness, not stream-cipher indistinguishability |
| Identifier mapping under brute force | Honey property: every wrong passphrase yields a different-but-plausible mapping |
| Streaming chunk boundaries | `StreamDeobfuscator` buffers on SSE `\n\n` delimiters so split identifiers never leak to the client |
| Audit trail | JSONL log at `~/.honey-proxy/audit.jsonl` records only counts and metadata — never real or fake names |
| Audit tamper evidence | SLH-DSA-SHA2-128s (FIPS 205) signatures on every audit entry; 7856-byte post-quantum signatures |
| Wire format evolution | Version byte in HE payloads enables algorithm rotation without breaking stored data |
| DoS protection | Identifier cap (5 000) → HTTP 413; passthrough body limit (10 MiB) → HTTP 413 |
| Audit canonicalization | Deterministic alphabetical field ordering in `canonicalizeEntry()` ensures SPHINCS+ signatures are reproducible and verifiable |

### What is not protected

| Asset | Reason |
|---|---|
| Code structure and logic flow | Intentional: Claude needs structure to give useful answers |
| Import paths and file names | Outside the scope of in-prompt fenced code blocks |
| String literals whose content is not an identifier | Only exact-match identifier values are replaced |
| Request metadata (timing, token counts, model name) | Visible to Anthropic regardless of obfuscation |
| Prose text outside fenced code blocks | Identifier names echoed in prose **are** deobfuscated in responses; however, prose in outgoing requests is not obfuscated (only code blocks are) |
| API key | Required by Anthropic; forwarded on every request |

---

## Development

```bash
# Run the full test suite (147 tests across 8 files)
bun test

# Type-check (zero errors expected; TypeScript strict mode)
bun run typecheck

# Run both — matches CI
bun run ci
```

### Running individual test files

```bash
bun test tests/honey.test.ts                # HE engine: encrypt/decrypt, key derivation, honey property, versioned format
bun test tests/dte.test.ts                  # DTE, FPE, comment stripping, numeric mapping, string literals
bun test tests/proxy.test.ts                # End-to-end: multi-turn, comment stripping, numeric round-trip
bun test tests/logger.test.ts               # Log-level filtering
bun test tests/audit.test.ts                # JSONL audit writer
bun test tests/stream-deobfuscator.test.ts  # SSE chunk-boundary deobfuscation
bun test tests/tree-sitter.test.ts          # AST extraction via web-tree-sitter
bun test tests/config.test.ts               # Env var loading + validation
```

### Manual end-to-end inspection

Start the proxy against a stub upstream to inspect obfuscated payloads without hitting the real Anthropic API:

```bash
# Terminal 1 — minimal echo server (requires netcat)
while true; do nc -l 9999 < /dev/null; done

# Terminal 2 — proxy
ANTHROPIC_API_KEY=test \
HONEY_PASSPHRASE=test \
ANTHROPIC_BASE_URL_UPSTREAM=http://localhost:9999 \
LOG_LEVEL=debug \
bun run src/proxy.ts
```

```bash
# Terminal 3 — send a request with proprietary code
curl -s http://localhost:8080/v1/messages \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-opus-4-6",
    "max_tokens": 1024,
    "messages": [{
      "role": "user",
      "content": "Review this:\n```typescript\n// VAT rate — confidential\nclass InvoiceProcessor {\n  calculateTax(amount: number): number { return amount * 0.21 }\n}\n```"
    }]
  }'
```

The body forwarded to the stub will contain:
- a different class name instead of `InvoiceProcessor`
- a different method name instead of `calculateTax`
- `0.21` replaced with a different two-decimal float
- the `// VAT rate — confidential` comment stripped

### Adding to the corpus

Open `src/corpus/data.ts` and append a new entry to the `CORPUS` array:

```typescript
{
  lang: 'typescript',
  source: 'your-oss-project',
  code: `// your code here`,
}
```

Escape any `${expr}` as `\${expr}` and any nested backticks as `` \` `` since entries are template literals.

---

## Operational features

These features harden the proxy for daily use beyond demo scenarios.

### Log-level filtering

`LOG_LEVEL` controls which messages reach stdout/stderr. Set to `error` for quiet production use, `debug` for troubleshooting. The priority order is `debug < info < warn < error` — any message below the configured threshold is suppressed.

### Graceful shutdown

`SIGINT` (Ctrl-C) and `SIGTERM` trigger a clean shutdown: the proxy calls `server.stop()`, logs the event, and exits with code 0. No requests are dropped mid-stream.

### Versioned HE wire format

The Honey Encryption engine supports three wire format versions. The encrypt path always produces v2 (LWE-DTE); the decrypt path auto-detects the version from the first byte:

| Version | Byte | Layout | Size | Algorithm |
|---|---|---|---|---|
| **v2** (default) | `0x02` | version(1) + HMAC(32) + nonce(16) + b_uint16BE(2) | 51 B | LWE-DTE |
| v1 | `0x01` | version(1) + nonce(16) + HMAC(32) + ciphertext(4) | 53 B | AES-256-CTR |
| v0 (legacy) | none | nonce(16) + HMAC(32) + ciphertext(4) | 52 B | AES-256-CTR |

v1 and v0 are retained for backward compatibility with previously stored payloads.

### Audit trail

Every proxied request appends a JSONL entry to `~/.honey-proxy/audit.jsonl` containing only metadata, signed with SLH-DSA-SHA2-128s (SPHINCS+):

```json
{
  "timestamp": "2026-02-20T14:32:01.123Z",
  "requestId": "a1b2c3d4-...",
  "sessionId": "f9e8d7c6-...",
  "identifiersObfuscated": 12,
  "numbersObfuscated": 3,
  "durationMs": 1823,
  "streaming": true,
  "upstreamStatus": 200,
  "signature": "AgE...base64url...",
  "sigAlgorithm": "slh-dsa-sha2-128s"
}
```

**Security invariant:** The audit log never contains real identifier names, fake names, or code content — only counts and timing.

**Tamper-evident signing:** Each audit entry is signed with SLH-DSA-SHA2-128s (FIPS 205), a hash-based post-quantum signature scheme. The signing key is derived via `HKDF(macKey, "honey:slh-dsa:salt", "honey:slh-dsa:v1", 48)` at proxy startup. Signatures are ~7856 bytes (~10.5 KB base64url). Signing is fire-and-forget — it does not block request processing.

**Offline verification:** Extract the `signature` field, reconstruct the entry without it, and verify against the session's SLH-DSA public key (logged at startup) to detect any post-hoc modification.

### Chunk-boundary-safe streaming

SSE responses from Anthropic are deobfuscated using a `StreamDeobfuscator` that buffers on `\n\n` event boundaries. This prevents a fake identifier split across two TCP chunks from leaking to the client as two unrecognised halves. Complete events are deobfuscated and forwarded immediately; the trailing incomplete fragment is held back until the next chunk or stream end.

---

## Phase roadmap

| Phase | Status | Deliverable |
|---|---|---|
| **1** | ✅ Complete | scrypt/HKDF key derivation, ML-KEM-768 hybrid, FPE identifier mapping, Bun proxy with SSE streaming |
| **2** | ✅ Complete | Comment/numeric/string FPE, LWE-DTE v2 engine (n=128, rejection sampling), SPHINCS+ audit signing with canonical JSON, `web-tree-sitter` AST extraction, security hardening (identifier cap, body limit, audit canonicalization) |
| **3** | Planned | Arithmetic Coding DTE backed by a local Ollama model — statistically optimal HE-IND guarantee replacing the HMAC corpus DTE |
| **4** | Planned | TEE (Trusted Execution Environment) deployment; proxy attestation so the operator can prove to users that the proxy binary has not been tampered with |

---

## Theoretical background

This project implements the Honey Encryption scheme introduced by Ari Juels and Thomas Ristenpart at EUROCRYPT 2014:

> *"Honey Encryption: Security Beyond the Brute-Force Bound"*
> Juels & Ristenpart, EUROCRYPT 2014.
> https://eprint.iacr.org/2014/166

### Classic symmetric encryption vs Honey Encryption

**Classic symmetric encryption** fails against brute force when the keyspace is small (passwords, passphrases). A wrong key produces garbled ciphertext that is trivially identified as wrong, so an attacker can enumerate candidate keys and detect the correct one immediately.

**Honey Encryption** adds a Distribution-Transforming Encoder (DTE):

```
encode: message (from known distribution D) → uniform random seed
decode: any seed → plausible message from D
```

Combined with a standard stream cipher:

```
encrypt(m, pw):  seed = DTE.encode(m);  c = StreamCipher(seed, KDF(pw));  return c
decrypt(c, pw'): seed = StreamCipher(c, KDF(pw'));  return DTE.decode(seed)
```

With a wrong password `pw′`, `StreamCipher(c, KDF(pw′))` produces a different but uniformly distributed seed, and `DTE.decode` maps it to a different but **plausible** message. The attacker sees only plausible-looking decryptions and cannot identify the real one.

### This implementation

| HE component | Implementation |
|---|---|
| Message distribution | Space of open-source code snippets (the embedded corpus of 53 entries) |
| DTE encode | `HMAC-SHA256(key, code) mod corpus_size` → corpus index |
| DTE decode | `corpus[index mod corpus_size]` → code snippet |
| HE cipher (v2, default) | LWE-DTE (n=128, q=7681, B=5) — honey from lattice hardness; rejection sampling |
| HE cipher (v1/v0, compat) | AES-256-CTR |
| Integrity | HMAC-SHA-256 over nonce + ciphertext/LWE scalar |
| Memory-hard KDF | scrypt(N=65536, r=8, p=1) — 64 MB RAM |
| PQ key derivation | ML-KEM-768 hybrid (FIPS 203) — optional capsule-based strengthening |
| Audit integrity | SLH-DSA-SHA2-128s (FIPS 205) — post-quantum tamper-evident signatures |
| FPE extension | Wrong passphrase → different `fpeKey` → different-but-plausible identifier names |

The FPE layer extends the honey property beyond the stored mapping to every live request: even without access to the stored ciphertext, an attacker with a wrong passphrase sees a completely different — but syntactically and stylistically plausible — version of the codebase.

### Why the DTE uses HMAC rather than sampling from a language model

The current DTE is deterministic (HMAC → index). This gives correctness guarantees and is fast, but it only approximates the ideal distribution over code — it samples from a fixed corpus rather than from the true distribution of "code a developer might write." The v2 LWE-DTE engine strengthens the honey property by deriving indistinguishability from lattice hardness rather than stream-cipher properties.

Phase 3 will replace the HMAC corpus DTE with an Arithmetic Coding DTE backed by a local language model (Ollama), which provides the statistically optimal HE-IND (Honey Encryption IND-security) guarantee: each wrong key decrypts to a sample drawn from the real distribution over code, making brute-force entirely useless even for an adversary with unbounded computational resources who can observe many ciphertexts.
