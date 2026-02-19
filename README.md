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
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Project structure](#project-structure)
- [Security properties](#security-properties)
- [Development](#development)
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

What Anthropic sees is syntactically valid code with a different vocabulary. Every identifier maps to a plausible word from a 256-entry programming vocabulary; numeric fakes stay in the same order of magnitude with the same number of decimal places. Round-trip accuracy is 100%: Claude's response is deobfuscated before being displayed.

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

A single passphrase produces three independent 32-byte keys via PBKDF2 + HKDF:

```
masterKey = PBKDF2(passphrase, salt, 250 000 iterations, SHA-256)

fpeKey = HKDF(masterKey, salt, "honey:fpe:v1")    ← identifier + numeric FPE
key    = HKDF(masterKey, salt, "honey:aes-ctr:v1") ← AES-256-CTR (HE engine)
macKey = HKDF(masterKey, salt, "honey:hmac:v1")    ← HMAC-SHA-256 (HE engine)
```

A fresh 16-byte random salt is generated each time the proxy starts, providing **forward secrecy**: compromising one session's key material does not expose past or future sessions.

**Layer 2 — Format-Preserving Encryption (`src/honey/fpe.ts`)**

Each user-defined identifier is mapped to a fake name using HMAC-SHA-256 against a 256-word vocabulary:

```
words      = split(identifier)           # by casing or underscores
fakeWords  = [VOCAB[HMAC(fpeKey, w) mod 256]  for w in words]
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

**Layer 3 — Honey Encryption engine (`src/honey/engine.ts`)**

The engine encrypts a corpus index derived from a code string using AES-256-CTR + HMAC-SHA-256:

```
Encrypt(code, sessionKey):
  index    = DTE.encode(code, key)         # HMAC(key, code) mod corpus_size
  nonce    = random(16 bytes)
  cipher   = AES-256-CTR(index.bytes, key, nonce)
  tag      = HMAC-SHA-256(nonce ‖ cipher, macKey)
  payload  = base64url(nonce ‖ tag ‖ cipher)   # 52 bytes total

Decrypt(payload, sessionKey):
  parse nonce, tag, cipher from payload
  assert HMAC-SHA-256(nonce ‖ cipher, macKey) == tag   # timing-safe compare
  index = AES-256-CTR.decrypt(cipher, key, nonce)
  return DTE.decode(index)                              # corpus snippet
```

> **Architectural note:** The proxy sends FPE-obfuscated code (not AES ciphertext) to Claude so that Claude can read and improve it. The HE engine is used for (a) encrypting the identifier mapping for secure local storage, and (b) demonstrating/testing the honey encryption security property against brute-force.

### Honey Encryption property

The "honey" property (Juels & Ristenpart, EUROCRYPT 2014) means that an adversary brute-forcing the passphrase cannot distinguish the real code from decoys:

- **Correct passphrase** → correct `fpeKey` → real identifier names
- **Wrong passphrase P′** → different `fpeKey K′` → different but plausible identifier mapping → syntactically valid code that looks like a completely different project

Because AES-CTR decryption never "fails" (it always produces some output bytes), every candidate passphrase yields a plausible-looking code snippet drawn from the embedded corpus of ~60 real-world OSS snippets. The attacker sees many valid-seeming decryptions and has no way to identify the real one.

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

The proxy logs every request as structured JSON to stdout:

```json
{"level":"info","msg":"Honey proxy starting","port":8080,"sessionId":"a3f1...","upstream":"https://api.anthropic.com"}
{"level":"info","msg":"Honey proxy ready","url":"http://127.0.0.1:8080"}
{"level":"info","msg":"Obfuscated identifiers","requestId":"...","count":17}
{"level":"info","msg":"Stream complete","requestId":"...","ms":1823}
```

---

## Configuration

All configuration is via environment variables.

| Variable | Required | Default | Description |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | **Yes** | — | Your real Anthropic API key. Forwarded to `api.anthropic.com` on every request. Never logged. |
| `HONEY_PASSPHRASE` | **Yes** | — | Passphrase for session key derivation. Use a random string of ≥ 20 characters. |
| `PROXY_PORT` | No | `8080` | TCP port the proxy listens on (`127.0.0.1` only). |
| `ANTHROPIC_BASE_URL_UPSTREAM` | No | `https://api.anthropic.com` | Override the upstream endpoint (useful for testing against a stub). |
| `LOG_LEVEL` | No | `info` | Verbosity: `debug`, `info`, `warn`, or `error`. |

---

## Project structure

```
honey-encryption-proxy/
├── src/
│   ├── proxy.ts              # Bun HTTP server — main entry point
│   ├── config.ts             # Environment variable loader + validator
│   ├── logger.ts             # Structured JSON logger
│   ├── types.ts              # Result<T,E>, SessionKey, CodeBlock, IdentifierMapping
│   │
│   ├── honey/
│   │   ├── key-manager.ts    # PBKDF2(250k) + HKDF → three 32-byte sub-keys
│   │   ├── fpe.ts            # Format-Preserving Encryption: identifiers, numbers,
│   │   │                     #   string literals; 256-word vocabulary; collision avoidance
│   │   ├── dte-corpus.ts     # Distribution-Transforming Encoder (corpus variant)
│   │   └── engine.ts         # AES-256-CTR + HMAC Honey Encryption pipeline
│   │
│   ├── ast/
│   │   ├── extractor.ts      # Comment stripping; fenced code block extraction;
│   │   │                     #   user-defined identifier token scan
│   │   └── mapper.ts         # obfuscateText / deobfuscateText high-level API
│   │
│   └── corpus/
│       ├── index.ts          # Indexed access layer with safe modular wrapping
│       └── data.ts           # ~60 embedded OSS code snippets (TypeScript, Python,
│                             #   Rust, Go) used as Honey Encryption decoys
│
├── tests/
│   ├── honey.test.ts         # HE engine + key derivation (17 tests)
│   ├── dte.test.ts           # DTE, FPE, extractor, mapper end-to-end (43 tests)
│   └── proxy.test.ts         # Full pipeline integration (7 tests)
│
├── package.json
└── tsconfig.json
```

### Module responsibilities

| Module | Responsibility |
|---|---|
| `proxy.ts` | Bun HTTP server; intercepts `POST /v1/messages`; passes everything else transparently; handles streaming (SSE) |
| `config.ts` | Loads and validates env vars; returns `Result<Config>` to force explicit error handling |
| `logger.ts` | Writes structured JSON log entries; errors go to `stderr`, all others to `stdout` |
| `types.ts` | All shared interfaces and the `Result<T,E>` monad for type-safe error propagation |
| `key-manager.ts` | Derives three independent 32-byte sub-keys from a passphrase; generates fresh salt per session |
| `fpe.ts` | Identifier FPE (HMAC→vocabulary), numeric FPE (HMAC→scaled value), string-literal FPE (exact-match replacement), collision avoidance, reverse mapping |
| `dte-corpus.ts` | Maps code strings to corpus indices via HMAC; maps corpus indices back to code |
| `engine.ts` | Combines DTE + AES-CTR + HMAC-SHA256 into a complete Honey Encryption envelope |
| `extractor.ts` | Single-pass regex to strip comments (preserving strings), extract fenced code blocks, extract identifier tokens |
| `mapper.ts` | Orchestrates the full obfuscation pipeline: strip → extract → map → transform |
| `corpus/data.ts` | 60 real-world OSS snippets across TypeScript, Python, Rust, Go used as plausible HE decoys |

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
| Passphrase | PBKDF2 with 250 000 iterations; brute-force cost ~250 ms per guess |
| Session key material | Forward secrecy: fresh random salt per proxy start |
| Key separation | Three independent sub-keys (fpe, aes, hmac) via HKDF |
| Identifier mapping under brute force | Honey property: every wrong passphrase yields a different-but-plausible mapping |

### What is not protected

| Asset | Reason |
|---|---|
| Code structure and logic flow | Intentional: Claude needs structure to give useful answers |
| Import paths and file names | Outside the scope of in-prompt fenced code blocks |
| String literals whose content is not an identifier | Only exact-match identifier values are replaced |
| Request metadata (timing, token counts, model name) | Visible to Anthropic regardless of obfuscation |
| Prose text outside fenced code blocks | Left untouched so Claude understands the question context |
| API key | Required by Anthropic; forwarded on every request |

> **Phase 2 note:** Migrating from regex-based extraction to `web-tree-sitter` will enable precise extraction of type parameters, import specifiers, JSX attribute names, and decorator names — closing the remaining gaps in identifier coverage.

---

## Development

```bash
# Run the full test suite (67 tests)
bun test

# Type-check (zero errors expected; TypeScript strict mode)
bun run typecheck

# Run both — matches CI
bun run ci
```

### Running individual test files

```bash
bun test tests/honey.test.ts    # HE engine: encrypt/decrypt, key derivation, honey property
bun test tests/dte.test.ts      # DTE, FPE, comment stripping, numeric mapping, string literals
bun test tests/proxy.test.ts    # End-to-end: multi-turn, comment stripping, numeric round-trip
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

## Phase roadmap

| Phase | Status | Deliverable |
|---|---|---|
| **1** | ✅ Complete | PBKDF2/HKDF key derivation, FPE identifier mapping, Bun proxy with SSE streaming support |
| **2** | 🔄 In progress | Comment stripping, numeric FPE, string-literal FPE, multi-turn obfuscation; `web-tree-sitter` AST extraction (regex-based for now); extended corpus (~10 000 snippets from GitHub API) |
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
| Message distribution | Space of open-source code snippets (the embedded corpus) |
| DTE encode | `HMAC-SHA256(key, code) mod corpus_size` → corpus index |
| DTE decode | `corpus[index mod corpus_size]` → code snippet |
| Stream cipher | AES-256-CTR |
| Integrity (for the proxy itself) | HMAC-SHA-256 over nonce + ciphertext |
| FPE extension | Wrong passphrase → different `fpeKey` → different-but-plausible identifier names |

The FPE layer extends the honey property beyond the stored mapping to every live request: even without access to the stored ciphertext, an attacker with a wrong passphrase sees a completely different — but syntactically and stylistically plausible — version of the codebase.

### Why the DTE uses HMAC rather than sampling from a language model

The current DTE is deterministic (HMAC → index). This gives correctness guarantees and is fast, but it only approximates the ideal distribution over code — it samples from a fixed corpus rather than from the true distribution of "code a developer might write."

Phase 3 will replace this with an Arithmetic Coding DTE backed by a local language model (Ollama), which provides the statistically optimal HE-IND (Honey Encryption IND-security) guarantee: each wrong key decrypts to a sample drawn from the real distribution over code, making brute-force entirely useless even for an adversary with unbounded computational resources who can observe many ciphertexts.
