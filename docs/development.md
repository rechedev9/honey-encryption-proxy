# Development

Source layout, tests, and the roadmap. Moved from the "Project structure", "Development" and "Phase roadmap" sections of the old README and updated to the current tree.

## Setup and commands

```bash
bun install
bun test                                   # all tests
bun test tests/stream-deobfuscator.test.ts # one file
bun run dev                                # runs src/proxy.ts, needs the env vars from the README
```

Other scripts in `package.json`: `typecheck` (`tsc --noEmit`), `lint` (`bunx eslint src tests`), `format:check` (`bunx prettier --check src tests`), `build` (`bun build src/proxy.ts --outdir dist --target bun`) and `ci` (`typecheck` then `test`).

Known state of a fresh clone, checked while writing this page:

- `bun run typecheck` fails with `TS2688: Cannot find type definition file for 'bun-types'`. `tsconfig.json` lists `bun-types` but `package.json` does not depend on it. `bun run ci` therefore fails at its first step.
- `bun test` ran 186 tests in 11 files. On a loaded machine three tests in `tests/stream-integration.test.ts` timed out at the 5 second default; that file passes when run alone.
- There is no CI workflow in the repository.

### Test files

| File | Tests | Covers |
|---|---|---|
| `tests/dte.test.ts` | 52 | DTE, FPE, comment stripping, numbers, string literals, mapper |
| `tests/tree-sitter.test.ts` | 27 | AST identifier extraction |
| `tests/proxy-integration.test.ts` | 25 | Handler against a stub upstream: obfuscation, restoring, headers, limits, passthrough |
| `tests/config.test.ts` | 18 | Environment variable loading and validation |
| `tests/honey.test.ts` | 16 | Engine, key derivation, wire formats, honey behaviour |
| `tests/proxy.test.ts` | 11 | Mapper round trips |
| `tests/audit.test.ts` | 9 | JSONL writer and signatures |
| `tests/stream-integration.test.ts` | 9 | SSE through the handler |
| `tests/logger.test.ts` | 7 | Level filtering |
| `tests/stream-deobfuscator.test.ts` | 7 | Chunk boundaries |
| `tests/e2e-smoke.test.ts` | 5 | Starts the real process: ready log, public key log, SIGTERM, missing passphrase |

`tests/setup.ts` is preloaded (see `bunfig.toml`) and initialises tree-sitter. `tests/helpers/` holds a stub Anthropic server and a test proxy that uses `createProxyHandler`. To see exactly what the proxy forwards, start the stub and the test proxy from those helpers, send a request, and read `stub.lastRequestBody()`; `tests/proxy-integration.test.ts` shows how. The upstream URL in the real proxy must be `https://`, so the stub is only reachable through the test proxy.

## Source layout

```
src/
  proxy.ts               entry point: config, key derivation, Bun.serve on 127.0.0.1, shutdown
  proxy-handler.ts       request handler: POST /v1/messages rewrite, passthrough, streaming, audit call
  config.ts              environment variable loader, returns Result<Config>
  logger.ts              JSON logger with level filter
  types.ts               Result, SessionKey, CodeBlock, IdentifierMapping, AuditEntry
  audit.ts               JSONL audit writer with SLH-DSA-SHA2-128s signatures
  stream-deobfuscator.ts SSE restoring, buffered on blank lines
  honey/
    key-manager.ts       scrypt, HKDF, ML-KEM-768 step: three 32-byte keys
    fpe.ts               name, number and string-literal mapping; vocabulary; skip lists
    dte-corpus.ts        HMAC to corpus index and back (engine only)
    lwe-dte.ts           LWE-style encoder (engine only)
    engine.ts            Honey Encryption payloads, wire formats v2, v1, v0 (not used by the proxy)
  ast/
    extractor.ts         comment stripping, fenced block extraction, identifier scan
    tree-sitter.ts       web-tree-sitter extraction for typescript, javascript, tsx
    mapper.ts            global mapping and the rewrite and restore functions
  corpus/
    index.ts             indexed access with modular wrapping
    data.ts              52 open-source snippets used by the engine as decoys
```

Conventions kept in `CLAUDE.md`: `Result<T, E>` for fallible calls, the JSON logger instead of `console.log`, `ReadonlyMap` and `ReadonlySet` for mappings, `lastIndex = 0` before using a global regex.

### Adding to the corpus

Append an entry to the `CORPUS` array in `src/corpus/data.ts`:

```typescript
{
  lang: 'typescript',
  source: 'your-oss-project',
  code: `// your code here`,
}
```

Entries are template literals, so escape `${expr}` as `\${expr}` and nested backticks as `` \` ``. Changing the size of the corpus changes the engine's output for the same key.

## Roadmap

From the old README and `CLAUDE.md`. Items marked planned do not exist in the code.

| Phase | Status | Contents |
|---|---|---|
| 1 | Done | scrypt and HKDF key derivation, ML-KEM-768 step, name mapping, Bun proxy with SSE streaming |
| 2 | Done | Comment, number and string-literal handling, LWE-style engine v2, audit signing, web-tree-sitter extraction, request caps. A larger corpus is still open. |
| 3 | Planned | Arithmetic-coding encoder backed by a local Ollama model, to replace the HMAC corpus encoder |
| 4 | Planned | Run the proxy in a trusted execution environment, with attestation |
