# Operations

Logging, shutdown and the audit trail. Moved from the "Operational features" and "Quick start" sections of the old README and checked against `src/logger.ts`, `src/proxy.ts`, `src/proxy-handler.ts` and `src/audit.ts`.

## Logging

The proxy writes one JSON object per line. `LOG_LEVEL` sets the minimum level (`debug`, `info`, `warn`, `error`; default `info`). An unrecognised value falls back to `info` without an error. `warn` and `error` lines go to stderr; `debug` and `info` go to stdout.

A start looks like this (each line also has a `time` field):

```json
{"level":"info","msg":"Honey proxy starting","port":8080,"upstream":"https://api.anthropic.com"}
{"level":"info","msg":"ML-KEM-768 public key (quantum-safe hybrid)","mlkemPublicKey":"..."}
{"level":"info","msg":"Honey proxy ready","url":"http://127.0.0.1:8080","tip":"Set ANTHROPIC_BASE_URL=http://localhost:8080 in Claude Code"}
```

Per request, at `info`:

```json
{"level":"info","msg":"Obfuscated identifiers","requestId":"...","count":17}
{"level":"info","msg":"Stream complete","requestId":"...","ms":1823}
```

`count` is the size of the mapping, which holds both identifiers and numbers. A non-streamed reply logs `Request complete` instead of `Stream complete`. The session id is logged only at `debug`. Real names, stand-ins and code are not logged. The API key and passphrase are not logged.

## Shutdown

`SIGINT` and `SIGTERM` run the same handler: it zeroes the session keys, calls `server.stop()` without forcing connections closed, and logs `Server stopped`. The handler does not call `process.exit`, so the process ends once Bun has nothing left to do. The smoke test in `tests/e2e-smoke.test.ts` accepts exit code 0 or 143 after `SIGTERM`.

## Audit trail

Each `POST /v1/messages` that reaches the upstream appends one line to `~/.honey-proxy/audit.jsonl`. For a streamed reply the line is written when the stream ends without error. The write does not block the response and a failure only logs a warning. The writer refuses to write if the file is a symlink.

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

An entry holds counts, timing and status. It never holds real names, stand-ins or code.

Each entry is signed with SLH-DSA-SHA2-128s (FIPS 205). The message signed is the canonical JSON of the entry with fields in alphabetical order and without the two signature fields. The signing key is derived at startup from `macKey` with `HKDF(macKey, "honey:slh-dsa:salt", "honey:slh-dsa:v1", 48)`. A signature is 7856 bytes, about 10.5 KB as base64url.

Limits, stated in the [threat model](threat-model.md#not-a-protection-today): the public key is not exported, `macKey` changes on every start, and entries are signed one by one, so the signatures cannot be verified from outside the running process and a deleted line leaves no trace.
