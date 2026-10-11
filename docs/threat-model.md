# Threat model and limits

What the proxy changes in a request, and what it leaves alone. Moved from the "Security properties" section of the old README and rewritten to match `src/proxy-handler.ts`, `src/ast/` and `src/honey/fpe.ts`.

The proxy replaces names and numbers with stand-ins. It is not encryption of your code, and it is not a data loss prevention system. Treat anything it does not rewrite as sent to Anthropic in clear text.

## What the proxy does

| Asset | What happens | Where |
|---|---|---|
| Identifiers found in fenced code blocks (classes, functions, variables, properties, types) | Replaced with a stand-in word set chosen by HMAC-SHA256 from a fixed 267-word vocabulary | `src/honey/fpe.ts` |
| Naming convention (PascalCase, camelCase, snake_case, SCREAMING_SNAKE) | Kept | `src/honey/fpe.ts` |
| Numbers in fenced code blocks, except the common values listed in [design.md](design.md#numbers) | Replaced: floats scaled by 0.5 to 1.5, integers keep their number of digits | `src/honey/fpe.ts` |
| String literals whose entire value is a mapped identifier | Replaced | `src/honey/fpe.ts` |
| `//` and `/* */` comments inside fenced code blocks | Removed (block comments become spaces) | `src/ast/extractor.ts` |
| The same names and numbers in the prose of the same text block | Replaced with the same stand-ins | `src/ast/mapper.ts` |
| A name used in several turns of one request | Same stand-in in every turn | `buildGlobalMapping` |
| Request body size | Over 10 MiB: HTTP 413. More than 5000 distinct identifiers in one request: HTTP 413 | `src/proxy-handler.ts`, `src/honey/fpe.ts` |
| Client headers | Only `content-type`, `anthropic-version`, `anthropic-beta`, `accept`, `accept-encoding` are forwarded; the client's `authorization` is dropped | `src/proxy-handler.ts` |
| Listening address | `127.0.0.1` only | `src/proxy.ts` |
| Upstream URL | Must be `https://`; redirects are not followed | `src/config.ts`, `src/proxy-handler.ts` |
| Audit log | Counts, timing and status only. No names, numbers or code | `src/audit.ts` |

## What it does not protect

These are sent to Anthropic as they are:

- **Anything that is not in a `text` content block or a plain string message.** The top-level `system` field, `tool_result` blocks (which is how Claude Code returns file contents it has read), and `tool_use` blocks (tool names, file paths and arguments) are forwarded unchanged. In a run with a stub upstream, an identifier in a `tool_result` and in a `tool_use` input arrived intact while the same identifier in a text block was replaced. In an agentic Claude Code session most of the code Claude sees arrives through tool results, so expect most of it to be unmodified.
- **Code that is not in a fenced block.** Identifiers are only discovered inside fences that start at the beginning of a line. A name that appears only in prose, in a file path, or in an unfenced paste is not mapped.
- **Every route other than `POST /v1/messages`.** It is forwarded unchanged, body included (for example `/v1/messages/count_tokens`).
- **Comments that are not `//` or `/* */`.** `#` comments in Python or shell, `--` in SQL and similar are not removed.
- **String literals that are not an exact identifier value.** Messages, SQL, URLs and paths in strings stay as written.
- **Numbers in the skip sets**: 0, 1, 2, 3, 4, 5, 8, 10, 16, 32, 64, 100, 128, 256, the listed HTTP status codes, and integers from 1900 to 2100.
- **Short names and builtins.** Identifiers under 3 characters and anything in the skip list (JS and TS keywords, common builtins) are not renamed.
- **Code structure and logic.** Control flow, types, call graph, the number of functions and their sizes, and the language and libraries in use stay visible. This is deliberate, since Claude needs the structure.
- **Request metadata.** Model name, token counts, timing, and the fact that you use the service.
- **Your API key.** The proxy sends its own `ANTHROPIC_API_KEY` to Anthropic as `x-api-key`. Requests are billed to that key. A Claude subscription login in the client is not used, because the `authorization` header is dropped.
- **Meaning that survives renaming.** The stand-ins come from a fixed list of 267 common programming words. Someone who reads the code can still infer what it does from structure, string literals, library calls and the unreplaced numbers and names listed above. Floats keep their rough size (0.5 to 1.5 times the original) and integers keep their digit count.

## What can go wrong when restoring

Restoring is a whole-word text replacement on the raw reply, run after the model has answered. Known consequences:

- **A stand-in split across streamed events is not restored.** Anthropic streams text in small pieces, and each SSE event is restored on its own. If a stand-in such as `WorkerGlobal` is sent as `Worker` in one event and `Global` in the next, Claude Code shows the stand-in. This was reproduced against `StreamDeobfuscator`. The 2 MiB overflow guard also sends buffered text without restoring it.
- **A stand-in that equals a protocol word corrupts the framing.** Restoring runs over the whole response text, not only the text deltas. The vocabulary contains words such as `data`, `event`, `index`, `message` and `model`. If one of them becomes the stand-in for a real name, the same word in the SSE field names or JSON keys is also rewritten. In a run with `data` mapped to a real name, the line `data: {...}` came back as `<realName>: {...}`.
- **A stand-in that the model writes on its own is rewritten.** If Claude uses the word naturally in an answer, it is turned into your real name.
- **Removed comments are not restored.** Comment stripping is one way. If Claude edits a file that you pasted, the comments that were not sent are not in its suggestion.
- **Numbers are replaced in prose too.** A replaced number is rewritten everywhere it appears as a whole word in the text blocks of the request, so a quantity in your question changes along with the one in the code.

## Not a protection today

- **The Honey Encryption engine.** It is not called by the proxy and nothing is stored with it, so there is no ciphertext for an attacker to guess keys against. See [crypto.md](crypto.md).
- **Post-quantum claims.** The only post-quantum primitives in use are ML-KEM-768 (which cannot take effect across restarts, see crypto.md) and SLH-DSA signatures on the audit log. Neither changes what Anthropic receives.
- **Audit tamper evidence.** Each line is signed on its own with SLH-DSA-SHA2-128s. Deleting or reordering lines is not detectable. The public key is not logged or written anywhere, and the signing key comes from a per-start random salt that is not stored, so the signatures cannot be checked from outside the running process with the code as shipped.
- **Secrets in memory.** The passphrase is a JavaScript string and cannot be zeroed. The API key is kept in memory for the life of the process.
- **Other local users and software.** Any process on your machine can reach `127.0.0.1:8080` and have its request sent upstream with your API key. The proxy has no client authentication.
