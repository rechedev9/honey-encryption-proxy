# Design

How the proxy rewrites a request and restores the reply. Moved from the old README and checked against the code in `src/`. For the cryptography see [crypto.md](crypto.md); for what the proxy does not protect see [threat-model.md](threat-model.md).

## Why this exists

Teams hesitate to use AI coding assistants because a prompt can carry proprietary code: class names that reveal business logic, constants that expose pricing, comments that explain a confidential algorithm. This proxy runs on the developer's machine and replaces those names and numbers with stand-ins before the request leaves the machine. It needs no change on the Anthropic side.

It is name and number substitution. It does not encrypt the code that Claude receives, and it does not hide the structure of the code (see the threat model).

## Request flow

```
Claude Code
    |  ANTHROPIC_BASE_URL=http://localhost:8080
    v
+-------------------------------------------------------------+
|  HONEY PROXY  (127.0.0.1:8080)                              |
|                                                             |
|  POST /v1/messages only:                                    |
|                                                             |
|  1. Parse the JSON body (reject non-JSON with 400)          |
|  2. Collect the text of every message: string content and   |
|     blocks of type "text", from user and assistant turns    |
|  3. Find fenced code blocks in that text and build ONE      |
|     identifier + number mapping for the whole conversation  |
|  4. Rewrite each message with that mapping                  |
|  5. Forward the rewritten body to the upstream API          |
|                                                             |
|  On the reply:                                              |
|  6. Replace every stand-in with the original text           |
|  7. Return the result to Claude Code                        |
+-------------------------------------------------------------+
    |  HTTPS to api.anthropic.com
    v
Anthropic receives: the same code, with other names and
other numbers, and without // and /* */ comments
```

Every other route is forwarded without any change to the body, for example `GET /v1/models`. The match is exact on the path `/v1/messages`, so a route such as `/v1/messages/count_tokens` is forwarded as received. The proxy forwards only these client headers: `content-type`, `anthropic-version`, `anthropic-beta`, `accept` and `accept-encoding`. It always sets `x-api-key` from its own `ANTHROPIC_API_KEY` and drops the client's `authorization` header.

### What the rewrite touches

The rewrite applies only to:

- message `content` that is a plain string;
- content blocks of `"type": "text"` inside a message.

It does not apply to the top-level `system` field, to `tool_result` blocks, to `tool_use` blocks (including their `input`), or to any other block type. Those are forwarded as received. Identifiers are only discovered inside fenced code blocks (lines that start with three backticks or three tildes). Once a name is discovered in a fenced block, the same replacement is also applied to the rest of that text block, including the prose around the fence.

## Obfuscation pipeline

`buildGlobalMapping` and `applyMappingToFullText` in `src/ast/mapper.ts` run these steps. `obfuscateText` in the same file runs the same steps on a single string.

```
1. extractCodeBlocks(text)
   finds fenced blocks (``` or ~~~) that start at the beginning of a line

2. stripComments(block.content)
   removes // line comments and /* */ block comments, leaves string literals alone,
   replaces the characters of a block comment with spaces (keeps line numbers)
   (only C-style comments: # comments in Python and similar are not removed)

3. extractIdentifiers(strippedCode, lang)
   typescript, javascript, tsx (and an empty tag): web-tree-sitter AST
   any other language tag, or if tree-sitter failed to load: regex token scan
   both skip keywords, builtins and tokens shorter than 3 characters

4. buildIdentifierMapping(identifiers, fpeKey)
   per word: HMAC-SHA256(fpeKey, word + ":" + offset) picks a word in a 267-word vocabulary
   keeps the naming convention, avoids collisions (up to 16 offsets)
   more than 5000 identifiers in one request: HTTP 413

5. buildNumericMapping(strippedCode, fpeKey)
   scans \b\d+\.?\d*\b and skips values that are too common to matter (see below)

6. merge both mappings, then for each text block:
   a. rewrite each fenced block: strip comments, apply the mapping,
      replace string literals whose whole value is a mapped identifier
   b. apply the same mapping to the text outside the fences (whole words only)
```

### Identifiers

Each identifier is split into words by casing or underscores. Each word is replaced by a vocabulary word chosen by `HMAC-SHA256(fpeKey, lowercase(word) + ":" + offset) mod 267`. The replacement words are joined back in the original convention.

```
words      = split(identifier)
fakeWords  = [VOCAB[HMAC(fpeKey, w, offset) mod 267]  for w in words]
fakeId     = reassemble(fakeWords, original_convention)
```

Illustrative conventions (the actual stand-ins depend on the session key):

| Convention | Original | Stand-in |
|---|---|---|
| PascalCase | `InvoiceProcessor` | `ScheduleProcessor` |
| camelCase | `calculateTax` | `computeCache` |
| snake_case | `fraud_detection_model` | `batch_stream_handler` |
| SCREAMING_SNAKE | `MAX_RETRY_COUNT` | `DEFAULT_QUEUE_SIZE` |

The mapping is a table kept in memory for the life of one request. It is built once per request from all messages, so the same name gets the same stand-in in every message of that request. Two different words can land on the same vocabulary word; the collision check is on the whole assembled identifier, and the retry offset depends on which other identifiers are in the request, so a name can get a different stand-in in a different request.

An identifier is never replaced if it is shorter than 3 characters, is purely numeric, or is in the skip list in `src/honey/fpe.ts` (JS and TS keywords and a list of common builtins such as `Array`, `Map`, `Promise`, `fetch`, `process`).

### Numbers

A number is replaced unless it is in one of these sets:

- trivial values: 0, 1, 2, 3, 4, 5, 8, 10, 16, 32, 64, 100, 128, 256;
- the HTTP status codes in an explicit set (200, 201, 202, 204, 206, 301, 302, 303, 304, 307, 308, 400, 401, 403, 404, 405, 406, 408, 409, 410, 415, 422, 429, 500, 501, 502, 503, 504, plus 100 and 101);
- integers from 1900 to 2100 (calendar years).

```
hash   = HMAC-SHA256(fpeKey, "num:<numStr>:<offset>")
factor = 0.5 + readUInt32BE(hash) / 2^32          # in [0.5, 1.5)
float  : (value * factor).toFixed(same number of decimals)
integer: a different integer with the same number of digits
```

### String literals

A string literal inside a fenced block is rewritten only when its entire value is an identifier that has a stand-in, for example `"invoiceId"` when `invoiceId` was mapped. Any other string literal is left as is.

### Restoring the reply

`deobfuscateText` replaces every whole-word occurrence of a stand-in with the original text. It runs on the raw response body (the JSON for a normal reply, the SSE text for a streamed one), so it applies both inside and outside code fences. Longer stand-ins are replaced first.

Restoring is a plain text replacement, so it has limits that are listed in the [threat model](threat-model.md#what-can-go-wrong-when-restoring).

## Streaming

For a streamed reply, `StreamDeobfuscator` (`src/stream-deobfuscator.ts`) reads the upstream body, buffers it, and splits it on blank lines (`\n\n`, the end of an SSE event). Each complete event is restored and sent on right away. The trailing incomplete part is held back until the next network chunk arrives or the stream ends, so a stand-in cut in half by a network chunk boundary is still restored. If no event delimiter arrives within 2 MiB of buffered text, the buffer is sent on without restoring.

Each event is restored on its own. A stand-in that Anthropic splits across two `content_block_delta` events (for example `Worker` in one event and `Global` in the next) is not recognised and reaches Claude Code as the stand-in.

A request is treated as streaming when the body has `"stream": true` or the upstream reply has `content-type: text/event-stream`.

## Audit trail

See [operations.md](operations.md#audit-trail).
