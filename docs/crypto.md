# Cryptography

The key derivation, the Honey Encryption engine and the post-quantum components, moved from the old README and corrected against `src/honey/`, `src/audit.ts` and `src/corpus/`.

Read this first: of everything on this page, only the key derivation and the HMAC-based name mapping take part in rewriting a request. The Honey Encryption engine (`src/honey/engine.ts`, `lwe-dte.ts`, `dte-corpus.ts`) is not called from the proxy. No file under `src/` other than the engine itself imports it; the tests exercise it. Claude receives renamed code, never ciphertext.

## Key derivation (`src/honey/key-manager.ts`)

One passphrase produces three independent 32-byte keys. An ML-KEM-768 step can be mixed in.

```
masterKey = scrypt(passphrase, salt, N=65536, r=8, p=1)

kyberSeed  = HKDF(masterKey, salt, "honey:kyber:seed:v1", 64)
(pk, sk)   = ml_kem768.keygen(kyberSeed)
if HONEY_KYBER_CAPSULE:
  ss        = ml_kem768.decapsulate(capsule, sk)
  masterKey = masterKey XOR HKDF(ss, salt, "honey:kyber:hybrid:v1", 32)

fpeKey = HKDF(masterKey, salt, "honey:fpe:v1")
key    = HKDF(masterKey, salt, "honey:aes-ctr:v1")
macKey = HKDF(masterKey, salt, "honey:hmac:v1")
```

The salt is 32 random bytes generated each time the proxy starts. It is never written to disk. The same passphrase therefore gives different keys, and a different mapping, on every start, and a past session cannot be re-derived later. The master key and the ML-KEM seed and secret key are zeroed after use; the three sub-keys are zeroed on shutdown. A JavaScript string such as the passphrase cannot be zeroed. `ANTHROPIC_API_KEY` and `HONEY_PASSPHRASE` are deleted from `process.env` after they are read.

scrypt is memory-hard, which raises the cost of guessing the passphrase compared with a plain iteration count.

### The ML-KEM capsule does not work across restarts

The old README described this flow: start the proxy, read the ML-KEM public key from the log, encapsulate a secret to it, then restart with `HONEY_KYBER_CAPSULE`. That flow cannot work with the current code. The keypair is derived from `masterKey`, which depends on the random salt, so every start logs a different public key (checked by deriving a session key twice from the same passphrase). A capsule made for an earlier start is decapsulated with the wrong secret key; ML-KEM does not fail in that case, it returns an unrelated secret. A capsule of the wrong length makes startup throw. In both cases the variable gives no benefit today. The variable is still read and passed to the derivation, and `tests/config.test.ts` only checks that it is loaded.

## Name and number mapping

See [design.md](design.md#identifiers). It uses `fpeKey` with HMAC-SHA256. It is a keyed lookup into a fixed 267-word vocabulary plus an in-memory table for reversing it. It is not format-preserving encryption in the sense of NIST FF1 or FF3, and it is not invertible without the table.

## Honey Encryption engine (not in the request path)

The engine takes a code string and returns a short payload. Decrypting with the right key does not give the original string back. It gives a snippet from the embedded corpus (52 open-source snippets in `src/corpus/data.ts`: 34 TypeScript, 10 Python, 4 Rust, 3 Go, 1 JavaScript). In a run for this documentation, `decrypt` of an encrypted `class Secret {}` returned a Go function from the corpus.

```
LWE parameters: n=128, q=7681, B=5, M=52 (corpus size), scale = floor(q/M) = 147
(the code comments call these demo-grade and say production LWE would use n >= 512)

Encrypt(code, session):
  index   = HMAC-SHA256(key, code) mod M
  nonce   = random(16 bytes)
  a       = [HMAC(key, nonce || "lwe:a:i:attempt") mod q  for i in 0..n-1]
  s       = [HMAC(fpeKey, "lwe:s:i:attempt") mod q        for i in 0..n-1]
  e       = (HMAC(fpeKey, nonce || "lwe:e:0") mod 11) - 5
  b       = (a.s + e + scale * index) mod q
  tag     = HMAC-SHA256(macKey, nonce || b)
  payload = 0x02 || tag(32) || nonce(16) || b_uint16BE(2)

Decrypt(payload, session):
  verify tag with a timing-safe compare, else the generic error "Decryption failed"
  a, s    = regenerate
  index   = round(((b - a.s) mod q) / scale) mod M
  return corpus[index]
```

Rejection sampling (`REJECTION_LIMIT = floor(2^32 / q) * q`) removes modular bias when turning a 32-bit value into a value mod q.

### Wire formats

The encrypt path always writes v2. The decrypt path reads the first byte to pick the format. v1 and v0 exist so that older payloads still decrypt.

| Version | Byte | Layout | Size | Cipher |
|---|---|---|---|---|
| v2 (default) | `0x02` | version(1) + HMAC(32) + nonce(16) + b_uint16BE(2) | 51 B | LWE-style |
| v1 | `0x01` | version(1) + nonce(16) + HMAC(32) + ciphertext(4) | 53 B | AES-256-CTR |
| v0 (legacy) | none | nonce(16) + HMAC(32) + ciphertext(4) | 52 B | AES-256-CTR |

`decryptHoneyUnsafe` skips the HMAC check. It exists for tests and demos and is not called in the request path.

### Honey property

The idea comes from Juels and Ristenpart, "Honey Encryption: Security Beyond the Brute-Force Bound" (EUROCRYPT 2014, https://eprint.iacr.org/2014/166). With a wrong key, decryption does not fail. It returns another plausible message, so an attacker who tries many keys cannot tell which result is right.

In this engine a wrong key gives a different corpus index, hence a different snippet, and `tests/honey.test.ts` checks that wrong keys give non-empty snippets and several distinct ones. The statement that this follows from the hardness of Learning With Errors does not hold for the code as written. In LWE the vector `a` is public random data. Here `a` is derived from the secret `key` with HMAC, and `s` is derived from `fpeKey` with HMAC, so the uniform-looking output under a wrong key rests on HMAC-SHA256 behaving like a random function. The LWE-shaped arithmetic is used, but no LWE assumption is relied on. The parameters are small (`n=128`, `q=7681`).

Because the proxy never stores an engine payload, there is currently no ciphertext for an attacker to brute-force. The honey property is exercised by tests only.

## Post-quantum components

These use post-quantum primitives from [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) (version 0.2.1 in `bun.lock`, pure TypeScript). Imports: `ml_kem768` from `@noble/post-quantum/ml-kem`, `slh_dsa_sha2_128s` from `@noble/post-quantum/slh-dsa`.

| Component | Primitive | What it does today |
|---|---|---|
| Key derivation | scrypt (N=65536) | Memory-hard passphrase stretching. Not post-quantum by itself. |
| Key strengthening | ML-KEM-768 (FIPS 203) | Mixes a decapsulated secret into the master key when `HONEY_KYBER_CAPSULE` is set. Not usable across restarts, see above. |
| Honey Encryption engine | LWE-style arithmetic with HMAC | Not in the request path. |
| Audit signatures | SLH-DSA-SHA2-128s (FIPS 205) | Signs each audit entry. See [operations.md](operations.md#audit-trail). |

None of these change what is sent to Anthropic. That traffic travels over HTTPS and carries renamed code, not ciphertext.

## Why the engine maps through a corpus

Classic symmetric encryption fails against guessing a low-entropy key because a wrong key gives garbage that is easy to reject. Honey Encryption adds a distribution-transforming encoder (DTE) so that every key decrypts to a plausible message.

| HE component | In this repository |
|---|---|
| Message distribution | 52 embedded open-source snippets |
| DTE encode | `HMAC-SHA256(key, code) mod M` gives a corpus index |
| DTE decode | `corpus[index mod M]` |
| Cipher (v2) | LWE-style, as above |
| Cipher (v1, v0) | AES-256-CTR, read-only for old payloads |
| Integrity | HMAC-SHA256 over nonce and ciphertext |

The encoder maps any input to one of 52 snippets, which is a coarse approximation of the real distribution of code. The roadmap in [development.md](development.md#roadmap) lists a planned replacement that samples from a local language model; it is not implemented.
