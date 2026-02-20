# Aegiss

**Security-first**, self-defending token library for Node.js. Fixed algorithms (Ed25519, ChaCha20-Poly1305), mandatory context binding (IP + User-Agent), constant-time checks, and built-in rate limiting. Zero dependencies — uses only Node.js built-in `crypto`.

---

## Table of contents

- [Overview](#overview)
- [Requirements & install](#requirements--install)
- [Token format & behavior](#token-format--behavior)
- [Quick start](#quick-start)
- [API reference](#api-reference)
- [Express middleware](#express-middleware)
- [Encryption](#encryption)
- [Security design](#security-design)
- [Error handling](#error-handling)
- [Constants & limits](#constants--limits)
- [Further reading](#further-reading)

---

## Overview

| Aspect | Description |
|--------|-------------|
| **Purpose** | Issue and verify cryptographically signed tokens bound to client context (IP + User-Agent). |
| **Token type** | Public only: signed, not encrypted. Payload is CBOR-encoded and base64url. |
| **Algorithms** | Ed25519 (signature), SHA-256 (context fingerprint), ChaCha20-Poly1305 (separate encrypt/decrypt helpers). |
| **Context binding** | Every token is tied to the `ip` and `userAgent` used at sign time. Verification fails if the request’s IP or User-Agent does not match. |
| **Dependencies** | None. Node.js >= 18 only. |

### Comparison with JWT / PASETO

| Feature | JWT | PASETO | Aegiss |
|---------|-----|--------|--------|
| Algorithm choice | User picks (risk of misuse) | Version-locked | Hardcoded: Ed25519 & ChaCha20 |
| Payload format | JSON | JSON | CBOR (binary, compact) |
| Context binding | None | None | Required IP + User-Agent fingerprint |
| Attack mitigation | External | External | Built-in (timing-safe, rate limit, revocation) |
| Verification error | Can leak reason | Can leak reason | Single generic message |

---

## Requirements & install

- **Runtime:** Node.js >= 18.
- **Install:** `npm install aegiss`
- **Import:** `const aegiss = require('aegiss');` (CommonJS). TypeScript types are provided via `src/index.d.ts`.

---

## Token format & behavior

- **Structure:** `v1.public.<payload_base64url>.<signature_base64url>`
  - `v1` = protocol version (only this version is accepted).
  - `public` = token type (signed, not encrypted).
  - Payload and signature are base64url-encoded; payload is CBOR.
- **Payload contents (always present):** `iat` (issued-at), `exp` (expiry), `jti` (unique id), `fingerprint` (hash of `ip|userAgent`). Plus any claims you pass to `sign()`.
- **Reserved claims:** The library always sets `iat`, `exp`, `jti`, and `fingerprint`. User payload cannot override these; they are merged after your payload.
- **Verification:** Checks in order: format → signature → expiry → optional `minIat` → optional `revokedJtis` → fingerprint (constant-time). Any failure throws `VerificationError` with message `"Invalid token"` (no detail leaked).

---

## Quick start

```js
const { generateKeys, sign, verify, getClientInfo } = require('aegiss');

// 1. Generate key pair (do once; store securely)
const { publicKey, privateKey } = generateKeys();

// 2. When user logs in: sign a token with current request context
const clientInfo = getClientInfo(req);  // { ip, userAgent }
const token = sign(
  { userId: '123', role: 'admin' },
  privateKey,
  { clientInfo, expiresInSeconds: 3600 }
);
// Return token to client (e.g. in JSON body).

// 3. On protected routes: verify using same request’s context
const clientInfoNow = getClientInfo(req);
const payload = verify(token, publicKey, clientInfoNow);
// payload.userId, payload.role, etc. Use payload; do not trust client-sent claims without this verify.
```

**Important for AI/implementers:**  
- `clientInfo` at **sign** must come from the same logical client (IP + User-Agent) as at **verify**. If the client uses a different IP (e.g. new network) or User-Agent, verification will fail.  
- Always use `getClientInfo(req)` (or equivalent) for both sign and verify so the fingerprint is consistent.

---

## API reference

### Key and token

| Function | Input | Output | Throws |
|----------|--------|--------|--------|
| `generateKeys()` | none | `{ publicKey: string, privateKey: string }` (base64url) | — |
| `sign(payload, privateKey, options)` | See below | Token string `v1.public....` | `Error` if invalid payload or missing `clientInfo` |
| `verify(token, publicKey, currentClientInfo, options?)` | See below | Decoded payload object | `VerificationError` on any verification failure |

**sign(payload, privateKey, options)**

- `payload`: Plain object. Any JSON-serializable claims (numbers, strings, etc.). Must not be null/array. Reserved names `iat`, `exp`, `jti`, `fingerprint` are overwritten by the library.
- `privateKey`: String (base64url Ed25519 private key from `generateKeys()`).
- `options`: Object.
  - `clientInfo`: **Required.** `{ ip: string, userAgent: string }`. Usually from `getClientInfo(req)`.
  - `expiresInSeconds`: Optional. Positive number. Default 3600. Token validity in seconds from issue time.

**verify(token, publicKey, currentClientInfo, options?)**

- `token`: String. The token returned by `sign()`.
- `publicKey`: String (base64url Ed25519 public key).
- `currentClientInfo`: **Required.** `{ ip: string, userAgent: string }`. Must match the context used at sign time (use `getClientInfo(req)`).
- `options`: Optional.
  - `minIat`: Optional. Number (Unix timestamp). If set, tokens with `iat < minIat` are rejected (replay prevention).
  - `revokedJtis`: Optional. `Set<string>` or `(jti: string) => boolean`. If the token’s `jti` is in the set or the function returns true, verification fails (revocation / logout).

### Request context

| Function | Input | Output |
|----------|--------|--------|
| `getClientInfo(req)` | Request-like object with `headers`, optional `socket.remoteAddress` | `{ ip: string, userAgent: string }` |

**req** must have:

- `headers['x-forwarded-for']` or `headers['x-real-ip']` or `socket.remoteAddress` (used for IP).
- `headers['user-agent']` (defaults to `''` if missing).

### Middleware

| Function | Input | Output |
|----------|--------|--------|
| `createVerifyMiddleware(publicKey, options?)` | publicKey string, optional options | Express middleware function |

Middleware behavior:

- Reads `Authorization: Bearer <token>`. If missing → 401, no block.
- If present: runs `verify(token, publicKey, getClientInfo(req), options)`. On success → `req.aegiss = payload`, `next()`. On failure → 401 and increments failure count for the IP; after `maxFailedAttempts` (default 10) failures, the IP is blocked for 15 minutes (subsequent requests get 429).
- Successful verification resets the failure count for that IP.

Options: `minIat`, `revokedJtis` (same as `verify`), `maxFailedAttempts` (positive number; default 10).

### Utilities and errors

| Function / export | Description |
|-------------------|-------------|
| `encrypt(plaintext, key)` | ChaCha20-Poly1305. `key`: 32-byte Buffer or equivalent. Returns string `iv.ciphertext.authTag` (base64url, dot-separated). |
| `decrypt(packed, key)` | Inverse of `encrypt`. Returns Buffer. |
| `hashFingerprint(input)` | SHA-256 of string, 64-char hex. Used internally for context binding. |
| `toBase64Url(buf)` / `fromBase64Url(str)` | Encoding helpers. |
| `clearBlockList()` | Clears in-memory block and failure-count stores (e.g. for tests). |
| `isBlocked(ip)` | Returns whether the IP is currently blocked. |
| `VerificationError` | Class. All verification failures throw this; `message` is always `"Invalid token"`. |
| `CHACHA_KEY_LENGTH`, `CHACHA_IV_LENGTH`, `AUTH_TAG_LENGTH`, `BLOCK_DURATION_MS` | Numeric constants. |

---

## Express middleware

```js
const { createVerifyMiddleware, getClientInfo, sign } = require('aegiss');

const { publicKey, privateKey } = generateKeys();  // or load from env

// Login: issue token
app.post('/login', (req, res) => {
  const clientInfo = getClientInfo(req);
  const token = sign(
    { userId: req.body.userId },
    privateKey,
    { clientInfo, expiresInSeconds: 3600 }
  );
  res.json({ token });
});

// Protected route: require valid Bearer token
app.get('/api/me', createVerifyMiddleware(publicKey), (req, res) => {
  res.json({ user: req.aegiss.userId });
});

// Optional: revocation (e.g. logout) — pass a Set or async store
const revokedJtis = new Set();
app.post('/logout', createVerifyMiddleware(publicKey, { revokedJtis }), (req, res) => {
  revokedJtis.add(req.aegiss.jti);
  res.json({ ok: true });
});
```

- Missing `Authorization` or invalid token → 401.  
- After 10 failed verifications (same IP) → that IP gets 429 for 15 minutes. Override with `maxFailedAttempts`.

---

## Encryption

Encryption is separate from tokens (no context binding). Use for symmetric secret data.

```js
const { encrypt, decrypt } = require('aegiss');
const crypto = require('crypto');

const key = crypto.randomBytes(32);  // 32 bytes required
const packed = encrypt(Buffer.from('secret data'), key);
const plain = decrypt(packed, key);
```

- Key must be 32 bytes.  
- Do not use the same key for tokens; tokens use Ed25519 key pairs.

---

## Security design

- **Algorithms:** Ed25519 (signing), SHA-256 (fingerprint), ChaCha20-Poly1305 (encryption helper).
- **Reserved claims:** `iat`, `exp`, `jti`, `fingerprint` are always set by the library; user payload cannot override them.
- **Single error:** All verification failures throw `VerificationError` with message `"Invalid token"` so attackers cannot distinguish signature, expiry, or context mismatch.
- **Constant-time:** Signature and fingerprint comparison use constant-time logic where applicable.
- **Context binding:** Token is valid only when the request’s IP and User-Agent match the sign-time context.
- **Replay:** Use `minIat` (e.g. last logout or password change time) to reject older tokens.
- **Revocation:** Use `revokedJtis` (Set or callback) to invalidate specific tokens (e.g. logout).
- **Rate limiting:** After N failed verifications (default 10) per IP, that IP is blocked for 15 minutes. Successful verify resets the count for that IP.
- **Input limits:** Token length, payload size, and CBOR structure are bounded to reduce DoS risk.

For more hardening ideas (key rotation, path binding, distributed block list, etc.) see [SECURITY.md](SECURITY.md).

---

## Error handling

- **Verification:** Always catch `VerificationError` when calling `verify()` or when using the middleware (middleware catches it and returns 401). Do not rely on the message text for logic; it is intentionally generic.
- **Sign / encrypt / decrypt:** Can throw generic `Error` for invalid arguments (e.g. missing `clientInfo`, wrong key length). Use try/catch and return a generic error to the client.

Example:

```js
const { verify, VerificationError } = require('aegiss');
try {
  const payload = verify(token, publicKey, getClientInfo(req));
  // use payload
} catch (err) {
  if (err instanceof VerificationError) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  throw err;
}
```

---

## Constants & limits

| Constant | Value | Meaning |
|----------|--------|--------|
| Default token TTL | 3600 | `expiresInSeconds` default (1 hour) |
| Max token length | 4096 | Characters; longer tokens rejected |
| Max payload size | 8192 | Bytes (CBOR); larger rejected |
| Max CBOR map entries | 64 | Per payload |
| Max string length (CBOR) | 1024 | Per value |
| Block duration | 15 min | After max failed attempts |
| Default max failed attempts | 10 | Before blocking IP |
| `CHACHA_KEY_LENGTH` | 32 | Bytes for encrypt/decrypt key |
| `FINGERPRINT_HEX_LENGTH` | 64 | SHA-256 hex length |

---

## Further reading

- [SECURITY.md](SECURITY.md) — Hardening ideas (key rotation, path binding, audit callbacks, distributed block list, threat model).
- [examples/basic-usage.js](examples/basic-usage.js) — Run with `node examples/basic-usage.js` for sign, verify, revocation, and reserved-claims behavior.
- [examples/express-middleware.js](examples/express-middleware.js) — Minimal Express server with login and protected route.

---

## License

MIT
