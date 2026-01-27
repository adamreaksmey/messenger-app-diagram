# FAQ — Device-based HMAC Authentication (X25519 + HKDF)

This FAQ covers the implementation in:
- **Frontend**: `dh-authentication/imp-note.js` (`AuthClient` methods)
- **Backend**: `dh-authentication/imp-note.go` (handlers + crypto helpers)

Pre-stuff:
1. What is nonce?
- Nonce is a random value that is used once and never reused.
### Why do we need a nonce?

Because HMAC alone does NOT stop replay attacks.

Without a nonce
- An attacker could:
- Capture a valid request
- Re-send it later
- Server sees a valid HMAC
- Request is accepted again

That’s what a replay attack is.

### What the nonce prevents

By including a nonce in the signed message:
HMAC(device_secret, message + nonce)

You guarantee:
- The signature is valid only once
- Replaying the same request fails
- Even if everything else is identical
- The server remembers used nonces and rejects duplicates.

### When does a nonce get generated:
The **nonce** is generated on the **client side** (mobile/desktop) **during login or any authenticated request**. It’s not part of device registration.

In your frontend code:

```js
const nonce = crypto.randomBytes(16).toString('hex');
```

* **When:** Each time you log in (or send an authenticated request).
* **Where:** Right before you generate the session ID and device signature.
* **Purpose:** Ensures that each request is unique and prevents **replay attacks**.

The **backend** then checks:

```go
if isNonceUsed(deviceID, nonce) { ... }
```

* If the same nonce has been used for that device/session before, the request is rejected.

So mathematically / logically:

1. Client picks a random 16-byte value → `nonce`.
2. `nonce` is included in the session ID HMAC and device signature:

```
session_id = HMAC(server_hmac_key, device_id + ":" + timestamp + ":" + nonce)
device_signature = HMAC(server_hmac_key, "login:" + username + ":" + timestamp + ":" + nonce)
```

3. Server verifies both **timestamp** and **nonce** to ensure freshness and uniqueness.

✅ Key point: **the nonce is always freshly generated per login/request by the client**.


---

### 1) What “token” are we generating here — is it a JWT?
No. The “token” is the **`session_id`**, which is an **HMAC output** generated on the frontend in `AuthClient.login()` using `AuthClient.generateHMAC()`.  
On the backend, `loginHandler()` verifies that `session_id` is correctly constructed using `GenerateHMAC()`.

---

### 2) What proves the device is legitimate during login?
The device proves possession of the derived key by sending `device_signature` created in `AuthClient.login()` via `AuthClient.generateHMAC()` over:
`login:${username}:${timestamp}:${nonce}`.  
The backend verifies this in `loginHandler()` using `VerifyHMAC()`.

---

### 3) Where does the shared secret come from?
From an **X25519 ECDH exchange** during device registration:
- Frontend: `AuthClient.generateX25519KeyPair()` + `ecdh.computeSecret()` inside `AuthClient.registerDevice()`
- Backend: `GenerateX25519KeyPair()` + `ComputeX25519SharedSecret()` inside `registerDeviceHandler()`

---

### 4) Why do we use HKDF and not “hash(shared_secret)”?
HKDF gives you **domain-separated** and **context-bound** keys:
- Frontend derives `deviceSecret` in `AuthClient.deriveDeviceSecret(sharedSecret, deviceInfo)`
- Backend derives the same in `DeriveDeviceSecret(sharedSecret, info)`

This avoids reusing the same raw shared secret across multiple purposes.

---

### 5) What gets stored on the frontend vs backend?
- **Frontend stores**: `device_secret` and `device_id` (via `storeSecurely()`), plus `session_id` after login.
  - See: `AuthClient.registerDevice()`, `AuthClient.login()`
- **Backend stores**: only `server_hmac_key` (derived from `device_secret`) in Postgres and sessions in Postgres + cache.
  - See: `registerDeviceHandler()` stores `server_hmac_key`  
  - `loginHandler()` inserts into `user_sessions`

---

### 6) Why doesn’t the backend store `device_secret`?
Because HMAC verification does not require `device_secret` if you derive and store a separate verification key:
- Backend derives server verification key with `DeriveServerHMACKey(deviceSecret)`
- Backend stores that derived key as `server_hmac_key`

This separation is the “Option 2” described in `analysis-note.md`.

---

### 7) Why does the frontend re-derive the HMAC key on every request?
To avoid storing more long-lived secrets than necessary.  
Frontend uses `AuthClient.deriveServerHMACKey(deviceSecret)` on-demand inside:
- `AuthClient.login()`
- `AuthClient.authenticatedRequest()`

---

### 8) How is an authenticated request signed?
Frontend creates:
`message = ${sessionId}:${method}:${path}:${body}:${timestamp}:${nonce}`  
and computes `signature = HMAC(serverHMACKey, message)` via:
- `AuthClient.generateSignature()` → `AuthClient.generateHMAC()`

Backend verifies in `authMiddleware()` by rebuilding the same `message` and calling `VerifyHMAC()`.

---

### 9) What prevents replay attacks?
Two checks:
- **Timestamp window**:
  - Frontend sends `timestamp` in `AuthClient.login()` and `AuthClient.authenticatedRequest()`
  - Backend validates via `isTimestampValid()`
- **Nonce uniqueness** (scoped correctly):
  - Login nonce scope is per **device**: `isNonceUsed(deviceID, nonce)` / `markNonceUsed(deviceID, nonce)` in `loginHandler()`
  - Request nonce scope is per **session**: `isNonceUsedForSession(sessionID, nonce)` / `markNonceUsedForSession(sessionID, nonce)` in `authMiddleware()`

---

### 10) Why is nonce scope different for login vs requests?
Because the identity boundary is different:
- **Login** is proving a **device** can authenticate → nonce is scoped to `device_id` (`isNonceUsed()`).
- **API requests** are proving a **session** is active → nonce is scoped to `session_id` (`isNonceUsedForSession()`).

---

### 11) What exactly does the backend verify during `POST /auth/login`?
In `loginHandler()`:
- Validates `timestamp` with `isTimestampValid()`
- Rejects replay using `isNonceUsed(req.DeviceID, req.Nonce)`
- Validates username/password (demo uses `verifyPassword()`)
- Loads the device’s `server_hmac_key` and decodes it via `getServerHMACKey()`
- Recomputes expected `session_id` using `GenerateHMAC(serverHMACKey, "${deviceID}:${timestamp}:${nonce}")`
- Verifies `device_signature` using `VerifyHMAC(serverHMACKey, "login:${username}:${timestamp}:${nonce}", device_signature)`
- Stores session in Postgres (`user_sessions`) and caches in Redis (`session:${sessionID}`)

---

### 12) What headers must the frontend send for authenticated requests?
In `AuthClient.authenticatedRequest()`:
- `Authorization: Session ${session_id}`
- `X-Signature: ${signature}` (from `generateSignature()`)
- `X-Timestamp: ${timestamp}`
- `X-Nonce: ${nonce}`

`authMiddleware()` rejects the request if any are missing or malformed.

---

### 13) How does the backend find the key to verify a request signature?
In `authMiddleware()`:
- Parses session ID from `Authorization`
- Loads `sessionData` using `getSession(sessionID)` (Redis first, then Postgres join)
- Extracts `server_hmac_key` and decodes it via `getServerHMACKeyFromSession()`
- Verifies signature with `VerifyHMAC(serverHMACKey, message, signature)`

---

### 14) What happens when the frontend gets a `401`?
In `AuthClient.authenticatedRequest()`:
- If `response.status === 401`, it calls `clearSession()` (removes `session_id`) and forces re-login.

---

### 15) How does logout work?
- Frontend calls `AuthClient.logout()` which internally calls `authenticatedRequest('POST', '/auth/logout')` and then `clearSession()`.
- Backend handles it in `logoutHandler()`:
  - Marks the session inactive in Postgres (`user_sessions.is_active = false`)
  - Deletes cached session (`session:${sessionID}`)
  - Adds to Redis blacklist (`blacklist:${sessionID}`) so the session can’t be reused

---

### 16) Do we still need HTTPS if we’re using X25519 + HMAC?
Yes. Without TLS, registration is vulnerable to MITM (explained in `analysis-note.md`).  
Even with HMAC on requests, an attacker can interfere in Phase 1 unless the channel is authenticated.

---

### 17) What should be encrypted at rest on the backend?
At minimum the `devices.server_hmac_key` column.  
`registerDeviceHandler()` currently stores hex-encoded key material and notes: “in production, encrypt this with KMS/HSM”.

---

### 18) Why does the backend cache session data in Redis if it’s also in Postgres?
To avoid a DB lookup on every request:
- Cache hit path: `getSession()` returns Redis `session:${sessionID}`
- Cache miss path: `getSession()` queries Postgres, then backfills Redis

This is used by `authMiddleware()`.

---

### 19) How is constant-time comparison handled?
Backend uses constant-time compare for signature checks:
- `VerifyHMAC()` uses `subtle.ConstantTimeCompare()`

For session ID equality in `loginHandler()`, prefer the same constant-time approach (the current code intends constant-time comparison there too).

---

### 20) What are the most common “it doesn’t work” causes?
- **Device not registered**: `AuthClient.login()` throws if `retrieveSecurely('device_secret')` / `retrieveSecurely('device_id')` are missing.
- **Clock skew**: backend rejects with `isTimestampValid()` if client clock is far off.
- **Nonce reuse**: backend rejects login via `isNonceUsed()` or requests via `isNonceUsedForSession()`.
- **Body mismatch**: request signature depends on the exact `bodyString` built in `AuthClient.authenticatedRequest()`; backend signs `string(body)` in `authMiddleware()`.
- **Wrong path/method**: both are part of the signed message (`generateSignature()` vs `authMiddleware()`).
