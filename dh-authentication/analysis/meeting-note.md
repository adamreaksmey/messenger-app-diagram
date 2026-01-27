# Authentication Flow Overview (Device-Bound HMAC Authentication)

This authentication system is **device-bound**, **session-based**, and **HMAC-authenticated**.
It does **not** use JWT or bearer tokens.

The core idea is:
> The client and server share a secret that is never sent over the network, and every request is authenticated by proving knowledge of that secret.

This document explains:
1. How the shared secret is established
2. How it is stored and used
3. How authentication works for login and API requests

---

## 1. Device Registration (First Install)

This step happens **once per device**.

### Goal
Establish a **shared secret** between client and server **without sending the secret over the network**.

This is done using **Elliptic Curve Diffie–Hellman (ECDH)**.

---

### Step 1: Key Exchange

- Frontend generates an ECDH key pair
  - Private key stays on the device
  - Public key is safe to share

- Frontend calls:
```

POST /auth/register-device

```
Payload includes:
- client_public_key
- device_info (OS, model, etc.)

- Backend generates its own ECDH key pair
- Private key stays on the server
- Public key is returned to the client

At this point:
- Frontend has: client_private_key + server_public_key
- Backend has: server_private_key + client_public_key

---

### Step 2: Shared Secret Derivation (Both Sides)

Both frontend and backend independently compute the same shared value:

- Backend:
```

shared_secret = ECDH(server_private_key, client_public_key)

```

- Frontend:
```

shared_secret = ECDH(client_private_key, server_public_key)

```

Because of the math behind ECDH:
> Both sides end up with the exact same shared_secret, even though it was never sent over the network.

---

### Step 3: Device Secret Derivation (HKDF)

The raw shared secret is **not used directly**.

Both sides run:
```

device_secret = HKDF-SHA256(
input_key_material = shared_secret,
salt = device_info,
info = "device-auth"
)

```

This produces a stable, device-specific secret.

---

### Step 4: Storage

- Backend:
  - Hashes the device_secret using SHA-256
  - Stores:
    - device_id
    - server_hmac_key
    - device_info
  - Returns:
    - device_id
    - server_public_key

- Frontend:
  - Stores the device_secret securely
    - Local storage (dev)
    - Keychain / Keystore (production)

The backend **never stores the device_secret itself**.
The frontend **never stores server secrets**.

---

## 2. Login (Session Creation)

Once a device is registered, login creates a **server-tracked session**.

### Goal
Prove:
- The user knows their password
- The request comes from a registered device

---

### Step 1: Session ID Creation (Client)

Frontend generates:
```

session_id = HMAC(
key = device_secret,
message = device_id + timestamp + nonce
)

```

This proves the client possesses the device_secret.

---

### Step 2: Login Request

Frontend sends:
```

POST /auth/login

```

Payload includes:
- username
- password
- device_id
- session_id
- timestamp
- nonce

---

### Step 3: Server Verification

Backend:
1. Verifies username & password
2. Retrieves server_hmac_key for device_id
3. Recomputes expected session_id using HMAC
4. Verifies timestamp freshness
5. Verifies nonce has not been used

If valid:
- Session is created and stored (DB + Redis)
- Session is now active

---

## 3. Authenticated API Requests (HMAC-Only)

After login, **every API request is authenticated using HMAC**.

### Goal
Ensure:
- Request integrity
- Request authenticity
- Replay protection

---

### Step 1: Request Signing (Client)

For each request, frontend computes:
```

signature = HMAC(
key = device_secret,
message = session_id
+ method
+ path
+ body_hash
+ timestamp
+ nonce
)

```

Headers:
```

Authorization: Session {session_id}
X-Signature: {signature}
X-Timestamp: {timestamp}
X-Nonce: {nonce}

```

---

### Step 2: Server Verification

Backend:
1. Loads session from Redis / DB
2. Retrieves server-side HMAC verification key
3. Recomputes expected signature
4. Validates timestamp and nonce
5. Compares signatures (constant-time)

If valid:
- Request is processed
- Session TTL is extended

---

## 4. Logout / Revocation

Logout:
- Marks session inactive in DB
- Removes session from Redis
- Blacklists session_id

Any future request using that session is rejected.

---

## Why HMAC?

HMAC provides:
- Proof of secret possession
- Message integrity
- Replay resistance (when combined with timestamp + nonce)

Unlike JWT:
- Tokens are not bearer credentials
- Tokens cannot be reused without the secret
- Sessions are revocable server-side

---

## Summary

- Shared secrets are never transmitted
- Devices are cryptographically bound
- Every request is authenticated, not just the login
- Sessions are server-controlled and revocable

This is a **device-bound, HMAC-authenticated session system**, designed for high security and fine-grained control.