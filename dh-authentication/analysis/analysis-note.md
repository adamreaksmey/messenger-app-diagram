# Security Analysis & Fixes

## Critical Security Issues Identified and Fixed

### Issue 1: Man-in-the-Middle (MITM) Attack During DH Key Exchange

#### The Problem

**Original assumption:** "The server public key I received really belongs to the server"

This assumption is **false** without authentication. During Phase 1 (device registration), the DH key exchange happens over plain HTTP:

```
Client                    Attacker                    Server
   |                         |                           |
   |--- client_pub_key ----->|                           |
   |                         |---- client_pub_key ------>|
   |                         |<--- server_pub_key -------|
   |<--- attacker_pub_key ---|                           |
   |                         |                           |
```

**Result:** The attacker establishes TWO separate shared secrets:
- `shared_secret_1` = between Client and Attacker
- `shared_secret_2` = between Attacker and Server

The client thinks it's talking to the server, but it's actually talking to the attacker!

#### The Solution: TLS/HTTPS

**Fix:** Run Phase 1 over HTTPS with valid TLS certificates

```
Client                    TLS Tunnel                    Server
   |                         |                           |
   |========== Encrypted & Authenticated Channel ========|
   |--- client_pub_key ------------------------------>   |
   |<------------------------ server_pub_key -------------|
   |                                                      |
```

**How TLS Solves This:**

1. **Server Authentication**: The server presents a certificate signed by a trusted CA
2. **Encrypted Channel**: All data (including DH public keys) is encrypted
3. **Integrity**: Prevents tampering with the key exchange

**Implementation:**

```go
// In production, use TLS:
log.Fatal(http.ListenAndServeTLS(":8080", "server.crt", "server.key", r))
```

```javascript
// Client automatically verifies TLS certificate
const client = new AuthClient('https://api.example.com');
```

**Additional Protection (Mobile Apps):**

For mobile apps, implement **certificate pinning** to prevent even compromised CAs:

```javascript
// React Native example
const pins = {
  'api.example.com': {
    'certificateHash': 'sha256/AAAAAAAAAA...'
  }
};
```

---

### Issue 2: Cannot HMAC with a Hash

#### The Problem

**Original code stored:**
```go
device_secret_hash = SHA256(device_secret)  // One-way hash
```

**But later tried to verify:**
```go
expected_signature = HMAC(device_secret, message)  // Needs the actual key!
```

**This is impossible** because:
- SHA256 is a one-way hash function
- You cannot derive the original `device_secret` from `device_secret_hash`
- HMAC requires the actual secret key, not a hash of it

#### Why This Happened

Confusion between two different use cases:
1. **Password storage**: Hash passwords because you only need to verify "does input match stored hash?"
2. **HMAC keys**: Need the actual key to compute signatures

#### The Solutions

##### Option 1: Encrypt the Device Secret (Industry Standard)

```go
// Encrypt with KMS/HSM before storage
encryptedSecret = KMS.Encrypt(device_secret)
db.Store(device_id, encryptedSecret)

// Later, decrypt to verify
device_secret = KMS.Decrypt(encryptedSecret)
expected = HMAC(device_secret, message)
```

**Pros:**
- Client and server use the exact same key
- Most secure with proper KMS

**Cons:**
- Requires KMS/HSM infrastructure
- Performance overhead for decryption

##### Option 2: Derive Separate Server Verification Key (Our Implementation)

```go
// During registration:
device_secret = HKDF(shared_secret, "device-auth-v1", device_info)
server_hmac_key = HKDF(device_secret, "server-hmac-key-v1", "server-verification")

// Store server_hmac_key (NOT device_secret)
db.Store(device_id, server_hmac_key)

// Client also derives the same server_hmac_key for signing
client_hmac_key = HKDF(device_secret, "server-hmac-key-v1", "server-verification")

// Both use server_hmac_key for HMAC
signature = HMAC(server_hmac_key, message)
```

**Pros:**
- No KMS needed for this specific key
- Deterministic derivation (both sides compute same key)
- Clear separation of concerns

**Cons:**
- Still need to protect `server_hmac_key` in database (should encrypt at rest)
- More complex key hierarchy

#### Our Implementation Details

**Key Derivation Hierarchy:**

```
DH Shared Secret (never stored)
        |
        v
    HKDF (salt: "device-auth-v1", info: device_info)
        |
        v
  device_secret (client stores in secure storage)
        |
        v
    HKDF (salt: "server-hmac-key-v1", info: "server-verification")
        |
        v
  server_hmac_key (server stores in DB, client derives)
        |
        v
   HMAC signatures (used for request authentication)
```

**Code Flow:**

```javascript
// CLIENT SIDE
const sharedSecret = clientDH.computeSecret(serverPublicKey);
const deviceSecret = HKDF(sharedSecret, "device-auth-v1", deviceInfo);
const serverHMACKey = HKDF(deviceSecret, "server-hmac-key-v1", "server-verification");

// Store both
secureStorage.set('device_secret', deviceSecret);  // For future re-derivation
secureStorage.set('server_hmac_key', serverHMACKey);  // For signing requests

// Sign requests
const signature = HMAC(serverHMACKey, message);
```

```go
// SERVER SIDE
sharedSecret := ComputeDHSharedSecret(serverPrivate, clientPublic)
deviceSecret := HKDF(sharedSecret, "device-auth-v1", deviceInfo)
serverHMACKey := HKDF(deviceSecret, "server-hmac-key-v1", "server-verification")

// Store only server_hmac_key (NOT device_secret)
db.Exec("INSERT INTO devices (device_id, server_hmac_key) VALUES (?, ?)",
    deviceID, hex.EncodeToString(serverHMACKey))

// Verify requests
storedKey := db.Query("SELECT server_hmac_key FROM devices WHERE device_id = ?", deviceID)
expectedSignature := HMAC(storedKey, message)
if constantTimeCompare(expectedSignature, receivedSignature) {
    // Valid
}
```

---

## Complete Security Architecture

### Phase 1: Device Registration (Over HTTPS)

```
┌─────────────────┐                                 ┌─────────────────┐
│     Client      │                                 │     Server      │
└────────┬────────┘                                 └────────┬────────┘
         │                                                   │
         │  1. Generate DH keypair (private, public)        │
         │     private_key (stays on device)                │
         │     public_key                                   │
         │                                                   │
         │  2. HTTPS POST /auth/register-device             │
         │     {public_key, device_info}                    │
         ├──────────────────────────────────────────────────>│
         │           [TLS protects this exchange]           │
         │                                                   │ 3. Generate server DH keypair
         │                                                   │    Compute: shared_secret = DH(server_priv, client_pub)
         │                                                   │    Derive: device_secret = HKDF(shared_secret, info)
         │                                                   │    Derive: server_hmac_key = HKDF(device_secret, "server")
         │                                                   │    Store: server_hmac_key in DB
         │                                                   │
         │  4. {server_public_key, device_id}               │
         │<──────────────────────────────────────────────────┤
         │                                                   │
         │  5. Compute: shared_secret = DH(client_priv, server_pub)
         │     Derive: device_secret = HKDF(shared_secret, info)
         │     Derive: server_hmac_key = HKDF(device_secret, "server")
         │     Store: both keys in secure storage           │
         │                                                   │
         │  ✓ Both have same server_hmac_key               │
         │    (derived from shared_secret, never transmitted)│
         │                                                   │
```

### Phase 2: Login (Over HTTPS)

```
Client generates:
  session_id = HMAC(device_secret, timestamp+nonce)
  
Sends:
  {username, password, device_id, session_id}
  
Server verifies:
  ✓ Password correct
  ✓ Device exists
  ✓ Session ID format valid
  
Stores:
  Redis: session → {user_id, device_id, server_hmac_key}
  PostgreSQL: session record
```

### Phase 3: Authenticated Request (Over HTTPS)

```
Client:
  message = session_id + method + path + body + timestamp + nonce
  signature = HMAC(server_hmac_key, message)
  
  Headers:
    Authorization: Session {session_id}
    X-Signature: {signature}
    X-Timestamp: {timestamp}
    X-Nonce: {nonce}

Server:
  1. Lookup session → get server_hmac_key
  2. Verify timestamp (within 5 min)
  3. Verify nonce not reused
  4. Recompute: expected = HMAC(server_hmac_key, message)
  5. Compare: constantTimeCompare(expected, signature)
  6. Process request if valid
```

---

## Security Properties Achieved

### ✅ Confidentiality
- Shared secrets never transmitted (DH key exchange)
- TLS encrypts all communication
- Secrets stored in secure storage (client) and encrypted at rest (server)

### ✅ Authentication
- Server authenticated via TLS certificate
- Client authenticated via HMAC signatures with device-specific key
- Every request cryptographically signed

### ✅ Integrity
- HMAC signatures prevent tampering
- TLS prevents modification in transit

### ✅ Replay Protection
- Timestamp validation (5-minute window)
- Nonce tracking (prevents duplicate requests)

### ✅ Forward Secrecy (Partial)
- DH private keys can be ephemeral per session for full forward secrecy
- Current implementation uses long-lived device keys (acceptable for device auth)

### ✅ Non-Repudiation
- All requests signed with device-specific keys
- Audit trail in session logs

---

## Production Deployment Checklist

### Must-Have (Critical)

- [ ] **Enable TLS/HTTPS** with valid certificates (Let's Encrypt)
- [ ] **Certificate pinning** for mobile apps
- [ ] **Encrypt database at rest** (especially `server_hmac_key` column)
- [ ] **Use KMS/HSM** for key encryption (AWS KMS, Google Cloud KMS, HashiCorp Vault)
- [ ] **Implement rate limiting** (per IP, per device, per user)
- [ ] **Add audit logging** for security events
- [ ] **Use bcrypt** for password hashing (not SHA256)
- [ ] **Secure storage** on clients (iOS Keychain, Android Keystore)

### Should-Have (Important)

- [ ] **Upgrade to Curve25519** (faster than 2048-bit MODP)
- [ ] **Implement MFA** for sensitive operations
- [ ] **Add device fingerprinting** for anomaly detection
- [ ] **Session rotation** on privilege escalation
- [ ] **Intrusion detection** system
- [ ] **Regular security audits**

### Nice-to-Have (Enhanced)

- [ ] **WebAuthn/FIDO2** support
- [ ] **Biometric authentication** on mobile
- [ ] **Zero-knowledge proofs** for privacy
- [ ] **Hardware security module** (HSM) integration

---

## Testing the Fixes

### Verify TLS Protection

```bash
# Test that HTTP is rejected
curl http://api.example.com/auth/register-device
# Should fail or redirect to HTTPS

# Test HTTPS works
curl https://api.example.com/auth/register-device -k
# Should succeed
```

### Verify HMAC Works

```javascript
// Test that signatures are correctly verified
const signature1 = HMAC(serverHMACKey, "message");
const signature2 = HMAC(serverHMACKey, "message");
assert(signature1 === signature2);  // Deterministic

const signature3 = HMAC(serverHMACKey, "different");
assert(signature1 !== signature3);  // Different messages → different signatures
```

### Verify Replay Protection

```javascript
// Send request twice with same nonce
const response1 = await authenticatedRequest('GET', '/api/messages');
// response1: 200 OK

const response2 = await authenticatedRequest('GET', '/api/messages');
// Uses same timestamp+nonce again
// response2: 401 Unauthorized (nonce reused)
```

---

## References

- [RFC 3526 - Diffie-Hellman Groups](https://www.rfc-editor.org/rfc/rfc3526)
- [RFC 5869 - HKDF](https://www.rfc-editor.org/rfc/rfc5869)
- [RFC 2104 - HMAC](https://www.rfc-editor.org/rfc/rfc2104)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST SP 800-63B - Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)