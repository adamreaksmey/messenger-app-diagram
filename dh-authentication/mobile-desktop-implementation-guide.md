# Mobile & Desktop Implementation Guide
## Device-Based HMAC Authentication (X25519 + HKDF)

This guide provides step-by-step instructions for implementing the authentication system on mobile (iOS/Android) and desktop platforms. **No code is provided**—you'll implement it yourself using your platform's native APIs.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Phase 1: Device Registration](#phase-1-device-registration)
4. [Phase 2: Login](#phase-2-login)
5. [Phase 3: Authenticated Requests](#phase-3-authenticated-requests)
6. [Phase 4: Logout](#phase-4-logout)
7. [Secure Storage Implementation](#secure-storage-implementation)
8. [Cryptographic Operations](#cryptographic-operations)
9. [Error Handling](#error-handling)
10. [Security Best Practices](#security-best-practices)
11. [Testing Checklist](#testing-checklist)

---

## Architecture Overview

The authentication system uses **X25519 key exchange** to establish a shared secret, then derives device-specific keys using **HKDF**. Each authenticated request is signed with **HMAC-SHA256** to prove device ownership.

### Key Components

- **Device Secret**: Derived from X25519 shared secret, stored securely on device
- **Server HMAC Key**: Derived from device secret on-demand (not stored)
- **Session ID**: HMAC output generated during login
- **Request Signatures**: HMAC of request details (method, path, body, timestamp, nonce)

### Flow Summary

1. **Device Registration**: Exchange X25519 keys → derive device secret → store securely
2. **Login**: Generate session ID + device signature → authenticate → receive session
3. **Authenticated Requests**: Sign each request with HMAC → include headers → verify on server
4. **Logout**: Invalidate session → clear local session data

---

## Prerequisites

### Required Cryptographic Libraries

- **X25519/Curve25519** key generation and ECDH
- **HKDF-SHA256** key derivation
- **HMAC-SHA256** signature generation
- **Cryptographically secure random number generator** (for nonces)

### Platform-Specific Requirements

#### iOS (Swift)
- `CryptoKit` framework (iOS 13+)
- `Keychain Services` for secure storage
- `URLSession` for HTTP requests

#### Android (Kotlin/Java)
- `BouncyCastle` or `Android Keystore System`
- `Android Keystore` for secure storage
- `OkHttp` or `Retrofit` for HTTP requests

#### Desktop (Electron/Flutter/React Native)
- Platform-specific crypto libraries
- Secure storage APIs (OS keychain/keyring)
- HTTP client libraries

---

## Phase 1: Device Registration

### Step 1: Generate X25519 Keypair

**What to do:**
- Generate a new X25519 keypair (private + public key)
- Keep the private key in memory only (never store it)
- Encode the public key as base64 for transmission

**Important:**
- Use cryptographically secure random number generation
- The private key must never leave the device or be logged
- Each device registration should generate a fresh keypair

### Step 2: Prepare Device Information

**What to include:**
- Operating system name and version
- Device model/manufacturer
- Application version
- Any other relevant device metadata

**Format:** JSON string (will be used as HKDF info parameter)

### Step 3: Send Registration Request

**Endpoint:** `POST /auth/register-device`

**Request Body:**
- `public_key`: Base64-encoded X25519 public key
- `device_info`: JSON string with device metadata

**Headers:**
- `Content-Type: application/json`

**Important:**
- Must use HTTPS (TLS) for this request
- Verify server certificate (implement certificate pinning for production)

### Step 4: Receive Server Response

**Response Body:**
- `device_id`: Unique identifier for this device
- `server_public_key`: Base64-encoded server X25519 public key

**What to do:**
- Decode the server public key from base64
- Store `device_id` securely (you'll need it for login)

### Step 5: Compute Shared Secret

**What to do:**
- Use your X25519 private key and the server's public key
- Compute the shared secret using ECDH
- The shared secret is typically 32 bytes

**Important:**
- The shared secret should never be stored
- Use it immediately to derive the device secret

### Step 6: Derive Device Secret

**HKDF Parameters:**
- **Hash function**: SHA-256
- **Input key material**: Shared secret from Step 5
- **Salt**: UTF-8 bytes of string `"device-auth-v1"` (fixed)
- **Info**: UTF-8 bytes of your `device_info` JSON string
- **Output length**: 32 bytes

**What to do:**
- Perform HKDF expansion to get 32-byte device secret
- This is the master secret for your device

### Step 7: Store Device Credentials Securely

**What to store:**
- `device_secret`: The 32-byte device secret (encode as base64 for storage)
- `device_id`: The device ID received from server

**What NOT to store:**
- X25519 private key (discard after use)
- Shared secret (discard after derivation)
- Server HMAC key (derive on-demand)

**Storage requirements:**
- Use platform secure storage (see [Secure Storage Implementation](#secure-storage-implementation))
- Encrypt at rest if your platform doesn't provide hardware-backed encryption
- Never store in plaintext files or SharedPreferences/UserDefaults

---

## Phase 2: Login

### Step 1: Load Device Credentials

**What to do:**
- Retrieve `device_secret` and `device_id` from secure storage
- Decode `device_secret` from base64 back to bytes
- If credentials are missing, throw error: "Device not registered"

### Step 2: Derive Server HMAC Key

**HKDF Parameters:**
- **Hash function**: SHA-256
- **Input key material**: Device secret (from Step 1)
- **Salt**: UTF-8 bytes of string `"server-hmac-key-v1"` (fixed)
- **Info**: UTF-8 bytes of string `"server-verification"` (fixed)
- **Output length**: 32 bytes

**Important:**
- Derive this key on-demand (don't store it)
- You'll derive it again for each authenticated request

### Step 3: Generate Timestamp and Nonce

**Timestamp:**
- Current time in milliseconds since Unix epoch
- Convert to string

**Nonce:**
- Generate 16 random bytes using cryptographically secure RNG
- Encode as hexadecimal string (32 hex characters)

**Important:**
- Nonce must be unique per login attempt
- Never reuse a nonce
- Timestamp must be accurate (sync device clock if needed)

### Step 4: Generate Session ID

**Message format:**
```
{device_id}:{timestamp}:{nonce}
```

**What to do:**
- Concatenate device_id, timestamp, and nonce with colons
- Compute HMAC-SHA256 of this message using server HMAC key
- Encode HMAC output as hexadecimal string
- This is your `session_id`

### Step 5: Generate Device Signature

**Message format:**
```
login:{username}:{timestamp}:{nonce}
```

**What to do:**
- Concatenate "login:", username, timestamp, and nonce with colons
- Compute HMAC-SHA256 of this message using server HMAC key
- Encode HMAC output as hexadecimal string
- This proves you possess the device secret

### Step 6: Send Login Request

**Endpoint:** `POST /auth/login`

**Request Body:**
- `username`: User's username
- `password`: User's password (plaintext, sent over HTTPS)
- `device_id`: Your stored device ID
- `session_id`: Session ID from Step 4
- `timestamp`: Timestamp from Step 3
- `nonce`: Nonce from Step 3
- `device_signature`: Device signature from Step 5

**Headers:**
- `Content-Type: application/json`

**Important:**
- Must use HTTPS
- Server validates timestamp (5-minute window)
- Server checks nonce hasn't been used for this device

### Step 7: Handle Login Response

**Success Response:**
- `session_id`: Confirmed session ID (should match what you sent)
- `user_id`: User's ID

**What to do:**
- Store `session_id` securely (you'll need it for authenticated requests)
- You can clear it from memory after storing

**Error Handling:**
- `401 Unauthorized`: Invalid credentials, device, or signature
- `400 Bad Request`: Missing or invalid parameters
- Handle network errors appropriately

---

## Phase 3: Authenticated Requests

### Step 1: Load Session and Device Secret

**What to do:**
- Retrieve `session_id` from secure storage
- Retrieve `device_secret` from secure storage
- Decode `device_secret` from base64

**If missing:**
- Throw error: "Not logged in. Please login first."

### Step 2: Derive Server HMAC Key

**Same as Login Step 2:**
- Derive server HMAC key from device secret using HKDF
- Use same parameters: salt `"server-hmac-key-v1"`, info `"server-verification"`

### Step 3: Generate Timestamp and Nonce

**Same as Login Step 3:**
- Current timestamp in milliseconds (as string)
- 16 random bytes → hex string (32 hex characters)
- Must be unique per request

### Step 4: Prepare Request Body

**What to do:**
- If request has a body, serialize to JSON string
- If no body, use empty string `""`
- Keep exact string representation (whitespace matters for signature)

### Step 5: Generate Request Signature

**Message format:**
```
{session_id}:{method}:{path}:{body}:{timestamp}:{nonce}
```

**Components:**
- `session_id`: Your stored session ID
- `method`: HTTP method (uppercase: GET, POST, PUT, DELETE, etc.)
- `path`: API path (e.g., `/api/messages`, `/api/users/123`)
- `body`: JSON string from Step 4 (or empty string)
- `timestamp`: Timestamp from Step 3
- `nonce`: Nonce from Step 3

**What to do:**
- Concatenate all components with colons
- Compute HMAC-SHA256 of this message using server HMAC key
- Encode HMAC output as hexadecimal string
- This is your request signature

**Important:**
- Path must match exactly what server expects (no trailing slashes unless server uses them)
- Method must be uppercase
- Body must be exact JSON string (no extra whitespace)

### Step 6: Send Authenticated Request

**Headers:**
- `Authorization: Session {session_id}` (space after "Session")
- `X-Signature: {signature}` (hex string from Step 5)
- `X-Timestamp: {timestamp}` (string from Step 3)
- `X-Nonce: {nonce}` (hex string from Step 3)
- `Content-Type: application/json` (if body present)

**What to do:**
- Send HTTP request with all headers
- Include body if present

### Step 7: Handle Response

**Success (200-299):**
- Process response data normally

**401 Unauthorized:**
- Session expired or invalid
- Clear stored `session_id`
- Prompt user to login again

**400 Bad Request:**
- Check signature, timestamp, or nonce format
- Verify request body serialization

**Other errors:**
- Handle according to your application's error handling strategy

---

## Phase 4: Logout

### Step 1: Check if Logged In

**What to do:**
- Check if `session_id` exists in secure storage
- If not, you're already logged out (no action needed)

### Step 2: Send Logout Request

**Endpoint:** `POST /auth/logout`

**What to do:**
- Use authenticated request flow (Phase 3)
- Include all required headers (Authorization, X-Signature, X-Timestamp, X-Nonce)
- Server will invalidate the session

**Important:**
- Even if logout request fails, clear local session data
- Don't retry logout indefinitely

### Step 3: Clear Local Session Data

**What to do:**
- Remove `session_id` from secure storage
- Keep `device_secret` and `device_id` (device remains registered)
- Clear any in-memory session state

**What NOT to delete:**
- `device_secret` (needed for future logins)
- `device_id` (needed for future logins)

---

## Secure Storage Implementation

### iOS (Keychain Services)

**What to use:**
- `SecItemAdd` / `SecItemUpdate` / `SecItemCopyMatching` / `SecItemDelete`
- Use `kSecClassGenericPassword` with appropriate attributes
- Set `kSecAttrAccessible` to `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (or more restrictive)

**Key attributes:**
- `kSecAttrService`: Your app's bundle identifier
- `kSecAttrAccount`: Key name (e.g., "device_secret", "device_id", "session_id")
- `kSecValueData`: The actual secret data

**Security considerations:**
- Enable "Data Protection" in your app capabilities
- Use `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` for highest security
- Never log keychain contents

### Android (Keystore System)

**What to use:**
- `AndroidKeystore` for hardware-backed keys (Android 6.0+)
- `EncryptedSharedPreferences` for API keys and non-sensitive data
- `KeyStore` API for managing keys

**For device_secret:**
- Use `AndroidKeystore` to generate/import a master key
- Encrypt `device_secret` with this master key
- Store encrypted data in `EncryptedSharedPreferences` or `SharedPreferences`

**Security considerations:**
- Prefer hardware-backed keystore when available
- Use `setUserAuthenticationRequired(true)` for additional protection
- Never store unencrypted secrets in `SharedPreferences`

### Desktop (OS Keyring)

**What to use:**
- **macOS**: `Security Framework` / `keychain`
- **Windows**: `Credential Manager` API / `DPAPI`
- **Linux**: `libsecret` / `Secret Service` (GNOME Keyring, KWallet)

**Implementation approach:**
- Use platform-specific keyring libraries
- Store each secret as a separate entry
- Use appropriate access controls

**Security considerations:**
- Never store in plaintext files
- Use OS-provided encryption
- Respect user's keyring unlock requirements

---

## Cryptographic Operations

### X25519 Key Generation

**Requirements:**
- Generate 32-byte private key (cryptographically random)
- Derive 32-byte public key from private key
- Use X25519/Curve25519 curve

**Platform libraries:**
- **iOS**: `CryptoKit.Curve25519.KeyAgreement.PrivateKey`
- **Android**: BouncyCastle `X25519KeyPairGenerator` or Android Keystore
- **Desktop**: Platform crypto libraries (OpenSSL, libsodium, etc.)

### ECDH Shared Secret Computation

**Requirements:**
- Use your private key and peer's public key
- Output is 32 bytes
- Must match server's computation exactly

**Important:**
- Shared secret is ephemeral (don't store)
- Use immediately for HKDF derivation

### HKDF-SHA256 Key Derivation

**Algorithm:**
1. Extract: `PRK = HMAC-SHA256(salt, input_key_material)`
2. Expand: `OKM = HMAC-SHA256(PRK, info || 0x01) || HMAC-SHA256(PRK, info || 0x02) || ...` (until desired length)

**Parameters:**
- **Hash**: SHA-256
- **Salt**: Fixed byte string (see Phase 1 Step 6 and Phase 2 Step 2)
- **Info**: Context-specific byte string
- **Length**: 32 bytes

**Platform libraries:**
- Most platforms have HKDF implementations
- If not available, implement using HMAC-SHA256 primitives

### HMAC-SHA256 Signature Generation

**Algorithm:**
- `HMAC-SHA256(key, message)`
- Output: 32 bytes (encode as hex string for transmission)

**Requirements:**
- Key: 32-byte server HMAC key
- Message: Concatenated string (see Phase 2 Step 4/5, Phase 3 Step 5)
- Output encoding: Hexadecimal (lowercase or uppercase, be consistent)

**Platform libraries:**
- Available in all major crypto libraries
- Use constant-time comparison on server side (not needed on client)

### Cryptographically Secure Random Number Generation

**Requirements:**
- Use platform CSPRNG (Cryptographically Secure Pseudorandom Number Generator)
- Never use regular random number generators
- Generate 16 bytes for nonces

**Platform APIs:**
- **iOS**: `SecRandomCopyBytes`
- **Android**: `SecureRandom`
- **Desktop**: Platform-specific secure RNG APIs

---

## Error Handling

### Device Registration Errors

**Network errors:**
- Retry with exponential backoff
- Show user-friendly error messages
- Don't retry indefinitely

**Server errors:**
- `400 Bad Request`: Invalid public key format → Regenerate keypair and retry
- `500 Internal Server Error`: Server issue → Retry later
- `429 Too Many Requests`: Rate limited → Wait before retry

**What to do on failure:**
- Don't store partial registration data
- Allow user to retry registration
- Log errors for debugging (don't log secrets)

### Login Errors

**Device not registered:**
- Error: "Device not registered. Please register device first."
- Action: Prompt user to register device

**Invalid credentials:**
- Error: `401 Unauthorized` with "Invalid credentials"
- Action: Show error, allow retry
- Don't clear device registration

**Invalid device signature:**
- Error: `401 Unauthorized` with "Device authentication failed"
- Action: May indicate device secret corruption → Consider re-registration
- Log for debugging

**Timestamp expired:**
- Error: `401 Unauthorized` with "Invalid or expired timestamp"
- Action: Check device clock, sync if needed, retry

**Nonce already used:**
- Error: `401 Unauthorized` with "Nonce already used"
- Action: Generate new nonce and retry (should be rare)

### Authenticated Request Errors

**401 Unauthorized:**
- Session expired or invalid
- Action: Clear `session_id`, prompt re-login
- Don't retry with same session

**400 Bad Request:**
- Missing or invalid headers
- Action: Check header format, verify signature generation
- Don't retry without fixing

**Timestamp expired:**
- Error: `401 Unauthorized` with "Invalid or expired timestamp"
- Action: Check device clock, generate new timestamp, retry

**Nonce already used:**
- Error: `401 Unauthorized` with "Nonce already used"
- Action: Generate new nonce and retry (should be rare)

**Network errors:**
- Retry with exponential backoff
- Don't retry indefinitely
- Show user-friendly messages

---

## Security Best Practices

### Key Management

1. **Never log secrets:**
   - Don't log `device_secret`, `server_hmac_key`, private keys, or shared secrets
   - Don't include in error messages
   - Use secure logging if debugging is needed

2. **Minimize secret lifetime:**
   - Derive `server_hmac_key` on-demand (don't store)
   - Clear shared secrets from memory immediately after use
   - Discard private keys after key exchange

3. **Secure storage:**
   - Use platform secure storage APIs
   - Enable hardware-backed encryption when available
   - Use appropriate access controls

### Network Security

1. **Always use HTTPS:**
   - Enforce TLS 1.2+ for all requests
   - Verify server certificates
   - Implement certificate pinning for production

2. **Certificate pinning:**
   - Pin server certificate or public key
   - Handle pinning failures appropriately
   - Update pins when certificates rotate

3. **Request security:**
   - Include all required headers
   - Verify signature format before sending
   - Use constant-time operations where applicable

### Clock Synchronization

1. **Sync device clock:**
   - Ensure device clock is accurate
   - Handle clock skew gracefully
   - Consider NTP synchronization

2. **Timestamp validation:**
   - Server validates 5-minute window
   - Account for network latency
   - Don't use future timestamps

### Nonce Management

1. **Generate securely:**
   - Use cryptographically secure RNG
   - Generate fresh nonce per request
   - Never reuse nonces

2. **Handle nonce errors:**
   - If server rejects nonce as used, generate new one
   - Don't retry with same nonce
   - Log for debugging (nonce is not secret)

### Error Handling Security

1. **Don't leak information:**
   - Don't reveal whether device exists
   - Don't reveal whether username exists
   - Use generic error messages

2. **Logging:**
   - Log security events (failed logins, invalid signatures)
   - Don't log sensitive data
   - Use secure logging mechanisms

---

## Testing Checklist

### Device Registration

- [ ] Successfully register device
- [ ] Handle network errors gracefully
- [ ] Handle invalid server responses
- [ ] Verify device_secret is stored securely
- [ ] Verify device_id is stored securely
- [ ] Verify X25519 private key is not stored
- [ ] Test with different device_info formats
- [ ] Test certificate pinning (if implemented)

### Login

- [ ] Successfully login with valid credentials
- [ ] Handle missing device credentials
- [ ] Handle invalid username/password
- [ ] Handle expired timestamp
- [ ] Handle nonce reuse (should be rejected)
- [ ] Verify session_id is stored securely
- [ ] Test with clock skew scenarios
- [ ] Test with network interruptions

### Authenticated Requests

- [ ] Successfully make authenticated GET request
- [ ] Successfully make authenticated POST request with body
- [ ] Successfully make authenticated PUT/DELETE requests
- [ ] Handle 401 Unauthorized (session expired)
- [ ] Handle missing session_id
- [ ] Handle invalid signature format
- [ ] Handle expired timestamp
- [ ] Handle nonce reuse
- [ ] Verify signature includes exact body string
- [ ] Verify signature includes correct path
- [ ] Verify signature includes correct method

### Logout

- [ ] Successfully logout
- [ ] Handle logout when not logged in
- [ ] Verify session_id is cleared
- [ ] Verify device_secret remains stored
- [ ] Handle logout network errors
- [ ] Verify session cannot be reused after logout

### Security Testing

- [ ] Verify secrets are not logged
- [ ] Verify secrets are stored securely
- [ ] Test with invalid/corrupted device_secret
- [ ] Test certificate pinning
- [ ] Test clock skew handling
- [ ] Test nonce uniqueness
- [ ] Test replay attack prevention
- [ ] Test with compromised network (MITM scenarios)

### Edge Cases

- [ ] Handle app backgrounding/foregrounding
- [ ] Handle device restart
- [ ] Handle app uninstall/reinstall
- [ ] Handle multiple simultaneous requests
- [ ] Handle request cancellation
- [ ] Handle very long request bodies
- [ ] Handle special characters in paths/usernames

---

## Additional Notes

### Session Management

- Sessions are managed server-side
- Client only stores `session_id`
- Server invalidates sessions on logout or expiration
- Client should handle 401 errors by clearing session and prompting re-login

### Device Re-registration

- If `device_secret` is lost, device must re-register
- Old device registration becomes invalid
- User must login again after re-registration
- Consider implementing device recovery flow if needed

### Offline Support

- This authentication system requires network connectivity
- Cache authentication state appropriately
- Handle offline scenarios gracefully
- Don't attempt requests when offline

### Performance Considerations

- HKDF derivation is fast but not free
- Derive `server_hmac_key` once per request (not per header)
- Cache derived key in memory for request lifetime only
- Don't pre-derive keys unnecessarily

---

## Support and Troubleshooting

### Common Issues

**"Device not registered" error:**
- Check if `device_secret` and `device_id` are stored
- Verify secure storage is working
- May need to re-register device

**"Invalid signature" error:**
- Verify HKDF parameters match server exactly
- Verify message format matches server expectations
- Check body serialization (whitespace, encoding)
- Verify path format (trailing slashes, case sensitivity)

**"Timestamp expired" error:**
- Check device clock accuracy
- Sync device clock if needed
- Account for network latency

**"Nonce already used" error:**
- Ensure nonce is generated fresh each time
- Don't retry failed requests with same nonce
- Check random number generator

### Debugging Tips

- Log non-sensitive data (device_id, session_id, timestamps, nonces)
- Never log secrets (device_secret, server_hmac_key, private keys)
- Use network debugging tools (Charles Proxy, mitmproxy) with caution
- Verify HKDF output matches server expectations
- Verify HMAC signatures match server expectations

---

## Conclusion

This implementation guide provides the framework for implementing device-based HMAC authentication on mobile and desktop platforms. Follow each phase carefully, implement secure storage appropriately for your platform, and test thoroughly.

Remember: **Security is paramount**. Use platform secure storage, never log secrets, always use HTTPS, and handle errors securely.

For questions or issues, refer to the FAQ document or consult with your security team.
