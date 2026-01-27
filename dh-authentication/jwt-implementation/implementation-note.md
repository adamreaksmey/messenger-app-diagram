# Practical Microservices Auth Architecture

## Your Situation

```
┌──────────┐
│  Client  │ ──── X25519 + HMAC auth ──→ User Service ✓
└──────────┘
                                              │
                                              │ Now what?
                                              ▼
                                    ┌─────────────────┐
                                    │  Chat Service   │ ❓
                                    │  Post Service   │ ❓
                                    │  Media Service  │ ❓
                                    └─────────────────┘
```

**The Question:** Chat service needs to know "who is this user?" without reimplementing the entire device auth flow.

---

## ❌ Bad Solutions (Don't Do These)

### 1. Share Device Secrets Across Services
```
Client ──device_secret──→ Chat Service
```
**Why Bad:**
- Defeats purpose of device binding
- One compromised service = all compromised
- Can't revoke per-service

### 2. Client Authenticates to Every Service
```
Client ──auth──→ User Service
Client ──auth──→ Chat Service  
Client ──auth──→ Post Service
```
**Why Bad:**
- N authentication handshakes
- N device registrations
- Mobile battery dies
- Complexity nightmare

### 3. Forward Device Signatures
```
Chat Service ──validate signature──→ User Service (for every request)
```
**Why Bad:**
- User Service becomes bottleneck
- Latency on every chat message
- SPOF (single point of failure)

---

## ✅ Good Solution: JWT + Service Tokens

### Architecture Overview

```
┌──────────┐
│  Client  │
└────┬─────┘
     │ 1. Device auth (X25519 + HMAC)
     ▼
┌─────────────────┐
│  User Service   │
│  (Auth Gateway) │
└────┬────────────┘
     │ 2. Issues JWT
     │
     ├─────────────────────────────────────┐
     │                                     │
     ▼                                     ▼
┌──────────────┐                    ┌──────────────┐
│ Chat Service │                    │ Post Service │
│ (JWT verify) │                    │ (JWT verify) │
└──────────────┘                    └──────────────┘
```

### How It Works

#### Phase 1: Client Authenticates (Your Current Flow)
```
Client → User Service: Device auth (X25519 + HMAC)
User Service → Client: Session + JWT
```

#### Phase 2: Client Calls Other Services
```
Client → Chat Service: JWT in Authorization header
Chat Service: Verifies JWT signature (no User Service call needed)
Chat Service: Extracts user_id, device_id from JWT
```

---

## Implementation

### 1. User Service Issues JWT After Login

**Add to loginHandler (after session creation):**

```go
import "github.com/golang-jwt/jwt/v5"

// JWT signing key (in production: use KMS, rotate regularly)
var jwtSigningKey = []byte("your-secret-key-change-this")

type JWTClaims struct {
	UserID    int64  `json:"user_id"`
	DeviceID  string `json:"device_id"`
	SessionID string `json:"session_id"`
	jwt.RegisteredClaims
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// ... existing login logic ...
	
	// After creating session, also issue JWT
	claims := JWTClaims{
		UserID:    user.ID,
		DeviceID:  req.DeviceID,
		SessionID: req.SessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "user-service",
			Subject:   strconv.FormatInt(user.ID, 10),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSigningKey)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	resp := LoginResponse{
		SessionID: req.SessionID,
		UserID:    user.ID,
		JWT:       tokenString, // Add this
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
```

### 2. Other Services Verify JWT Locally

**Chat Service (Go):**

```go
package main

import (
	"fmt"
	"net/http"
	"strings"
	"github.com/golang-jwt/jwt/v5"
)

// Same key as User Service (or fetch from shared config/KMS)
var jwtSigningKey = []byte("your-secret-key-change-this")

type JWTClaims struct {
	UserID    int64  `json:"user_id"`
	DeviceID  string `json:"device_id"`
	SessionID string `json:"session_id"`
	jwt.RegisteredClaims
}

// Middleware for JWT verification
func jwtAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract JWT from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing authorization header", http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]

		// Parse and verify JWT
		token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
			// Verify signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSigningKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Extract claims
		claims, ok := token.Claims.(*JWTClaims)
		if !ok {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		// Optional: Check if session is still valid (cache check)
		// if isSessionBlacklisted(claims.SessionID) {
		//     http.Error(w, "Session invalidated", http.StatusUnauthorized)
		//     return
		// }

		// Add user info to context
		ctx := r.Context()
		ctx = context.WithValue(ctx, "user_id", claims.UserID)
		ctx = context.WithValue(ctx, "device_id", claims.DeviceID)

		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// Example chat endpoint
func sendMessageHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(int64)
	
	// Now you have the user ID, no need to call User Service!
	log.Printf("User %d sending message", userID)
	
	// ... chat logic ...
}

func main() {
	http.HandleFunc("/chat/send", jwtAuthMiddleware(sendMessageHandler))
	http.ListenAndServe(":8081", nil)
}
```

### 3. Client Usage

**Client (JavaScript):**

```javascript
class AuthClient {
  constructor(apiBaseUrl) {
    this.userServiceUrl = apiBaseUrl;
    this.jwt = null;
  }

  async login(username, password) {
    // ... existing login logic ...
    
    const data = await response.json();
    this.sessionId = data.session_id;
    this.jwt = data.jwt; // Store JWT
    
    // Store JWT (for other services)
    this.storeSecurely('jwt', this.jwt);
    
    return this.sessionId;
  }

  // Call User Service (with device signature)
  async callUserService(method, path, body) {
    // Use existing authenticatedRequest with HMAC signatures
    return this.authenticatedRequest(method, path, body);
  }

  // Call Other Services (with JWT only)
  async callOtherService(serviceUrl, method, path, body) {
    if (!this.jwt) {
      throw new Error('Not logged in');
    }

    const response = await fetch(`${serviceUrl}${path}`, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.jwt}` // Just JWT, no HMAC
      },
      body: body ? JSON.stringify(body) : undefined
    });

    if (!response.ok) {
      throw new Error(`Request failed: ${response.statusText}`);
    }

    return response.json();
  }
}

// Usage
const client = new AuthClient('http://localhost:8080');
await client.login('john.doe', 'password');

// Call User Service (device auth required)
await client.callUserService('POST', '/api/update-profile', {...});

// Call Chat Service (JWT only)
await client.callOtherService('http://localhost:8081', 'POST', '/chat/send', {
  recipient: 'jane.doe',
  message: 'Hello!'
});
```

---

## Key Design Decisions

### 1. JWT Only Contains Public Info
```json
{
  "user_id": 12345,
  "device_id": "abc123",
  "session_id": "xyz789",
  "exp": 1234567890,
  "iat": 1234567000,
  "iss": "user-service"
}
```

**Don't put in JWT:**
- ❌ Device secrets
- ❌ Server HMAC keys  
- ❌ Passwords
- ❌ PII (email, phone)

### 2. User Service is Auth Gateway
- Only service that validates device signatures
- Issues JWTs after successful device auth
- Maintains session state (Redis)
- Handles logout (blacklisting)

### 3. Other Services Trust JWT
- Verify signature locally (fast)
- No calls to User Service per request
- Can optionally check session blacklist (cache)

---

## Handling Logout & Revocation

### Problem: JWT Can't Be "Revoked" (It's Stateless)

### Solution 1: Short-Lived JWT + Refresh (Recommended)

```go
// Issue short-lived access token (15 min)
AccessToken: expires in 15 minutes

// Issue long-lived refresh token (7 days)
RefreshToken: expires in 7 days, stored in User Service
```

**Flow:**
```
1. Login → Get Access JWT (15 min) + Refresh Token (7 days)
2. Use Access JWT for requests
3. When Access JWT expires → Use Refresh Token to get new Access JWT
4. On logout → Blacklist Refresh Token
```

**Benefits:**
- Access JWT short-lived (limited damage if stolen)
- Refresh Token can be revoked (stored in User Service)
- Other services still don't call User Service for every request

### Solution 2: JWT + Blacklist Cache (Simpler)

```go
// Other services check blacklist cache
func jwtAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// ... parse JWT ...
		
		// Check if session is blacklisted (fast Redis check)
		exists, _ := rdb.Exists(ctx, fmt.Sprintf("blacklist:%s", claims.SessionID)).Result()
		if exists > 0 {
			http.Error(w, "Session invalidated", http.StatusUnauthorized)
			return
		}
		
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
```

**Benefits:**
- Simple to implement
- Fast (Redis check ~1ms)
- Logout works immediately

**Trade-off:**
- All services need Redis access
- Small latency added

---

## Service-to-Service Calls (Backend Only)

### Problem: Chat Service Needs User Info from User Service

```
Chat receives message → Needs to check if recipient exists
```

### Solution: Service Tokens (Not User JWT)

```go
// User Service generates service-specific tokens
var serviceTokens = map[string]string{
	"chat-service": "service_token_abc123",
	"post-service": "service_token_xyz789",
}

// Chat Service calls User Service with service token
req, _ := http.NewRequest("GET", "http://user-service/internal/users/12345", nil)
req.Header.Set("X-Service-Token", "service_token_abc123")

// User Service validates service token
func internalAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		serviceToken := r.Header.Get("X-Service-Token")
		
		// Validate service token
		serviceName := validateServiceToken(serviceToken)
		if serviceName == "" {
			http.Error(w, "Unauthorized service", http.StatusUnauthorized)
			return
		}
		
		// Add service name to context
		ctx := context.WithValue(r.Context(), "service_name", serviceName)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
```

**Better: Use mTLS for service-to-service**
- Each service has TLS cert
- Services verify each other's certs
- No tokens needed

---

## Complete Architecture Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                         CLIENT                                │
└───────┬──────────────────────────────────────────────────────┘
        │
        │ 1. Device Auth (X25519 + HMAC)
        ▼
┌────────────────────────────────────────────────────────────────┐
│                      USER SERVICE                              │
│  - Device registration (X25519)                                │
│  - Login (verify device signature)                             │
│  - Issues: Session + JWT                                       │
│  - Maintains: Session state (Redis)                            │
│  - Handles: Logout (blacklist)                                 │
└───────┬────────────────────────────────────────────────────────┘
        │
        │ 2. Returns JWT
        │
        ▼
┌──────────────────────────────────────────────────────────────┐
│                         CLIENT                                │
│  - Stores JWT                                                 │
└───┬───────────────────────┬──────────────────────────────────┘
    │                       │
    │ JWT                   │ JWT
    │                       │
    ▼                       ▼
┌───────────────┐      ┌───────────────┐
│ Chat Service  │      │ Post Service  │
│ - Verify JWT  │      │ - Verify JWT  │
│ - No User Svc │      │ - No User Svc │
│   call needed │      │   call needed │
└───────────────┘      └───────────────┘
        │                       │
        │ Service-to-Service   │
        └───────────┬───────────┘
                    │ mTLS / Service Token
                    ▼
        ┌───────────────────────┐
        │   User Service        │
        │   /internal/users/:id │
        └───────────────────────┘
```

---

## Implementation Checklist

### User Service
- [x] Device registration (X25519)
- [x] Login with device signature
- [x] Session management
- [ ] **Add JWT issuance after login**
- [ ] **Add refresh token endpoint**
- [x] Logout with blacklist
- [ ] **Internal API for service-to-service**

### Other Services (Chat, Post, etc.)
- [ ] **JWT verification middleware**
- [ ] **Shared Redis for blacklist check** (optional)
- [ ] **Service token for calling User Service**

### Client
- [ ] **Store JWT after login**
- [ ] **Use JWT for non-User-Service calls**
- [ ] **Keep HMAC auth for User Service**
- [ ] **Handle JWT refresh**

---

## Production Considerations

### 1. JWT Signing Key Management
```go
// DON'T: Hardcode key
var jwtSigningKey = []byte("secret")

// DO: Use environment variable or KMS
var jwtSigningKey = []byte(os.Getenv("JWT_SIGNING_KEY"))

// BETTER: Rotate keys
var jwtSigningKeys = map[string][]byte{
    "key-2024-01": loadKey("2024-01"),
    "key-2024-02": loadKey("2024-02"),
}
```

### 2. JWT Claims Validation
```go
// Always validate:
- exp (expiration)
- iat (issued at)
- iss (issuer)
- nbf (not before)

// Verify issuer matches
if claims.Issuer != "user-service" {
    return errors.New("invalid issuer")
}
```

### 3. Service Discovery
```go
// DON'T: Hardcode URLs
chatServiceURL := "http://localhost:8081"

// DO: Use service discovery
chatServiceURL := serviceRegistry.Get("chat-service")

// OR: Use Kubernetes service DNS
chatServiceURL := "http://chat-service.default.svc.cluster.local"
```

### 4. Rate Limiting Per Service
```go
// User Service: Strict limits (auth is expensive)
RateLimit: 10 req/sec per IP

// Chat Service: Looser limits (JWT verification is cheap)
RateLimit: 100 req/sec per user
```

---

## Why This Works

✅ **Client → User Service**: Strong device auth (X25519 + HMAC)  
✅ **Client → Other Services**: Fast JWT verification (no User Service calls)  
✅ **Service → Service**: mTLS or service tokens  
✅ **Logout**: Blacklist works across all services  
✅ **Scalable**: Other services don't bottleneck on User Service  
✅ **Simple**: No enterprise BS, just JWT + good key management  

This is the pragmatic middle ground between "perfect security" and "actually works in production."