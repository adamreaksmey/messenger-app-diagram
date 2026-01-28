# JWT Authentication Implementation Plan (Login-Based)

## Overview
- JWT key pair generation happens **during login** (not registration)
- Registration only handles device registration (DH + HMAC)
- Login validates credentials, generates JWT tokens, stores refresh token
- Chat-service verifies JWTs independently

---

## Phase 1: RSA Key Generation & Management

### 1.1 Generate RSA Key Pair (One-time setup for user-service)

```go
// cmd/keygen/main.go
package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "log"
    "os"
)

func main() {
    // Generate 2048-bit RSA key pair
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        log.Fatal("Failed to generate private key:", err)
    }

    // Save private key
    privateKeyFile, err := os.Create("keys/jwt_private_key.pem")
    if err != nil {
        log.Fatal("Failed to create private key file:", err)
    }
    defer privateKeyFile.Close()

    privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
    privateKeyPEM := &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: privateKeyBytes,
    }
    if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
        log.Fatal("Failed to write private key:", err)
    }
    log.Println("✓ Private key saved to keys/jwt_private_key.pem")

    // Save public key
    publicKeyFile, err := os.Create("keys/jwt_public_key.pem")
    if err != nil {
        log.Fatal("Failed to create public key file:", err)
    }
    defer publicKeyFile.Close()

    publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
    if err != nil {
        log.Fatal("Failed to marshal public key:", err)
    }
    publicKeyPEM := &pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: publicKeyBytes,
    }
    if err := pem.Encode(publicKeyFile, publicKeyPEM); err != nil {
        log.Fatal("Failed to write public key:", err)
    }
    log.Println("✓ Public key saved to keys/jwt_public_key.pem")
}
```

**Action items:**
- [ ] Create `keys/` directory in user-service root
- [ ] Run: `go run cmd/keygen/main.go`
- [ ] Secure private key (chmod 600, never commit to git)
- [ ] Add `keys/*.pem` to .gitignore

---

## Phase 2: User-Service - JWT Generation

### 2.1 Load RSA Private Key at Startup

```go
// internal/auth/keys.go
package auth

import (
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "os"
)

var jwtPrivateKey *rsa.PrivateKey

func LoadPrivateKey(filepath string) error {
    keyData, err := os.ReadFile(filepath)
    if err != nil {
        return fmt.Errorf("failed to read private key: %w", err)
    }

    block, _ := pem.Decode(keyData)
    if block == nil {
        return fmt.Errorf("failed to decode PEM block")
    }

    privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return fmt.Errorf("failed to parse private key: %w", err)
    }

    jwtPrivateKey = privateKey
    return nil
}

func GetPrivateKey() *rsa.PrivateKey {
    return jwtPrivateKey
}
```

```go
// cmd/server/main.go
func main() {
    // ... existing setup ...

    // Load JWT private key
    if err := auth.LoadPrivateKey("keys/jwt_private_key.pem"); err != nil {
        logger.Fatal("Failed to load JWT private key", "error", err)
    }
    logger.Info("✓ JWT private key loaded")

    // ... rest of server setup ...
}
```

### 2.2 JWT Claims Structure

```go
// internal/auth/jwt.go
package auth

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "time"

    "github.com/golang-jwt/jwt/v5"
)

type JWTClaims struct {
    UserID   string `json:"user_id"`
    DeviceID string `json:"device_id"`
    jwt.RegisteredClaims
}

const (
    AccessTokenExpiry  = 2 * time.Hour
    RefreshTokenExpiry = 30 * 24 * time.Hour // 30 days
)
```

### 2.3 Token Generation Functions

```go
// internal/auth/jwt.go

func GenerateAccessToken(userID, deviceID string) (string, error) {
    privateKey := GetPrivateKey()
    if privateKey == nil {
        return "", fmt.Errorf("JWT private key not loaded")
    }

    claims := JWTClaims{
        UserID:   userID,
        DeviceID: deviceID,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(AccessTokenExpiry)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            Issuer:    "user-service",
            Subject:   userID,
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
    return token.SignedString(privateKey)
}

func GenerateRefreshToken() (string, error) {
    // Opaque token (32 random bytes)
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(b), nil
}

type TokenPair struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    ExpiresIn    int    `json:"expires_in"` // seconds
    TokenType    string `json:"token_type"`
}

func GenerateTokenPair(userID, deviceID string) (*TokenPair, error) {
    accessToken, err := GenerateAccessToken(userID, deviceID)
    if err != nil {
        return nil, fmt.Errorf("failed to generate access token: %w", err)
    }

    refreshToken, err := GenerateRefreshToken()
    if err != nil {
        return nil, fmt.Errorf("failed to generate refresh token: %w", err)
    }

    return &TokenPair{
        AccessToken:  accessToken,
        RefreshToken: refreshToken,
        ExpiresIn:    int(AccessTokenExpiry.Seconds()),
        TokenType:    "Bearer",
    }, nil
}
```

### 2.4 Database Schema for Refresh Tokens

```sql
-- migrations/003_create_refresh_tokens.sql

CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token VARCHAR(255) UNIQUE NOT NULL,
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP,
    last_used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_refresh_token ON refresh_tokens(token);
CREATE INDEX idx_refresh_device ON refresh_tokens(device_id);
CREATE INDEX idx_refresh_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_expires ON refresh_tokens(expires_at);
CREATE UNIQUE INDEX idx_one_token_per_device ON refresh_tokens(device_id) WHERE revoked = FALSE;
```

### 2.5 Refresh Token Repository

```go
// internal/repository/refresh_token_repository.go
package repository

import (
    "context"
    "database/sql"
    "fmt"
    "time"

    "github.com/google/uuid"
)

type RefreshTokenRepository interface {
    Store(ctx context.Context, token, userID, deviceID string, expiresAt time.Time) error
    Validate(ctx context.Context, token string) (userID, deviceID string, err error)
    Revoke(ctx context.Context, token string) error
    RevokeAllForUser(ctx context.Context, userID string) error
    RevokeForDevice(ctx context.Context, deviceID string) error
}

type refreshTokenRepository struct {
    db *sql.DB
}

func NewRefreshTokenRepository(db *sql.DB) RefreshTokenRepository {
    return &refreshTokenRepository{db: db}
}

func (r *refreshTokenRepository) Store(ctx context.Context, token, userID, deviceID string, expiresAt time.Time) error {
    _, err := r.db.ExecContext(ctx, `
        INSERT INTO refresh_tokens (token, user_id, device_id, expires_at)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (device_id) WHERE revoked = FALSE
        DO UPDATE SET 
            token = EXCLUDED.token,
            created_at = CURRENT_TIMESTAMP,
            expires_at = EXCLUDED.expires_at,
            last_used_at = CURRENT_TIMESTAMP
    `, token, userID, deviceID, expiresAt)
    
    return err
}

func (r *refreshTokenRepository) Validate(ctx context.Context, token string) (userID, deviceID string, err error) {
    var revoked bool
    var expiresAt time.Time
    
    err = r.db.QueryRowContext(ctx, `
        SELECT user_id, device_id, revoked, expires_at 
        FROM refresh_tokens 
        WHERE token = $1
    `, token).Scan(&userID, &deviceID, &revoked, &expiresAt)
    
    if err == sql.ErrNoRows {
        return "", "", fmt.Errorf("invalid refresh token")
    }
    if err != nil {
        return "", "", err
    }
    
    if revoked {
        return "", "", fmt.Errorf("refresh token revoked")
    }
    
    if time.Now().After(expiresAt) {
        return "", "", fmt.Errorf("refresh token expired")
    }
    
    // Update last_used_at asynchronously
    go r.db.ExecContext(context.Background(), 
        "UPDATE refresh_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE token = $1", token)
    
    return userID, deviceID, nil
}

func (r *refreshTokenRepository) Revoke(ctx context.Context, token string) error {
    _, err := r.db.ExecContext(ctx, `
        UPDATE refresh_tokens 
        SET revoked = TRUE, revoked_at = CURRENT_TIMESTAMP 
        WHERE token = $1
    `, token)
    return err
}

func (r *refreshTokenRepository) RevokeAllForUser(ctx context.Context, userID string) error {
    _, err := r.db.ExecContext(ctx, `
        UPDATE refresh_tokens 
        SET revoked = TRUE, revoked_at = CURRENT_TIMESTAMP 
        WHERE user_id = $1 AND revoked = FALSE
    `, userID)
    return err
}

func (r *refreshTokenRepository) RevokeForDevice(ctx context.Context, deviceID string) error {
    _, err := r.db.ExecContext(ctx, `
        UPDATE refresh_tokens 
        SET revoked = TRUE, revoked_at = CURRENT_TIMESTAMP 
        WHERE device_id = $1 AND revoked = FALSE
    `, deviceID)
    return err
}
```

### 2.6 Update Login Response

```go
// internal/models/response/auth_response.go
package response

type AuthResponse struct {
    SessionID    string       `json:"session_id"`
    AccessToken  string       `json:"access_token"`
    RefreshToken string       `json:"refresh_token"`
    ExpiresIn    int          `json:"expires_in"`
    TokenType    string       `json:"token_type"`
    User         UserResponse `json:"user"`
}
```

### 2.7 Update LoginWithPassword to Generate JWT

```go
// internal/service/auth_service.go

func (s *authService) LoginWithPassword(ctx context.Context, request *request.LoginRequest) (*response.AuthResponse, error) {
    // ... [Steps 1-8 remain exactly the same] ...

    // 9. create session in db
    sessionID := request.SessionID
    expiresAt := time.Now().Add(s.config.Session.Expiration)

    session := &models.UserSession{
        SessionID:      sessionID,
        UserID:         user.UserID,
        DeviceID:       device.DeviceID,
        DeviceInfo:     request.DeviceInfo,
        IPAddress:      request.IPAddress,
        ExpiresAt:      expiresAt,
        LastActivityAt: time.Now(),
        IsActive:       true,
    }

    err = s.sessionRepo.Create(ctx, session)
    if err != nil {
        logger.Error("failed to create session", "error", err)
        return nil, apperrors.InternalServer(constants.ErrInternalServer)
    }

    // 10. cache session in redis
    sessionData := &repository.SessionData{
        UserID:        user.UserID.String(),
        DeviceID:      device.DeviceID.String(),
        ServerHMACKey: device.ServerHMACKey,
    }

    err = s.sessionRepo.SetSessionCache(ctx, sessionID, sessionData, s.config.Session.Expiration)
    if err != nil {
        logger.Warn("failed to cache session", "error", err)
    }

    // 11. Generate JWT token pair (NEW)
    tokens, err := auth.GenerateTokenPair(user.UserID.String(), device.DeviceID.String())
    if err != nil {
        logger.Error("failed to generate JWT tokens", "error", err)
        return nil, apperrors.InternalServer(constants.ErrInternalServer)
    }

    // 12. Store refresh token (NEW)
    refreshExpiresAt := time.Now().Add(auth.RefreshTokenExpiry)
    err = s.refreshTokenRepo.Store(ctx, tokens.RefreshToken, user.UserID.String(), device.DeviceID.String(), refreshExpiresAt)
    if err != nil {
        logger.Error("failed to store refresh token", "error", err)
        return nil, apperrors.InternalServer(constants.ErrInternalServer)
    }

    logger.Info("✓ JWT tokens generated and stored", "userId", user.UserID, "deviceId", device.DeviceID)

    return &response.AuthResponse{
        SessionID:    sessionID,
        AccessToken:  tokens.AccessToken,
        RefreshToken: tokens.RefreshToken,
        ExpiresIn:    tokens.ExpiresIn,
        TokenType:    tokens.TokenType,
        User: response.UserResponse{
            UserID:      user.UserID.String(),
            Username:    user.Username,
            PhoneNumber: user.PhoneNumber,
            DisplayName: user.DisplayName,
            AvatarUrl:   user.AvatarUrl,
            IsNewUser:   false,
        },
    }, nil
}
```

### 2.8 Add Refresh Token Endpoint

```go
// internal/models/request/refresh_request.go
package request

type RefreshRequest struct {
    RefreshToken string `json:"refresh_token" validate:"required"`
}
```

```go
// internal/models/response/refresh_response.go
package response

type RefreshResponse struct {
    AccessToken string `json:"access_token"`
    ExpiresIn   int    `json:"expires_in"`
    TokenType   string `json:"token_type"`
}
```

```go
// internal/service/auth_service.go

func (s *authService) RefreshAccessToken(ctx context.Context, request *request.RefreshRequest) (*response.RefreshResponse, error) {
    // Validate refresh token
    userID, deviceID, err := s.refreshTokenRepo.Validate(ctx, request.RefreshToken)
    if err != nil {
        logger.Error("invalid refresh token", "error", err)
        return nil, apperrors.Unauthorized(constants.ErrInvalidRefreshToken)
    }

    // Generate new access token
    accessToken, err := auth.GenerateAccessToken(userID, deviceID)
    if err != nil {
        logger.Error("failed to generate access token", "error", err)
        return nil, apperrors.InternalServer(constants.ErrInternalServer)
    }

    logger.Info("✓ Access token refreshed", "userId", userID, "deviceId", deviceID)

    return &response.RefreshResponse{
        AccessToken: accessToken,
        ExpiresIn:   int(auth.AccessTokenExpiry.Seconds()),
        TokenType:   "Bearer",
    }, nil
}
```

```go
// internal/handler/auth_handler.go

func (h *AuthHandler) RefreshToken(c *gin.Context) {
    var req request.RefreshRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
        return
    }

    resp, err := h.authService.RefreshAccessToken(c.Request.Context(), &req)
    if err != nil {
        handleError(c, err)
        return
    }

    c.JSON(http.StatusOK, resp)
}
```

### 2.9 Add Logout Endpoint

```go
// internal/models/request/logout_request.go
package request

type LogoutRequest struct {
    RefreshToken string `json:"refresh_token" validate:"required"`
}
```

```go
// internal/service/auth_service.go

func (s *authService) Logout(ctx context.Context, request *request.LogoutRequest) error {
    err := s.refreshTokenRepo.Revoke(ctx, request.RefreshToken)
    if err != nil {
        logger.Error("failed to revoke refresh token", "error", err)
        return apperrors.InternalServer(constants.ErrInternalServer)
    }

    logger.Info("✓ User logged out successfully")
    return nil
}

func (s *authService) LogoutAllDevices(ctx context.Context, userID string) error {
    err := s.refreshTokenRepo.RevokeAllForUser(ctx, userID)
    if err != nil {
        logger.Error("failed to revoke all tokens", "error", err)
        return apperrors.InternalServer(constants.ErrInternalServer)
    }

    logger.Info("✓ All devices logged out", "userId", userID)
    return nil
}
```

```go
// internal/handler/auth_handler.go

func (h *AuthHandler) Logout(c *gin.Context) {
    var req request.LogoutRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
        return
    }

    err := h.authService.Logout(c.Request.Context(), &req)
    if err != nil {
        handleError(c, err)
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "logged out successfully"})
}

func (h *AuthHandler) LogoutAllDevices(c *gin.Context) {
    // Extract userID from validated JWT (from middleware)
    userID := c.GetString("user_id")

    err := h.authService.LogoutAllDevices(c.Request.Context(), userID)
    if err != nil {
        handleError(c, err)
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "logged out from all devices"})
}
```

### 2.10 Public Key Endpoint

```go
// internal/handler/auth_handler.go

func (h *AuthHandler) GetPublicKey(c *gin.Context) {
    privateKey := auth.GetPrivateKey()
    if privateKey == nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "public key not available"})
        return
    }

    publicKey := &privateKey.PublicKey
    publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to marshal public key"})
        return
    }

    publicKeyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: publicKeyBytes,
    })

    c.Header("Content-Type", "application/x-pem-file")
    c.Data(http.StatusOK, "application/x-pem-file", publicKeyPEM)
}
```

### 2.11 Register Routes

```go
// internal/routes/routes.go

func SetupRoutes(router *gin.Engine, authHandler *handler.AuthHandler) {
    api := router.Group("/api")
    {
        auth := api.Group("/auth")
        {
            // Existing routes
            auth.POST("/register-device", authHandler.RegisterDevice)
            auth.POST("/login", authHandler.LoginWithPassword)
            
            // New JWT routes
            auth.POST("/refresh", authHandler.RefreshToken)
            auth.POST("/logout", authHandler.Logout)
            auth.GET("/public-key", authHandler.GetPublicKey)
            
            // Protected route (requires JWT)
            auth.POST("/logout-all", middleware.JWTAuthMiddleware(), authHandler.LogoutAllDevices)
        }
    }
}
```

**Action items:**
- [ ] Add RefreshTokenRepository to service dependencies
- [ ] Update AuthService constructor
- [ ] Run database migration
- [ ] Test login flow returns JWT tokens
- [ ] Test refresh token flow
- [ ] Test logout revocation

---

## Phase 3: Chat-Service - JWT Verification

### 3.1 Load RSA Public Key at Startup

```go
// chat-service/internal/auth/keys.go
package auth

import (
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "io"
    "net/http"
    "os"
)

var jwtPublicKey *rsa.PublicKey

// Load from file (for development)
func LoadPublicKeyFromFile(filepath string) error {
    keyData, err := os.ReadFile(filepath)
    if err != nil {
        return fmt.Errorf("failed to read public key: %w", err)
    }

    return parsePublicKey(keyData)
}

// Load from user-service endpoint (for production)
func LoadPublicKeyFromUserService(userServiceURL string) error {
    resp, err := http.Get(userServiceURL + "/api/auth/public-key")
    if err != nil {
        return fmt.Errorf("failed to fetch public key: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        return fmt.Errorf("failed to fetch public key: status %d", resp.StatusCode)
    }

    keyData, err := io.ReadAll(resp.Body)
    if err != nil {
        return fmt.Errorf("failed to read public key response: %w", err)
    }

    return parsePublicKey(keyData)
}

func parsePublicKey(keyData []byte) error {
    block, _ := pem.Decode(keyData)
    if block == nil {
        return fmt.Errorf("failed to decode PEM block")
    }

    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return fmt.Errorf("failed to parse public key: %w", err)
    }

    var ok bool
    jwtPublicKey, ok = pub.(*rsa.PublicKey)
    if !ok {
        return fmt.Errorf("not an RSA public key")
    }

    return nil
}

func GetPublicKey() *rsa.PublicKey {
    return jwtPublicKey
}
```

```go
// chat-service/cmd/server/main.go
func main() {
    // ... existing setup ...

    // Load JWT public key from user-service
    userServiceURL := os.Getenv("USER_SERVICE_URL") // e.g., http://user-service:8080
    if userServiceURL == "" {
        logger.Fatal("USER_SERVICE_URL environment variable not set")
    }

    if err := auth.LoadPublicKeyFromUserService(userServiceURL); err != nil {
        logger.Fatal("Failed to load JWT public key", "error", err)
    }
    logger.Info("✓ JWT public key loaded from user-service")

    // ... rest of server setup ...
}
```

### 3.2 JWT Verification Function

```go
// chat-service/internal/auth/jwt.go
package auth

import (
    "fmt"
    "github.com/golang-jwt/jwt/v5"
)

type JWTClaims struct {
    UserID   string `json:"user_id"`
    DeviceID string `json:"device_id"`
    jwt.RegisteredClaims
}

func VerifyAccessToken(tokenString string) (*JWTClaims, error) {
    publicKey := GetPublicKey()
    if publicKey == nil {
        return nil, fmt.Errorf("JWT public key not loaded")
    }

    token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
        // Verify signing method
        if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return publicKey, nil
    })

    if err != nil {
        return nil, fmt.Errorf("failed to parse token: %w", err)
    }

    claims, ok := token.Claims.(*JWTClaims)
    if !ok || !token.Valid {
        return nil, fmt.Errorf("invalid token claims")
    }

    return claims, nil
}
```

### 3.3 Authentication Middleware

```go
// chat-service/internal/middleware/jwt_middleware.go
package middleware

import (
    "net/http"
    "strings"
    
    "chat-service/internal/auth"
    "github.com/gin-gonic/gin"
)

func JWTAuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Extract token from Authorization header
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
            c.Abort()
            return
        }

        // Check Bearer scheme
        parts := strings.Split(authHeader, " ")
        if len(parts) != 2 || parts[0] != "Bearer" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
            c.Abort()
            return
        }

        tokenString := parts[1]

        // Verify JWT
        claims, err := auth.VerifyAccessToken(tokenString)
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
            c.Abort()
            return
        }

        // Add claims to context
        c.Set("user_id", claims.UserID)
        c.Set("device_id", claims.DeviceID)

        c.Next()
    }
}
```

### 3.4 Protected Chat Endpoints

```go
// chat-service/internal/handler/message_handler.go
package handler

import (
    "net/http"
    "github.com/gin-gonic/gin"
)

type MessageHandler struct {
    // ... your dependencies
}

func (h *MessageHandler) SendMessage(c *gin.Context) {
    // Extract user info from context (set by middleware)
    userID := c.GetString("user_id")
    deviceID := c.GetString("device_id")

    var req struct {
        RoomID  string `json:"room_id" validate:"required"`
        Message string `json:"message" validate:"required"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
        return
    }

    // Process message...
    // logger.Info("User sent message", "userId", userID, "deviceId", deviceID, "roomId", req.RoomID)

    // Store in database, broadcast to room, etc.

    c.JSON(http.StatusOK, gin.H{
        "status": "message sent",
        "user_id": userID,
    })
}

func (h *MessageHandler) GetMessages(c *gin.Context) {
    userID := c.GetString("user_id")
    roomID := c.Param("room_id")

    // Fetch messages for this room...
    // Verify user has access to this room...

    c.JSON(http.StatusOK, gin.H{
        "room_id": roomID,
        "user_id": userID,
        "messages": []string{}, // Your actual messages
    })
}
```

### 3.5 Register Protected Routes

```go
// chat-service/internal/routes/routes.go

func SetupRoutes(router *gin.Engine, messageHandler *handler.MessageHandler) {
    api := router.Group("/api")
    {
        // All message routes require JWT authentication
        messages := api.Group("/messages")
        messages.Use(middleware.JWTAuthMiddleware())
        {
            messages.POST("/send", messageHandler.SendMessage)
            messages.GET("/:room_id", messageHandler.GetMessages)
        }

        rooms := api.Group("/rooms")
        rooms.Use(middleware.JWTAuthMiddleware())
        {
            rooms.POST("/create", messageHandler.CreateRoom)
            rooms.POST("/join", messageHandler.JoinRoom)
            rooms.POST("/leave", messageHandler.LeaveRoom)
        }
    }
}
```

**Action items:**
- [ ] Set USER_SERVICE_URL environment variable
- [ ] Implement JWT verification
- [ ] Add auth middleware to all protected routes
- [ ] Test authenticated requests
- [ ] Test expired/invalid token rejection

---

## Phase 4: Client Implementation

### 4.1 Token Storage

```javascript
// client/src/auth/tokenManager.js

class TokenManager {
    constructor() {
        this.accessToken = localStorage.getItem('access_token');
        this.refreshToken = localStorage.getItem('refresh_token');
        this.expiresAt = parseInt(localStorage.getItem('token_expires_at') || '0');
        
        // Check and refresh on initialization
        this.checkAndRefresh();
        
        // Check every 30 minutes
        setInterval(() => this.checkAndRefresh(), 30 * 60 * 1000);
    }

    saveTokens(accessToken, refreshToken, expiresIn) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expiresAt = Math.floor(Date.now() / 1000) + expiresIn;

        localStorage.setItem('access_token', accessToken);
        localStorage.setItem('refresh_token', refreshToken);
        localStorage.setItem('token_expires_at', this.expiresAt.toString());
    }

    async checkAndRefresh() {
        const now = Math.floor(Date.now() / 1000);
        const timeUntilExpiry = this.expiresAt - now;

        // Refresh if less than 30 minutes until expiry
        if (timeUntilExpiry < 30 * 60 && this.refreshToken) {
            console.log('Token expiring soon, refreshing...');
            await this.refreshAccessToken();
        }
    }

    async refreshAccessToken() {
        if (!this.refreshToken) {
            console.error('No refresh token available');
            return false;
        }

        try {
            const response = await fetch('http://localhost:8080/api/auth/refresh', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ refresh_token: this.refreshToken })
            });

            if (response.ok) {
                const data = await response.json();
                // Keep the same refresh token, only update access token
                this.saveTokens(data.access_token, this.refreshToken, data.expires_in);
                console.log('✓ Token refreshed successfully');
                return true;
            } else {
                console.error('Token refresh failed:', response.status);
                this.clearTokens();
                // Redirect to login
                window.location.href = '/login';
                return false;
            }
        } catch (error) {
            console.error('Token refresh error:', error);
            return false;
        }
    }

    getAccessToken() {
        return this.accessToken;
    }

    clearTokens() {
        this.accessToken = null;
        this.refreshToken = null;
        this.expiresAt = 0;
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('token_expires_at');
    }

    async logout() {
        try {
            await fetch('http://localhost:8080/api/auth/logout', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ refresh_token: this.refreshToken })
            });
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            this.clearTokens();
            window.location.href = '/login';
        }
    }
}

export const tokenManager = new TokenManager();
```

### 4.2 API Client with Auto-Retry

```javascript
// client/src/api/client.js

import { tokenManager } from '../auth/tokenManager';

class APIClient {
    constructor(baseURL) {
        this.baseURL = baseURL;
    }

    async request(endpoint, options = {}) {
        const token = tokenManager.getAccessToken();
        
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers,
        };

        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        const url = `${this.baseURL}${endpoint}`;
        let response = await fetch(url, {
            ...options,
            headers,
        });

        // If 401, try refreshing token once
        if (response.status === 401) {
            console.log('Got 401, attempting token refresh...');
            const refreshed = await tokenManager.refreshAccessToken();
            
            if (refreshed) {
                // Retry with new token
                headers['Authorization'] = `Bearer ${tokenManager.getAccessToken()}`;
                response = await fetch(url, {
                    ...options,
                    headers,
                });
            } else {
                // Refresh failed, redirect to login
                window.location.href = '/login';
                throw new Error('Authentication failed');
            }
        }

        return response;
    }

    async get(endpoint) {
        return this.request(endpoint, { method: 'GET' });
    }

    async post(endpoint, data) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(data),
        });
    }
}

export const chatClient = new APIClient('http://localhost:8081/api');
export const authClient = new APIClient('http://localhost:8080/api');
```

### 4.3 Login Flow

```javascript
// client/src/auth/login.js

import { tokenManager } from './tokenManager';
import { authClient } from '../api/client';
import { generateHMAC, generateNonce } from './crypto';

async function login(username, password, deviceID, serverHMACKey) {
    const timestamp = Date.now();
    const nonce = generateNonce();
    
    // Generate session ID
    const sessionData = `${deviceID}:${timestamp}:${nonce}`;
    const sessionID = generateHMAC(serverHMACKey, sessionData);
    
    // Generate device signature
    const loginMessage = `login:${username}:${timestamp}:${nonce}`;
    const deviceSignature = generateHMAC(serverHMACKey, loginMessage);

    const response = await fetch('http://localhost:8080/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            username,
            password,
            device_id: deviceID,
            timestamp: timestamp.toString(),
            nonce,
            session_id: sessionID,
            device_signature: deviceSignature,
            device_info: navigator.userAgent,
            ip_address: '', // Will be set by server
        }),
    });

    if (response.ok) {
        const data = await response.json();
        
        // Save JWT tokens
        tokenManager.saveTokens(
            data.access_token,
            data.refresh_token,
            data.expires_in
        );

        console.log('✓ Logged in successfully');
        console.log('User:', data.user);
        
        return data;
    } else {
        const error = await response.json();
        throw new Error(error.error || 'Login failed');
    }
}

export { login };
```

### 4.4 Chat API Usage

```javascript
// client/src/chat/messages.js

import { chatClient } from '../api/client';

async function sendMessage(roomID, message) {
    try {
        const response = await chatClient.post('/messages/send', {
            room_id: roomID,
            message: message,
        });

        if (response.ok) {
            const data = await response.json();
            console.log('✓ Message sent:', data);
            return data;
        } else {
            const error = await response.json();
            throw new Error(error.error || 'Failed to send message');
        }
    } catch (error) {
        console.error('Send message error:', error);
        throw error;
    }
}

async function getMessages(roomID) {
    try {
        const response = await chatClient.get(`/messages/${roomID}`);

        if (response.ok) {
            const data = await response.json();
            return data.messages;
        } else {
            const error = await response.json();
            throw new Error(error.error || 'Failed to get messages');
        }
    } catch (error) {
        console.error('Get messages error:', error);
        throw error;
    }
}

export { sendMessage, getMessages };
```

**Action items:**
- [ ] Implement TokenManager class
- [ ] Implement API client with auto-retry
- [ ] Update login flow to save tokens
- [ ] Test token refresh flow
- [ ] Test chat API calls with JWT

---

## Phase 5: Testing & Validation

### 5.1 Test Checklist

**User-Service:**
- [ ] Generate RSA keys successfully
- [ ] Load private key at startup
- [ ] Login returns JWT tokens
- [ ] Refresh token endpoint works
- [ ] Logout revokes refresh token
- [ ] Public key endpoint returns valid PEM
- [ ] Cannot refresh with revoked token
- [ ] Cannot refresh with expired token

**Chat-Service:**
- [ ] Load public key at startup
- [ ] Verify valid JWT successfully
- [ ] Reject expired JWT
- [ ] Reject invalid signature
- [ ] Extract user_id and device_id from JWT
- [ ] Protected endpoints require valid JWT
- [ ] 401 on missing/invalid token

**Client:**
- [ ] Store tokens after login
- [ ] Include JWT in API requests
- [ ] Auto-refresh before expiry
- [ ] Retry failed requests after refresh
- [ ] Logout clears tokens
- [ ] Redirect to login when refresh fails

### 5.2 Manual Testing Scripts

```bash
# 1. Login (after device registration)
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "testpass123",
    "device_id": "your-device-id",
    "timestamp": "1234567890",
    "nonce": "random-nonce",
    "session_id": "hmac-session-id",
    "device_signature": "hmac-signature",
    "device_info": "test-device"
  }'

# Save access_token and refresh_token from response

# 2. Test chat service with JWT
curl -X POST http://localhost:8081/api/messages/send \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"room_id":"test-room","message":"Hello World"}'

# 3. Test token refresh
curl -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'

# 4. Test logout
curl -X POST http://localhost:8080/api/auth/logout \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'

# 5. Verify JWT is now invalid (should get 401)
curl -X POST http://localhost:8081/api/messages/send \
  -H "Authorization: Bearer <old_access_token>" \
  -H "Content-Type: application/json" \
  -d '{"room_id":"test-room","message":"Should fail"}'
```

### 5.3 Integration Test

```go
// user-service/tests/integration/jwt_test.go
package integration

import (
    "testing"
    "time"
)

func TestJWTFlow(t *testing.T) {
    // 1. Login and get tokens
    loginResp := loginUser(t, "testuser", "testpass")
    accessToken := loginResp.AccessToken
    refreshToken := loginResp.RefreshToken

    // 2. Verify access token works
    err := sendMessage(t, accessToken, "test-room", "hello")
    assert.NoError(t, err)

    // 3. Wait for token to expire (in test, use short expiry)
    time.Sleep(3 * time.Second)

    // 4. Access token should be expired
    err = sendMessage(t, accessToken, "test-room", "should fail")
    assert.Error(t, err)

    // 5. Refresh token
    newAccessToken := refreshAccessToken(t, refreshToken)

    // 6. New access token should work
    err = sendMessage(t, newAccessToken, "test-room", "should work")
    assert.NoError(t, err)

    // 7. Logout
    logout(t, refreshToken)

    // 8. Cannot refresh after logout
    err = refreshAccessToken(t, refreshToken)
    assert.Error(t, err)
}
```

---

## Phase 6: Production Considerations

### 6.1 Environment Variables

```bash
# user-service/.env
JWT_PRIVATE_KEY_PATH=keys/jwt_private_key.pem
ACCESS_TOKEN_EXPIRY=2h
REFRESH_TOKEN_EXPIRY=720h  # 30 days
```

```bash
# chat-service/.env
USER_SERVICE_URL=http://user-service:8080
JWT_PUBLIC_KEY_FETCH_RETRY=3
JWT_PUBLIC_KEY_FETCH_TIMEOUT=10s
```

### 6.2 Security Hardening

- [ ] Store private key in KMS/Vault (AWS KMS, HashiCorp Vault)
- [ ] Use HTTPS/TLS for all communication
- [ ] Implement rate limiting on refresh endpoint (max 10/hour per device)
- [ ] Add request logging and monitoring
- [ ] Implement token revocation list in Redis (if needed)
- [ ] Set secure CORS policies
- [ ] Add CSRF protection where needed

### 6.3 Monitoring & Observability

```go
// Add metrics
func (s *authService) LoginWithPassword(ctx context.Context, request *request.LoginRequest) (*response.AuthResponse, error) {
    metrics.LoginAttempts.Inc()
    startTime := time.Now()
    defer func() {
        metrics.LoginDuration.Observe(time.Since(startTime).Seconds())
    }()

    // ... existing code ...
}

func (s *authService) RefreshAccessToken(ctx context.Context, request *request.RefreshRequest) (*response.RefreshResponse, error) {
    metrics.TokenRefreshes.Inc()
    // ... existing code ...
}
```

### 6.4 Cleanup Jobs

```go
// cmd/cleanup/main.go
// Run as a cron job to clean up expired tokens

func cleanupExpiredTokens() {
    db := connectDB()
    
    result, err := db.Exec(`
        DELETE FROM refresh_tokens 
        WHERE expires_at < NOW() 
        OR (revoked = TRUE AND revoked_at < NOW() - INTERVAL '30 days')
    `)
    
    if err != nil {
        log.Printf("Failed to cleanup tokens: %v", err)
        return
    }
    
    rows, _ := result.RowsAffected()
    log.Printf("Cleaned up %d expired tokens", rows)
}
```

### 6.5 Future Enhancements

- [ ] Add `kid` (Key ID) for key rotation
- [ ] Implement proper JWKS endpoint (JSON format)
- [ ] Add refresh token rotation (new refresh token on each refresh)
- [ ] Add device management UI (list/revoke devices)
- [ ] Implement "remember this device" feature
- [ ] Add JWT revocation list for immediate invalidation
- [ ] Support multiple active sessions per user

---

## Summary Timeline

| Phase | Estimated Time | Priority |
|-------|---------------|----------|
| Phase 1: Key Generation | 30 min | HIGH |
| Phase 2: User-Service JWT | 4-5 hours | HIGH |
| Phase 3: Chat-Service Verification | 2-3 hours | HIGH |
| Phase 4: Client Implementation | 2-3 hours | HIGH |
| Phase 5: Testing | 2 hours | HIGH |
| Phase 6: Production Hardening | Ongoing | MEDIUM |

**Total MVP Time: ~11-14 hours**

---

## Quick Start Commands

```bash
# 1. Generate keys
cd user-service
mkdir -p keys
go run cmd/keygen/main.go

# 2. Run migrations
# (assuming you have a migration tool setup)
migrate -path migrations -database "postgres://..." up

# 3. Start user-service
JWT_PRIVATE_KEY_PATH=keys/jwt_private_key.pem go run cmd/server/main.go

# 4. Start chat-service
USER_SERVICE_URL=http://localhost:8080 go run cmd/server/main.go

# 5. Test login
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d @test_login.json
```