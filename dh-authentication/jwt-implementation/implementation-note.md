# Simple Mobile/Desktop Chat Authentication Implementation Plan

## Table of Contents

- [Overview](#overview)
- [Phase 1: User-Service - Session Management](#phase-1-user-service---session-management)
  - [1.1 Update Session Configuration](#11-update-session-configuration)
  - [1.2 Update Database Schema](#12-update-database-schema)
  - [1.3 Update Login to Create Long-Lived Sessions](#13-update-login-to-create-long-lived-sessions)
  - [1.4 Add Session Validation Endpoint (for chat-service to use)](#14-add-session-validation-endpoint-for-chat-service-to-use)
  - [1.5 Add Logout Endpoint](#15-add-logout-endpoint)
  - [1.6 Register Routes](#16-register-routes)
- [Phase 2: Chat-Service - Session Validation](#phase-2-chat-service---session-validation)
  - [2.1 Setup Configuration](#21-setup-configuration)
  - [2.2 Session Data Model](#22-session-data-model)
  - [2.3 Session Validator (with Redis + user-service fallback)](#23-session-validator-with-redis--user-service-fallback)
  - [2.4 Authentication Middleware](#24-authentication-middleware)
  - [2.5 Setup Chat Service](#25-setup-chat-service)
  - [2.6 Protected Handlers Example](#26-protected-handlers-example)
- [Phase 3: Mobile/Desktop Client Implementation](#phase-3-mobiledesktop-client-implementation)
  - [3.1 Secure Storage Setup](#31-secure-storage-setup)
  - [3.2 Authentication Service](#32-authentication-service)
  - [3.3 Chat API Service](#33-chat-api-service)
  - [3.4 Usage Example](#34-usage-example)
- [Phase 4: Testing & Validation](#phase-4-testing--validation)
  - [4.1 Manual Testing](#41-manual-testing)
  - [4.2 Test Checklist](#42-test-checklist)
  - [4.3 Performance Testing](#43-performance-testing)
- [Phase 5: Production Setup](#phase-5-production-setup)
  - [5.1 Environment Variables](#51-environment-variables)
  - [5.2 Docker Compose (for local development)](#52-docker-compose-for-local-development)
  - [5.3 Security Checklist](#53-security-checklist)
  - [5.4 Cleanup Job (Optional)](#54-cleanup-job-optional)
- [Summary](#summary)
  - [Architecture](#architecture)
  - [Performance](#performance)
  - [Implementation Time](#implementation-time)
  - [Key Benefits](#key-benefits)

---

## Overview
- **No JWT complexity** - just session IDs
- **No web concerns** - mobile/desktop only (no cookies, CORS, XSS)
- **Database as source of truth** - Redis as fast cache
- Session ID passed via `Authorization: Bearer <session_id>` header
- "Forever" login via long-lived sessions (1 year, refreshed on activity)

---

## Phase 1: User-Service - Session Management

### 1.1 Update Session Configuration

```go
// internal/config/config.go
type SessionConfig struct {
    CacheTTL     time.Duration // Redis cache TTL (1 hour)
    DatabaseTTL  time.Duration // Database session TTL (1 year)
}

func LoadConfig() *Config {
    return &Config{
        Session: SessionConfig{
            CacheTTL:    1 * time.Hour,
            DatabaseTTL: 365 * 24 * time.Hour, // 1 year
        },
    }
}
```

### 1.2 Update Database Schema

```sql
-- migrations/004_update_sessions_for_long_lived.sql

-- Make expires_at nullable for "forever" sessions
ALTER TABLE user_sessions 
ALTER COLUMN expires_at DROP NOT NULL;

-- Set default to 1 year from now
ALTER TABLE user_sessions 
ALTER COLUMN expires_at SET DEFAULT NOW() + INTERVAL '1 year';

-- Add index for faster lookups
CREATE INDEX IF NOT EXISTS idx_user_sessions_lookup 
ON user_sessions(session_id, is_active) 
WHERE is_active = true;

-- Add last_activity_at for tracking
ALTER TABLE user_sessions 
ADD COLUMN IF NOT EXISTS last_activity_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

CREATE INDEX IF NOT EXISTS idx_user_sessions_activity 
ON user_sessions(last_activity_at);
```

### 1.3 Update Login to Create Long-Lived Sessions

```go
// internal/service/auth_service.go

func (s *authService) LoginWithPassword(ctx context.Context, request *request.LoginRequest) (*response.AuthResponse, error) {
    // ... [Steps 1-8 remain exactly the same - your existing validation] ...

    // 9. Create session in DB with long expiry
    sessionID := request.SessionID
    expiresAt := time.Now().Add(s.config.Session.DatabaseTTL) // 1 year

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

    // 10. Cache session in Redis with SHORT TTL (will be refreshed)
    sessionData := &repository.SessionData{
        UserID:        user.UserID.String(),
        DeviceID:      device.DeviceID.String(),
        ServerHMACKey: device.ServerHMACKey,
    }

    err = s.sessionRepo.SetSessionCache(ctx, sessionID, sessionData, s.config.Session.CacheTTL) // 1 hour
    if err != nil {
        logger.Warn("failed to cache session", "error", err)
    }

    logger.Info("✓ Session created", "userId", user.UserID, "deviceId", device.DeviceID, "expiresAt", expiresAt)

    return &response.AuthResponse{
        SessionID: sessionID, // Client stores this securely
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

### 1.4 Add Session Validation Endpoint (for chat-service to use)

```go
// internal/models/request/validate_session_request.go
package request

type ValidateSessionRequest struct {
    SessionID string `json:"session_id" validate:"required"`
}
```

```go
// internal/models/response/validate_session_response.go
package response

type ValidateSessionResponse struct {
    Valid    bool   `json:"valid"`
    UserID   string `json:"user_id,omitempty"`
    DeviceID string `json:"device_id,omitempty"`
}
```

```go
// internal/service/auth_service.go

func (s *authService) ValidateSession(ctx context.Context, sessionID string) (*response.ValidateSessionResponse, error) {
    // Check Redis cache first
    sessionData, err := s.sessionRepo.GetSessionCache(ctx, sessionID)
    if err == nil {
        // Cache hit - update last activity asynchronously
        go s.updateLastActivity(sessionID)
        
        return &response.ValidateSessionResponse{
            Valid:    true,
            UserID:   sessionData.UserID,
            DeviceID: sessionData.DeviceID,
        }, nil
    }

    // Cache miss - check database
    session, err := s.sessionRepo.GetBySessionID(ctx, sessionID)
    if err != nil {
        return &response.ValidateSessionResponse{Valid: false}, nil
    }

    // Verify session is still valid
    if !session.IsActive {
        return &response.ValidateSessionResponse{Valid: false}, nil
    }

    if session.ExpiresAt != nil && time.Now().After(*session.ExpiresAt) {
        return &response.ValidateSessionResponse{Valid: false}, nil
    }

    // Cache it for next time
    sessionData = &repository.SessionData{
        UserID:   session.UserID.String(),
        DeviceID: session.DeviceID.String(),
    }
    
    s.sessionRepo.SetSessionCache(ctx, sessionID, sessionData, s.config.Session.CacheTTL)
    
    // Update last activity
    go s.updateLastActivity(sessionID)

    return &response.ValidateSessionResponse{
        Valid:    true,
        UserID:   session.UserID.String(),
        DeviceID: session.DeviceID.String(),
    }, nil
}

func (s *authService) updateLastActivity(sessionID string) {
    ctx := context.Background()
    s.sessionRepo.UpdateLastActivity(ctx, sessionID)
}
```

```go
// internal/repository/session_repository.go

func (r *sessionRepository) GetBySessionID(ctx context.Context, sessionID string) (*models.UserSession, error) {
    var session models.UserSession
    
    err := r.db.QueryRowContext(ctx, `
        SELECT session_id, user_id, device_id, device_info, ip_address, 
               expires_at, last_activity_at, is_active, created_at, updated_at
        FROM user_sessions
        WHERE session_id = $1
    `, sessionID).Scan(
        &session.SessionID,
        &session.UserID,
        &session.DeviceID,
        &session.DeviceInfo,
        &session.IPAddress,
        &session.ExpiresAt,
        &session.LastActivityAt,
        &session.IsActive,
        &session.CreatedAt,
        &session.UpdatedAt,
    )
    
    if err == sql.ErrNoRows {
        return nil, errors.New("session not found")
    }
    
    return &session, err
}

func (r *sessionRepository) UpdateLastActivity(ctx context.Context, sessionID string) error {
    _, err := r.db.ExecContext(ctx, `
        UPDATE user_sessions 
        SET last_activity_at = NOW() 
        WHERE session_id = $1
    `, sessionID)
    
    return err
}
```

```go
// internal/handler/auth_handler.go

func (h *AuthHandler) ValidateSession(c *gin.Context) {
    var req request.ValidateSessionRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
        return
    }

    resp, err := h.authService.ValidateSession(c.Request.Context(), req.SessionID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
        return
    }

    if !resp.Valid {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid session"})
        return
    }

    c.JSON(http.StatusOK, resp)
}
```

### 1.5 Add Logout Endpoint

```go
// internal/models/request/logout_request.go
package request

type LogoutRequest struct {
    SessionID string `json:"session_id" validate:"required"`
}
```

```go
// internal/service/auth_service.go

func (s *authService) Logout(ctx context.Context, sessionID string) error {
    // Invalidate in database
    err := s.sessionRepo.Invalidate(ctx, sessionID)
    if err != nil {
        logger.Error("failed to invalidate session", "error", err)
        return apperrors.InternalServer(constants.ErrInternalServer)
    }

    // Remove from cache
    s.sessionRepo.DeleteSessionCache(ctx, sessionID)

    logger.Info("✓ Session logged out", "sessionId", sessionID)
    return nil
}

func (s *authService) LogoutAllDevices(ctx context.Context, userID string) error {
    // Invalidate all sessions for this user
    err := s.sessionRepo.InvalidateAllForUser(ctx, userID)
    if err != nil {
        logger.Error("failed to invalidate all sessions", "error", err)
        return apperrors.InternalServer(constants.ErrInternalServer)
    }

    // Clear cache (use pattern matching or prefix scan)
    // This is optional - cache will expire naturally
    
    logger.Info("✓ All sessions logged out", "userId", userID)
    return nil
}
```

```go
// internal/repository/session_repository.go

func (r *sessionRepository) Invalidate(ctx context.Context, sessionID string) error {
    _, err := r.db.ExecContext(ctx, `
        UPDATE user_sessions 
        SET is_active = false, updated_at = NOW()
        WHERE session_id = $1
    `, sessionID)
    
    return err
}

func (r *sessionRepository) InvalidateAllForUser(ctx context.Context, userID string) error {
    _, err := r.db.ExecContext(ctx, `
        UPDATE user_sessions 
        SET is_active = false, updated_at = NOW()
        WHERE user_id = $1 AND is_active = true
    `, userID)
    
    return err
}

func (r *sessionRepository) DeleteSessionCache(ctx context.Context, sessionID string) error {
    return r.redis.Del(ctx, "session:"+sessionID).Err()
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

    err := h.authService.Logout(c.Request.Context(), req.SessionID)
    if err != nil {
        handleError(c, err)
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "logged out successfully"})
}

func (h *AuthHandler) LogoutAllDevices(c *gin.Context) {
    // Extract userID from validated session (from middleware)
    userID := c.GetString("user_id")
    if userID == "" {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
        return
    }

    err := h.authService.LogoutAllDevices(c.Request.Context(), userID)
    if err != nil {
        handleError(c, err)
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "logged out from all devices"})
}
```

### 1.6 Register Routes

```go
// internal/routes/routes.go

func SetupRoutes(router *gin.Engine, authHandler *handler.AuthHandler) {
    api := router.Group("/api")
    {
        auth := api.Group("/auth")
        {
            // Public routes
            auth.POST("/register-device", authHandler.RegisterDevice)
            auth.POST("/login", authHandler.LoginWithPassword)
            auth.POST("/logout", authHandler.Logout)
            
            // Internal route for chat-service
            auth.POST("/validate-session", authHandler.ValidateSession)
            
            // Protected routes (require session validation)
            // auth.POST("/logout-all", middleware.SessionAuthMiddleware(), authHandler.LogoutAllDevices)
        }
    }
}
```

**Action items:**
- [ ] Run database migration
- [ ] Update session configuration
- [ ] Implement validation endpoint
- [ ] Implement logout endpoints
- [ ] Test login flow returns session ID
- [ ] Test session validation endpoint

---

## Phase 2: Chat-Service - Session Validation

### 2.1 Setup Configuration

```go
// chat-service/internal/config/config.go
package config

import (
    "os"
    "time"
)

type Config struct {
    Server      ServerConfig
    Redis       RedisConfig
    UserService UserServiceConfig
}

type ServerConfig struct {
    Port string
}

type RedisConfig struct {
    URL      string // Shared with user-service
    CacheTTL time.Duration
}

type UserServiceConfig struct {
    URL string // For validation API calls (fallback)
}

func Load() *Config {
    return &Config {
        Server: ServerConfig{
            Port: getEnv("PORT", "8081"),
        },
        Redis: RedisConfig{
            URL:      getEnv("REDIS_URL", "redis://localhost:6379"),
            CacheTTL: 1 * time.Hour,
        },
        UserService: UserServiceConfig{
            URL: getEnv("USER_SERVICE_URL", "http://localhost:8080"),
        },
    }
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}
```

### 2.2 Session Data Model

```go
// chat-service/internal/models/session.go
package models

type SessionData struct {
    UserID   string `json:"user_id"`
    DeviceID string `json:"device_id"`
}
```

### 2.3 Session Validator (with Redis + user-service fallback)

```go
// chat-service/internal/auth/session_validator.go
package auth

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "time"

    "chat-service/internal/config"
    "chat-service/internal/models"
    
    "github.com/redis/go-redis/v9"
)

type SessionValidator struct {
    redis      *redis.Client
    config     *config.Config
    httpClient *http.Client
}

func NewSessionValidator(redis *redis.Client, cfg *config.Config) *SessionValidator {
    return &SessionValidator{
        redis:  redis,
        config: cfg,
        httpClient: &http.Client{
            Timeout: 2 * time.Second,
        },
    }
}

func (v *SessionValidator) Validate(ctx context.Context, sessionID string) (*models.SessionData, error) {
    // Try Redis first (fast path - 1-2ms)
    session, err := v.getFromRedis(ctx, sessionID)
    if err == nil {
        return session, nil
    }

    // Cache miss - call user-service validation endpoint
    session, err = v.validateViaUserService(ctx, sessionID)
    if err != nil {
        return nil, err
    }

    // Optional: cache in Redis (user-service should already be caching,
    // but this keeps chat-service resilient if that ever changes)
    v.cacheSession(ctx, sessionID, session)

    return session, nil
}

func (v *SessionValidator) getFromRedis(ctx context.Context, sessionID string) (*models.SessionData, error) {
    sessionJSON, err := v.redis.Get(ctx, "session:"+sessionID).Result()
    if err != nil {
        return nil, err
    }

    var session models.SessionData
    if err := json.Unmarshal([]byte(sessionJSON), &session); err != nil {
        return nil, err
    }

    return &session, nil
}

func (v *SessionValidator) validateViaUserService(ctx context.Context, sessionID string) (*models.SessionData, error) {
    // Request/response types mirror user-service ValidateSession API
    type validateRequest struct {
        SessionID string `json:"session_id"`
    }
    type validateResponse struct {
        Valid    bool   `json:"valid"`
        UserID   string `json:"user_id"`
        DeviceID string `json:"device_id"`
    }

    reqBody, err := json.Marshal(validateRequest{SessionID: sessionID})
    if err != nil {
        return nil, err
    }

    url := fmt.Sprintf(\"%s/api/auth/validate-session\", v.config.UserService.URL)

    httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
    if err != nil {
        return nil, err
    }
    httpReq.Header.Set(\"Content-Type\", \"application/json\")

    resp, err := v.httpClient.Do(httpReq)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf(\"validate-session failed with status %d\", resp.StatusCode)
    }

    var body validateResponse
    if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
        return nil, err
    }

    if !body.Valid {
        return nil, fmt.Errorf(\"session invalid or expired\")
    }

    return &models.SessionData{
        UserID:   body.UserID,
        DeviceID: body.DeviceID,
    }, nil
}

func (v *SessionValidator) cacheSession(ctx context.Context, sessionID string, session *models.SessionData) {
    sessionJSON, err := json.Marshal(session)
    if err != nil {
        return
    }

    v.redis.Set(ctx, "session:"+sessionID, sessionJSON, v.config.Redis.CacheTTL)
}
```

### 2.4 Authentication Middleware

```go
// chat-service/internal/middleware/auth.go
package middleware

import (
    "net/http"
    "strings"

    "chat-service/internal/auth"
    
    "github.com/gin-gonic/gin"
)

func AuthMiddleware(validator *auth.SessionValidator) gin.HandlerFunc {
    return func(c *gin.Context) {
        // Extract session ID from Authorization header
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
            c.Abort()
            return
        }

        // Expect: "Bearer <session_id>"
        parts := strings.Split(authHeader, " ")
        if len(parts) != 2 || parts[0] != "Bearer" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization format"})
            c.Abort()
            return
        }

        sessionID := parts[1]

        // Validate session
        session, err := validator.Validate(c.Request.Context(), sessionID)
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired session"})
            c.Abort()
            return
        }

        // Add to context for handlers to use
        c.Set("user_id", session.UserID)
        c.Set("device_id", session.DeviceID)

        c.Next()
    }
}
```

### 2.5 Setup Chat Service

```go
// chat-service/cmd/server/main.go
package main

import (
    "log"

    "chat-service/internal/auth"
    "chat-service/internal/config"
    "chat-service/internal/handler"
    "chat-service/internal/middleware"
    
    "github.com/gin-gonic/gin"
    "github.com/redis/go-redis/v9"
)

func main() {
    // Load configuration
    cfg := config.Load()

    // Connect to Redis (shared with user-service)
    redisClient := redis.NewClient(&redis.Options{
        Addr: cfg.Redis.URL,
    })

    if err := redisClient.Ping(ctx).Err(); err != nil {
        log.Fatal("Failed to connect to Redis:", err)
    }
    log.Println("✓ Connected to Redis")

    // Initialize session validator (Redis + user-service fallback)
    sessionValidator := auth.NewSessionValidator(redisClient, cfg)

    // Initialize handlers
    messageHandler := handler.NewMessageHandler(/* your dependencies */)

    // Setup router
    router := gin.Default()

    // Health check
    router.GET("/health", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "ok"})
    })

    // API routes with authentication
    api := router.Group("/api")
    {
        messages := api.Group("/messages")
        messages.Use(middleware.AuthMiddleware(sessionValidator))
        {
            messages.POST("/send", messageHandler.SendMessage)
            messages.GET("/:room_id", messageHandler.GetMessages)
        }

        rooms := api.Group("/rooms")
        rooms.Use(middleware.AuthMiddleware(sessionValidator))
        {
            rooms.POST("/create", messageHandler.CreateRoom)
            rooms.POST("/join", messageHandler.JoinRoom)
            rooms.POST("/leave", messageHandler.LeaveRoom)
        }
    }

    log.Printf("🚀 Chat service running on :%s", cfg.Server.Port)
    router.Run(":" + cfg.Server.Port)
}
```

### 2.6 Protected Handlers Example

```go
// chat-service/internal/handler/message_handler.go
package handler

import (
    "net/http"

    "github.com/gin-gonic/gin"
)

type MessageHandler struct {
    // your dependencies
}

func NewMessageHandler(/* deps */) *MessageHandler {
    return &MessageHandler{}
}

func (h *MessageHandler) SendMessage(c *gin.Context) {
    // Extract user info from context (set by auth middleware)
    userID := c.GetString("user_id")
    deviceID := c.GetString("device_id")

    var req struct {
        RoomID  string `json:"room_id" binding:"required"`
        Message string `json:"message" binding:"required"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
        return
    }

    // Process message...
    // Store in database, broadcast to room, etc.
    
    c.JSON(http.StatusOK, gin.H{
        "status":  "message sent",
        "user_id": userID,
        "room_id": req.RoomID,
    })
}

func (h *MessageHandler) GetMessages(c *gin.Context) {
    userID := c.GetString("user_id")
    roomID := c.Param("room_id")

    // Fetch messages for this room...
    // Verify user has access to this room...

    c.JSON(http.StatusOK, gin.H{
        "room_id":  roomID,
        "user_id":  userID,
        "messages": []interface{}{}, // Your actual messages
    })
}

func (h *MessageHandler) CreateRoom(c *gin.Context) {
    userID := c.GetString("user_id")

    var req struct {
        Name string `json:"name" binding:"required"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
        return
    }

    // Create room logic...

    c.JSON(http.StatusOK, gin.H{
        "status":  "room created",
        "creator": userID,
    })
}

func (h *MessageHandler) JoinRoom(c *gin.Context) {
    userID := c.GetString("user_id")
    // Join room logic...
    c.JSON(http.StatusOK, gin.H{"status": "joined", "user_id": userID})
}

func (h *MessageHandler) LeaveRoom(c *gin.Context) {
    userID := c.GetString("user_id")
    // Leave room logic...
    c.JSON(http.StatusOK, gin.H{"status": "left", "user_id": userID})
}
```

**Action items:**
- [ ] Set environment variables (DATABASE_URL, REDIS_URL)
- [ ] Implement session validator
- [ ] Add auth middleware
- [ ] Protect all chat endpoints
- [ ] Test with valid session ID
- [ ] Test with invalid/expired session ID

---

## Phase 3: Mobile/Desktop Client Implementation

### 3.1 Secure Storage Setup

```javascript
// React Native
import * as SecureStore from 'expo-secure-store';

// Electron
import keytar from 'keytar';

const SecureStorage = {
    // React Native implementation
    async setItem(key, value) {
        if (Platform.OS === 'web') {
            // Desktop Electron
            await keytar.setPassword('myapp', key, value);
        } else {
            // Mobile
            await SecureStore.setItemAsync(key, value);
        }
    },
    
    async getItem(key) {
        if (Platform.OS === 'web') {
            return await keytar.getPassword('myapp', key);
        } else {
            return await SecureStore.getItemAsync(key);
        }
    },
    
    async removeItem(key) {
        if (Platform.OS === 'web') {
            await keytar.deletePassword('myapp', key);
        } else {
            await SecureStore.deleteItemAsync(key);
        }
    }
};

export default SecureStorage;
```

### 3.2 Authentication Service

```javascript
// src/services/auth.js
import SecureStorage from './secureStorage';
import { generateHMAC, generateNonce } from './crypto';

const USER_SERVICE_URL = 'https://your-domain.com/api/auth';

export const AuthService = {
    async login(username, password, deviceID, serverHMACKey) {
        const timestamp = Date.now().toString();
        const nonce = generateNonce();
        
        // Generate session ID (HMAC-based)
        const sessionData = `${deviceID}:${timestamp}:${nonce}`;
        const sessionID = generateHMAC(serverHMACKey, sessionData);
        
        // Generate device signature
        const loginMessage = `login:${username}:${timestamp}:${nonce}`;
        const deviceSignature = generateHMAC(serverHMACKey, loginMessage);

        const response = await fetch(`${USER_SERVICE_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username,
                password,
                device_id: deviceID,
                timestamp,
                nonce,
                session_id: sessionID,
                device_signature: deviceSignature,
                device_info: getDeviceInfo(),
                ip_address: '', // Server will set this
            }),
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Login failed');
        }

        const data = await response.json();
        
        // Store session ID securely
        await SecureStorage.setItem('session_id', data.session_id);
        await SecureStorage.setItem('user_id', data.user.user_id);
        
        return data;
    },

    async logout() {c
        const sessionID = await SecureStorage.getItem('session_id');
        
        if (sessionID) {
            try {
                await fetch(`${USER_SERVICE_URL}/logout`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ session_id: sessionID }),
                });
            } catch (error) {
                console.error('Logout request failed:', error);
            }
        }
        
        // Clear local storage
        await SecureStorage.removeItem('session_id');
        await SecureStorage.removeItem('user_id');
    },

    async getSessionID() {
        return await SecureStorage.getItem('session_id');
    },

    async isLoggedIn() {
        const sessionID = await this.getSessionID();
        return !!sessionID;
    }
};

function getDeviceInfo() {
    // Return device info string
    return `${Platform.OS} ${Platform.Version}`;
}
```

### 3.3 Chat API Service

```javascript
// src/services/chat.js
import SecureStorage from './secureStorage';
import { AuthService } from './auth';

const CHAT_SERVICE_URL = 'https://your-domain.com/api';

class ChatAPI {
    async request(endpoint, options = {}) {
        const sessionID = await SecureStorage.getItem('session_id');
        
        if (!sessionID) {
            throw new Error('Not authenticated');
        }

        const headers = {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${sessionID}`,
            ...options.headers,
        };

        const response = await fetch(`${CHAT_SERVICE_URL}${endpoint}`, {
            ...options,
            headers,
        });

        // Handle 401 - session expired
        if (response.status === 401) {
            // Clear invalid session and redirect to login
            await AuthService.logout();
            throw new Error('Session expired. Please login again.');
        }

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Request failed');
        }

        return response.json();
    }

    async sendMessage(roomID, message) {
        return this.request('/messages/send', {
            method: 'POST',
            body: JSON.stringify({
                room_id: roomID,
                message: message,
            }),
        });
    }

    async getMessages(roomID) {
        return this.request(`/messages/${roomID}`, {
            method: 'GET',
        });
    }

    async createRoom(name) {
        return this.request('/rooms/create', {
            method: 'POST',
            body: JSON.stringify({ name }),
        });
    }

    async joinRoom(roomID) {
        return this.request('/rooms/join', {
            method: 'POST',
            body: JSON.stringify({ room_id: roomID }),
        });
    }

    async leaveRoom(roomID) {
        return this.request('/rooms/leave', {
            method: 'POST',
            body: JSON.stringify({ room_id: roomID }),
        });
    }
}

export const chatAPI = new ChatAPI();
```

### 3.4 Usage Example

```javascript
// src/screens/LoginScreen.js
import { AuthService } from '../services/auth';

export default function LoginScreen() {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');

    const handleLogin = async () => {
        try {
            const deviceID = await getDeviceID(); // Your device registration logic
            const serverHMACKey = await getServerHMACKey(); // From device registration
            
            const result = await AuthService.login(
                username, 
                password, 
                deviceID, 
                serverHMACKey
            );
            
            console.log('Logged in:', result.user);
            // Navigate to chat screen
        } catch (error) {
            alert(error.message);
        }
    };

    return (
        <View>
            <TextInput value={username} onChangeText={setUsername} />
            <TextInput value={password} onChangeText={setPassword} secureTextEntry />
            <Button title="Login" onPress={handleLogin} />
        </View>
    );
}
```

```javascript
// src/screens/ChatScreen.js
import { chatAPI } from '../services/chat';

export default function ChatScreen({ roomID }) {
    const [message, setMessage] = useState('');
    const [messages, setMessages] = useState([]);

    useEffect(() => {
        loadMessages();
    }, []);

    const loadMessages = async () => {
        try {
            const result = await chatAPI.getMessages(roomID);
            setMessages(result.messages);
        } catch (error) {
            alert(error.message);
        }
    };

    const handleSend = async () => {
        try {
            await chatAPI.sendMessage(roomID, message);
            setMessage('');
            loadMessages(); // Refresh messages
        } catch (error) {
            alert(error.message);
        }
    };

    return (
        <View>
            <FlatList data={messages} renderItem={({ item }) => (
                <Text>{item.message}</Text>
            )} />
            <TextInput value={message} onChangeText={setMessage} />
            <Button title="Send" onPress={handleSend} />
        </View>
    );
}
```

**Action items:**
- [ ] Setup secure storage (expo-secure-store or keytar)
- [ ] Implement AuthService
- [ ] Implement ChatAPI
- [ ] Test login flow
- [ ] Test chat operations
- [ ] Test session expiry handling

---

## Phase 4: Testing & Validation

### 4.1 Manual Testing

```bash
# 1. Test login
curl -X POST https://your-domain.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "testpass123",
    "device_id": "device-123",
    "timestamp": "1234567890",
    "nonce": "random-nonce",
    "session_id": "hmac-session-id",
    "device_signature": "hmac-signature",
    "device_info": "iOS 17"
  }'

# Response: { "session_id": "...", "user": {...} }
# Save the session_id

# 2. Test chat with valid session
curl -X POST https://your-domain.com/api/messages/send \
  -H "Authorization: Bearer <session_id>" \
  -H "Content-Type: application/json" \
  -d '{"room_id":"room-1","message":"Hello World"}'

# Response: { "status": "message sent", "user_id": "..." }

# 3. Test Redis cache (first request hits DB, second hits cache)
# Run the same request twice and check logs

# 4. Test logout
curl -X POST https://your-domain.com/api/auth/logout \
  -H "Content-Type: application/json" \
  -d '{"session_id":"<session_id>"}'

# 5. Test session is now invalid
curl -X POST https://your-domain.com/api/messages/send \
  -H "Authorization: Bearer <old_session_id>" \
  -H "Content-Type: application/json" \
  -d '{"room_id":"room-1","message":"Should fail"}'

# Response: 401 Unauthorized
```

### 4.2 Test Checklist

**User-Service:**
- [ ] Login creates session in database
- [ ] Login caches session in Redis
- [ ] Session has 1 year expiry
- [ ] Validation endpoint works
- [ ] Logout invalidates session
- [ ] Cannot use session after logout

**Chat-Service:**
- [ ] Rejects requests without Authorization header
- [ ] Rejects requests with invalid session
- [ ] Accepts requests with valid session
- [ ] First request checks DB (cache miss)
- [ ] Second request uses Redis (cache hit)
- [ ] Extracts user_id and device_id correctly

**Client:**
- [ ] Stores session ID in secure storage
- [ ] Includes session ID in all chat requests
- [ ] Handles 401 by logging out
- [ ] Login persists across app restarts

### 4.3 Performance Testing

```bash
# Test Redis performance
redis-cli --latency
# Should be < 1ms

# Test DB performance
psql -d yourdb -c "EXPLAIN ANALYZE SELECT user_id, device_id FROM user_sessions WHERE session_id = 'test' AND is_active = true;"

# Load test chat-service
# Install: npm install -g artillery
artillery quick --count 100 --num 10 https://your-domain.com/api/messages/send \
  -H "Authorization: Bearer <valid_session>" \
  -p '{"room_id":"test","message":"load test"}'
```

---

## Phase 5: Production Setup

### 5.1 Environment Variables

```bash
# user-service/.env
DATABASE_URL=postgresql://user:pass@localhost:5432/chatapp
REDIS_URL=redis://localhost:6379
SESSION_CACHE_TTL=1h
SESSION_DB_TTL=8760h  # 1 year
PORT=8080

# chat-service/.env
DATABASE_URL=postgresql://user:pass@localhost:5432/chatapp  # Same as user-service
REDIS_URL=redis://localhost:6379  # Same as user-service
USER_SERVICE_URL=http://user-service:8080  # Fallback (optional)
PORT=8081
```

### 5.2 Docker Compose (for local development)

```yaml
# docker-compose.yml
version: '3.8'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: chatapp
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

  user-service:
    build: ./user-service
    ports:
      - "8080:8080"
    environment:
      DATABASE_URL: postgresql://user:pass@postgres:5432/chatapp
      REDIS_URL: redis://redis:6379
    depends_on:
      - postgres
      - redis

  chat-service:
    build: ./chat-service
    ports:
      - "8081:8081"
    environment:
      DATABASE_URL: postgresql://user:pass@postgres:5432/chatapp
      REDIS_URL: redis://redis:6379
      USER_SERVICE_URL: http://user-service:8080
    depends_on:
      - postgres
      - redis
      - user-service

volumes:
  postgres_data:
  redis_data:
```

### 5.3 Security Checklist

- [ ] **HTTPS everywhere** - Use Let's Encrypt or AWS Certificate Manager
- [ ] **Rate limiting** - Prevent brute force attacks
```go
import "github.com/didip/tollbooth"

limiter := tollbooth.NewLimiter(10, nil) // 10 requests per second
router.Use(tollbooth_gin.LimitHandler(limiter))
```
- [ ] **Database connection pooling**
```go
db.SetMaxOpenConns(25)
db.SetMaxIdleConns(25)
db.SetConnMaxLifetime(5 * time.Minute)
```
- [ ] **Redis connection pooling**
```go
redis.NewClient(&redis.Options{
    PoolSize: 10,
    MinIdleConns: 5,
})
```
- [ ] **Logging** - Log all authentication events
- [ ] **Monitoring** - Track session validation latency

### 5.4 Cleanup Job (Optional)

```go
// cmd/cleanup/main.go
// Run daily via cron to clean up expired sessions

func main() {
    db := connectDB()
    
    result, err := db.Exec(`
        DELETE FROM user_sessions 
        WHERE is_active = false 
        AND updated_at < NOW() - INTERVAL '30 days'
    `)
    
    if err != nil {
        log.Fatal(err)
    }
    
    rows, _ := result.RowsAffected()
    log.Printf("Cleaned up %d old sessions", rows)
}
```

---

## Summary

### Architecture

```
┌──────────────┐
│ Mobile/      │
│ Desktop      │
│ Client       │
└──────┬───────┘
       │ Authorization: Bearer <session_id>
       │
       ├──────────────────────┐
       │                      │
       ▼                      ▼
┌──────────────┐      ┌──────────────┐
│ User-Service │      │ Chat-Service │
│ (Login)      │      │ (Messages)   │
└──────┬───────┘      └──────┬───────┘
       │                     │
       │  ┌──────────────────┤
       │  │                  │
       ▼  ▼                  ▼
   ┌─────────┐          ┌─────────┐
   │ Redis   │          │ Postgres│
   │ (Cache) │          │  (DB)   │
   └─────────┘          └─────────┘
```

### Performance

- **99% of requests**: Redis cache hit (1-2ms) ✅
- **1% of requests**: DB lookup (10-20ms) → cached ✅
- **Sessions last**: 1 year (refreshed on activity) ✅
- **User experience**: "Forever" login like Telegram ✅

### Implementation Time

| Phase | Time | Priority |
|-------|------|----------|
| Phase 1: User-Service Updates | 2-3 hours | HIGH |
| Phase 2: Chat-Service Implementation | 2-3 hours | HIGH |
| Phase 3: Client Implementation | 2-3 hours | HIGH |
| Phase 4: Testing | 1-2 hours | HIGH |
| Phase 5: Production Setup | 1-2 hours | MEDIUM |

**Total: ~8-13 hours**

### Key Benefits

✅ **Simple** - No JWT complexity, no key management  
✅ **Secure** - HTTPS + secure storage + session validation  
✅ **Fast** - Redis caching, minimal latency  
✅ **Scalable** - Handles millions of sessions  
✅ **Flexible** - Can logout, revoke, track devices  
✅ **Mobile-first** - Designed for mobile/desktop apps  

Ready to implement? 🚀