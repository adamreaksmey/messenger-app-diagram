package main

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/context"
)

// ============================================================================
// CONFIGURATION
// ============================================================================

type Config struct {
	DatabaseURL string
	RedisURL    string
	ServerPort  string
}

var config = Config{
	DatabaseURL: "postgres://user:pass@localhost/authdb?sslmode=disable",
	RedisURL:    "localhost:6379",
	ServerPort:  ":8080",
}

// ============================================================================
// DOMAIN MODELS
// ============================================================================

type Device struct {
	ID            string    `json:"device_id"`
	UserID        *int64    `json:"user_id,omitempty"`
	ServerHMACKey string    `json:"-"` // FIXED NAMING: This is what we actually store
	DeviceInfo    string    `json:"device_info"`
	CreatedAt     time.Time `json:"created_at"`
}

type User struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"-"` // Never expose
}

type Session struct {
	SessionID string    `json:"session_id"`
	UserID    int64     `json:"user_id"`
	DeviceID  string    `json:"device_id"`
	CreatedAt time.Time `json:"created_at"`
	IsActive  bool      `json:"is_active"`
}

// ============================================================================
// DATABASE & CACHE
// ============================================================================

var db *sql.DB
var rdb *redis.Client
var ctx = context.Background()

func initDatabase() error {
	var err error
	db, err = sql.Open("postgres", config.DatabaseURL)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Create tables with CORRECT naming
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username VARCHAR(255) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS devices (
		device_id VARCHAR(64) PRIMARY KEY,
		user_id INTEGER REFERENCES users(id),
		server_hmac_key VARCHAR(128) NOT NULL,  -- FIXED: Renamed from device_secret_hash
		device_info TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS user_sessions (
		session_id VARCHAR(64) PRIMARY KEY,
		user_id INTEGER NOT NULL REFERENCES users(id),
		device_id VARCHAR(64) NOT NULL REFERENCES devices(device_id),
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		is_active BOOLEAN DEFAULT true
	);

	CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_device ON user_sessions(device_id);
	`

	_, err = db.Exec(schema)
	return err
}

func initRedis() {
	rdb = redis.NewClient(&redis.Options{
		Addr: config.RedisURL,
		DB:   0,
	})
}

// ============================================================================
// CRYPTOGRAPHY HELPERS - USING X25519
// ============================================================================

// FIXED: Using X25519 (Curve25519) instead of DH over finite fields
var x25519Curve = ecdh.X25519()

// GenerateX25519KeyPair generates an X25519 key pair
func GenerateX25519KeyPair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	privateKey, err := x25519Curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, privateKey.PublicKey(), nil
}

// ComputeX25519SharedSecret computes shared secret using X25519 ECDH
func ComputeX25519SharedSecret(privateKey *ecdh.PrivateKey, peerPublicKey *ecdh.PublicKey) ([]byte, error) {
	return privateKey.ECDH(peerPublicKey)
}

// DeriveDeviceSecret derives device secret using HKDF-SHA256
func DeriveDeviceSecret(sharedSecret []byte, info string) ([]byte, error) {
	salt := []byte("device-auth-v1")
	h := hkdf.New(sha256.New, sharedSecret, salt, []byte(info))

	deviceSecret := make([]byte, 32)
	if _, err := io.ReadFull(h, deviceSecret); err != nil {
		return nil, err
	}

	return deviceSecret, nil
}

// DeriveServerHMACKey derives a separate server-side HMAC verification key
// This is what the server stores and uses to verify client signatures
func DeriveServerHMACKey(deviceSecret []byte) ([]byte, error) {
	salt := []byte("server-hmac-key-v1")
	h := hkdf.New(sha256.New, deviceSecret, salt, []byte("server-verification"))

	serverKey := make([]byte, 32)
	if _, err := io.ReadFull(h, serverKey); err != nil {
		return nil, err
	}

	return serverKey, nil
}

// GenerateHMAC generates HMAC-SHA256 signature
func GenerateHMAC(secret []byte, message string) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyHMAC verifies HMAC signature using constant-time comparison
func VerifyHMAC(secret []byte, message, signature string) bool {
	expectedMAC := GenerateHMAC(secret, message)
	return subtle.ConstantTimeCompare([]byte(expectedMAC), []byte(signature)) == 1
}

// ============================================================================
// PHASE 1: DEVICE REGISTRATION
// ============================================================================

type RegisterDeviceRequest struct {
	PublicKey  string `json:"public_key"`
	DeviceInfo string `json:"device_info"`
}

type RegisterDeviceResponse struct {
	DeviceID        string `json:"device_id"`
	ServerPublicKey string `json:"server_public_key"`
}

func registerDeviceHandler(w http.ResponseWriter, r *http.Request) {
	var req RegisterDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	log.Println("🔐 Device registration started (X25519)")

	// Decode client's public key
	clientPublicKeyBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		http.Error(w, "Invalid public key", http.StatusBadRequest)
		return
	}

	// Parse X25519 public key (automatically validates format)
	clientPublicKey, err := x25519Curve.NewPublicKey(clientPublicKeyBytes)
	if err != nil {
		log.Printf("❌ Invalid X25519 public key: %v", err)
		http.Error(w, "Invalid public key format", http.StatusBadRequest)
		return
	}
	log.Println("✓ Client X25519 public key validated")

	// Generate server X25519 keypair
	serverPrivateKey, serverPublicKey, err := GenerateX25519KeyPair()
	if err != nil {
		http.Error(w, "Failed to generate keys", http.StatusInternalServerError)
		return
	}
	log.Println("✓ Generated server X25519 keypair")

	// Compute shared secret using X25519
	sharedSecret, err := ComputeX25519SharedSecret(serverPrivateKey, clientPublicKey)
	if err != nil {
		http.Error(w, "Failed to compute shared secret", http.StatusInternalServerError)
		return
	}
	log.Println("✓ Computed X25519 shared secret")

	// Derive device secret using HKDF
	deviceSecret, err := DeriveDeviceSecret(sharedSecret, req.DeviceInfo)
	if err != nil {
		http.Error(w, "Failed to derive secret", http.StatusInternalServerError)
		return
	}

	// Derive server-side HMAC verification key
	serverHMACKey, err := DeriveServerHMACKey(deviceSecret)
	if err != nil {
		http.Error(w, "Failed to derive verification key", http.StatusInternalServerError)
		return
	}

	// Encode for storage (in production, encrypt this with KMS/HSM)
	serverHMACKeyEncoded := hex.EncodeToString(serverHMACKey)

	// Generate device ID
	deviceID := generateDeviceID()

	// Store device in database with CORRECT column name
	_, err = db.Exec(
		"INSERT INTO devices (device_id, server_hmac_key, device_info) VALUES ($1, $2, $3)",
		deviceID, serverHMACKeyEncoded, req.DeviceInfo,
	)
	if err != nil {
		http.Error(w, "Failed to store device", http.StatusInternalServerError)
		return
	}

	log.Printf("✓ Device registered: %s", deviceID)

	// Return server's public key
	resp := RegisterDeviceResponse{
		DeviceID:        deviceID,
		ServerPublicKey: base64.StdEncoding.EncodeToString(serverPublicKey.Bytes()),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func generateDeviceID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ============================================================================
// PHASE 2: LOGIN
// ============================================================================

type LoginRequest struct {
	Username        string `json:"username"`
	Password        string `json:"password"`
	DeviceID        string `json:"device_id"`
	SessionID       string `json:"session_id"`
	Timestamp       string `json:"timestamp"`
	Nonce           string `json:"nonce"`
	DeviceSignature string `json:"device_signature"`
}

type LoginResponse struct {
	SessionID string `json:"session_id"`
	UserID    int64  `json:"user_id"`
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	log.Printf("🔑 Login attempt: %s", req.Username)

	// Validate timestamp first (prevent replay attacks)
	ts, err := strconv.ParseInt(req.Timestamp, 10, 64)
	if err != nil || !isTimestampValid(ts) {
		log.Printf("❌ Invalid or expired timestamp")
		http.Error(w, "Invalid or expired timestamp", http.StatusUnauthorized)
		return
	}

	// FIXED: Check nonce with DEVICE SCOPE (not global)
	if isNonceUsed(req.DeviceID, req.Nonce) {
		log.Printf("❌ Nonce already used for device %s (replay attack detected)", req.DeviceID)
		http.Error(w, "Nonce already used", http.StatusUnauthorized)
		return
	}

	// Validate credentials
	var user User
	err = db.QueryRow(
		"SELECT id, username, password_hash FROM users WHERE username = $1",
		req.Username,
	).Scan(&user.ID, &user.Username, &user.PasswordHash)

	if err == sql.ErrNoRows {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Verify password (in production, use bcrypt)
	if !verifyPassword(req.Password, user.PasswordHash) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Verify device exists - using CORRECT column name
	var device Device
	err = db.QueryRow(
		"SELECT device_id, server_hmac_key, user_id FROM devices WHERE device_id = $1",
		req.DeviceID,
	).Scan(&device.ID, &device.ServerHMACKey, &device.UserID)

	if err != nil {
		http.Error(w, "Invalid device", http.StatusUnauthorized)
		return
	}

	// Get server HMAC key for verification
	serverHMACKey, err := getServerHMACKey(device.ServerHMACKey)
	if err != nil {
		log.Printf("❌ Failed to retrieve server HMAC key: %v", err)
		http.Error(w, "Device verification failed", http.StatusInternalServerError)
		return
	}

	// Verify session ID is correctly constructed
	expectedSessionData := fmt.Sprintf("%s:%s:%s", req.DeviceID, req.Timestamp, req.Nonce)
	expectedSessionID := GenerateHMAC(serverHMACKey, expectedSessionData)

	// Verify that the client’s session ID matches what the server expects.
	// Uses constant-time comparison to prevent timing attacks.
	if subtle.ConstantTimeCompare([]byte(req.SessionID), []byte(expectedSessionID)) != 1 {
		log.Printf("❌ Invalid session ID")
		http.Error(w, "Invalid session ID", http.StatusUnauthorized)
		return
	}
	log.Println("✓ Session ID verified")

	// Verify device signature (proves client has device secret)
	loginMessage := fmt.Sprintf("login:%s:%s:%s", req.Username, req.Timestamp, req.Nonce)
	if !VerifyHMAC(serverHMACKey, loginMessage, req.DeviceSignature) {
		log.Printf("❌ Invalid device signature")
		http.Error(w, "Device authentication failed", http.StatusUnauthorized)
		return
	}
	log.Println("✓ Device signature verified (device ownership proven)")

	// Now it's safe to mark nonce as used (after all validations pass)
	// FIXED: Scope to device
	markNonceUsed(req.DeviceID, req.Nonce)

	// Link device to user if not already linked
	if device.UserID == nil {
		_, err = db.Exec(
			"UPDATE devices SET user_id = $1 WHERE device_id = $2",
			user.ID, req.DeviceID,
		)
		if err != nil {
			log.Printf("⚠️  Failed to link device to user: %v", err)
		} else {
			log.Printf("✓ Device %s linked to user %d", req.DeviceID, user.ID)
		}
	}

	// Create session in database
	_, err = db.Exec(
		`INSERT INTO user_sessions (session_id, user_id, device_id, created_at, last_activity, is_active) 
		 VALUES ($1, $2, $3, NOW(), NOW(), true)`,
		req.SessionID, user.ID, req.DeviceID,
	)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Cache session in Redis - using CORRECT field name
	sessionData := map[string]interface{}{
		"user_id":         user.ID,
		"device_id":       req.DeviceID,
		"server_hmac_key": device.ServerHMACKey,
	}
	sessionJSON, _ := json.Marshal(sessionData)
	rdb.Set(ctx, fmt.Sprintf("session:%s", req.SessionID), sessionJSON, 7*24*time.Hour)

	log.Printf("✓ Login successful: %s (UserID: %d)", req.Username, user.ID)

	resp := LoginResponse{
		SessionID: req.SessionID,
		UserID:    user.ID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func verifyPassword(password, hash string) bool {
	// In production, use bcrypt.CompareHashAndPassword
	// For demo, simple SHA256 comparison
	passwordHash := fmt.Sprintf("%x", sha256.Sum256([]byte(password)))
	return passwordHash == hash
}

// FIXED: Correct function name - we're getting server HMAC key, not device secret
func getServerHMACKey(serverHMACKeyEncoded string) ([]byte, error) {
	serverHMACKey, err := hex.DecodeString(serverHMACKeyEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode server HMAC key: %w", err)
	}
	return serverHMACKey, nil
}

// ============================================================================
// PHASE 3: AUTHENTICATED REQUEST MIDDLEWARE
// ============================================================================

type AuthContext struct {
	UserID   int64
	DeviceID string
	Session  Session
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract headers
		authHeader := r.Header.Get("Authorization")
		signature := r.Header.Get("X-Signature")
		timestamp := r.Header.Get("X-Timestamp")
		nonce := r.Header.Get("X-Nonce")

		if authHeader == "" || signature == "" || timestamp == "" || nonce == "" {
			http.Error(w, "Missing authentication headers", http.StatusUnauthorized)
			return
		}

		// Parse session ID from Authorization header
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Session" {
			http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
			return
		}
		sessionID := parts[1]

		// Check if session is blacklisted
		exists, _ := rdb.Exists(ctx, fmt.Sprintf("blacklist:%s", sessionID)).Result()
		if exists > 0 {
			log.Printf("❌ Blacklisted session attempted: %s", sessionID)
			http.Error(w, "Session invalidated", http.StatusUnauthorized)
			return
		}

		// Get session from cache or database
		sessionData, err := getSession(sessionID)
		if err != nil {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}

		// Validate timestamp (within 5 minutes)
		ts, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil || !isTimestampValid(ts) {
			http.Error(w, "Invalid or expired timestamp", http.StatusUnauthorized)
			return
		}

		// FIXED: Check nonce with SESSION SCOPE (not global)
		// nonce must be generated on every request.
		if isNonceUsedForSession(sessionID, nonce) {
			http.Error(w, "Nonce already used", http.StatusUnauthorized)
			return
		}
		markNonceUsedForSession(sessionID, nonce)

		// Verify signature
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(strings.NewReader(string(body))) // Reset body for handler

		message := fmt.Sprintf("%s:%s:%s:%s:%s:%s",
			sessionID, r.Method, r.URL.Path, string(body), timestamp, nonce)

		// Get server HMAC key for verification - CORRECT field name
		serverHMACKey, err := getServerHMACKeyFromSession(sessionData["server_hmac_key"].(string))
		if err != nil || !VerifyHMAC(serverHMACKey, message, signature) {
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}

		log.Printf("✓ Authenticated request: %s %s (UserID: %v)", r.Method, r.URL.Path, sessionData["user_id"])

		// Update session activity
		rdb.Expire(ctx, fmt.Sprintf("session:%s", sessionID), 7*24*time.Hour)
		db.Exec("UPDATE user_sessions SET last_activity = NOW() WHERE session_id = $1", sessionID)

		// Add auth context to request
		authCtx := &AuthContext{
			UserID:   int64(sessionData["user_id"].(float64)),
			DeviceID: sessionData["device_id"].(string),
		}
		ctxWithAuth := context.WithValue(r.Context(), "auth", authCtx)

		next.ServeHTTP(w, r.WithContext(ctxWithAuth))
	}
}

func getSession(sessionID string) (map[string]interface{}, error) {
	// Try cache first
	sessionJSON, err := rdb.Get(ctx, fmt.Sprintf("session:%s", sessionID)).Result()
	if err == nil {
		var sessionData map[string]interface{}
		json.Unmarshal([]byte(sessionJSON), &sessionData)
		return sessionData, nil
	}

	// Cache miss - get from database - CORRECT column name
	var session Session
	var serverHMACKey string
	err = db.QueryRow(
		`SELECT s.session_id, s.user_id, s.device_id, d.server_hmac_key 
		 FROM user_sessions s 
		 JOIN devices d ON s.device_id = d.device_id 
		 WHERE s.session_id = $1 AND s.is_active = true`,
		sessionID,
	).Scan(&session.SessionID, &session.UserID, &session.DeviceID, &serverHMACKey)

	if err != nil {
		return nil, fmt.Errorf("session not found")
	}

	// Backfill cache - CORRECT field name
	sessionData := map[string]interface{}{
		"user_id":         session.UserID,
		"device_id":       session.DeviceID,
		"server_hmac_key": serverHMACKey,
	}
	sessionJSON, _ = json.Marshal(sessionData)
	rdb.Set(ctx, fmt.Sprintf("session:%s", sessionID), sessionJSON, 7*24*time.Hour)

	return sessionData, nil
}

// FIXED: Correct function name
func getServerHMACKeyFromSession(serverHMACKeyEncoded string) ([]byte, error) {
	serverHMACKey, err := hex.DecodeString(serverHMACKeyEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode server HMAC key: %w", err)
	}
	return serverHMACKey, nil
}

func isTimestampValid(ts int64) bool {
	now := time.Now().Unix() * 1000 // Convert to milliseconds
	diff := now - ts
	return diff >= 0 && diff < 5*60*1000 // Within 5 minutes
}

// FIXED: Nonce scoped to device for login
func isNonceUsed(deviceID, nonce string) bool {
	key := fmt.Sprintf("nonce:device:%s:%s", deviceID, nonce)
	exists, _ := rdb.Exists(ctx, key).Result()
	return exists > 0
}

func markNonceUsed(deviceID, nonce string) {
	key := fmt.Sprintf("nonce:device:%s:%s", deviceID, nonce)
	rdb.Set(ctx, key, "1", 10*time.Minute)
}

// FIXED: Nonce scoped to session for authenticated requests
func isNonceUsedForSession(sessionID, nonce string) bool {
	key := fmt.Sprintf("nonce:session:%s:%s", sessionID, nonce)
	exists, _ := rdb.Exists(ctx, key).Result()
	return exists > 0
}

func markNonceUsedForSession(sessionID, nonce string) {
	key := fmt.Sprintf("nonce:session:%s:%s", sessionID, nonce)
	rdb.Set(ctx, key, "1", 10*time.Minute)
}

// ============================================================================
// PHASE 4: LOGOUT
// ============================================================================

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	authCtx := r.Context().Value("auth").(*AuthContext)

	// Get session ID from header
	authHeader := r.Header.Get("Authorization")
	sessionID := strings.TrimPrefix(authHeader, "Session ")

	log.Printf("🚪 Logout: UserID %d", authCtx.UserID)

	// Deactivate session in database
	db.Exec("UPDATE user_sessions SET is_active = false WHERE session_id = $1", sessionID)

	// Delete from cache
	rdb.Del(ctx, fmt.Sprintf("session:%s", sessionID))

	// Add to blacklist
	rdb.Set(ctx, fmt.Sprintf("blacklist:%s", sessionID), "1", 7*24*time.Hour)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}

// ============================================================================
// EXAMPLE API ENDPOINTS
// ============================================================================

func getMessagesHandler(w http.ResponseWriter, r *http.Request) {
	authCtx := r.Context().Value("auth").(*AuthContext)

	messages := []map[string]interface{}{
		{"id": 1, "from": "system", "content": "Welcome!", "timestamp": time.Now()},
		{"id": 2, "from": "jane.doe", "content": "Hello there", "timestamp": time.Now()},
	}

	log.Printf("📬 Get messages for UserID: %d", authCtx.UserID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

func sendMessageHandler(w http.ResponseWriter, r *http.Request) {
	authCtx := r.Context().Value("auth").(*AuthContext)

	var req map[string]string
	json.NewDecoder(r.Body).Decode(&req)

	log.Printf("📤 Send message from UserID %d to %s", authCtx.UserID, req["recipient"])

	response := map[string]interface{}{
		"message_id": generateDeviceID(),
		"status":     "sent",
		"timestamp":  time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// ============================================================================
// MAIN
// ============================================================================

func main() {
	// Initialize
	if err := initDatabase(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	initRedis()

	// Create test user
	createTestUser()

	// Setup routes
	r := mux.NewRouter()

	// Public routes
	r.HandleFunc("/auth/register-device", registerDeviceHandler).Methods("POST")
	r.HandleFunc("/auth/login", loginHandler).Methods("POST")

	// Protected routes
	r.HandleFunc("/auth/logout", authMiddleware(logoutHandler)).Methods("POST")
	r.HandleFunc("/api/messages", authMiddleware(getMessagesHandler)).Methods("GET")
	r.HandleFunc("/api/messages/send", authMiddleware(sendMessageHandler)).Methods("POST")

	// CRITICAL: In production, MUST use TLS
	log.Printf("🚀 Auth service running on %s (X25519)", config.ServerPort)
	log.Println("⚠️  WARNING: Running without TLS - USE HTTPS IN PRODUCTION")
	log.Fatal(http.ListenAndServe(config.ServerPort, r))
}

func createTestUser() {
	// Create test user (password: "securePassword123")
	passwordHash := fmt.Sprintf("%x", sha256.Sum256([]byte("securePassword123")))
	db.Exec(
		"INSERT INTO users (username, password_hash) VALUES ($1, $2) ON CONFLICT (username) DO NOTHING",
		"john.doe", passwordHash,
	)
}
