package main

import (
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
	"math/big"
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
	ID               string    `json:"device_id"`
	UserID           *int64    `json:"user_id,omitempty"`
	DeviceSecretHash string    `json:"-"` // Never expose
	DeviceInfo       string    `json:"device_info"`
	CreatedAt        time.Time `json:"created_at"`
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

	// Create tables
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
		device_secret_hash VARCHAR(128) NOT NULL,  -- Actually stores server_hmac_key (hex-encoded), should rename to server_hmac_key
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
// CRYPTOGRAPHY HELPERS
// ============================================================================

// DHParams holds Diffie-Hellman parameters (using 2048-bit MODP group)
type DHParams struct {
	Prime     *big.Int
	Generator *big.Int
}

// Standard 2048-bit MODP Group (RFC 3526 - Group 14)
var dhParams = DHParams{
	Prime: func() *big.Int {
		p, _ := new(big.Int).SetString(
			"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
				"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
				"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
				"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
				"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
				"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
				"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
				"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
				"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"+
				"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"+
				"15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
		return p
	}(),
	Generator: big.NewInt(2),
}

// GenerateDHKeyPair generates a DH private/public key pair
func GenerateDHKeyPair() (*big.Int, *big.Int, error) {
	// Generate random private key (256 bits)
	privateKey, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 256))
	if err != nil {
		return nil, nil, err
	}

	// Compute public key: g^private mod p
	publicKey := new(big.Int).Exp(dhParams.Generator, privateKey, dhParams.Prime)
	return privateKey, publicKey, nil
}

// ComputeDHSharedSecret computes shared secret from private key and peer's public key
func ComputeDHSharedSecret(privateKey, peerPublicKey *big.Int) *big.Int {
	// shared_secret = peer_public^private mod p
	return new(big.Int).Exp(peerPublicKey, privateKey, dhParams.Prime)
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

	log.Println("🔐 Device registration started")

	// Decode client's public key
	clientPublicKeyBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		http.Error(w, "Invalid public key", http.StatusBadRequest)
		return
	}
	clientPublicKey := new(big.Int).SetBytes(clientPublicKeyBytes)

	// Generate server DH keypair
	serverPrivateKey, serverPublicKey, err := GenerateDHKeyPair()
	if err != nil {
		http.Error(w, "Failed to generate keys", http.StatusInternalServerError)
		return
	}
	log.Println("✓ Generated server DH keypair")

	// Compute shared secret
	sharedSecret := ComputeDHSharedSecret(serverPrivateKey, clientPublicKey)
	log.Println("✓ Computed shared secret")

	// Derive device secret using HKDF
	deviceSecret, err := DeriveDeviceSecret(sharedSecret.Bytes(), req.DeviceInfo)
	if err != nil {
		http.Error(w, "Failed to derive secret", http.StatusInternalServerError)
		return
	}

	// Derive server-side HMAC verification key
	// This is what we store - NOT the device_secret itself
	serverHMACKey, err := DeriveServerHMACKey(deviceSecret)
	if err != nil {
		http.Error(w, "Failed to derive verification key", http.StatusInternalServerError)
		return
	}

	// Encode for storage (in production, encrypt this with KMS/HSM)
	serverHMACKeyEncoded := hex.EncodeToString(serverHMACKey)

	// Generate device ID
	deviceID := generateDeviceID()

	// Store device in database
	_, err = db.Exec(
		"INSERT INTO devices (device_id, device_secret_hash, device_info) VALUES ($1, $2, $3)",
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
	Username  string `json:"username"`
	Password  string `json:"password"`
	DeviceID  string `json:"device_id"`
	SessionID string `json:"session_id"`
	Timestamp string `json:"timestamp"`
	Nonce     string `json:"nonce"`
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

	// Validate credentials
	var user User
	err := db.QueryRow(
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

	// Verify device exists and belongs to user (or is unassigned)
	var device Device
	err = db.QueryRow(
		"SELECT device_id, device_secret_hash FROM devices WHERE device_id = $1",
		req.DeviceID,
	).Scan(&device.ID, &device.DeviceSecretHash)

	if err != nil {
		http.Error(w, "Invalid device", http.StatusUnauthorized)
		return
	}

	// Link device to user if not already linked
	_, err = db.Exec(
		"UPDATE devices SET user_id = $1 WHERE device_id = $2 AND user_id IS NULL",
		user.ID, req.DeviceID,
	)

	// Verify session ID format (should be HMAC of device_id:timestamp:nonce)
	// For simplicity, we'll accept it and store it

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

	// Cache session in Redis
	sessionData := map[string]interface{}{
		"user_id":            user.ID,
		"device_id":          req.DeviceID,
		"device_secret_hash": device.DeviceSecretHash,
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

		// Step 1: Get session from cache or database
		sessionData, err := getSession(sessionID)
		if err != nil {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}

		// Step 2: Validate timestamp (within 5 minutes)
		ts, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil || !isTimestampValid(ts) {
			http.Error(w, "Invalid or expired timestamp", http.StatusUnauthorized)
			return
		}

		// Step 3: Check nonce not reused
		if isNonceUsed(nonce) {
			http.Error(w, "Nonce already used", http.StatusUnauthorized)
			return
		}
		markNonceUsed(nonce)

		// Step 4: Verify signature
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(strings.NewReader(string(body))) // Reset body for handler

		message := fmt.Sprintf("%s:%s:%s:%s:%s:%s",
			sessionID, r.Method, r.URL.Path, string(body), timestamp, nonce)

		// Get device secret for verification
		deviceSecret, err := getDeviceSecret(sessionData["device_secret_hash"].(string))
		if err != nil || !VerifyHMAC(deviceSecret, message, signature) {
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

	// Cache miss - get from database
	var session Session
	var deviceSecretHash string
	err = db.QueryRow(
		`SELECT s.session_id, s.user_id, s.device_id, d.device_secret_hash 
		 FROM user_sessions s 
		 JOIN devices d ON s.device_id = d.device_id 
		 WHERE s.session_id = $1 AND s.is_active = true`,
		sessionID,
	).Scan(&session.SessionID, &session.UserID, &session.DeviceID, &deviceSecretHash)

	if err != nil {
		return nil, fmt.Errorf("session not found")
	}

	// Backfill cache
	sessionData := map[string]interface{}{
		"user_id":            session.UserID,
		"device_id":          session.DeviceID,
		"device_secret_hash": deviceSecretHash,
	}
	sessionJSON, _ = json.Marshal(sessionData)
	rdb.Set(ctx, fmt.Sprintf("session:%s", sessionID), sessionJSON, 7*24*time.Hour)

	return sessionData, nil
}

func getDeviceSecret(serverHMACKeyEncoded string) ([]byte, error) {
	// Decode the server HMAC key from storage
	// In production, this should be decrypted using KMS/HSM
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

func isNonceUsed(nonce string) bool {
	exists, _ := rdb.Exists(ctx, fmt.Sprintf("nonce:%s", nonce)).Result()
	return exists > 0
}

func markNonceUsed(nonce string) {
	rdb.Set(ctx, fmt.Sprintf("nonce:%s", nonce), "1", 10*time.Minute)
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

	// CRITICAL: In production, MUST use TLS to prevent MITM attacks during DH key exchange
	// Use ListenAndServeTLS instead:
	// log.Fatal(http.ListenAndServeTLS(config.ServerPort, "server.crt", "server.key", r))

	log.Printf("🚀 Auth service running on %s", config.ServerPort)
	log.Println("⚠️  WARNING: Running without TLS - VULNERABLE TO MITM ATTACKS")
	log.Println("⚠️  Use HTTPS in production to authenticate server's DH public key")
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
