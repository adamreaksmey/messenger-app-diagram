/**
 * Authentication Client - Frontend Implementation (FIXED)
 * Handles device registration, login, and authenticated API requests
 */

const crypto = require('crypto');

class AuthClient {
  constructor(apiBaseUrl) {
    this.apiBaseUrl = apiBaseUrl;
    this.deviceSecret = null;
    this.sessionId = null;
    this.deviceId = null;
    this.serverHMACKey = null;
  }

  // ========================================================================
  // PHASE 1: DEVICE REGISTRATION
  // ========================================================================

  /**
   * Generate Diffie-Hellman keypair for device registration
   * Uses 2048-bit modp group (can upgrade to Curve25519 for production)
   */
  generateDHKeyPair() {
    const dh = crypto.createDiffieHellman(2048);
    dh.generateKeys();
    return {
      privateKey: dh.getPrivateKey(),
      publicKey: dh.getPublicKey(),
      dh: dh // Keep DH instance for computing shared secret
    };
  }

  /**
   * Register device and establish shared secret
   * @param {string} deviceInfo - Device metadata (OS, model, etc.)
   * @returns {Promise<string>} device_id
   */
  async registerDevice(deviceInfo) {
    console.log('🔐 Starting device registration...');

    // Step 1: Generate client DH keypair
    const clientDH = this.generateDHKeyPair();
    console.log('✓ Generated client DH keypair');

    // Step 2: Send public key to server
    const response = await fetch(`${this.apiBaseUrl}/auth/register-device`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        public_key: clientDH.publicKey.toString('base64'),
        device_info: deviceInfo
      })
    });

    if (!response.ok) {
      throw new Error(`Device registration failed: ${response.statusText}`);
    }

    const data = await response.json();
    console.log('✓ Received server public key');

    // Step 3: Compute shared secret using server's public key
    const serverPublicKey = Buffer.from(data.server_public_key, 'base64');
    const sharedSecret = clientDH.dh.computeSecret(serverPublicKey);
    console.log('✓ Computed shared secret (never transmitted!)');

    // Step 4: Derive device secret using HKDF (FIXED IMPLEMENTATION)
    this.deviceSecret = await this.deriveDeviceSecret(sharedSecret, deviceInfo);
    this.deviceId = data.device_id;
    console.log('✓ Derived device secret using HKDF');

    // Step 5: Derive server HMAC key (what server uses to verify our signatures)
    this.serverHMACKey = await this.deriveServerHMACKey(this.deviceSecret);
    console.log('✓ Derived server HMAC key for request signing');

    // Step 6: Store in secure storage (localStorage for demo, use Keychain/Keystore in production)
    this.storeSecurely('device_secret', this.deviceSecret.toString('base64'));
    this.storeSecurely('server_hmac_key', this.serverHMACKey.toString('base64'));
    this.storeSecurely('device_id', this.deviceId);
    console.log(`✓ Device registered: ${this.deviceId}`);

    return this.deviceId;
  }

  /**
   * FIX #1: Proper HKDF implementation using Node.js crypto.hkdf
   * Derives device secret from shared secret using HKDF-SHA256
   * @param {Buffer} sharedSecret 
   * @param {string} info - Context information
   * @returns {Promise<Buffer>} 32-byte device secret
   */
  async deriveDeviceSecret(sharedSecret, info) {
    const salt = Buffer.from('device-auth-v1');
    const infoBuffer = Buffer.from(info, 'utf8');
    
    return new Promise((resolve, reject) => {
      // Use proper HKDF from Node.js crypto (Node 15+)
      crypto.hkdf('sha256', sharedSecret, salt, infoBuffer, 32, (err, derivedKey) => {
        if (err) reject(err);
        else resolve(derivedKey);
      });
    });
  }

  /**
   * FIX #1: Proper HKDF implementation for server HMAC key derivation
   * Derive server HMAC key from device secret
   * This matches what the server stores and uses for verification
   * @param {Buffer} deviceSecret 
   * @returns {Promise<Buffer>} 32-byte server HMAC key
   */
  async deriveServerHMACKey(deviceSecret) {
    const salt = Buffer.from('server-hmac-key-v1');
    const info = Buffer.from('server-verification', 'utf8');
    
    return new Promise((resolve, reject) => {
      crypto.hkdf('sha256', deviceSecret, salt, info, 32, (err, derivedKey) => {
        if (err) reject(err);
        else resolve(derivedKey);
      });
    });
  }

  // ========================================================================
  // PHASE 2: LOGIN
  // ========================================================================

  /**
   * Login with username and password
   * Generates a session authenticated with device secret
   * @param {string} username 
   * @param {string} password 
   * @returns {Promise<string>} session_id
   */
  async login(username, password) {
    console.log('🔑 Starting login...');

    // Load device credentials
    if (!this.deviceSecret) {
      const storedSecret = this.retrieveSecurely('device_secret');
      const storedHMACKey = this.retrieveSecurely('server_hmac_key');
      const storedDeviceId = this.retrieveSecurely('device_id');
      
      if (!storedSecret || !storedHMACKey || !storedDeviceId) {
        throw new Error('Device not registered. Please register device first.');
      }
      
      this.deviceSecret = Buffer.from(storedSecret, 'base64');
      this.serverHMACKey = Buffer.from(storedHMACKey, 'base64');
      this.deviceId = storedDeviceId;
    }

    // Generate session ID using HMAC
    const timestamp = Date.now().toString();
    const nonce = crypto.randomBytes(16).toString('hex');
    const sessionData = `${this.deviceId}:${timestamp}:${nonce}`;
    
    // Use serverHMACKey for session ID (this is what server will verify against)
    const hmac = crypto.createHmac('sha256', this.serverHMACKey);
    hmac.update(sessionData);
    const sessionId = hmac.digest('hex');

    console.log('✓ Generated session ID');

    // FIX #5: Generate device signature to prove device ownership
    const loginMessage = `login:${username}:${timestamp}:${nonce}`;
    const deviceSignature = this.generateHMAC(this.serverHMACKey, loginMessage);
    console.log('✓ Generated device signature');

    // Send login request
    const response = await fetch(`${this.apiBaseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        password,
        device_id: this.deviceId,
        session_id: sessionId,
        timestamp,
        nonce,
        device_signature: deviceSignature // FIX #5: Include proof of device ownership
      })
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Login failed: ${error}`);
    }

    const data = await response.json();
    this.sessionId = data.session_id;
    
    // Store session
    this.storeSecurely('session_id', this.sessionId);
    console.log('✓ Login successful');

    return this.sessionId;
  }

  // ========================================================================
  // PHASE 3: AUTHENTICATED API REQUESTS
  // ========================================================================

  /**
   * Make authenticated API request with HMAC signature
   * @param {string} method - HTTP method
   * @param {string} path - API path
   * @param {Object} body - Request body
   * @returns {Promise<Object>} Response data
   */
  async authenticatedRequest(method, path, body = null) {
    if (!this.sessionId || !this.serverHMACKey) {
      throw new Error('Not logged in. Please login first.');
    }

    const timestamp = Date.now().toString();
    const nonce = crypto.randomBytes(16).toString('hex');
    const bodyString = body ? JSON.stringify(body) : '';

    // Generate HMAC signature
    const signature = this.generateSignature(
      method,
      path,
      bodyString,
      timestamp,
      nonce
    );

    console.log(`📤 ${method} ${path} (signed)`);

    // Make request
    const response = await fetch(`${this.apiBaseUrl}${path}`, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Session ${this.sessionId}`,
        'X-Signature': signature,
        'X-Timestamp': timestamp,
        'X-Nonce': nonce
      },
      body: bodyString || undefined
    });

    if (response.status === 401) {
      console.error('❌ Authentication failed - session may be expired');
      this.clearSession();
      throw new Error('Unauthorized - please login again');
    }

    if (!response.ok) {
      throw new Error(`Request failed: ${response.statusText}`);
    }

    const data = await response.json();
    console.log('✓ Request successful');
    return data;
  }

  /**
   * Generate HMAC signature for request using server HMAC key
   * @param {string} method 
   * @param {string} path 
   * @param {string} body 
   * @param {string} timestamp 
   * @param {string} nonce 
   * @returns {string} Hex-encoded signature
   */
  generateSignature(method, path, body, timestamp, nonce) {
    const message = `${this.sessionId}:${method}:${path}:${body}:${timestamp}:${nonce}`;
    return this.generateHMAC(this.serverHMACKey, message);
  }

  /**
   * Helper function to generate HMAC
   * @param {Buffer} secret 
   * @param {string} message 
   * @returns {string} Hex-encoded HMAC
   */
  generateHMAC(secret, message) {
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(message);
    return hmac.digest('hex');
  }

  // ========================================================================
  // PHASE 4: LOGOUT
  // ========================================================================

  /**
   * Logout and invalidate session
   */
  async logout() {
    if (!this.sessionId) {
      console.log('Already logged out');
      return;
    }

    console.log('🚪 Logging out...');

    try {
      await this.authenticatedRequest('POST', '/auth/logout');
      console.log('✓ Logout successful');
    } catch (error) {
      console.error('Logout request failed:', error.message);
    } finally {
      this.clearSession();
    }
  }

  /**
   * Clear session data
   */
  clearSession() {
    this.sessionId = null;
    if (typeof localStorage !== 'undefined') {
      localStorage.removeItem('session_id');
    }
  }

  // ========================================================================
  // SECURE STORAGE (Use platform-specific secure storage in production)
  // ========================================================================

  storeSecurely(key, value) {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(key, value);
    }
  }

  retrieveSecurely(key) {
    if (typeof localStorage !== 'undefined') {
      return localStorage.getItem(key);
    }
    return null;
  }
}

// ========================================================================
// USAGE EXAMPLE
// ========================================================================

async function example() {
  const client = new AuthClient('http://localhost:8080');

  try {
    // Register device (first time only)
    const deviceInfo = JSON.stringify({
      os: 'Linux',
      model: 'Desktop',
      app_version: '1.0.0'
    });
    
    await client.registerDevice(deviceInfo);

    // Login
    await client.login('john.doe', 'securePassword123');

    // Make authenticated requests
    const messages = await client.authenticatedRequest('GET', '/api/messages');
    console.log('Messages:', messages);

    const newMessage = await client.authenticatedRequest('POST', '/api/messages/send', {
      recipient: 'jane.doe',
      content: 'Hello from authenticated client!'
    });
    console.log('Message sent:', newMessage);

    // Logout
    await client.logout();

  } catch (error) {
    console.error('Error:', error.message);
  }
}

// Uncomment to run example
// example();

module.exports = AuthClient;