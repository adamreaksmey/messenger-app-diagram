/**
 * Authentication Client - Frontend Implementation (PROPERLY FIXED)
 * - Uses X25519 (not random DH)
 * - Only stores device_secret, derives server_hmac_key on demand
 * - Handles device registration, login, and authenticated API requests
 */

const crypto = require('crypto');

class AuthClient {
  constructor(apiBaseUrl) {
    this.apiBaseUrl = apiBaseUrl;
    this.deviceSecret = null;  // Only this is stored persistently
    this.sessionId = null;
    this.deviceId = null;
  }

  // ========================================================================
  // PHASE 1: DEVICE REGISTRATION
  // ========================================================================

  /**
   * FIXED: Generate X25519 keypair (not random DH group)
   */
  generateX25519KeyPair() {
    const ecdh = crypto.createECDH('x25519');
    ecdh.generateKeys();
    return {
      privateKey: ecdh.getPrivateKey(),
      publicKey: ecdh.getPublicKey(),
      ecdh: ecdh
    };
  }

  /**
   * Register device and establish shared secret
   * @param {string} deviceInfo - Device metadata (OS, model, etc.)
   * @returns {Promise<string>} device_id
   */
  async registerDevice(deviceInfo) {
    console.log('🔐 Starting device registration (X25519)...');

    // Step 1: Generate client X25519 keypair
    const clientECDH = this.generateX25519KeyPair();
    console.log('✓ Generated client X25519 keypair');

    // Step 2: Send public key to server
    const response = await fetch(`${this.apiBaseUrl}/auth/register-device`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        public_key: clientECDH.publicKey.toString('base64'),
        device_info: deviceInfo
      })
    });

    if (!response.ok) {
      throw new Error(`Device registration failed: ${response.statusText}`);
    }

    const data = await response.json();
    console.log('✓ Received server public key');

    // Step 3: Compute shared secret using X25519
    const serverPublicKey = Buffer.from(data.server_public_key, 'base64');
    const sharedSecret = clientECDH.ecdh.computeSecret(serverPublicKey);
    console.log('✓ Computed X25519 shared secret');

    // Step 4: Derive device secret using proper HKDF
    this.deviceSecret = await this.deriveDeviceSecret(sharedSecret, deviceInfo);
    this.deviceId = data.device_id;
    console.log('✓ Derived device secret using HKDF');

    // Step 5: ONLY store device_secret (not server_hmac_key)
    // We'll derive server_hmac_key on demand when needed
    this.storeSecurely('device_secret', this.deviceSecret.toString('base64'));
    this.storeSecurely('device_id', this.deviceId);
    console.log(`✓ Device registered: ${this.deviceId}`);
    console.log('✓ Storing only device_secret (server_hmac_key derived on demand)');

    return this.deviceId;
  }

  /**
   * Proper HKDF implementation using Node.js crypto.hkdf
   * @param {Buffer} sharedSecret 
   * @param {string} info - Context information
   * @returns {Promise<Buffer>} 32-byte device secret
   */
  async deriveDeviceSecret(sharedSecret, info) {
    const salt = Buffer.from('device-auth-v1');
    const infoBuffer = Buffer.from(info, 'utf8');
    
    return new Promise((resolve, reject) => {
      crypto.hkdf('sha256', sharedSecret, salt, infoBuffer, 32, (err, derivedKey) => {
        if (err) reject(err);
        else resolve(derivedKey);
      });
    });
  }

  /**
   * FIXED: Derive server HMAC key on demand from device secret
   * Not stored persistently - computed when needed
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
   * @param {string} username 
   * @param {string} password 
   * @returns {Promise<string>} session_id
   */
  async login(username, password) {
    console.log('🔑 Starting login...');

    // Load device credentials if not in memory
    if (!this.deviceSecret) {
      const storedSecret = this.retrieveSecurely('device_secret');
      const storedDeviceId = this.retrieveSecurely('device_id');
      
      if (!storedSecret || !storedDeviceId) {
        throw new Error('Device not registered. Please register device first.');
      }
      
      this.deviceSecret = Buffer.from(storedSecret, 'base64');
      this.deviceId = storedDeviceId;
    }

    // Derive server HMAC key on demand (not stored)
    const serverHMACKey = await this.deriveServerHMACKey(this.deviceSecret);
    console.log('✓ Derived server_hmac_key from device_secret (ephemeral)');

    // Generate session ID using HMAC
    const timestamp = Date.now().toString();
    const nonce = crypto.randomBytes(16).toString('hex');
    const sessionData = `${this.deviceId}:${timestamp}:${nonce}`;
    
    const sessionId = this.generateHMAC(serverHMACKey, sessionData);
    console.log('✓ Generated session ID');

    // Generate device signature to prove device ownership
    const loginMessage = `login:${username}:${timestamp}:${nonce}`;
    const deviceSignature = this.generateHMAC(serverHMACKey, loginMessage);
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
        device_signature: deviceSignature
      })
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Login failed: ${error}`);
    }

    const data = await response.json();
    this.sessionId = data.session_id;
    
    // Store session (only session_id, not keys)
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
    if (!this.sessionId || !this.deviceSecret) {
      throw new Error('Not logged in. Please login first.');
    }

    // Derive server HMAC key on demand (not stored)
    const serverHMACKey = await this.deriveServerHMACKey(this.deviceSecret);

    const timestamp = Date.now().toString();
    const nonce = crypto.randomBytes(16).toString('hex');
    const bodyString = body ? JSON.stringify(body) : '';

    // Generate HMAC signature
    const signature = this.generateSignature(
      serverHMACKey,
      method,
      path,
      bodyString,
      timestamp,
      nonce
    );

    console.log(`📤 ${method} ${path} (signed with ephemeral key)`);

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
   * Generate HMAC signature for request
   * @param {Buffer} serverHMACKey - Derived on demand
   * @param {string} method 
   * @param {string} path 
   * @param {string} body 
   * @param {string} timestamp 
   * @param {string} nonce 
   * @returns {string} Hex-encoded signature
   */
  generateSignature(serverHMACKey, method, path, body, timestamp, nonce) {
    const message = `${this.sessionId}:${method}:${path}:${body}:${timestamp}:${nonce}`;
    return this.generateHMAC(serverHMACKey, message);
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
   * Clear session data (but keep device_secret)
   */
  clearSession() {
    this.sessionId = null;
    if (typeof localStorage !== 'undefined') {
      localStorage.removeItem('session_id');
    }
  }

  // ========================================================================
  // SECURE STORAGE
  // ========================================================================

  storeSecurely(key, value) {
    // In production:
    // - iOS: Use Keychain
    // - Android: Use Keystore
    // - Web: Use IndexedDB with encryption
    // - Desktop: Use system keyring
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
    console.log('\n💡 Note: Only device_secret stored. server_hmac_key derived on demand.\n');

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