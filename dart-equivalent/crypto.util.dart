import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:x25519/x25519.dart' as x25519_lib;

// ---------------------------------------------------------------------------
// HMAC-SHA256
// ---------------------------------------------------------------------------

/// Equivalent of computeHMAC(key, message) → hex string
Future<String> computeHMAC(Uint8List key, String message) async {
  final hmac = Hmac.sha256();
  final secretKey = SecretKey(key);
  final mac = await hmac.calculateMac(
    utf8.encode(message),
    secretKey: secretKey,
  );
  return _bytesToHex(Uint8List.fromList(mac.bytes));
}

/// Equivalent of generateHMAC(secret, message) → hex string (Buffer key variant)
Future<String> generateHMAC(Uint8List secret, String message) async {
  return computeHMAC(secret, message);
}

// ---------------------------------------------------------------------------
// Nonce / Random
// ---------------------------------------------------------------------------

/// Equivalent of generateNonce() → 32-char hex string (16 random bytes)
String generateNonce() {
  final random = Random.secure();
  final bytes = Uint8List(16);
  for (var i = 0; i < 16; i++) {
    bytes[i] = random.nextInt(256);
  }
  return _bytesToHex(bytes);
}

/// UUID v4 equivalent of crypto.randomUUID()
String randomUUID() {
  final random = Random.secure();
  final bytes = List<int>.generate(16, (_) => random.nextInt(256));
  bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant bits
  final hex = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-'
      '${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
}

// ---------------------------------------------------------------------------
// X25519 Key Exchange
// ---------------------------------------------------------------------------

class X25519KeyPair {
  final Uint8List privateKey;
  final Uint8List publicKey;
  const X25519KeyPair({required this.privateKey, required this.publicKey});
}

/// Equivalent of generateX25519KeyPair()
X25519KeyPair generateX25519KeyPair() {
  final keyPair = x25519_lib.generateKeyPair();
  return X25519KeyPair(
    privateKey: Uint8List.fromList(keyPair.privateKey),
    publicKey: Uint8List.fromList(keyPair.publicKey),
  );
}

/// Equivalent of computeSharedSecret(privateKey, serverPublicKey)
Uint8List computeSharedSecret(Uint8List privateKey, Uint8List serverPublicKey) {
  final shared = x25519_lib.X25519(privateKey, serverPublicKey);
  return Uint8List.fromList(shared);
}

// ---------------------------------------------------------------------------
// Base64
// ---------------------------------------------------------------------------

/// Equivalent of base64Encode(bytes)
String base64Encode(Uint8List bytes) => base64.encode(bytes);

/// Equivalent of base64Decode(str)
Uint8List base64Decode(String str) => base64.decode(str);

// ---------------------------------------------------------------------------
// HKDF key derivation
// ---------------------------------------------------------------------------

/// Equivalent of deriveDeviceSecret(sharedSecret, deviceInfo)
Future<Uint8List> deriveDeviceSecret(
    Uint8List sharedSecret, String deviceInfo) async {
  return _hkdf(
    inputKeyMaterial: sharedSecret,
    salt: utf8.encode('device-auth-v1'),
    info: utf8.encode(deviceInfo),
    outputLength: 32,
  );
}

/// Equivalent of deriveServerHMACKey(deviceSecret)
Future<Uint8List> deriveServerHMACKey(Uint8List deviceSecret) async {
  return _hkdf(
    inputKeyMaterial: deviceSecret,
    salt: utf8.encode('server-hmac-key-v1'),
    info: utf8.encode('server-verification'),
    outputLength: 32,
  );
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

Future<Uint8List> _hkdf({
  required List<int> inputKeyMaterial,
  required List<int> salt,
  required List<int> info,
  required int outputLength,
}) async {
  final algorithm = Hkdf(
    hmac: Hmac.sha256(),
    outputLength: outputLength,
  );
  final secretKey = SecretKey(inputKeyMaterial);
  final output = await algorithm.deriveKey(
    secretKey: secretKey,
    nonce: salt,
    info: info,
  );
  final bytes = await output.extractBytes();
  return Uint8List.fromList(bytes);
}

String _bytesToHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}