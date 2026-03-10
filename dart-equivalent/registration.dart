import 'dart:convert';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'crypto_utils.dart';

// ---------------------------------------------------------------------------
// Request / Response models  (mirrors interface.ts)
// ---------------------------------------------------------------------------

class DeviceRegistrationRequest {
  final String clientPublicKey;
  final String deviceInfo;
  final String platform;
  final String deviceName;

  const DeviceRegistrationRequest({
    required this.clientPublicKey,
    required this.deviceInfo,
    required this.platform,
    required this.deviceName,
  });

  Map<String, dynamic> toJson() => {
        'clientPublicKey': clientPublicKey,
        'deviceInfo': deviceInfo,
        'platform': platform,
        'deviceName': deviceName,
      };
}

class DeviceRegistrationResponse {
  final String deviceId;
  final String serverPublicKey;

  const DeviceRegistrationResponse(
      {required this.deviceId, required this.serverPublicKey});

  factory DeviceRegistrationResponse.fromJson(Map<String, dynamic> json) =>
      DeviceRegistrationResponse(
        deviceId: json['deviceId'] as String,
        serverPublicKey: json['serverPublicKey'] as String,
      );
}

class CheckUserRequest {
  final String identifier;
  const CheckUserRequest({required this.identifier});
  Map<String, dynamic> toJson() => {'identifier': identifier};
}

class CheckUserResponse {
  final bool exists;
  final List<String> loginMethods;

  const CheckUserResponse(
      {required this.exists, required this.loginMethods});

  factory CheckUserResponse.fromJson(Map<String, dynamic> json) =>
      CheckUserResponse(
        exists: json['exists'] as bool,
        loginMethods: List<String>.from(json['loginMethods'] ?? []),
      );
}

class OTPRequest {
  final String phoneNumber;
  const OTPRequest({required this.phoneNumber});
  Map<String, dynamic> toJson() => {'phoneNumber': phoneNumber};
}

class OTPResponse {
  final String message;
  const OTPResponse({required this.message});
  factory OTPResponse.fromJson(Map<String, dynamic> json) =>
      OTPResponse(message: json['message'] as String);
}

class VerifyOTPRequest {
  final String phoneNumber;
  final String otp;
  final String deviceId;

  const VerifyOTPRequest({
    required this.phoneNumber,
    required this.otp,
    required this.deviceId,
  });

  Map<String, dynamic> toJson() => {
        'phoneNumber': phoneNumber,
        'otp': otp,
        'deviceId': deviceId,
      };
}

class UserInfo {
  final String id;
  final bool isNewUser;
  final Map<String, dynamic> extra;

  const UserInfo(
      {required this.id, required this.isNewUser, required this.extra});

  factory UserInfo.fromJson(Map<String, dynamic> json) => UserInfo(
        id: json['id'] as String,
        isNewUser: json['isNewUser'] as bool? ?? false,
        extra: json,
      );
}

class AuthResponse {
  final String sessionId;
  final UserInfo user;

  const AuthResponse({required this.sessionId, required this.user});

  factory AuthResponse.fromJson(Map<String, dynamic> json) => AuthResponse(
        sessionId: json['sessionId'] as String,
        user: UserInfo.fromJson(json['user'] as Map<String, dynamic>),
      );
}

class ProfileSetupRequest {
  final Map<String, dynamic> fields;
  const ProfileSetupRequest(this.fields);
  Map<String, dynamic> toJson() => fields;
}

// ---------------------------------------------------------------------------
// RegistrationClient
// ---------------------------------------------------------------------------

class RegistrationClient {
  late final Dio _dio;
  final String baseURL;
  final String deviceInfo;
  final String platform; // 'ios' | 'android' | 'web'

  // State (persisted securely via flutter_secure_storage)
  String? deviceId;
  Uint8List? deviceSecret;
  Uint8List? serverHMACKey;
  String? sessionId;

  static const _storage = FlutterSecureStorage();

  RegistrationClient({
    required this.baseURL,
    required this.deviceInfo,
    required this.platform,
  }) {
    final cleanBase = baseURL.replaceAll(RegExp(r'/$'), '');
    _dio = Dio(BaseOptions(
      baseUrl: cleanBase,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': deviceInfo,
      },
      connectTimeout: const Duration(seconds: 15),
      receiveTimeout: const Duration(seconds: 15),
    ));
  }

  // --------------------------------------------------------------------------
  // Step 1: Device Registration
  // --------------------------------------------------------------------------
  Future<DeviceRegistrationResponse> registerDevice(
      {String deviceName = ''}) async {
    final keyPair = generateX25519KeyPair();
    final clientPublicKeyBase64 = base64Encode(keyPair.publicKey);

    final payload = DeviceRegistrationRequest(
      clientPublicKey: clientPublicKeyBase64,
      deviceInfo: deviceInfo,
      platform: platform,
      deviceName: deviceName,
    );

    final response = await _dio.post<Map<String, dynamic>>(
      '/api/v1/device/register',
      data: payload.toJson(),
    );

    final data = DeviceRegistrationResponse.fromJson(response.data!);

    // Derive shared secret and keys
    final serverPubKeyBytes = base64Decode(data.serverPublicKey);
    final sharedSecret =
        computeSharedSecret(keyPair.privateKey, serverPubKeyBytes);
    final derived = await deriveDeviceSecret(sharedSecret, deviceInfo);
    final hmacKey = await deriveServerHMACKey(derived);

    deviceId = data.deviceId;
    deviceSecret = derived;
    serverHMACKey = hmacKey;

    // Persist securely
    await _storage.write(
        key: 'device_secret', value: base64Encode(deviceSecret!));
    await _storage.write(key: 'device_id', value: deviceId!);

    return data;
  }

  // --------------------------------------------------------------------------
  // Step 2: Check User
  // --------------------------------------------------------------------------
  Future<CheckUserResponse> checkUser(String identifier) async {
    final response = await _dio.post<Map<String, dynamic>>(
      '/api/v1/auth/check',
      data: CheckUserRequest(identifier: identifier).toJson(),
    );
    return CheckUserResponse.fromJson(response.data!);
  }

  // --------------------------------------------------------------------------
  // Step 3: Request OTP
  // --------------------------------------------------------------------------
  Future<OTPResponse> requestOTP(String phoneNumber) async {
    final response = await _dio.post<Map<String, dynamic>>(
      '/api/v1/auth/otp/send',
      data: OTPRequest(phoneNumber: phoneNumber).toJson(),
    );
    return OTPResponse.fromJson(response.data!);
  }

  // --------------------------------------------------------------------------
  // Step 4: Verify OTP
  // --------------------------------------------------------------------------
  Future<AuthResponse> verifyOTP(String phoneNumber, String otp) async {
    if (deviceId == null || serverHMACKey == null) {
      throw StateError(
          'Device must be registered first. Call registerDevice().');
    }

    final timestamp =
        (DateTime.now().millisecondsSinceEpoch ~/ 1000).toString();
    final nonce = randomUUID();

    // Session ID: HMAC(serverHMACKey, "{deviceId}:{timestamp}:{nonce}")
    final sessionMessage =
        '${deviceId!.toLowerCase()}:$timestamp:$nonce';
    final computedSessionId =
        await computeHMAC(serverHMACKey!, sessionMessage);

    // X-Signature: HMAC(serverHMACKey, "otp-verify:{phoneNumber}:{timestamp}:{nonce}")
    final signatureMessage = 'otp-verify:$phoneNumber:$timestamp:$nonce';
    final signature =
        await computeHMAC(serverHMACKey!, signatureMessage);

    final payload = VerifyOTPRequest(
      phoneNumber: phoneNumber,
      otp: otp,
      deviceId: deviceId!,
    );

    final response = await _dio.post<Map<String, dynamic>>(
      '/api/v1/auth/otp/verify',
      data: payload.toJson(),
      options: Options(headers: {
        'Authorization': 'Session $computedSessionId',
        'X-Signature': signature,
        'X-Timestamp': timestamp,
        'X-Nonce': nonce,
      }),
    );

    final data = AuthResponse.fromJson(response.data!);
    sessionId = data.sessionId;
    return data;
  }

  // --------------------------------------------------------------------------
  // Step 5: Setup Profile
  // --------------------------------------------------------------------------
  Future<Map<String, dynamic>> setupProfile(
      ProfileSetupRequest profile) async {
    if (sessionId == null || serverHMACKey == null) {
      throw StateError('Must be logged in. Call verifyOTP() first.');
    }

    final timestamp =
        (DateTime.now().millisecondsSinceEpoch ~/ 1000).toString();
    final nonce = randomUUID();
    const path = '/api/v1/user/profile/setup';
    final body = jsonEncode(profile.toJson());

    final message = '$sessionId:POST:$path:$body:$timestamp:$nonce';
    final signature = await computeHMAC(serverHMACKey!, message);

    final headers = {
      'Authorization': 'Session $sessionId',
      'X-Signature': signature,
      'X-Timestamp': timestamp,
      'X-Nonce': nonce,
    };

    // ignore: avoid_print
    print('show headers: $headers');

    final response = await _dio.post<Map<String, dynamic>>(
      path,
      data: profile.toJson(),
      options: Options(headers: headers),
    );

    return response.data!;
  }

  // --------------------------------------------------------------------------
  // Convenience: Full registration flow
  // --------------------------------------------------------------------------
  Future<AuthResponse> fullRegistrationFlow(
    String phoneNumber,
    String otp, {
    ProfileSetupRequest? profile,
  }) async {
    final authResult = await verifyOTP(phoneNumber, otp);

    if (authResult.user.isNewUser && profile != null) {
      await setupProfile(profile);
    }

    return authResult;
  }

  // --------------------------------------------------------------------------
  // Restore persisted state (call on app start)
  // --------------------------------------------------------------------------
  Future<void> restoreState() async {
    final storedDeviceId = await _storage.read(key: 'device_id');
    final storedDeviceSecret = await _storage.read(key: 'device_secret');

    if (storedDeviceId != null && storedDeviceSecret != null) {
      deviceId = storedDeviceId;
      deviceSecret = base64Decode(storedDeviceSecret);
      serverHMACKey = await deriveServerHMACKey(deviceSecret!);
    }
  }
}