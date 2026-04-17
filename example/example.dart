import 'dart:convert';
import 'dart:typed_data';

import 'package:fortis/fortis.dart';

Future<void> main() async {
  await aesKeyExample();
  await aesEncryptionExample();
  await aesAuthenticatedExample();
  await ccmTagSizeExample();
  await aesPayloadExample();
  await aesDecryptInputFormatsExample();
  await rsaBasicExample();
  await rsaPaddingHashMatrixExample();
  await rsaLabelExample();
  await rsaKeySerializationExample();
  await ecdhBasicExample();
  await ecdhKeySerializationExample();
  await ecdhAdvancedDerivationExample();
  await errorHandlingExample();
}

Future<void> aesKeyExample() async {
  final key128 = await Fortis.aes().keySize(128).generateKey();
  final key192 = await Fortis.aes().keySize(192).generateKey();
  final key256 = await Fortis.aes().keySize(256).generateKey();

  print('AES-128 key size: ${key128.keySize}');
  print('AES-192 key size: ${key192.keySize}');
  print('AES-256 key size: ${key256.keySize}');

  // From existing bytes
  final key = FortisAesKey.fromBytes(Uint8List(32));
  print('Key from bytes: ${key.keySize}-bit');

  // Base64 round-trip
  final b64 = key256.toBase64();
  final restored = FortisAesKey.fromBase64(b64);
  print('Key restored: ${restored.keySize}-bit');
}

Future<void> aesEncryptionExample() async {
  final key = await Fortis.aes().keySize(256).generateKey();

  // CBC (block mode) — requires padding
  final cbc = Fortis.aes().cbc().cipher(key);
  final cbcCiphertext = cbc.encrypt('hello fortis');
  print('AES-CBC decrypted: ${cbc.decryptToString(cbcCiphertext)}');

  // CTR (stream mode) — no padding needed
  final ctr = Fortis.aes().ctr().cipher(key);
  final ctrCiphertext = ctr.encrypt('hello fortis');
  print('AES-CTR decrypted: ${ctr.decryptToString(ctrCiphertext)}');

  // CFB (stream mode)
  final cfb = Fortis.aes().cfb().cipher(key);
  final cfbCiphertext = cfb.encrypt('hello fortis');
  print('AES-CFB decrypted: ${cfb.decryptToString(cfbCiphertext)}');

  // OFB (stream mode)
  final ofb = Fortis.aes().ofb().cipher(key);
  final ofbCiphertext = ofb.encrypt('hello fortis');
  print('AES-OFB decrypted: ${ofb.decryptToString(ofbCiphertext)}');

  // ECB (block mode) — no IV
  final ecb = Fortis.aes().ecb().cipher(key);
  final ecbCiphertext = ecb.encrypt('hello fortis');
  print('AES-ECB decrypted: ${ecb.decryptToString(ecbCiphertext)}');

  // Encrypt with explicit IV (deterministic output)
  final cipher = Fortis.aes().gcm().cipher(key);
  final iv = Uint8List(12);
  final r1 = cipher.encrypt('hello', iv: iv);
  final r2 = cipher.encrypt('hello', iv: iv);
  print('Deterministic IV produces same output: ${r1.length == r2.length}');

  // encryptToString returns Base64
  final b64 = cipher.encryptToString('hello fortis');
  print('Base64 ciphertext valid: ${base64Decode(b64).isNotEmpty}');

  // Two ciphers with same key are compatible
  final cipher1 = Fortis.aes().gcm().cipher(key);
  final cipher2 = Fortis.aes().gcm().cipher(key);
  final ciphertext = cipher1.encrypt('hello fortis');
  print('Cross-cipher decrypt: ${cipher2.decryptToString(ciphertext)}');
}

Future<void> aesAuthenticatedExample() async {
  final key = await Fortis.aes().keySize(256).generateKey();

  // GCM — default IV size (12 bytes)
  final gcm = Fortis.aes().mode(AesMode.gcm).cipher(key);
  final gcmCiphertext = gcm.encrypt('hello fortis');
  print('AES-GCM decrypted: ${gcm.decryptToString(gcmCiphertext)}');

  // CCM — default IV size (11 bytes)
  final ccm = Fortis.aes().mode(AesMode.ccm).cipher(key);
  final ccmCiphertext = ccm.encrypt('hello fortis');
  print('AES-CCM decrypted: ${ccm.decryptToString(ccmCiphertext)}');

  // GCM with AAD (Additional Authenticated Data)
  final aad = Uint8List.fromList(utf8.encode('additional-data'));
  final gcmWithAad = Fortis.aes().gcm().aad(aad).cipher(key);
  final aadCiphertext = gcmWithAad.encrypt('hello fortis');
  print('AES-GCM+AAD decrypted: ${gcmWithAad.decryptToString(aadCiphertext)}');

  // GCM with custom IV size
  final gcmCustom = Fortis.aes().gcm().ivSize(8).cipher(key);
  final customCiphertext = gcmCustom.encrypt('hello fortis');
  print(
    'AES-GCM iv=8 decrypted: ${gcmCustom.decryptToString(customCiphertext)}',
  );

  // CCM with custom IV sizes (7–13 bytes)
  for (final size in [7, 11, 13]) {
    final ccmCustom = Fortis.aes().ccm().ivSize(size).cipher(key);
    final ct = ccmCustom.encrypt('hello fortis');

    print('AES-CCM iv=$size decrypted: ${ccmCustom.decryptToString(ct)}');
  }
}

Future<void> aesPayloadExample() async {
  final key = await Fortis.aes().keySize(256).generateKey();

  // Authenticated payload (GCM/CCM) — has iv, data, tag.
  // .gcm() returns AesAuthCipher, so encryptToPayload() is statically
  // typed as AesAuthPayload — no cast required.
  final gcm = Fortis.aes().gcm().cipher(key);
  final authPayload = gcm.encryptToPayload('hello');
  print('Auth payload iv: ${authPayload.iv}');
  print('Auth payload data: ${authPayload.data}');
  print('Auth payload tag: ${authPayload.tag}');
  print('Auth payload map: ${authPayload.toMap()}');
  print('Auth payload map (nonce): ${authPayload.toMap(ivKey: 'nonce')}');

  // Non-authenticated payload (CBC/CTR/CFB/OFB) — has iv, data.
  // .cbc() returns AesStandardCipher → encryptToPayload() is AesPayload.
  final cbc = Fortis.aes().cbc().cipher(key);
  final payload = cbc.encryptToPayload('hello');
  print('Payload iv: ${payload.iv}');
  print('Payload data: ${payload.data}');
  print('Payload map: ${payload.toMap()}');

  // Decrypt from payload object
  print('Decrypt from AesAuthPayload: ${gcm.decryptToString(authPayload)}');
  print('Decrypt from AesPayload: ${cbc.decryptToString(payload)}');
}

Future<void> aesDecryptInputFormatsExample() async {
  final key = await Fortis.aes().keySize(256).generateKey();
  final cipher = Fortis.aes().gcm().cipher(key);
  const plaintext = 'hello fortis';

  // From Uint8List
  final bytes = cipher.encrypt(plaintext);
  print('From Uint8List: ${cipher.decryptToString(bytes)}');

  // From Base64 String
  final b64 = cipher.encryptToString(plaintext);
  print('From Base64: ${cipher.decryptToString(b64)}');

  // From Map with 'iv' key
  final payload = cipher.encryptToPayload(plaintext);
  print('From Map (iv): ${cipher.decryptToString(payload.toMap())}');

  // From Map with 'nonce' key
  print(
    'From Map (nonce): ${cipher.decryptToString(payload.toMap(ivKey: 'nonce'))}',
  );

  // From AesAuthPayload object
  print('From AesAuthPayload: ${cipher.decryptToString(payload)}');

  // Interop: decrypt .NET-style separated fields
  final ciphertext = cipher.encrypt(plaintext);
  final iv = base64Encode(ciphertext.sublist(0, 12));
  final tag = base64Encode(ciphertext.sublist(ciphertext.length - 16));
  final data = base64Encode(ciphertext.sublist(12, ciphertext.length - 16));
  print(
    'Interop (.NET-style): ${cipher.decryptToString({'nonce': iv, 'data': data, 'tag': tag})}',
  );
}

Future<void> rsaBasicExample() async {
  final pair = await Fortis.rsa().keySize(2048).generateKeyPair();

  final encrypter = Fortis.rsa()
      .padding(RsaPadding.oaep_v2)
      .hash(RsaHash.sha256)
      .encrypter(pair.publicKey);

  final decrypter = Fortis.rsa()
      .padding(RsaPadding.oaep_v2)
      .hash(RsaHash.sha256)
      .decrypter(pair.privateKey);

  // Encrypt String
  final ciphertext = encrypter.encrypt('hello fortis');
  print('RSA decrypt (bytes): ${decrypter.decryptToString(ciphertext)}');

  // Encrypt Uint8List
  final bytesInput = Uint8List.fromList([1, 2, 3, 4, 5]);
  final bytesCiphertext = encrypter.encrypt(bytesInput);
  print('RSA decrypt (Uint8List): ${decrypter.decrypt(bytesCiphertext)}');

  // encryptToString → decryptToString
  final b64 = encrypter.encryptToString('hello fortis');
  print('RSA Base64 round-trip: ${decrypter.decryptToString(b64)}');
}

Future<void> rsaPaddingHashMatrixExample() async {
  final pair = await Fortis.rsa().keySize(2048).generateKeyPair();
  final plaintext = Uint8List.fromList('round-trip test'.codeUnits);

  // PKCS#1 v1.5
  final pkcs1Ct = Fortis.rsa()
      .padding(RsaPadding.pkcs1_v1_5)
      .hash(RsaHash.sha256)
      .encrypter(pair.publicKey)
      .encrypt(plaintext);
  final pkcs1Pt = Fortis.rsa()
      .padding(RsaPadding.pkcs1_v1_5)
      .hash(RsaHash.sha256)
      .decrypter(pair.privateKey)
      .decrypt(pkcs1Ct);
  print('PKCS#1 v1.5: ${String.fromCharCodes(pkcs1Pt)}');

  // OAEP v1 + SHA-1
  final oaep1Ct = Fortis.rsa()
      .padding(RsaPadding.oaep_v1)
      .hash(RsaHash.sha1)
      .encrypter(pair.publicKey)
      .encrypt(plaintext);
  final oaep1Pt = Fortis.rsa()
      .padding(RsaPadding.oaep_v1)
      .hash(RsaHash.sha1)
      .decrypter(pair.privateKey)
      .decrypt(oaep1Ct);
  print('OAEP v1: ${String.fromCharCodes(oaep1Pt)}');

  // OAEP v2 with all hash algorithms
  for (final hash in RsaHash.values) {
    final ct = Fortis.rsa()
        .padding(RsaPadding.oaep_v2)
        .hash(hash)
        .encrypter(pair.publicKey)
        .encrypt(plaintext);
    final pt = Fortis.rsa()
        .padding(RsaPadding.oaep_v2)
        .hash(hash)
        .decrypter(pair.privateKey)
        .decrypt(ct);

    print('OAEP v2 + $hash: ${String.fromCharCodes(pt)}');
  }

  // OAEP v2.1 with all hash algorithms
  for (final hash in RsaHash.values) {
    final ct = Fortis.rsa()
        .padding(RsaPadding.oaep_v2_1)
        .hash(hash)
        .encrypter(pair.publicKey)
        .encrypt(plaintext);
    final pt = Fortis.rsa()
        .padding(RsaPadding.oaep_v2_1)
        .hash(hash)
        .decrypter(pair.privateKey)
        .decrypt(ct);

    print('OAEP v2.1 + $hash: ${String.fromCharCodes(pt)}');
  }
}

Future<void> rsaLabelExample() async {
  final pair = await Fortis.rsa().keySize(2048).generateKeyPair();
  final plaintext = Uint8List.fromList('round-trip test'.codeUnits);

  // String label
  final encrypter = Fortis.rsa()
      .padding(RsaPadding.oaep_v2_1)
      .hash(RsaHash.sha256)
      .encrypter(pair.publicKey, label: 'my-label');
  final decrypter = Fortis.rsa()
      .padding(RsaPadding.oaep_v2_1)
      .hash(RsaHash.sha256)
      .decrypter(pair.privateKey, label: 'my-label');

  final ciphertext = encrypter.encrypt(plaintext);
  final recovered = decrypter.decrypt(ciphertext);
  print('OAEP v2.1 String label: ${String.fromCharCodes(recovered)}');

  // Uint8List label
  final labelBytes = Uint8List.fromList('binary-label'.codeUnits);
  final encrypterBytes = Fortis.rsa()
      .padding(RsaPadding.oaep_v2_1)
      .hash(RsaHash.sha256)
      .encrypter(pair.publicKey, label: labelBytes);
  final decrypterBytes = Fortis.rsa()
      .padding(RsaPadding.oaep_v2_1)
      .hash(RsaHash.sha256)
      .decrypter(pair.privateKey, label: labelBytes);

  final ct = encrypterBytes.encrypt(plaintext);
  final pt = decrypterBytes.decrypt(ct);
  print('OAEP v2.1 Uint8List label: ${String.fromCharCodes(pt)}');
}

Future<void> rsaKeySerializationExample() async {
  final pair = await Fortis.rsa().keySize(2048).generateKeyPair();

  // --- Public key ---
  // PEM X.509 (default)
  final pubPemX509 = pair.publicKey.toPem();
  final pubFromPem = FortisRsaPublicKey.fromPem(pubPemX509);
  print('Public PEM X.509 round-trip: ${pubFromPem.toPem() == pubPemX509}');

  // PEM PKCS#1
  final pubPemPkcs1 = pair.publicKey.toPem(format: RsaPublicKeyFormat.pkcs1);
  final pubFromPkcs1 = FortisRsaPublicKey.fromPem(
    pubPemPkcs1,
    format: RsaPublicKeyFormat.pkcs1,
  );
  print(
    'Public PEM PKCS#1 round-trip: '
    '${pubFromPkcs1.toPem(format: RsaPublicKeyFormat.pkcs1) == pubPemPkcs1}',
  );

  // DER Base64
  final publicB64 = pair.publicKey.toDerBase64();
  final restoredPublic = FortisRsaPublicKey.fromDerBase64(publicB64);
  print(
    'Public DER Base64 round-trip: ${restoredPublic.toDerBase64() == publicB64}',
  );

  // --- Private key ---
  // PEM PKCS#8 (default)
  final privPemPkcs8 = pair.privateKey.toPem();
  final privFromPkcs8 = FortisRsaPrivateKey.fromPem(privPemPkcs8);
  print(
    'Private PEM PKCS#8 round-trip: ${privFromPkcs8.toPem() == privPemPkcs8}',
  );

  // PEM PKCS#1
  final privPemPkcs1 = pair.privateKey.toPem(format: RsaPrivateKeyFormat.pkcs1);
  final privFromPkcs1 = FortisRsaPrivateKey.fromPem(
    privPemPkcs1,
    format: RsaPrivateKeyFormat.pkcs1,
  );
  print(
    'Private PEM PKCS#1 round-trip: '
    '${privFromPkcs1.toPem(format: RsaPrivateKeyFormat.pkcs1) == privPemPkcs1}',
  );

  // DER Base64
  final privateB64 = pair.privateKey.toDerBase64();
  final restoredPrivate = FortisRsaPrivateKey.fromDerBase64(privateB64);
  print(
    'Private DER Base64 round-trip: '
    '${restoredPrivate.toDerBase64() == privateB64}',
  );
}

Future<void> ccmTagSizeExample() async {
  final key = await Fortis.aes().keySize(256).generateKey();

  // All tag sizes valid per NIST SP 800-38C
  for (final bits in [32, 64, 96, 128]) {
    final cipher = Fortis.aes().ccm().tagSize(bits).cipher(key);
    final ct = cipher.encrypt('hello fortis');
    print('AES-CCM tag=$bits decrypted: ${cipher.decryptToString(ct)}');
  }

  // Invalid tag size → FortisConfigException up front
  try {
    Fortis.aes().ccm().tagSize(65).cipher(key);
  } on FortisConfigException catch (e) {
    print('AES-CCM tag=65 rejected: ${e.message}');
  }
}

Future<void> ecdhBasicExample() async {
  // Defaults (P-256)
  final alice = await Fortis.ecdh().generateKeyPair();
  final bob = await Fortis.ecdh().generateKeyPair();

  // Alice and Bob derive the same AES key independently
  final aliceKey = Fortis.ecdh()
      .keyDerivation(alice.privateKey)
      .deriveAesKey(bob.publicKey);
  final bobKey = Fortis.ecdh()
      .keyDerivation(bob.privateKey)
      .deriveAesKey(alice.publicKey);

  print(
    'ECDH P-256 shared keys match: ${aliceKey.toBase64() == bobKey.toBase64()}',
  );

  // Use the derived key with AES-GCM
  final cipher = Fortis.aes().gcm().cipher(aliceKey);
  final ct = cipher.encrypt('hello fortis');
  final recovered = Fortis.aes().gcm().cipher(bobKey).decryptToString(ct);
  print('ECDH → AES-GCM round-trip: $recovered');

  // P-384 and P-521
  for (final curve in [EcdhCurve.p384, EcdhCurve.p521]) {
    final a = await Fortis.ecdh().curve(curve).generateKeyPair();
    final b = await Fortis.ecdh().curve(curve).generateKeyPair();
    final k1 = Fortis.ecdh()
        .curve(curve)
        .keyDerivation(a.privateKey)
        .deriveAesKey(b.publicKey);
    final k2 = Fortis.ecdh()
        .curve(curve)
        .keyDerivation(b.privateKey)
        .deriveAesKey(a.publicKey);
    print('ECDH $curve shared keys match: ${k1.toBase64() == k2.toBase64()}');
  }
}

Future<void> ecdhKeySerializationExample() async {
  final pair = await Fortis.ecdh().generateKeyPair();

  // Public — PEM X.509 (only PEM format supported for ECDH public)
  final pubPem = pair.publicKey.toPem();
  final pubFromPem = FortisEcdhPublicKey.fromPem(pubPem);
  print('ECDH public PEM round-trip: ${pubFromPem.toPem() == pubPem}');

  // Public — DER Base64
  final pubB64 = pair.publicKey.toDerBase64();
  final pubFromB64 = FortisEcdhPublicKey.fromDerBase64(pubB64);
  print(
    'ECDH public DER Base64 round-trip: ${pubFromB64.toDerBase64() == pubB64}',
  );

  // Public — raw uncompressed point (interop with WebCrypto / JWK / many JS libs)
  final raw = pair.publicKey.toDer(
    format: EcdhPublicKeyFormat.uncompressedPoint,
  );
  final pubFromRaw = FortisEcdhPublicKey.fromDer(
    raw,
    format: EcdhPublicKeyFormat.uncompressedPoint,
    curve: EcdhCurve.p256,
  );
  print('ECDH public uncompressed point length: ${raw.length} bytes');
  print(
    'ECDH public uncompressed round-trip: '
    '${pubFromRaw.toDerBase64() == pair.publicKey.toDerBase64()}',
  );

  // Private — PEM PKCS#8 (default)
  final privPemPkcs8 = pair.privateKey.toPem();
  final privFromPkcs8 = FortisEcdhPrivateKey.fromPem(privPemPkcs8);
  print(
    'ECDH private PEM PKCS#8 round-trip: '
    '${privFromPkcs8.toPem() == privPemPkcs8}',
  );

  // Private — PEM SEC1 (openssl default for EC keys)
  final privPemSec1 = pair.privateKey.toPem(format: EcdhPrivateKeyFormat.sec1);
  final privFromSec1 = FortisEcdhPrivateKey.fromPem(
    privPemSec1,
    format: EcdhPrivateKeyFormat.sec1,
  );
  print(
    'ECDH private PEM SEC1 round-trip: '
    '${privFromSec1.toPem(format: EcdhPrivateKeyFormat.sec1) == privPemSec1}',
  );
}

Future<void> ecdhAdvancedDerivationExample() async {
  final alice = await Fortis.ecdh().generateKeyPair();
  final bob = await Fortis.ecdh().generateKeyPair();

  // Raw shared secret (the x-coord of the ECDH point, left-padded to field size)
  final secret = Fortis.ecdh()
      .keyDerivation(alice.privateKey)
      .deriveSharedSecret(bob.publicKey);
  print('ECDH raw shared secret: ${secret.length} bytes');

  // Derive arbitrary key material via HKDF-SHA256 with salt + info context
  final salt = Uint8List.fromList(utf8.encode('session-123'));
  final info = Uint8List.fromList(utf8.encode('fortis/chat-v1'));
  final keyBytes = Fortis.ecdh()
      .keySize(512) // 64 bytes
      .keyDerivation(alice.privateKey)
      .deriveKey(bob.publicKey, salt: salt, info: info);
  print('ECDH derived key bytes (HKDF): ${keyBytes.length} bytes');

  // Static utility: stretch any pre-shared secret into an AES key
  final preShared = Uint8List.fromList(List.filled(32, 0x42));
  final aesFromPreShared = EcdhKeyDerivation.hkdfDeriveAesKey(
    preShared,
    keySize: 256,
    salt: salt,
    info: info,
  );
  final cipher = Fortis.aes().gcm().cipher(aesFromPreShared);
  final ct = cipher.encrypt('hello from pre-shared');
  print('HKDF static utility decrypt: ${cipher.decryptToString(ct)}');
}

Future<void> errorHandlingExample() async {
  final key = await Fortis.aes().keySize(256).generateKey();

  // (a) Tampered ciphertext → FortisEncryptionException (GCM auth failure)
  final gcm = Fortis.aes().gcm().cipher(key);
  final ct = gcm.encrypt('hello fortis');
  final tampered = Uint8List.fromList(ct)..[ct.length ~/ 2] ^= 0xFF;
  try {
    gcm.decrypt(tampered);
  } on FortisEncryptionException catch (e) {
    print('Tampering detected: ${e.message.split('.').first}');
  }

  // (b) Invalid Base64 input → FortisConfigException (wrapped FormatException)
  try {
    gcm.decrypt('!!!not base64!!!');
  } on FortisConfigException catch (e) {
    print('Invalid Base64 rejected: ${e.message}');
  }

  // (c) Invalid tagSize on AesAuthCipher constructor → FortisConfigException
  try {
    AesAuthCipher(mode: AesMode.gcm, key: key, tagSizeBits: 96);
  } on FortisConfigException catch (e) {
    print('Invalid tagSize rejected: ${e.message.split('.').first}');
  }
}
