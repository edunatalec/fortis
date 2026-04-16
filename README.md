# Fortis

[![pub package](https://img.shields.io/pub/v/fortis.svg)](https://pub.dev/packages/fortis)
[![package publisher](https://img.shields.io/pub/publisher/validart.svg)](https://pub.dev/packages/validart/publisher)

High-level cryptography for Dart. Fluent builder API with compile-time safety, sane defaults, and seamless cross-platform interoperability.

## Features

- **AES** encryption with 7 cipher modes (ECB, CBC, CTR, CFB, OFB, GCM, CCM)
- **RSA** encryption with 4 padding schemes (PKCS#1 v1.5, OAEP v1/v2/v2.1)
- **ECDH** key agreement with NIST curves (P-256, P-384, P-521) and HKDF-SHA256 derivation
- Fluent builder API with compile-time safety — phantom types for RSA and sealed cipher variants for AES
- Automatic IV/nonce generation with cryptographically secure random
- Structured payloads for easy serialization
- Key serialization in PEM, DER, and Base64 formats
- Async key generation using isolates (non-blocking)
- Consistent exception hierarchy for error handling

## Learn Cryptography

New to cryptography or want to understand the concepts behind AES, RSA, padding schemes, and cipher modes? Check out our [Cryptography Guide](doc/cryptography/en.md)

## Quick Start

```dart
import 'package:fortis/fortis.dart';

// AES-256-GCM encryption
final key = await Fortis.aes().generateKey();
final cipher = Fortis.aes().gcm().cipher(key); // AesAuthCipher

final ciphertext = cipher.encrypt('Hello, Fortis!');
final plaintext = cipher.decryptToString(ciphertext);

// RSA-OAEP encryption
final pair = await Fortis.rsa().generateKeyPair();

final encrypter = Fortis.rsa()
    .padding(RsaPadding.oaep_v2)
    .hash(RsaHash.sha256)
    .encrypter(pair.publicKey);

final decrypter = Fortis.rsa()
    .padding(RsaPadding.oaep_v2)
    .hash(RsaHash.sha256)
    .decrypter(pair.privateKey);

final encrypted = encrypter.encrypt('Hello, Fortis!');
final decrypted = decrypter.decryptToString(encrypted);

// ECDH → shared AES key
final alice = await Fortis.ecdh().generateKeyPair();
final bob = await Fortis.ecdh().generateKeyPair();

final sharedKey = Fortis.ecdh()
    .keyDerivation(alice.privateKey)
    .deriveAesKey(bob.publicKey);

final sharedCipher = Fortis.aes().gcm().cipher(sharedKey);
```

---

## AES (Advanced Encryption Standard)

### Supported Modes

| Mode  | Type          | IV/Nonce                             | Description                                                  |
| ----- | ------------- | ------------------------------------ | ------------------------------------------------------------ |
| `ECB` | Block         | None                                 | Electronic Code Book — no IV, not recommended for production |
| `CBC` | Block         | 16 bytes                             | Cipher Block Chaining                                        |
| `CTR` | Stream        | 16 bytes                             | Counter Mode                                                 |
| `CFB` | Stream        | 16 bytes                             | Cipher Feedback                                              |
| `OFB` | Stream        | 16 bytes                             | Output Feedback                                              |
| `GCM` | Authenticated | Configurable (default 12)            | Galois/Counter Mode with authentication tag                  |
| `CCM` | Authenticated | Configurable 7–13 bytes (default 11) | Counter with CBC-MAC                                         |

### Supported Padding (Block Modes Only)

Padding applies only to **ECB** and **CBC** modes. Stream and authenticated modes do not use padding.

| Padding       | Description                                    |
| ------------- | ---------------------------------------------- |
| `pkcs7`       | PKCS#7 — standard, recommended                 |
| `iso7816`     | ISO 7816-4 — `0x80` followed by zero bytes     |
| `zeroPadding` | Zero-byte padding — ambiguous, legacy use only |
| `noPadding`   | No padding — data must be 16-byte aligned      |

### Key Sizes

128, 192, and 256 bits. Default is **256 bits**.

### Key Generation

```dart
// Generate a random key (default 256-bit)
final key = await Fortis.aes().generateKey();

// Generate with specific size
final key128 = await Fortis.aes().keySize(128).generateKey();
final key192 = await Fortis.aes().keySize(192).generateKey();

// Create from existing bytes
final key = FortisAesKey.fromBytes(myBytes);

// Serialize / deserialize
final base64 = key.toBase64();
final restored = FortisAesKey.fromBase64(base64);
```

### Block Modes (ECB, CBC)

```dart
// CBC with PKCS7 padding
final cipher = Fortis.aes()
    .mode(AesMode.cbc)
    .padding(AesPadding.pkcs7)
    .cipher(key);

final ciphertext = cipher.encrypt('secret message');
final plaintext = cipher.decryptToString(ciphertext);

// With explicit IV
final ciphertext = cipher.encrypt('secret message', iv: myIv);
```

### Stream Modes (CTR, CFB, OFB)

```dart
// CTR mode — no padding needed
final cipher = Fortis.aes()
    .mode(AesMode.ctr)
    .cipher(key);

final ciphertext = cipher.encrypt('secret message');
final plaintext = cipher.decryptToString(ciphertext);
```

### Authenticated Modes (GCM, CCM)

GCM and CCM provide both encryption and integrity verification via an authentication tag.

```dart
// GCM with default settings
final cipher = Fortis.aes()
    .mode(AesMode.gcm)
    .cipher(key);

final ciphertext = cipher.encrypt('secret message');
final plaintext = cipher.decryptToString(ciphertext);
```

#### Additional Authenticated Data (AAD)

```dart
final aad = Uint8List.fromList(utf8.encode('metadata'));

final cipher = Fortis.aes()
    .mode(AesMode.gcm)
    .aad(aad)
    .cipher(key);

// AAD must match during decryption
final ciphertext = cipher.encrypt('secret message');
final plaintext = cipher.decryptToString(ciphertext);
```

#### Custom Nonce Size

```dart
// GCM with custom nonce size
final cipher = Fortis.aes()
    .mode(AesMode.gcm)
    .nonceSize(16)
    .cipher(key);

// CCM with custom nonce size (7–13 bytes)
final cipher = Fortis.aes()
    .mode(AesMode.ccm)
    .nonceSize(13)
    .cipher(key);
```

### Payloads

`encryptToPayload` returns a structured object for easy serialization. Use the typed shortcuts (`.gcm()`, `.ccm()`, `.cbc()`, `.ctr()`, `.cfb()`, `.ofb()`) to get the concrete cipher type — the payload type is inferred statically, no cast required.

```dart
// Authenticated modes (GCM/CCM) → AesAuthCipher → AesAuthPayload
final gcm = Fortis.aes().gcm().cipher(key);
final authPayload = gcm.encryptToPayload('hello');
print(authPayload.iv);   // Base64-encoded nonce
print(authPayload.data); // Base64-encoded ciphertext
print(authPayload.tag);  // Base64-encoded authentication tag
print(authPayload.toMap()); // {'iv': '...', 'data': '...', 'tag': '...'}

// Non-authenticated modes (CBC/CTR/CFB/OFB) → AesStandardCipher → AesPayload
final cbc = Fortis.aes().cbc().cipher(key);
final payload = cbc.encryptToPayload('hello');
print(payload.iv);   // Base64-encoded IV
print(payload.data); // Base64-encoded ciphertext
print(payload.toMap()); // {'iv': '...', 'data': '...'}
```

> When the mode is only known at runtime, use `Fortis.aes().mode(runtimeMode).cipher(key)` — it returns the sealed base `AesCipher`; pattern-match or cast to the concrete variant before calling `encryptToPayload`.

### Decryption Input Formats

The `decrypt` method accepts multiple input types:

```dart
// From Uint8List (raw bytes)
cipher.decrypt(ciphertextBytes);

// From String (Base64-encoded)
cipher.decrypt(base64String);

// From Map
cipher.decrypt({'iv': '...', 'data': '...'});
cipher.decrypt({'nonce': '...', 'data': '...', 'tag': '...'});

// From payload object
cipher.decrypt(payload);
```

---

## RSA (Rivest-Shamir-Adleman)

### Supported Padding Schemes

| Padding      | Description                                          |
| ------------ | ---------------------------------------------------- |
| `pkcs1_v1_5` | PKCS#1 v1.5 — legacy, widely supported               |
| `oaep_v1`    | OAEP with SHA-1                                      |
| `oaep_v2`    | OAEP with configurable hash and MGF1                 |
| `oaep_v2_1`  | OAEP with configurable hash, MGF1, and label support |

### Supported Hash Algorithms

| Hash       | Bits |
| ---------- | ---- |
| `sha1`     | 160  |
| `sha224`   | 224  |
| `sha256`   | 256  |
| `sha384`   | 384  |
| `sha512`   | 512  |
| `sha3_256` | 256  |
| `sha3_512` | 512  |

### Key Sizes

Minimum **2048 bits**, must be a power of 2 (2048, 4096, 8192, ...). Default is **2048 bits**.

### Key Pair Generation

```dart
// Generate with default size (2048-bit)
final pair = await Fortis.rsa().generateKeyPair();

// Generate with specific size
final pair = await Fortis.rsa().keySize(4096).generateKeyPair();

final publicKey = pair.publicKey;
final privateKey = pair.privateKey;
```

### Key Serialization

#### Public Key

```dart
// PEM format
final pem = publicKey.toPem(); // X.509 (default)
final pem = publicKey.toPem(format: RsaPublicKeyFormat.pkcs1);

// DER format
final der = publicKey.toDer();
final derBase64 = publicKey.toDerBase64();

// Import
final key = FortisRsaPublicKey.fromPem(pemString);
final key = FortisRsaPublicKey.fromDer(derBytes);
final key = FortisRsaPublicKey.fromDerBase64(base64String);

// With specific format
final key = FortisRsaPublicKey.fromPem(pem, format: RsaPublicKeyFormat.pkcs1);
```

#### Private Key

```dart
// PEM format
final pem = privateKey.toPem(); // PKCS#8 (default)
final pem = privateKey.toPem(format: RsaPrivateKeyFormat.pkcs1);

// DER format
final der = privateKey.toDer();
final derBase64 = privateKey.toDerBase64();

// Import
final key = FortisRsaPrivateKey.fromPem(pemString);
final key = FortisRsaPrivateKey.fromDer(derBytes);
final key = FortisRsaPrivateKey.fromDerBase64(base64String);

// With specific format
final key = FortisRsaPrivateKey.fromPem(pem, format: RsaPrivateKeyFormat.pkcs1);
```

### Encryption & Decryption

```dart
// OAEP v2 with SHA-256
final encrypter = Fortis.rsa()
    .padding(RsaPadding.oaep_v2)
    .hash(RsaHash.sha256)
    .encrypter(pair.publicKey);

final decrypter = Fortis.rsa()
    .padding(RsaPadding.oaep_v2)
    .hash(RsaHash.sha256)
    .decrypter(pair.privateKey);

// Encrypt
final ciphertext = encrypter.encrypt('Hello, Fortis!');
final ciphertextBase64 = encrypter.encryptToString('Hello, Fortis!');

// Decrypt
final plaintext = decrypter.decrypt(ciphertext);
final text = decrypter.decryptToString(ciphertext);

// Also accepts Uint8List input
final ciphertext = encrypter.encrypt(Uint8List.fromList([1, 2, 3]));
```

### PKCS#1 v1.5

```dart
final encrypter = Fortis.rsa()
    .padding(RsaPadding.pkcs1_v1_5)
    .hash(RsaHash.sha256)
    .encrypter(pair.publicKey);

final decrypter = Fortis.rsa()
    .padding(RsaPadding.pkcs1_v1_5)
    .hash(RsaHash.sha256)
    .decrypter(pair.privateKey);
```

### OAEP v2.1 with Label

OAEP v2.1 supports an optional label for domain separation:

```dart
// With string label
final encrypter = Fortis.rsa()
    .padding(RsaPadding.oaep_v2_1)
    .hash(RsaHash.sha256)
    .encrypter(pair.publicKey, label: 'my-context');

final decrypter = Fortis.rsa()
    .padding(RsaPadding.oaep_v2_1)
    .hash(RsaHash.sha256)
    .decrypter(pair.privateKey, label: 'my-context');

// With Uint8List label
final encrypter = Fortis.rsa()
    .padding(RsaPadding.oaep_v2_1)
    .hash(RsaHash.sha256)
    .encrypter(pair.publicKey, label: Uint8List.fromList([1, 2, 3]));
```

---

## ECDH (Elliptic Curve Diffie–Hellman)

### Supported Curves

| Curve  | Security Level | Description          |
| ------ | -------------- | -------------------- |
| `p256` | 128-bit        | NIST P-256 (default) |
| `p384` | 192-bit        | NIST P-384           |
| `p521` | 256-bit        | NIST P-521           |

### Key Pair Generation

```dart
// Default (P-256)
final pair = await Fortis.ecdh().generateKeyPair();

// Specific curve
final pair = await Fortis.ecdh().curve(EcdhCurve.p384).generateKeyPair();

final publicKey = pair.publicKey;
final privateKey = pair.privateKey;
```

### Key Serialization

```dart
// Public key — PEM (X.509), DER, Base64
final pem = publicKey.toPem();
final der = publicKey.toDer();
final derBase64 = publicKey.toDerBase64();

// Private key — PEM defaults to PKCS#8; SEC1 available for interop
final pem = privateKey.toPem();
final sec1 = privateKey.toPem(format: EcdhPrivateKeyFormat.sec1);
final der = privateKey.toDer();

// Import
final publicKey = FortisEcdhPublicKey.fromPem(pemString);
final privateKey = FortisEcdhPrivateKey.fromPem(pemString);
final publicKey = FortisEcdhPublicKey.fromDerBase64(base64String);
```

### Deriving a Shared AES Key

Classic ECDH handshake — each peer generates a key pair, exchanges public keys, and derives the same AES key via HKDF-SHA256.

```dart
// Alice and Bob each generate a key pair
final alice = await Fortis.ecdh().generateKeyPair();
final bob = await Fortis.ecdh().generateKeyPair();

// Alice derives the shared AES key (default 256-bit)
final aliceKey = Fortis.ecdh()
    .keyDerivation(alice.privateKey)
    .deriveAesKey(bob.publicKey);

// Bob derives the same key independently
final bobKey = Fortis.ecdh()
    .keyDerivation(bob.privateKey)
    .deriveAesKey(alice.publicKey);

// Use directly with Fortis.aes()
final cipher = Fortis.aes().gcm().cipher(aliceKey);
```

### Advanced Derivation

```dart
// Raw derived bytes with HKDF (configurable size, salt, and info)
final bytes = Fortis.ecdh()
    .keySize(512)
    .keyDerivation(myPrivateKey)
    .deriveKey(
      theirPublicKey,
      salt: sessionSalt,
      info: utf8.encode('fortis/session-v1'),
    );

// Raw shared secret (without HKDF) — for protocols with their own KDF
final secret = Fortis.ecdh()
    .keyDerivation(myPrivateKey)
    .deriveSharedSecret(theirPublicKey);

// Pre-shared secret → AES key (static utility)
final aesKey = EcdhKeyDerivation.hkdfDeriveAesKey(
  preSharedSecret,
  salt: sessionSalt,
  info: utf8.encode('fortis/aes-key'),
);
```

---

## Error Handling

Fortis uses a consistent exception hierarchy:

| Exception                   | Description                                                                          |
| --------------------------- | ------------------------------------------------------------------------------------ |
| `FortisException`           | Abstract base class for all Fortis errors                                            |
| `FortisConfigException`     | Invalid configuration (e.g., unsupported key size, invalid mode/padding combination) |
| `FortisKeyException`        | Key-related errors (e.g., invalid key bytes, failed PEM/DER parsing)                 |
| `FortisEncryptionException` | Encryption/decryption failures (e.g., tampered ciphertext, wrong key, AAD mismatch)  |

```dart
try {
  final plaintext = cipher.decrypt(ciphertext);
} on FortisEncryptionException catch (e) {
  print('Decryption failed: ${e.message}');
} on FortisException catch (e) {
  print('Fortis error: ${e.message}');
}
```

## License

See [LICENSE](LICENSE) for details.
