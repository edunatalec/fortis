# Changelog

## 0.2.0 - 2026-04-16

### Added

- ECDH key agreement with NIST curves P-256, P-384, and P-521
- HKDF-SHA256 key derivation: `deriveSharedSecret`, `deriveKey`, and `deriveAesKey`
- Static HKDF utilities (`EcdhKeyDerivation.hkdf`, `EcdhKeyDerivation.hkdfDeriveAesKey`) for pre-shared secrets
- ECDH key serialization (PEM X.509 / PKCS#8 / SEC1, DER, Base64, raw uncompressed point)
- Typed AES builder shortcuts (`.ecb()`, `.cbc()`, `.ctr()`, `.cfb()`, `.ofb()`, `.gcm()`, `.ccm()`) returning statically-typed cipher variants
- Sealed `AesCipher` hierarchy (`AesEcbCipher`, `AesStandardCipher`, `AesAuthCipher`) — `encryptToPayload` is now statically typed per variant (no casts)
- Multilingual cryptography guides (`doc/`) for AES, RSA, and ECDH in English, Spanish, and Portuguese
- Comprehensive edge-case and validation tests across all three algorithms

### Changed

- Bumped `lints` to `^6.1.0` and `test` to `^1.31.0`

## 0.1.0 - 2026-04-12

### Added

- RSA encryption/decryption with PKCS#1 v1.5 and OAEP padding support
- AES encryption/decryption with ECB, CBC, CTR, GCM, CFB, OFB, and CCM modes
- Fluent builder API with compile-time safety via phantom types
- Async key generation via Dart Isolate
- Key serialization (PEM, DER, Base64)
- AAD support for GCM and CCM
- Automatic IV/nonce management
- `FortisException` hierarchy for structured error handling
