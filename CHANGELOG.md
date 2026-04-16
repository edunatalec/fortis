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

- Split `AesAuthModeBuilder` into `AesGcmModeBuilder` (exposes `aad` and `ivSize`; tag fixed at 128 bits) and `AesCcmModeBuilder` (exposes `aad`, `ivSize`, and `tagSize` validated against NIST SP 800-38C: {32, 48, 64, 80, 96, 112, 128}). Calling `tagSize` on GCM is now a compile-time error instead of a runtime `ArgumentError`. The sealed `AesAuthModeBuilder` remains as a common base type.
- Renamed `AesAuthModeBuilder.nonceSize` to `ivSize` for consistency with the `encrypt(iv: ...)` parameter.
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
