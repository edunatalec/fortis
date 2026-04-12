# Changelog

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
