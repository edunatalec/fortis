# Changelog

## [0.3.3] - 2026-08-01

### Added

- `CONTRIBUTING.md` now ships in the published archive, which is what makes pub.dev show the "Contributing" link in the package sidebar.

### Changed

- API reference: every symbol cited in prose is now a link, each public type ends with a `See also:` block, and the library page explains how the three builders and the phantom types fit together.
- API reference grouped into Core, AES, RSA, ECDH and Errors, each with its own topic page — the fifty public types no longer render as one flat alphabetical list.
- README follows the skeleton shared by the published packages: `## Contents` lists only what comes after it, `## Features` became `## Why fortis`, and the runnable tour moved out of the Quick start into `## Example`, with the command that runs it.
- README gained a `## Contributing` section, and links to repository files are now absolute. A relative link is rewritten to GitHub on the package page but left untouched in the generated API reference, where it resolved to a 404.

## [0.3.2] - 2026-07-28

### Changed

- Reformatted the LICENSE into the canonical single-line-paragraph MIT template with a standardized copyright line — no change to the license terms.
- Adopted the stricter shared analysis options (strict casts, plus async, import, immutability and bug-prone lints); source and tests adjusted to the new rules — no behavior change.

## [0.3.1] - 2026-07-28

### Changed

- Lowered the minimum SDK from Dart `^3.11.0` to `^3.8.0` — no language feature above 3.8 is used, so the package installs on toolchains back to mid-2025.

## [0.3.0] - 2026-04-24

### Added

- Flutter web support: `Fortis.aes().generateKey()`, `Fortis.ecdh().generateKeyPair()`, and `Fortis.rsa().generateKeyPair()` now work on web. Implementation uses conditional imports — `dart:isolate` on VM/AOT, synchronous execution wrapped in `Future.sync` on web (since `dart:isolate` is unavailable there).
- `FortisLog.warn` now fires on web when generating RSA keys ≥ 2048 bits to flag that the main thread will be blocked.

### Changed

- Internal: key-generation call sites now route through `lib/src/core/platform.dart` instead of importing `dart:isolate` directly.
- Docstrings of `generateKey` / `generateKeyPair` now describe the web behaviour alongside the VM/Isolate path.

## [0.2.0] - 2026-04-16

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

### Fixed

- `AesCipher.decrypt(String|Map)` and `RsaDecrypter.decrypt(String)` now wrap `FormatException` from `base64Decode` as `FortisConfigException` instead of letting it escape the public API.
- `AesAuthCipher` constructor now fails fast on invalid `tagSizeBits` (GCM ≠ 128, or CCM outside `{32, 48, 64, 80, 96, 112, 128}`) via `FortisConfigException`, instead of surfacing a runtime `ArgumentError` from PointyCastle.
- `AesStandardCipher` constructor now rejects CBC without padding and stream modes (CTR/CFB/OFB) with padding, instead of crashing later or silently ignoring the value.
- `RsaEncrypter` and `RsaDecrypter` constructors now reject `label` combined with any padding other than `RsaPadding.oaep_v2_1` (previously the label was silently ignored at encrypt/decrypt time).
- `FortisAesKey.fromTrustedBytes` now validates the byte length (16/24/32). Although named "trusted", the symbol is exported publicly, so an invalid size would surface as a cryptic PointyCastle error on the first `encrypt` call.
- `FortisEcdhPublicKey` and `FortisEcdhPrivateKey` constructors now reject `key`/`curve` mismatches (e.g., a P-256 key declared as P-384). Previously the combination was accepted silently and surfaced as inconsistent shared secrets or cryptic errors downstream.

## [0.1.0] - 2026-04-12

### Added

- RSA encryption/decryption with PKCS#1 v1.5 and OAEP padding support
- AES encryption/decryption with ECB, CBC, CTR, GCM, CFB, OFB, and CCM modes
- Fluent builder API with compile-time safety via phantom types
- Async key generation via Dart Isolate
- Key serialization (PEM, DER, Base64)
- AAD support for GCM and CCM
- Automatic IV/nonce management
- `FortisException` hierarchy for structured error handling
