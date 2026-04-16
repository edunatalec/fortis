// Internal imports — builder return types for Fortis factory methods
import 'src/algorithms/rsa/rsa_builder.dart';
import 'src/algorithms/aes/aes_builder.dart';
import 'src/algorithms/ecdh/ecdh_builder.dart';

// Exceptions
export 'src/exceptions/fortis_exception.dart';
export 'src/exceptions/fortis_config_exception.dart';
export 'src/exceptions/fortis_key_exception.dart';
export 'src/exceptions/fortis_encryption_exception.dart';

// RSA enums
export 'src/algorithms/rsa/rsa_hash.dart';
export 'src/algorithms/rsa/rsa_padding.dart';
export 'src/algorithms/rsa/rsa_public_key_format.dart';
export 'src/algorithms/rsa/rsa_private_key_format.dart';

// RSA keys
export 'src/algorithms/rsa/rsa_key_pair.dart';
export 'src/algorithms/rsa/rsa_public_key.dart';
export 'src/algorithms/rsa/rsa_private_key.dart';

// RSA builder — includes phantom type markers (implementation details;
// users never need to reference them directly)
export 'src/algorithms/rsa/rsa_builder.dart';

// RSA operations
export 'src/algorithms/rsa/rsa_encrypter.dart';
export 'src/algorithms/rsa/rsa_decrypter.dart';

// AES enums
export 'src/algorithms/aes/aes_mode.dart';
export 'src/algorithms/aes/aes_padding.dart';

// AES key
export 'src/algorithms/aes/aes_key.dart';

// AES payload classes
export 'src/algorithms/aes/aes_auth_payload.dart';
export 'src/algorithms/aes/aes_payload.dart';

// AES builder + cipher
export 'src/algorithms/aes/aes_builder.dart';
export 'src/algorithms/aes/aes_cipher.dart';

// ECDH enums
export 'src/algorithms/ecdh/ecdh_curve.dart';
export 'src/algorithms/ecdh/ecdh_public_key_format.dart';
export 'src/algorithms/ecdh/ecdh_private_key_format.dart';

// ECDH keys
export 'src/algorithms/ecdh/ecdh_key_pair.dart';
export 'src/algorithms/ecdh/ecdh_public_key.dart';
export 'src/algorithms/ecdh/ecdh_private_key.dart';

// ECDH builder + key derivation
export 'src/algorithms/ecdh/ecdh_builder.dart';
export 'src/algorithms/ecdh/ecdh_key_derivation.dart';

/// Entry point for the Fortis cryptography library.
///
/// Three algorithm families, each with a fluent builder:
/// - [aes] — AES symmetric encryption (ECB, CBC, CTR, CFB, OFB, GCM, CCM).
/// - [rsa] — RSA asymmetric encryption (OAEP v2 / v2.1 / v1, PKCS#1 v1.5).
/// - [ecdh] — ECDH key agreement (P-256, P-384, P-521) + HKDF.
///
/// ```dart
/// import 'package:fortis/fortis.dart';
///
/// // ─── AES (GCM — recommended default) ─────────────────────────────
/// final key = await Fortis.aes().generateKey();          // 256-bit
/// final cipher = Fortis.aes().gcm().cipher(key);         // AesAuthCipher
/// final payload = cipher.encryptToPayload('hello');      // AesAuthPayload
/// final recovered = cipher.decryptToString(payload);
///
/// // ─── RSA ─────────────────────────────────────────────────────────
/// final pair = await Fortis.rsa().generateKeyPair();     // 2048-bit
/// final encrypter = Fortis.rsa()
///     .padding(RsaPadding.oaep_v2)
///     .hash(RsaHash.sha256)
///     .encrypter(pair.publicKey);
/// final ct = encrypter.encrypt('hello fortis');
///
/// // ─── ECDH + HKDF → AES key ──────────────────────────────────────
/// final ec = await Fortis.ecdh().generateKeyPair();      // P-256
/// final aesKey = Fortis.ecdh()
///     .keyDerivation(ec.privateKey)
///     .deriveAesKey(remotePublicKey);
/// ```
sealed class Fortis {
  /// Creates a new [RsaBuilder] for RSA key generation and encryption.
  ///
  /// Defaults: `keySize` = 2048. `padding` and `hash` are unset — calling
  /// `.encrypter()` / `.decrypter()` requires both to be configured first
  /// (enforced at compile time via phantom types).
  ///
  /// ```dart
  /// final pair = await Fortis.rsa().generateKeyPair();
  ///
  /// final encrypter = Fortis.rsa()
  ///     .padding(RsaPadding.oaep_v2)
  ///     .hash(RsaHash.sha256)
  ///     .encrypter(pair.publicKey);
  /// ```
  static RsaBuilder<RsaBuilderPaddingUnset, RsaBuilderHashUnset> rsa() =>
      RsaBuilder<RsaBuilderPaddingUnset, RsaBuilderHashUnset>();

  /// Creates a new [AesBuilder] for AES key generation and encryption.
  ///
  /// Defaults: `keySize` = 256 bits. Pick the mode via a typed shortcut
  /// ([AesBuilder.gcm], [AesBuilder.cbc], [AesBuilder.ecb], etc.) for a
  /// statically-typed cipher, or [AesBuilder.mode] for runtime dispatch.
  ///
  /// ```dart
  /// final key = await Fortis.aes().generateKey();
  /// final cipher = Fortis.aes().gcm().cipher(key); // AesAuthCipher
  /// ```
  static AesBuilder aes() => AesBuilder();

  /// Creates a new [EcdhBuilder] for ECDH key agreement and key derivation.
  ///
  /// Defaults: `curve` = [EcdhCurve.p256], `keySize` = 256 bits (for
  /// derivation). Zero-config usage:
  ///
  /// ```dart
  /// final pair = await Fortis.ecdh().generateKeyPair();
  ///
  /// final aesKey = Fortis.ecdh()
  ///     .keyDerivation(pair.privateKey)
  ///     .deriveAesKey(remotePublicKey);
  /// ```
  static EcdhBuilder ecdh() => EcdhBuilder();
}
