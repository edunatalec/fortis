/// Cryptography for Dart and Flutter — AES, RSA and ECDH behind a single
/// fluent, compile-time-checked API.
///
/// Three algorithm families hang off the [Fortis] entry point, each reached
/// through its own builder: [AesBuilder] for symmetric encryption,
/// [RsaBuilder] for asymmetric encryption, and [EcdhBuilder] for key
/// agreement. Configuration is carried by the type system instead of being
/// checked at runtime — phantom types stop an [RsaBuilder] from producing an
/// encrypter before padding and hash are set, and the sealed [AesCipher]
/// variants make each mode's payload type known statically. IVs and nonces
/// are generated per operation and travel with the ciphertext, so there is no
/// separate value to store, transmit or forget.
///
/// ```dart
/// final key = await Fortis.aes().generateKey();
/// final cipher = Fortis.aes().gcm().cipher(key);
///
/// final payload = cipher.encryptToPayload('hello fortis');
/// final plaintext = cipher.decryptToString(payload); // 'hello fortis'
/// ```
///
/// See also:
///
///  * [Fortis], the entry point every builder is created from.
///  * [AesBuilder], which configures AES key size, mode and padding.
///  * [RsaBuilder], which configures RSA key size, padding and hash.
///  * [EcdhBuilder], which configures the curve and derives shared keys.
///  * [FortisException], the base type of every error this library throws.
library;

import 'src/algorithms/aes/aes_builder.dart';
import 'src/algorithms/ecdh/ecdh_builder.dart';
import 'src/algorithms/rsa/rsa_builder.dart';

export 'src/algorithms/aes/aes_auth_payload.dart';
export 'src/algorithms/aes/aes_builder.dart';
export 'src/algorithms/aes/aes_cipher.dart';
export 'src/algorithms/aes/aes_key.dart';
export 'src/algorithms/aes/aes_mode.dart';
export 'src/algorithms/aes/aes_padding.dart';
export 'src/algorithms/aes/aes_payload.dart';
export 'src/algorithms/ecdh/ecdh_builder.dart';
export 'src/algorithms/ecdh/ecdh_curve.dart';
export 'src/algorithms/ecdh/ecdh_key_derivation.dart';
export 'src/algorithms/ecdh/ecdh_key_pair.dart';
export 'src/algorithms/ecdh/ecdh_private_key.dart';
export 'src/algorithms/ecdh/ecdh_private_key_format.dart';
export 'src/algorithms/ecdh/ecdh_public_key.dart';
export 'src/algorithms/ecdh/ecdh_public_key_format.dart';
export 'src/algorithms/rsa/rsa_builder.dart';
export 'src/algorithms/rsa/rsa_decrypter.dart';
export 'src/algorithms/rsa/rsa_encrypter.dart';
export 'src/algorithms/rsa/rsa_hash.dart';
export 'src/algorithms/rsa/rsa_key_pair.dart';
export 'src/algorithms/rsa/rsa_padding.dart';
export 'src/algorithms/rsa/rsa_private_key.dart';
export 'src/algorithms/rsa/rsa_private_key_format.dart';
export 'src/algorithms/rsa/rsa_public_key.dart';
export 'src/algorithms/rsa/rsa_public_key_format.dart';
export 'src/exceptions/fortis_config_exception.dart';
export 'src/exceptions/fortis_encryption_exception.dart';
export 'src/exceptions/fortis_exception.dart';
export 'src/exceptions/fortis_key_exception.dart';

/// Entry point for the Fortis cryptography library.
///
/// Three algorithm families, each with a fluent builder:
/// - [aes] — AES symmetric encryption (ECB, CBC, CTR, CFB, OFB, GCM, CCM).
/// - [rsa] — RSA asymmetric encryption (OAEP v2 / v2.1 / v1, PKCS#1 v1.5).
/// - [ecdh] — ECDH key agreement (P-256, P-384, P-521) + HKDF.
///
/// ```dart
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
/// final remotePublicKey = (await Fortis.ecdh().generateKeyPair()).publicKey;
/// final aesKey = Fortis.ecdh()
///     .keyDerivation(ec.privateKey)
///     .deriveAesKey(remotePublicKey);
/// ```
///
/// See also:
///
///  * [AesBuilder], returned by [aes] for symmetric encryption.
///  * [RsaBuilder], returned by [rsa] for asymmetric encryption.
///  * [EcdhBuilder], returned by [ecdh] for key agreement and derivation.
///  * [FortisException], the base type of every error these builders throw.
sealed class Fortis {
  /// Creates a new [RsaBuilder] for RSA key generation and encryption.
  ///
  /// Defaults: [RsaBuilder.keySize] = 2048. [RsaBuilder.padding] and
  /// [RsaBuilder.hash] are unset — calling [RsaBuilderReady.encrypter] /
  /// [RsaBuilderReady.decrypter] requires both to be configured first
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
  /// Defaults: [AesBuilder.keySize] = 256 bits. Pick the mode via a typed
  /// shortcut ([AesBuilder.gcm], [AesBuilder.cbc], [AesBuilder.ecb], etc.)
  /// for a statically-typed cipher, or [AesBuilder.mode] for runtime
  /// dispatch.
  ///
  /// ```dart
  /// final key = await Fortis.aes().generateKey();
  /// final cipher = Fortis.aes().gcm().cipher(key); // AesAuthCipher
  /// ```
  static AesBuilder aes() => AesBuilder();

  /// Creates a new [EcdhBuilder] for ECDH key agreement and key derivation.
  ///
  /// Defaults: [EcdhBuilder.curve] = [EcdhCurve.p256],
  /// [EcdhBuilder.keySize] = 256 bits (for derivation). Zero-config usage:
  ///
  /// ```dart
  /// final pair = await Fortis.ecdh().generateKeyPair();
  /// final remotePublicKey = (await Fortis.ecdh().generateKeyPair()).publicKey;
  ///
  /// final aesKey = Fortis.ecdh()
  ///     .keyDerivation(pair.privateKey)
  ///     .deriveAesKey(remotePublicKey);
  /// ```
  static EcdhBuilder ecdh() => EcdhBuilder();
}
