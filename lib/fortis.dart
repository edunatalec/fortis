// Internal imports — builder return types for Fortis factory methods
import 'src/algorithms/rsa/rsa_builder.dart';
import 'src/algorithms/aes/aes_builder.dart';

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

// AES builder + operations
export 'src/algorithms/aes/aes_builder.dart';
export 'src/algorithms/aes/aes_encrypter.dart';
export 'src/algorithms/aes/aes_decrypter.dart';

// Warnings
export 'src/core/fortis_crypto_warning.dart';

/// Entry point for the Fortis cryptography library.
///
/// ```dart
/// import 'package:fortis/fortis.dart';
///
/// // AES key generation
/// final key = await Fortis.aes().keySize(256).generateKey();
///
/// // AES encrypt/decrypt
/// final encrypter = Fortis.aes().mode(AesMode.gcm).key(key).encrypter();
/// final decrypter = Fortis.aes().mode(AesMode.gcm).key(key).decrypter();
/// final ciphertext = encrypter.encrypt(plaintext);
/// final recovered  = decrypter.decrypt(ciphertext);
///
/// // RSA
/// final pair = await Fortis.rsa().keySize(2048).generateKeyPair();
///
/// final rsaEncrypter = Fortis.rsa()
///     .padding(RsaPadding.oaep_v2)
///     .hash(RsaHash.sha256)
///     .encrypter(pair.publicKey);
///
/// final ciphertext = rsaEncrypter.encrypt(plaintext);
/// ```
sealed class Fortis {
  /// Creates a new [RsaBuilder] for RSA key generation and encryption.
  static RsaBuilder<RsaBuilderPaddingUnset, RsaBuilderHashUnset> rsa() =>
      RsaBuilder<RsaBuilderPaddingUnset, RsaBuilderHashUnset>();

  /// Creates a new [AesBuilder] for AES key generation and encryption.
  static AesBuilder aes() => AesBuilder();
}
