// ignore_for_file: constant_identifier_names

import 'package:pointycastle/export.dart';

/// The hash algorithm used inside RSA padding schemes (OAEP MGF1).
///
/// Passed to [RsaBuilder.hash]. Defaults to none — the phantom-typed builder
/// requires you to call [RsaBuilder.hash] before `.encrypter()`/`.decrypter()`.
///
/// Selection guide:
///
/// | Hash           | When to use                                    |
/// |----------------|------------------------------------------------|
/// | [sha256]       | **Recommended default** for new designs.       |
/// | [sha384]       | Paired with RSA-3072+ for higher security.     |
/// | [sha512]       | Paired with RSA-4096+ (note: reduces max msg). |
/// | [sha224]       | Legacy interop; avoid for new designs.         |
/// | [sha1]         | Legacy only. Cryptographically broken.         |
/// | [sha3_256/512] | Interop with systems that require SHA-3.       |
///
/// Larger hashes leave less room for the plaintext: with OAEP, the maximum
/// message size is `keyBytes − 2·hashBytes − 2` (e.g. RSA-2048 + SHA-256
/// allows 190 bytes; RSA-2048 + SHA-512 allows 62 bytes).
///
/// Note: [RsaPadding.pkcs1_v1_5] and [RsaPadding.oaep_v1] ignore this choice
/// (PKCS#1 v1.5 has no hash; OAEP v1 is hard-wired to SHA-1).
enum RsaHash {
  /// SHA-1 (160-bit). Legacy; avoid in new designs.
  ///
  /// Example:
  /// ```dart
  /// final encrypter = Fortis.rsa()
  ///     .padding(RsaPadding.oaep_v1)
  ///     .hash(RsaHash.sha1)
  ///     .encrypter(pair.publicKey);
  /// ```
  sha1,

  /// SHA-224 (224-bit). Rare; mostly kept for niche interop.
  sha224,

  /// SHA-256 (256-bit). **Recommended default.**
  ///
  /// Example:
  /// ```dart
  /// final encrypter = Fortis.rsa()
  ///     .padding(RsaPadding.oaep_v2)
  ///     .hash(RsaHash.sha256)
  ///     .encrypter(pair.publicKey);
  /// ```
  sha256,

  /// SHA-384 (384-bit). Good pair for RSA-3072 or larger.
  sha384,

  /// SHA-512 (512-bit). Good pair for RSA-4096 — but eats more padding
  /// overhead so the usable plaintext is smaller.
  sha512,

  /// SHA3-256 (256-bit, Keccak-based). Use only when interoperating with
  /// systems that require SHA-3.
  sha3_256,

  /// SHA3-512 (512-bit, Keccak-based). Use only when interoperating with
  /// systems that require SHA-3.
  sha3_512;

  /// Returns the PointyCastle [Digest] instance corresponding to this hash.
  Digest toDigest() => switch (this) {
    sha1 => SHA1Digest(),
    sha224 => SHA224Digest(),
    sha256 => SHA256Digest(),
    sha384 => SHA384Digest(),
    sha512 => SHA512Digest(),
    sha3_256 => SHA3Digest(256),
    sha3_512 => SHA3Digest(512),
  };
}
