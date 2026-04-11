// ignore_for_file: constant_identifier_names

import 'package:pointycastle/export.dart';

/// The hash algorithm used in RSA padding schemes.
enum RsaHash {
  /// SHA-1 (160-bit). Legacy; avoid in new designs.
  sha1,

  /// SHA-224 (224-bit).
  sha224,

  /// SHA-256 (256-bit). Recommended default.
  sha256,

  /// SHA-384 (384-bit).
  sha384,

  /// SHA-512 (512-bit).
  sha512,

  /// SHA3-256 (256-bit, Keccak-based).
  sha3_256,

  /// SHA3-512 (512-bit, Keccak-based).
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
