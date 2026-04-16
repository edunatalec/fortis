// ignore_for_file: constant_identifier_names

/// The RSA padding scheme used by [RsaEncrypter] and [RsaDecrypter].
///
/// Passed to [RsaBuilder.padding]. Padding is **mandatory** — RSA without
/// padding is insecure. There is no default; the phantom-typed builder
/// won't let you call `.encrypter()` / `.decrypter()` until you pick one.
///
/// Selection guide:
///
/// | Padding         | When to use                               |
/// |-----------------|-------------------------------------------|
/// | [oaep_v2_1]     | New designs. Supports a `label`.          |
/// | [oaep_v2]       | New designs. No label support.            |
/// | [oaep_v1]       | Legacy — SHA-1 only. Avoid.               |
/// | [pkcs1_v1_5]    | Legacy interop only (TLS ≤ 1.1, old CMS). |
enum RsaPadding {
  /// PKCS#1 v1.5 padding (RFC 8017 §7.2). Legacy; still widely supported.
  ///
  /// ⚠️ Vulnerable to Bleichenbacher-style attacks when poorly implemented
  /// on the server side. Prefer [oaep_v2] or [oaep_v2_1] for new designs.
  /// The hash passed to [RsaBuilder.hash] is ignored for this padding.
  ///
  /// Example:
  /// ```dart
  /// final encrypter = Fortis.rsa()
  ///     .padding(RsaPadding.pkcs1_v1_5)
  ///     .hash(RsaHash.sha256) // ignored, but still required by the builder
  ///     .encrypter(pair.publicKey);
  /// ```
  pkcs1_v1_5,

  /// OAEP v1 — SHA-1 based with MGF1. Deprecated in favor of OAEP v2+.
  ///
  /// Ignores the hash passed to [RsaBuilder.hash] — always uses SHA-1.
  /// Included for interop with older libraries. Avoid in new designs.
  ///
  /// Example:
  /// ```dart
  /// final encrypter = Fortis.rsa()
  ///     .padding(RsaPadding.oaep_v1)
  ///     .hash(RsaHash.sha1)
  ///     .encrypter(pair.publicKey);
  /// ```
  oaep_v1,

  /// OAEP v2.0 — configurable hash, MGF1 (RFC 2437).
  ///
  /// Combines with any [RsaHash]. Recommended when you don't need label
  /// support. Combine with [RsaHash.sha256] for the standard modern
  /// configuration.
  ///
  /// Example:
  /// ```dart
  /// final encrypter = Fortis.rsa()
  ///     .padding(RsaPadding.oaep_v2)
  ///     .hash(RsaHash.sha256)
  ///     .encrypter(pair.publicKey);
  /// ```
  oaep_v2,

  /// OAEP v2.1 — configurable hash, MGF1, and **label support**
  /// (RFC 3447 / RFC 8017).
  ///
  /// Same as [oaep_v2] but lets you bind ciphertext to an application
  /// context via `label`. Encrypter and decrypter must use the same label.
  ///
  /// Example (with label):
  /// ```dart
  /// final encrypter = Fortis.rsa()
  ///     .padding(RsaPadding.oaep_v2_1)
  ///     .hash(RsaHash.sha256)
  ///     .encrypter(pair.publicKey, label: 'user:42');
  ///
  /// final decrypter = Fortis.rsa()
  ///     .padding(RsaPadding.oaep_v2_1)
  ///     .hash(RsaHash.sha256)
  ///     .decrypter(pair.privateKey, label: 'user:42');
  /// ```
  oaep_v2_1,
}
