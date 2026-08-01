One exception hierarchy, three failure kinds.

`FortisException` is the base type — catch it to catch everything this package
throws. The three subtypes say where the failure happened, which is usually
what decides the recovery:

- `FortisConfigException` — the configuration is impossible before any data is
  touched: an unsupported key size, a mode paired with a padding it does not
  take, a MAC length outside the standard.
- `FortisKeyException` — a key could not be imported or exported: malformed
  PEM, invalid DER, undecodable Base64, or two ECDH keys on different curves.
- `FortisEncryptionException` — the operation itself failed: a wrong key, a
  corrupted payload, or an authentication tag that does not verify.
