Asymmetric encryption: a public key encrypts, a private key decrypts.

`Fortis.rsa()` opens an `RsaBuilder` whose configuration is tracked by phantom
types. Padding and hash each move the builder into a new state, and only
`RsaBuilderReady` exposes `encrypter` and `decrypter` — so a builder missing
either one is a compile error, not a runtime exception.

Keys come as a `FortisRsaKeyPair` of `FortisRsaPublicKey` and
`FortisRsaPrivateKey`, each serializable to PEM, DER or Base64 through the
matching format enum. Generation is asynchronous because it runs off the main
thread wherever `dart:isolate` exists.
