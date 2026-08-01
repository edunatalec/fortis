Key agreement: two parties derive the same secret without transmitting it.

`Fortis.ecdh()` opens an `EcdhBuilder` over a NIST curve — P-256, P-384 or
P-521, named by `EcdhCurve`. Each side generates a `FortisEcdhKeyPair`,
exchanges only the `FortisEcdhPublicKey`, and `EcdhKeyDerivation` turns the
pair of one side and the public key of the other into the shared secret.

The common ending is `deriveAesKey`, which runs the secret through HKDF-SHA256
and hands back a `FortisAesKey` ready for any AES cipher — which is why ECDH
and AES are usually used together: ECDH agrees on the key, AES moves the data.
