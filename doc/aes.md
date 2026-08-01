Symmetric encryption: one key encrypts and decrypts.

`Fortis.aes()` opens an `AesBuilder`, and the mode you pick decides the type
you get back. Block and stream modes produce an `AesStandardCipher` over an
`AesPayload`; the authenticated modes (GCM, CCM) produce an `AesAuthCipher`
over an `AesAuthPayload`, which carries the authentication tag alongside the
ciphertext. The distinction is in the type, not in a runtime flag, so a mode
that cannot authenticate never offers a tag to read.

Keys are `FortisAesKey` — 128, 192 or 256 bits, generated or restored from
bytes, PEM or Base64. IVs and nonces are generated per operation and travel
inside the payload, so there is no second value to store or transmit.
