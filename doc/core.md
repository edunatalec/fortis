The entry point, and the logging every algorithm shares.

`Fortis` is the only class you construct from — `Fortis.aes()`, `Fortis.rsa()`
and `Fortis.ecdh()` each return the builder of one algorithm family, and every
type in the other categories is reached from one of them.

`FortisLog` carries the warnings the algorithms emit when a configuration is
legal but costly, such as generating an RSA key on Flutter web, where
`dart:isolate` is unavailable and the work runs on the main thread.
