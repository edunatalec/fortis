// Internal constants shared by AES cipher, builder, and padding impls.
//
// Not exported from `package:fortis/fortis.dart`.

/// AES block size in bytes (fixed by the AES spec — always 16).
const aesBlockSize = 16;

/// IV size for modes that use the full block as IV: CBC, CTR, CFB, OFB.
const standardIvSize = aesBlockSize;

/// GCM default IV size (96 bits — NIST SP 800-38D recommended).
const gcmDefaultIvSize = 12;

/// CCM default IV size (11 bytes — allows ~4 GB messages, per RFC 3610).
const ccmDefaultIvSize = 11;

/// GCM/CCM authentication tag size in bytes (128 bits).
const authTagSize = 16;
