# ECDH (Elliptic Curve Diffie-Hellman)

## Table of Contents

- [1. What is ECDH?](#1-what-is-ecdh)
- [2. How It Works](#2-how-it-works)
- [3. Recommended Curves](#3-recommended-curves)
- [4. Why Use a KDF (Key Derivation Function)?](#4-why-use-a-kdf-key-derivation-function)
- [5. ECDH + Symmetric Encryption](#5-ecdh--symmetric-encryption)
- [6. Key Agreement Schemes](#6-key-agreement-schemes)
- [7. Key Formats](#7-key-formats)
- [8. Security Considerations](#8-security-considerations)
- [9. Use Cases](#9-use-cases)
- [10. References](#10-references)

---

## 1. What is ECDH?

### 1.1 Definition

ECDH is a **key agreement protocol** based on elliptic curve cryptography. Unlike RSA (which encrypts data directly), ECDH allows two parties to independently derive the same **shared secret** over an insecure channel. Neither party ever sends the secret -- both compute it from their own private key and the other party's public key.

Analogy: imagine two people each mix a secret color with a shared public color. They exchange the mixtures. Each person then mixes their own secret color with the mixture they received. Both arrive at the same final color -- but an observer who saw only the exchanged mixtures cannot determine the final color. ECDH works on the same principle, but with elliptic curve mathematics instead of colors.

### 1.2 Key Agreement vs Encryption

It is essential to understand that ECDH **does not encrypt data directly**. It produces a shared secret that is then used with a **symmetric algorithm** (like AES) to encrypt data. This is fundamentally different from RSA, which can encrypt data directly (within size limits).

| Characteristic | ECDH | RSA |
|---|---|---|
| Purpose | Key agreement | Encryption and signatures |
| Encrypts data directly? | No | Yes (limited by key size) |
| Output | Shared secret (raw bytes) | Ciphertext |
| Requires symmetric cipher? | Yes, always | No (but hybrid is recommended) |
| Number of participants | Exactly 2 | 1 sender, 1 receiver |

This means ECDH is always used as **part of a larger protocol**: ECDH produces the shared secret, a KDF derives a key from it, and a symmetric cipher (like AES-GCM) encrypts the actual data.

### 1.3 Mathematical Foundation

ECDH's security is based on the **Elliptic Curve Discrete Logarithm Problem (ECDLP)**. An elliptic curve over a finite field is defined by an equation of the form:

```
y^2 = x^3 + ax + b  (mod p)
```

On such a curve, a special operation called **point multiplication** is defined: given a base point G and a scalar d, we can compute Q = d * G (adding G to itself d times using the curve's group law). This operation is efficient to compute.

However, the **reverse problem** -- given Q and G, find d -- is computationally infeasible for large curves. This is the ECDLP. The best known attack is **Pollard's rho algorithm** with O(sqrt(n)) complexity, meaning an n-bit curve provides approximately **n/2 bits of security**.

For comparison, RSA's security is based on integer factorization, where sub-exponential attacks exist (general number field sieve). This is why ECC achieves equivalent security with dramatically smaller key sizes.

---

## 2. How It Works

The ECDH key agreement process follows these steps:

### Step-by-Step

1. **Both parties agree on curve parameters**: an elliptic curve E defined over a finite field, and a base point G of prime order n. These parameters are public and standardized (e.g., NIST P-256).

2. **Party A generates a key pair**:
   - Chooses a random private key d_A in the range [1, n-1].
   - Computes the public key Q_A = d_A * G.

3. **Party B generates a key pair**:
   - Chooses a random private key d_B in the range [1, n-1].
   - Computes the public key Q_B = d_B * G.

4. **They exchange public keys**: Q_A and Q_B are sent over the (possibly insecure) channel. The private keys d_A and d_B are **never transmitted**.

5. **Party A computes the shared secret**:
   - S = d_A * Q_B = d_A * (d_B * G)

6. **Party B computes the shared secret**:
   - S = d_B * Q_A = d_B * (d_A * G)

7. **Both arrive at the same point S**: because scalar multiplication on elliptic curves is associative and commutative, d_A * (d_B * G) = d_B * (d_A * G).

8. **The shared secret** is the x-coordinate of point S.

### Visual Diagram

```
Party A                              Party B
------                              ------
d_A (private)                       d_B (private)
Q_A = d_A * G                      Q_B = d_B * G
        ---- Q_A ---->
        <---- Q_B ----
S = d_A * Q_B                      S = d_B * Q_A
    = d_A * d_B * G                    = d_B * d_A * G
    (same point!)                       (same point!)
```

An eavesdropper who observes Q_A and Q_B cannot compute S without knowing either d_A or d_B. To do so, they would need to solve the ECDLP, which is computationally infeasible for properly sized curves.

### Why It Is Secure

The security comes from the fact that while computing Q = d * G is easy (polynomial time), recovering d from Q and G is hard (exponential time for properly chosen curves). An attacker observing Q_A = d_A * G and Q_B = d_B * G cannot efficiently compute d_A * d_B * G without knowing at least one of the private scalars.

This is formalized as the **Computational Diffie-Hellman (CDH) assumption** on elliptic curves: given G, d_A * G, and d_B * G, it is infeasible to compute d_A * d_B * G.

---

## 3. Recommended Curves

NIST has standardized several elliptic curves for cryptographic use. The following table compares the three primary NIST curves:

| Curve | Field Size | Security Level | ECC Key Size | Equivalent RSA Key | Ratio RSA:ECC |
|---|---|---|---|---|---|
| P-256 (secp256r1) | 256 bits | 128 bits | 256 bits | 3072 bits | 12:1 |
| P-384 (secp384r1) | 384 bits | 192 bits | 384 bits | 7680 bits | 20:1 |
| P-521 (secp521r1) | 521 bits | ~260 bits | 521 bits | 15360 bits | ~29:1 |

The key insight here is that ECC provides **equivalent security at dramatically smaller key sizes**. At 128-bit security, an ECC key is 256 bits versus RSA's 3072 bits -- a 12:1 ratio. This translates to faster computations, less bandwidth, and smaller certificates.

### How to Choose

- **P-256**: the most widely used curve. Provides 128-bit security, which is considered sufficient for most applications today and for the foreseeable future. This is the default choice for TLS 1.3, and it benefits from hardware acceleration on modern processors.

- **P-384**: provides 192-bit security. Used when regulations or compliance requirements demand a higher security margin (e.g., certain government or financial systems).

- **P-521**: provides approximately 260-bit security. Rarely needed in practice -- 128-bit security is already beyond brute-force reach. However, it may be chosen for maximum security margin in long-lived keys.

> **Recommendation**: use **P-256** for general use. It is the most widely supported, the most performant, and provides an ample security margin.

### A Note on Curve25519

While not a NIST curve, **Curve25519** (used via the X25519 key exchange function) deserves mention. Designed by Daniel J. Bernstein, it provides approximately 128-bit security and is widely used in modern protocols (TLS 1.3, Signal, WireGuard). Its design prioritizes resistance to implementation pitfalls and side-channel attacks.

---

## 4. Why Use a KDF (Key Derivation Function)?

The raw shared secret produced by ECDH must **never** be used directly as a cryptographic key. A **Key Derivation Function (KDF)** must always be applied first.

### Reasons

1. **Non-uniform distribution**: the x-coordinate of the shared point is biased by the curve structure. It is not uniformly distributed across all possible bit strings of its length, which means using it directly as a key would introduce subtle weaknesses.

2. **Context binding**: a KDF can bind the derived key to specific context information -- party identifiers, algorithm identifiers, nonces, and session data. This prevents an attacker from reusing a shared secret in a different context.

3. **Key separation**: from a single shared secret, a KDF can derive multiple independent keys for different purposes (e.g., one key for encryption, another for authentication). Without a KDF, using the same raw secret for multiple purposes would create dangerous cross-dependencies.

4. **Forward secrecy support**: when used with ephemeral keys, each session produces independent keying material. The KDF ensures that the derived keys are cryptographically independent even if the shared secrets are related.

### HKDF (RFC 5869)

**HKDF** (HMAC-based Key Derivation Function) is the recommended KDF for use with ECDH. It operates in two phases:

1. **Extract**: takes the non-uniform input keying material (IKM) and an optional salt, and produces a pseudorandom key (PRK):
   ```
   PRK = HMAC-Hash(salt, IKM)
   ```
   The salt should be a random or pseudorandom value. If not available, a string of zeros of length equal to the hash output can be used.

2. **Expand**: takes the PRK and optional context/application-specific information (info), and produces the output keying material (OKM) of the desired length:
   ```
   T(1) = HMAC-Hash(PRK, info || 0x01)
   T(2) = HMAC-Hash(PRK, T(1) || info || 0x02)
   OKM = first L bytes of T(1) || T(2) || ...
   ```

**SHA-256** is the standard hash choice for HKDF. The info parameter should include identifiers for both parties and the intended use of the key.

---

## 5. ECDH + Symmetric Encryption

### 5.1 Recommended Pairing with AES

AES is the natural choice for the symmetric encryption step because it is NIST-approved, benefits from hardware acceleration (AES-NI), is extremely fast, and is universally supported across platforms and languages.

The following table shows the recommended pairing between ECDH curves and AES key sizes, matching their security levels:

| Curve | Recommended AES | Security Match |
|---|---|---|
| P-256 | AES-128 | 128-bit <-> 128-bit |
| P-384 | AES-192 or AES-256 | 192-bit <-> 192/256-bit |
| P-521 | AES-256 | ~260-bit <-> 256-bit |

**AES-GCM** is the recommended mode, as it provides both confidentiality and authentication (AEAD -- Authenticated Encryption with Associated Data). This means it not only encrypts the data but also produces an authentication tag that detects any tampering.

### 5.2 Other Symmetric Algorithms

ECDH is not limited to AES. The shared secret, once processed through a KDF, produces raw key bytes that can be used with **any** symmetric cipher. Other options include:

- **ChaCha20-Poly1305**: a popular alternative to AES-GCM, widely used in TLS 1.3. It is particularly efficient in software on platforms without AES hardware acceleration.
- **Camellia**: a NIST-approved alternative to AES with a similar block cipher structure.
- Any other symmetric cipher that accepts key material of the appropriate length.

The choice of symmetric algorithm is **independent** of ECDH -- the KDF produces raw key bytes that can be fed into any cipher.

### 5.3 Practical Flow

The complete flow from key exchange to encrypted communication:

```
1. Key Exchange (one time):
   App     -> generates (privA, pubA), sends pubA to Backend
   Backend -> generates (privB, pubB), sends pubB to App
   Both derive: sharedSecret = ECDH(myPrivate, theirPublic)
   Both derive: aesKey = HKDF(sharedSecret)

2. Communication (every message):
   Sender:   ciphertext = AES-GCM(aesKey, plaintext)
   Receiver: plaintext  = AES-GCM(aesKey, ciphertext)
```

This is the hybrid encryption pattern: ECDH handles the key agreement (solving the key distribution problem), and AES handles the bulk data encryption (fast, no size limits).

---

## 6. Key Agreement Schemes

NIST SP 800-56A defines several key agreement schemes based on the types of keys used by each party. The distinction is between **ephemeral** keys (generated fresh for each session) and **static** keys (long-lived, stored persistently).

| Scheme | Description | Forward Secrecy |
|---|---|---|
| dhEphem (C(2e, 0s)) | Both parties use ephemeral keys only | Yes |
| dhOneFlow (C(1e, 1s)) | One party ephemeral, one static | Partial |
| dhStatic (C(0e, 2s)) | Both parties use static keys | No |
| dhHybrid1 (C(2e, 2s)) | Both ephemeral and static keys combined | Yes |

### Ephemeral vs Static Keys

- **Ephemeral keys** are generated fresh for each session and destroyed after the shared secret is computed. They provide **forward secrecy**: if a long-term private key is compromised in the future, past sessions remain secure because the ephemeral keys no longer exist.

- **Static keys** are long-lived and reused across sessions. They are simpler to manage (no need to generate new keys for every session) but do **not** provide forward secrecy: if the static private key is compromised, all past sessions using that key can be decrypted.

### Choosing a Scheme

- **dhEphem (C(2e, 0s))**: both parties generate fresh key pairs for each session. This is the strongest option and is used in TLS 1.3. However, it does not provide key confirmation or identity authentication by itself -- those must come from additional mechanisms (e.g., digital signatures on the ephemeral public keys).

- **dhOneFlow (C(1e, 1s))**: one party (typically a server) has a static key, while the other (typically a client) uses an ephemeral key. This provides partial forward secrecy -- if the server's static key is compromised, past sessions are exposed, but if the client's ephemeral key is safe, the current session is protected.

- **dhStatic (C(0e, 2s))**: both parties use static keys. The shared secret is the same for every session between the same two parties. No forward secrecy. Useful only in constrained environments where key generation per session is impractical.

- **dhHybrid1 (C(2e, 2s))**: combines both ephemeral and static keys. The final shared secret incorporates both. Provides forward secrecy and also allows authentication through the static keys.

---

## 7. Key Formats

### 7.1 Public Key Formats

| Format | Description | PEM Header |
|---|---|---|
| X.509 (SubjectPublicKeyInfo) | Standard format with algorithm identifier and curve OID | `BEGIN PUBLIC KEY` |
| Uncompressed Point | Raw bytes: 0x04 || x || y | N/A (raw bytes) |

#### X.509 (SubjectPublicKeyInfo)

This is the standard format for EC public keys, analogous to the X.509 format used for RSA public keys. It wraps the raw public point with an algorithm identifier that specifies both the key type (EC) and the curve.

ASN.1 structure:

```
SEQUENCE {
  SEQUENCE {                    -- AlgorithmIdentifier
    OID 1.2.840.10045.2.1      -- id-ecPublicKey
    OID <curve-oid>             -- namedCurve (e.g., 1.2.840.10045.3.1.7 for P-256)
  }
  BIT STRING <0x04 || x || y>  -- uncompressed point
}
```

PEM encoding:

```
-----BEGIN PUBLIC KEY-----
(Base64-encoded DER data)
-----END PUBLIC KEY-----
```

#### Uncompressed Point Format

The raw public key is represented as a single byte 0x04 (indicating uncompressed format) followed by the x and y coordinates of the point, each padded to the field size:

```
04 || x-coordinate || y-coordinate
```

For P-256, this is 1 + 32 + 32 = 65 bytes. For P-384, it is 1 + 48 + 48 = 97 bytes. For P-521, it is 1 + 66 + 66 = 133 bytes.

### 7.2 Private Key Formats

| Format | Description | PEM Header |
|---|---|---|
| PKCS#8 (PrivateKeyInfo) | Standard generic format with algorithm identifier | `BEGIN PRIVATE KEY` |
| SEC1 (RFC 5915) | EC-specific format with optional curve and public key | `BEGIN EC PRIVATE KEY` |

#### PKCS#8 (PrivateKeyInfo)

The generic private key format, identical in concept to the PKCS#8 format used for RSA. It wraps the EC-specific key data with an algorithm identifier.

```
-----BEGIN PRIVATE KEY-----
(Base64-encoded DER data)
-----END PRIVATE KEY-----
```

Advantages:
- Algorithm-agnostic: the same format is used for RSA, EC, and other key types.
- Supports encryption of the private key itself (EncryptedPrivateKeyInfo).
- Widely supported across platforms and libraries.

#### SEC1 (RFC 5915)

An EC-specific format that contains the private scalar d and optionally includes the curve parameters and the corresponding public key.

ASN.1 structure:

```
SEQUENCE {
  INTEGER 1                        -- version
  OCTET STRING <private-key-d>     -- private key (padded to field size)
  [0] OID <curve-oid>              -- parameters (optional)
  [1] BIT STRING <public-point>    -- publicKey (optional)
}
```

PEM encoding:

```
-----BEGIN EC PRIVATE KEY-----
(Base64-encoded DER data)
-----END EC PRIVATE KEY-----
```

### Format Comparison

| Format | Key Type | EC-Specific? | PEM Header |
|---|---|---|---|
| X.509 | Public only | No (generic) | `BEGIN PUBLIC KEY` |
| Uncompressed Point | Public only | Yes | N/A (raw bytes) |
| PKCS#8 | Private only | No (generic) | `BEGIN PRIVATE KEY` |
| SEC1 | Private only | Yes | `BEGIN EC PRIVATE KEY` |

---

## 8. Security Considerations

1. **Always validate public keys** (mandatory per NIST SP 800-56A Section 5.6.2.3):
   - Verify the point is not the point at infinity.
   - Verify the point lies on the curve (satisfies the curve equation).
   - Verify n * Q = O (the point is in the correct subgroup of prime order).
   - Failure to validate enables **invalid curve attacks**, where an attacker sends a carefully crafted point that lies on a different (weaker) curve, potentially allowing recovery of the private key.

2. **Always apply a KDF**: never use the raw shared secret directly as a cryptographic key. The x-coordinate of the shared point is not uniformly distributed and lacks context binding (see section 4).

3. **Use approved curves only**: P-256, P-384, and P-521 from NIST SP 800-186. Avoid non-standard or deprecated curves.

4. **Use a cryptographically secure RNG**: private keys must be generated using a random number generator compliant with NIST SP 800-90A. Weak randomness completely undermines the security of the protocol -- if an attacker can predict or narrow the private key space, the ECDLP becomes tractable.

5. **Destroy ephemeral private keys**: after computing the shared secret, ephemeral private keys must be destroyed immediately. Retaining them negates the forward secrecy benefit of ephemeral key agreement.

6. **Include context in KDF**: bind derived keys to protocol context via the info parameter of HKDF. This should include party identifiers, algorithm identifiers, and session-specific data to prevent cross-protocol attacks.

7. **Check for zero output**: verify that the shared secret is not the point at infinity (all-zero x-coordinate). A zero shared secret indicates a **small-subgroup attack** and the key exchange must be aborted.

8. **Match security levels**: use consistent security levels across all components. Do not pair P-256 (128-bit security) with AES-256 (256-bit security) -- the overall security is limited by the weakest link. P-256 should be paired with AES-128, P-384 with AES-192 or AES-256, and P-521 with AES-256.

---

## 9. Use Cases

ECDH (and its ephemeral variant ECDHE) is used in virtually all modern security protocols:

- **TLS 1.3** (RFC 8446): ECDHE is mandatory for key exchange. Static RSA key transport was removed entirely in TLS 1.3. Supported groups include x25519, secp256r1, secp384r1, and secp521r1.

- **Signal Protocol**: uses X25519 (Curve25519-based Diffie-Hellman) for X3DH (Extended Triple Diffie-Hellman) initial key agreement and for the ongoing Double Ratchet DH ratchet that provides forward secrecy for each message.

- **WireGuard VPN**: uses X25519 for its Noise_IKpsk2 handshake pattern, establishing a secure tunnel with minimal round trips.

- **SSH** (RFC 5656, RFC 8731): ECDH key exchange with NIST curves (ecdh-sha2-nistp256, ecdh-sha2-nistp384, ecdh-sha2-nistp521) and curve25519 (curve25519-sha256).

- **ECIES** (Elliptic Curve Integrated Encryption Scheme): combines ECDH + KDF + symmetric encryption + MAC into a complete hybrid encryption scheme. Defined in SEC 1 Section 5.1. This is useful when one party has a static public key and the other wants to encrypt a message to them without prior interaction.

- **Password vaults and secure apps**: bidirectional communication between a mobile app and a backend using ECDH for key agreement combined with AES for data encryption. The app and backend exchange public keys once, derive a shared symmetric key, and then encrypt all subsequent communication with AES-GCM.

---

## 10. References

### NIST Standards

- [**NIST SP 800-56A Rev. 3**](https://csrc.nist.gov/pubs/sp/800/56/a/r3/final) -- Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography. NIST, 2018.
- [**NIST SP 800-186**](https://csrc.nist.gov/pubs/sp/800/186/final) -- Recommendations for Discrete Logarithm-based Cryptography: Elliptic Curve Domain Parameters. NIST, 2023.
- [**FIPS 186-5**](https://csrc.nist.gov/pubs/fips/186-5/final) -- Digital Signature Standard (DSS). NIST, 2023.
- [**NIST SP 800-57 Part 1 Rev. 5**](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) -- Recommendation for Key Management: Part 1 -- General. NIST, 2020.
- [**NIST SP 800-90A Rev. 1**](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final) -- Recommendation for Random Number Generation Using Deterministic Random Bit Generators. NIST, 2015.

### RFCs (IETF)

- [**RFC 6090**](https://datatracker.ietf.org/doc/html/rfc6090) -- Fundamental Elliptic Curve Cryptography Algorithms. IETF, 2011.
- [**RFC 5869**](https://datatracker.ietf.org/doc/html/rfc5869) -- HMAC-based Extract-and-Expand Key Derivation Function (HKDF). IETF, 2010.
- [**RFC 7748**](https://datatracker.ietf.org/doc/html/rfc7748) -- Elliptic Curves for Security. IETF, 2016.
- [**RFC 5915**](https://datatracker.ietf.org/doc/html/rfc5915) -- Elliptic Curve Private Key Structure. IETF, 2010.
- [**RFC 8446**](https://datatracker.ietf.org/doc/html/rfc8446) -- The Transport Layer Security (TLS) Protocol Version 1.3. IETF, 2018.
- [**RFC 5656**](https://datatracker.ietf.org/doc/html/rfc5656) -- Elliptic Curve Algorithm Integration in the Secure Shell Transport Layer. IETF, 2009.

### Industry Standards

- [**SEC 1 v2**](https://www.secg.org/sec1-v2.pdf) -- Elliptic Curve Cryptography. SECG, 2009.
- [**SEC 2 v2**](https://www.secg.org/sec2-v2.pdf) -- Recommended Elliptic Curve Domain Parameters. SECG, 2010.
