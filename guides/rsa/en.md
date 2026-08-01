# RSA (Rivest-Shamir-Adleman)

## Table of Contents

- [1. What is RSA?](#1-what-is-rsa)
- [2. History](#2-history)
- [3. How It Works](#3-how-it-works)
- [4. Key Sizes](#4-key-sizes)
- [5. Padding Schemes](#5-padding-schemes)
- [6. Hash Algorithms Used with RSA](#6-hash-algorithms-used-with-rsa)
- [7. Key Formats](#7-key-formats)
- [8. Security Considerations](#8-security-considerations)
- [9. References](#9-references)

---

## 1. What is RSA?

RSA is the most well-known and widely used asymmetric encryption algorithm. It can be used for both **encryption** and **digital signatures**.

---

## 2. History

In **1977**, three MIT researchers — **Ron Rivest**, **Adi Shamir**, and **Leonard Adleman** — published the first practical public-key cryptosystem. Rivest and Shamir, both computer scientists, proposed candidate functions, while Adleman, a mathematician, tried to break them. After 42 failed attempts, in April 1977, Rivest formalized the idea that would become RSA.

The algorithm was published in **Scientific American** magazine in 1977 and quickly became the standard for public-key cryptography. The US patent for RSA expired in **September 2000**, making it free to use worldwide.

The name "RSA" comes from the initials of the three creators' surnames: **R**ivest, **S**hamir, and **A**dleman.

---

## 3. How It Works

RSA's security is based on a mathematical problem: the **difficulty of factoring the product of two very large prime numbers**. Multiplying two primes is fast, but given only the result, finding the original factors is computationally infeasible for sufficiently large numbers.

### Key Generation

1. Choose two large prime numbers **p** and **q** (each with hundreds of digits).
2. Compute **n = p × q** (the modulus). This value is public.
3. Compute **φ(n) = (p − 1) × (q − 1)** (Euler's totient function).
4. Choose a public exponent **e**, coprime to φ(n). The most commonly used value is **e = 65537** (0x10001), chosen because it is prime and has few active bits (efficient for exponentiation).
5. Compute the private exponent **d = e⁻¹ mod φ(n)** (the modular inverse of e).

- **Public key**: (n, e)
- **Private key**: (n, d)

### Encryption and Decryption

- **Encrypt**: c = m^e mod n (where m is the numeric message and c is the ciphertext)
- **Decrypt**: m = c^d mod n

Security relies on the fact that, without knowing p and q (which compose d), it is computationally infeasible to calculate d from only (n, e).

---

## 4. Key Sizes

The RSA key size (in bits) refers to the size of the modulus **n**. Larger keys offer more security but are slower.

The table below shows the equivalence between RSA key size and equivalent security in symmetric bits, according to **NIST SP 800-57 Part 1 Rev. 5**:

| RSA Key Size | Equivalent Security (symmetric bits) | Status |
|---|---|---|
| 1024 bits | ~80 bits | **Obsolete** — do not use |
| 2048 bits | ~112 bits | Currently recommended minimum |
| 3072 bits | ~128 bits | Good security margin |
| 4096 bits | ~140 bits | High security |
| 7680 bits | ~192 bits | Very high security |
| 15360 bits | ~256 bits | Maximum security (rare in practice) |

> **Recommendation**: use at least **2048 bits**. For long-term security, prefer **4096 bits**. Note that generating 4096-bit keys can be significantly slower.

The key size also limits the **maximum data size** that can be directly encrypted (detailed in section 5).

---

## 5. Padding Schemes

In RSA, the plaintext message needs to be transformed into a number between 0 and n−1 before encryption. **Padding** (or encoding scheme) is the process that performs this transformation securely. Encrypting without padding (called "textbook RSA") is extremely insecure.

### 5.1 PKCS#1 v1.5

**Reference**: RFC 8017 (consolidation), originally RFC 2313

The oldest and still widely found scheme. The encoded message format is:

```
0x00 || 0x02 || PS || 0x00 || M
```

Where:
- `PS` is padding of **random non-zero bytes** with at least 8 bytes.
- `M` is the original message.

The maximum message size is: **mLen ≤ k − 11** bytes (where k is the key size in bytes).

**Vulnerability**: in 1998, Daniel Bleichenbacher demonstrated an attack (*Bleichenbacher's attack*, also called the "million message attack") that exploits servers that reveal whether the padding of a decrypted message is valid or not. This type of *padding oracle* allows an attacker to decrypt messages without the private key, by sending millions of modified ciphertexts and observing the server's responses. Variants of this attack continued to be exploitable in 2018 (ROBOT) and 2023 (Marvin Attack).

**PKCS#1 v1.5 is maintained only for compatibility with legacy systems. It should not be used in new projects.**

### 5.2 OAEP (Optimal Asymmetric Encryption Padding)

OAEP was proposed by **Bellare and Rogaway** in 1994 as a provably secure alternative to PKCS#1 v1.5. It uses a structure similar to a **two-round Feistel network** combined with hash functions and an **MGF** (*Mask Generation Function*).

The EME-OAEP encoding process (as per RFC 8017) works as follows:

1. Hash the **label** L (by default, an empty string) to obtain `lHash`.
2. Create the data block: `DB = lHash || PS || 0x01 || M` (where PS are zero padding bytes).
3. Generate a **random seed** of length equal to the hash.
4. Compute `dbMask = MGF1(seed, length_of_DB)`.
5. Compute `maskedDB = DB ⊕ dbMask`.
6. Compute `seedMask = MGF1(maskedDB, hash_length)`.
7. Compute `maskedSeed = seed ⊕ seedMask`.
8. The final encoded message is: `EM = 0x00 || maskedSeed || maskedDB`.

The maximum message size is: **mLen ≤ k − 2·hLen − 2** bytes (where hLen is the hash output size in bytes).

### OAEP Versions

| Version | Reference | Details |
|---|---|---|
| OAEP v1 | Bellare-Rogaway (1994) | Original proposal with SHA-1 |
| OAEP v2.0 | PKCS#1 v2.0 (RFC 2437) | Incorporation into PKCS#1 standard with MGF1 |
| OAEP v2.1 | PKCS#1 v2.1 (RFC 3447) / v2.2 (RFC 8017) | **Recommended** — configurable hash, MGF1, label support |

> **Recommendation**: always use **OAEP v2.1** (or later) with **SHA-256** or higher. As per RFC 8017: *"RSAES-OAEP is required to be supported for new applications"*.

---

## 6. Hash Algorithms Used with RSA

Hash functions are used in RSA in several contexts:

- **OAEP padding**: the hash function is used to generate `lHash` and as the basis for MGF1.
- **Digital signatures**: the message is hashed before being signed (*hash-then-sign*).
- **Key fingerprints**: summarized identification of public keys.

The choice of hash directly affects the **maximum message size** in OAEP (since `hLen` enters the formula `k − 2·hLen − 2`).

| Algorithm | Output Size (hLen) | Status with RSA | Max Message (RSA-2048) |
|---|---|---|---|
| SHA-1 | 20 bytes | Legacy — avoid | 214 bytes |
| SHA-224 | 28 bytes | Valid, rarely used | 198 bytes |
| SHA-256 | 32 bytes | **Recommended** (default) | 190 bytes |
| SHA-384 | 48 bytes | High security | 158 bytes |
| SHA-512 | 64 bytes | High security | 126 bytes |
| SHA3-256 | 32 bytes | Modern alternative | 190 bytes |
| SHA3-512 | 64 bytes | Modern alternative | 126 bytes |

> **Note**: the "Max Message" column assumes RSA-2048 (k = 256 bytes) and OAEP. Formula: k − 2·hLen − 2.

---

## 7. Key Formats

RSA keys can be stored and transmitted in different standardized formats. Each format has a specific purpose.

### 7.1 PKCS#1

Format **specific to RSA**. Contains only the RSA mathematical parameters.

- **Public key**: contains (n, e).
- **Private key**: contains (n, e, d, p, q, dP, dQ, qInv).
- Encoding: ASN.1 DER, typically wrapped in PEM.

```
-----BEGIN RSA PUBLIC KEY-----
(Base64-encoded data)
-----END RSA PUBLIC KEY-----

-----BEGIN RSA PRIVATE KEY-----
(Base64-encoded data)
-----END RSA PRIVATE KEY-----
```

### 7.2 PKCS#8 (PrivateKeyInfo)

**Reference**: RFC 5958

**Generic** format (not RSA-specific) for private keys. Encapsulates the key with an algorithm identifier, allowing distinction between keys from different algorithms.

```
-----BEGIN PRIVATE KEY-----
(Base64-encoded data)
-----END PRIVATE KEY-----
```

Advantages:
- Supports encryption of the private key itself (`EncryptedPrivateKeyInfo`).
- Portability across different algorithms.

### 7.3 X.509 (SubjectPublicKeyInfo)

**Reference**: RFC 5280

**Generic** format for public keys, widely used in digital certificates. Encapsulates the public key with an algorithm identifier.

```
-----BEGIN PUBLIC KEY-----
(Base64-encoded data)
-----END PUBLIC KEY-----
```

### Format Comparison

| Format | Key Type | RSA-Specific? | PEM Header |
|---|---|---|---|
| PKCS#1 | Public and Private | Yes | `BEGIN RSA PUBLIC KEY` / `BEGIN RSA PRIVATE KEY` |
| PKCS#8 | Private only | No (generic) | `BEGIN PRIVATE KEY` |
| X.509 | Public only | No (generic) | `BEGIN PUBLIC KEY` |

---

## 8. Security Considerations

- **Minimum key size**: use at least **2048 bits**. 1024-bit keys are considered obsolete.
- **Always use OAEP**: avoid PKCS#1 v1.5 for encryption in new projects due to the Bleichenbacher vulnerability.
- **Do not encrypt large data directly**: RSA is limited by key size. For larger data, use hybrid cryptography.
- **Prime generation**: the quality of the random number generator is critical. Predictable primes completely compromise security.
- **Quantum threat**: **Shor's algorithm** allows a sufficiently large quantum computer to factor integers in polynomial time, which would break RSA. Although quantum computers of this capability do not yet exist, sensitive organizations are already planning migration to post-quantum algorithms (such as those selected by NIST: CRYSTALS-Kyber for encryption and CRYSTALS-Dilithium for signatures).

---

## 9. References

- [RFC 8017 — PKCS#1 v2.2](https://datatracker.ietf.org/doc/html/rfc8017)
- [RFC 3447 — PKCS#1 v2.1](https://datatracker.ietf.org/doc/html/rfc3447)
- [RFC 2437 — PKCS#1 v2.0](https://datatracker.ietf.org/doc/html/rfc2437)
- [RFC 5958 — PKCS#8](https://datatracker.ietf.org/doc/html/rfc5958)
- [RFC 5280 — X.509](https://datatracker.ietf.org/doc/html/rfc5280)
- [NIST SP 800-57 — Recommendation for Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
