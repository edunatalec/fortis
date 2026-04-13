# AES (Advanced Encryption Standard)

AES is the most widely used symmetric encryption algorithm in the world. It is a United States government standard and is adopted globally in virtually all modern security protocols and systems.

## Table of Contents

- [1. What is AES?](#1-what-is-aes)
- [2. History](#2-history)
- [3. How It Works](#3-how-it-works)
- [4. Key Sizes](#4-key-sizes)
- [5. Modes of Operation](#5-modes-of-operation)
  - [5.1 ECB (Electronic Codebook)](#51-ecb-electronic-codebook)
  - [5.2 CBC (Cipher Block Chaining)](#52-cbc-cipher-block-chaining)
  - [5.3 CTR (Counter)](#53-ctr-counter)
  - [5.4 GCM (Galois/Counter Mode)](#54-gcm-galoiscounter-mode)
  - [5.5 CFB (Cipher Feedback)](#55-cfb-cipher-feedback)
  - [5.6 OFB (Output Feedback)](#56-ofb-output-feedback)
  - [5.7 CCM (Counter with CBC-MAC)](#57-ccm-counter-with-cbc-mac)
- [6. Modes of Operation Comparison](#6-modes-of-operation-comparison)
- [7. Padding](#7-padding)
  - [7.1 PKCS#7](#71-pkcs7)
  - [7.2 ISO 7816-4](#72-iso-7816-4)
  - [7.3 Zero Padding](#73-zero-padding)
  - [7.4 No Padding](#74-no-padding)
- [8. Security Considerations](#8-security-considerations)
- [9. References](#9-references)

---

## 1. What is AES?

AES (*Advanced Encryption Standard*) is the most widely used symmetric encryption algorithm in the world. It is a United States government standard, officially published as **FIPS 197** by NIST, and is adopted globally in virtually all modern security protocols and systems — including TLS 1.3, SSH, IPsec, Wi-Fi WPA2, disk encryption (BitLocker, FileVault, LUKS), and many others.

AES is a **block cipher**: it operates on fixed-size data blocks of **128 bits (16 bytes)**, using keys of **128**, **192**, or **256 bits**. It was designed to be efficient in both software and hardware, and remains secure against all known practical attacks.

---

## 2. History

In the 1990s, **DES** (*Data Encryption Standard*), which had been the standard since 1977, was clearly aging. With a key of only 56 bits, it could already be broken by brute force — in 1999, a dedicated machine broke DES in less than 24 hours.

In **January 1997**, NIST (*National Institute of Standards and Technology*) launched an open international call for proposals for a new encryption standard. The process was open and transparent:

- **15 algorithms** were submitted by teams from around the world.
- **5 finalists** were selected: Rijndael, Serpent, Twofish, RC6, and MARS.
- In **October 2000**, NIST announced the winner: **Rijndael**.

Rijndael was developed by two Belgian cryptographers, **Joan Daemen** and **Vincent Rijmen**, from the ESAT/COSIC laboratory at KU Leuven University in Belgium. The choice surprised many observers, who did not expect the American government to adopt a standard created by non-Americans — which demonstrated the seriousness and impartiality of the selection process.

On **November 26, 2001**, AES was officially published as **FIPS 197** by NIST.

---

## 3. How It Works

AES is a **block cipher**: it operates on fixed-size data blocks of **128 bits (16 bytes)**. If the data to be encrypted is larger than 128 bits, a **mode of operation** (section 5) is needed to process multiple blocks.

Internally, AES uses a **substitution-permutation network** (SPN). Data passes through multiple **rounds** of transformation, where each round applies four operations:

1. **SubBytes** — Each byte of the block is replaced by another using a substitution table (S-box). This step introduces **non-linearity**, essential for security.

2. **ShiftRows** — The rows of the state matrix (4×4 bytes) are cyclically shifted. The first row doesn't change, the second is shifted by 1 position, the third by 2 positions, and the fourth by 3 positions. This ensures **diffusion** across columns.

3. **MixColumns** — Each column of the matrix is transformed by matrix multiplication in the GF(2⁸) field. This provides additional **diffusion**, making each output byte depend on all bytes of the input column. (This step is omitted in the last round.)

4. **AddRoundKey** — The block is combined (XOR) with a subkey derived from the main key. Without this step, the previous operations would be just a fixed substitution that could be pre-computed.

---

## 4. Key Sizes

AES supports three key sizes. The main difference is the number of transformation rounds:

| Key Size | Number of Rounds | Security Level |
|---|---|---|
| 128 bits (16 bytes) | 10 | Secure for general use |
| 192 bits (24 bytes) | 12 | Additional security margin |
| 256 bits (32 bytes) | 14 | Maximum — required for classified data by the US government |

All three sizes are considered secure today. **AES-128** is sufficient for the vast majority of use cases. **AES-256** is recommended when extra security margin is desired against possible future advances (including quantum computing, where Grover's algorithm would effectively reduce AES-256's security to ~128 symmetric bits).

---

## 5. Modes of Operation

Since AES operates on 128-bit blocks, a **mode of operation** is needed to encrypt data larger than a single block. Each mode defines how blocks are processed and chained, and each has distinct security and performance properties.

### 5.1 ECB (Electronic Codebook)

**Reference**: NIST SP 800-38A

Each block is encrypted **independently** with the same key. No IV (*Initialization Vector*) is used.

```
Block 1 → AES(key) → Encrypted block 1
Block 2 → AES(key) → Encrypted block 2
Block 3 → AES(key) → Encrypted block 3
```

**INSECURE for most uses.** The main problem is that identical plaintext blocks produce identical ciphertext blocks, which leaks patterns from the original data. The classic example is the "ECB penguin": when encrypting an image with ECB, the silhouette of the original image remains clearly visible in the encrypted result.

ECB is only acceptable in very specific scenarios, such as encrypting a single block of data (for example, a single AES key).

### 5.2 CBC (Cipher Block Chaining)

**Reference**: NIST SP 800-38A

Each plaintext block is combined (XOR) with the **previous ciphertext block** before being encrypted. The first block uses an **IV** (*Initialization Vector*) of 16 bytes.

```
Ciphertext 1 = AES(key, IV ⊕ Block 1)
Ciphertext 2 = AES(key, Ciphertext 1 ⊕ Block 2)
Ciphertext 3 = AES(key, Ciphertext 2 ⊕ Block 3)
```

**Characteristics:**

- The IV must be **random and unpredictable** for each encryption operation.
- Encryption is **sequential** (cannot be parallelized).
- Decryption **can** be parallelized.
- Requires **padding** (since data must be a multiple of the block size).
- Vulnerable to **padding oracle attacks** if not combined with authentication (MAC).

### 5.3 CTR (Counter)

**Reference**: NIST SP 800-38A

Transforms the block cipher into a **stream cipher**. A **nonce** concatenated with a **sequential counter** is encrypted, and the result is combined (XOR) with the plaintext.

```
Keystream 1 = AES(key, nonce || counter_1)    →  Ciphertext 1 = Keystream 1 ⊕ Block 1
Keystream 2 = AES(key, nonce || counter_2)    →  Ciphertext 2 = Keystream 2 ⊕ Block 2
```

**Characteristics:**

- Fully **parallelizable** (both encryption and decryption).
- **No padding required** — operates byte by byte.
- The **nonce must never be reused** with the same key. Reuse completely compromises security.
- Does not provide authentication — only confidentiality.

### 5.4 GCM (Galois/Counter Mode)

**Reference**: NIST SP 800-38D (2007)

GCM combines **CTR** mode (for confidentiality) with **GHASH** authentication (based on multiplication in the Galois field). It is an **AEAD** (*Authenticated Encryption with Associated Data*) mode, meaning it provides **confidentiality and authenticity** simultaneously.

**Characteristics:**

- Produces an **authentication tag** (typically 128 bits) that allows verification of whether data has been tampered with.
- Supports **AAD** (*Additional Authenticated Data*): data that is authenticated but not encrypted (such as protocol headers).
- The recommended nonce/IV is **96 bits (12 bytes)** — different lengths are supported but reduce security.
- Fully **parallelizable**.
- The **nonce must never be reused** with the same key. Nonce reuse in GCM is catastrophic: it allows recovery of the authentication key and message forgery.

GCM is the **recommended mode for most modern applications**. It is used in TLS 1.3, SSH, IPsec, and many other protocols.

### 5.5 CFB (Cipher Feedback)

**Reference**: NIST SP 800-38A

Transforms the block cipher into a **self-synchronizing stream cipher**. The previous ciphertext block (or the IV for the first block) is encrypted, and the result is combined (XOR) with the plaintext.

```
Keystream 1 = AES(key, IV)                →  Ciphertext 1 = Keystream 1 ⊕ Block 1
Keystream 2 = AES(key, Ciphertext 1)      →  Ciphertext 2 = Keystream 2 ⊕ Block 2
```

**Characteristics:**

- Encryption is **sequential**.
- Decryption **can** be parallelized.
- Requires a 16-byte **IV**.
- No padding required.
- Bit errors in ciphertext affect the current block and the next one, then self-correct.

### 5.6 OFB (Output Feedback)

**Reference**: NIST SP 800-38A

Generates a **keystream independent** of the plaintext and ciphertext. The result of encrypting the IV (or the previous keystream) is used as input for the next step, and the keystream is combined (XOR) with the plaintext.

```
Keystream 1 = AES(key, IV)              →  Ciphertext 1 = Keystream 1 ⊕ Block 1
Keystream 2 = AES(key, Keystream 1)     →  Ciphertext 2 = Keystream 2 ⊕ Block 2
```

**Characteristics:**

- Encryption and decryption are **identical** (same XOR operation).
- **Not parallelizable** (neither encryption nor decryption).
- **Bit errors do not propagate** — a corrupted bit in the ciphertext affects only the corresponding bit in the plaintext.
- The **IV must never be reused** with the same key.
- No padding required.

### 5.7 CCM (Counter with CBC-MAC)

**Reference**: NIST SP 800-38C, RFC 3610

CCM combines **CTR** mode (for confidentiality) with **CBC-MAC** (for authentication). Like GCM, it is an **AEAD** mode.

**Characteristics:**

- Requires **two passes** over the data (one for the MAC, another for encryption), unlike GCM which does it in a single pass.
- The nonce size is between **7 and 13 bytes** (default: 11 bytes). There is an inverse relationship: L + N = 15, where L is the field defining the maximum message size and N is the nonce size.
- Supports AAD.
- Widely used in **IEEE 802.11i (Wi-Fi WPA2)** and **Bluetooth**.
- Less efficient than GCM, but may be preferred in hardware-constrained environments.

---

## 6. Modes of Operation Comparison

| Mode | Confidentiality | Authentication | Parallelizable (Encrypt) | Parallelizable (Decrypt) | IV/Nonce | Padding |
|---|---|---|---|---|---|---|
| ECB | Yes | No | Yes | Yes | Not used | Yes |
| CBC | Yes | No | No | Yes | 16 bytes (random) | Yes |
| CTR | Yes | No | Yes | Yes | Nonce (unique) | No |
| **GCM** | **Yes** | **Yes** | **Yes** | **Yes** | **12 bytes (recommended)** | **No** |
| CFB | Yes | No | No | Yes | 16 bytes | No |
| OFB | Yes | No | No | No | 16 bytes (unique) | No |
| **CCM** | **Yes** | **Yes** | **Yes** | **Yes** | **7-13 bytes** | **No** |

> **Recommendation**: for most scenarios, use **GCM**. It provides confidentiality and authentication, is parallelizable, and is the default mode in modern protocols. Use **CCM** when working with constrained hardware or protocols that require it (like WPA2).

---

## 7. Padding

Padding is only necessary for **block modes** (ECB and CBC), where the plaintext must be an exact multiple of 16 bytes (128 bits). Stream modes (CTR, CFB, OFB) and authenticated modes (GCM, CCM) do not require padding.

### 7.1 PKCS#7

**Reference**: RFC 5652

The most widely used and recommended padding scheme. Pads with N bytes, each with the value N (where N is the number of bytes needed to complete the block).

```
Data:     [0x48 0x65 0x6C 0x6C 0x6F]              (5 bytes — "Hello")
Padding:  [0x48 0x65 0x6C 0x6C 0x6F 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B]
                                                    (11 bytes of padding, each = 0x0B)
```

If the data is already a multiple of 16, a **full padding block is added** (16 bytes with value 0x10). This ensures that padding is always **unambiguously reversible**.

### 7.2 ISO 7816-4

**Reference**: ISO/IEC 7816-4

Also called *bit padding*. Pads with byte `0x80` followed by `0x00` bytes until the block is complete.

```
Data:     [0x48 0x65 0x6C 0x6C 0x6F]
Padding:  [0x48 0x65 0x6C 0x6C 0x6F 0x80 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
```

Originally used in **smart card** applications. Also unambiguously reversible, since the `0x80` marker indicates where padding begins.

### 7.3 Zero Padding

Pads with `0x00` bytes until the block is complete.

```
Data:     [0x48 0x65 0x6C 0x6C 0x6F]
Padding:  [0x48 0x65 0x6C 0x6C 0x6F 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
```

**Problem**: if the plaintext ends with `0x00` bytes, it's impossible to distinguish the real bytes from the padding bytes. This makes zero padding **ambiguous for binary data** and not recommended for general use. It may be acceptable when data is known to be exclusively text.

### 7.4 No Padding

No padding is added. The plaintext **must** be an exact multiple of 16 bytes. Otherwise, the operation will fail.

Used with stream modes (CTR, CFB, OFB) and authenticated modes (GCM, CCM), which operate at byte level and do not require block alignment.

### Padding Schemes Comparison

| Scheme | Unambiguously Reversible | When to Use |
|---|---|---|
| PKCS#7 | Yes | **Recommended** for ECB and CBC |
| ISO 7816-4 | Yes | Smart cards or when required by standard |
| Zero Padding | No (binary data) | Text only — legacy use |
| No Padding | N/A | CTR, GCM, CFB, OFB, CCM |

---

## 8. Security Considerations

- **Never reuse a nonce/IV with the same key.** In CTR and GCM, reuse is catastrophic. In CBC, it compromises the confidentiality of initial blocks.
- **Always prefer authenticated modes** (GCM or CCM). Without authentication, an attacker can alter ciphertext in ways that produce predictable changes in the plaintext.
- **Never use ECB** for data larger than one block, as it leaks patterns.
- **Key derivation**: never use a password directly as an AES key. Use key derivation functions like PBKDF2, HKDF, or Argon2 to transform a password into a proper cryptographic key.
- **IV/nonce generation**: always use a cryptographically secure random number generator (CSPRNG).

---

## 9. References

### NIST Standards (FIPS)

- [**FIPS 197**](https://csrc.nist.gov/pubs/fips/197/final) — Advanced Encryption Standard (AES). NIST, 2001 (updated 2023).

### NIST Special Publications (SP)

- [**NIST SP 800-38A**](https://csrc.nist.gov/pubs/sp/800/38/a/final) — Recommendation for Block Cipher Modes of Operation: Methods and Techniques (ECB, CBC, CFB, OFB, CTR). NIST, 2001.
- [**NIST SP 800-38C**](https://csrc.nist.gov/pubs/sp/800/38/c/upd1/final) — Recommendation for Block Cipher Modes of Operation: The CCM Mode for Authentication and Confidentiality. NIST, 2004.
- [**NIST SP 800-38D**](https://csrc.nist.gov/pubs/sp/800/38/d/final) — Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC. NIST, 2007.

### RFCs (IETF)

- [**RFC 5652**](https://datatracker.ietf.org/doc/html/rfc5652) — Cryptographic Message Syntax (CMS). IETF, 2009.
- [**RFC 3610**](https://datatracker.ietf.org/doc/html/rfc3610) — Counter with CBC-MAC (CCM). IETF, 2003.
