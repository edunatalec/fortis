# Cryptography

A comprehensive guide on cryptography, covering fundamental concepts through to technical details of the main cryptographic algorithms.

## Table of Contents

- [1. What is Cryptography](#1-what-is-cryptography)
- [2. Symmetric vs Asymmetric Cryptography](#2-symmetric-vs-asymmetric-cryptography)
- [3. Hash Functions](#3-hash-functions)
- [4. AES (Advanced Encryption Standard)](#4-aes-advanced-encryption-standard)
- [5. RSA (Rivest-Shamir-Adleman)](#5-rsa-rivest-shamir-adleman)
- [6. When to Use AES vs RSA](#6-when-to-use-aes-vs-rsa)
- [7. References](#7-references)

---

## 1. What is Cryptography

### 1.1 Definition

The word **cryptography** comes from the Greek: *kryptós* (hidden, secret) and *gráphein* (writing). In simple terms, cryptography is the science of transforming readable information into something incomprehensible, so that only those who possess the correct "key" can reverse the process and read the original information.

Think of a safe: anyone can see the safe, but only the person who has the key (or the combination) can open it and access what's inside. Cryptography works the same way — it "locks" your data so that only authorized recipients can "unlock" and read it.

### 1.2 Why Cryptography Matters

Cryptography supports four fundamental pillars of information security:

- **Confidentiality**: ensures that only authorized people can read the data. Example: when you access your bank on your phone, cryptography prevents someone from intercepting your financial information.
- **Integrity**: ensures that data has not been altered during transit. If someone modifies an encrypted message, the recipient can detect the tampering.
- **Authentication**: confirms the identity of the data sender. Digital certificates, for example, use cryptography to prove that a website is really who it claims to be.
- **Non-repudiation**: prevents the author from denying they sent a message. Digital signatures provide mathematical proof of authorship.

In everyday life, cryptography is present in virtually everything:

- **HTTPS**: the padlock in the browser indicates that communication with the website is encrypted.
- **Messaging apps**: applications like WhatsApp and Signal use end-to-end encryption.
- **Online banking**: all transactions are protected by multiple cryptographic layers.
- **Wi-Fi**: the WPA2/WPA3 protocol encrypts your wireless network traffic.

### 1.3 Fundamental Concepts

Before moving forward, it's important to understand some terms that will be used throughout this document:

- **Plaintext**: the original, readable information. Example: the message "Hello, world!".
- **Ciphertext**: the result of encryption — scrambled, unreadable data. Example: `a7f3b2c9e1d8...`.
- **Key**: a secret value used to encrypt and/or decrypt data. The larger the key, the harder it is to break the encryption.
- **Encrypt**: the process of transforming plaintext into ciphertext using an algorithm and a key.
- **Decrypt**: the reverse process — transforming ciphertext back into plaintext using the correct key.
- **Algorithm**: the mathematical procedure that defines how data is encrypted and decrypted. Examples: AES, RSA.

---

## 2. Symmetric vs Asymmetric Cryptography

There are two major categories of cryptography. Understanding the difference between them is essential to knowing when and how to use each one.

### 2.1 Symmetric Cryptography

In symmetric cryptography, **the same key** is used for both encryption and decryption.

Analogy: imagine a door with a regular lock. The same key that locks it also unlocks it. If you want someone else to open the door, you need to give them a copy of the key.

**Advantages:**

- Extremely fast — ideal for large volumes of data.
- Efficient algorithms that can be hardware-accelerated.

**Main disadvantage:**

- The **key distribution problem**: how do you securely deliver the key to the recipient? If someone intercepts the key during the exchange, the entire communication is compromised.

The most widely used symmetric algorithm today is **AES** (detailed in section 4).

### 2.2 Asymmetric Cryptography

In asymmetric cryptography, **two mathematically related keys** are used: a **public key** and a **private key**.

- The **public key** can be freely shared with anyone.
- The **private key** must be kept absolutely secret.

What one key encrypts, only the other can decrypt.

Analogy: imagine a public mailbox. Anyone can drop a letter through the slot (encrypt with the public key), but only the owner of the mailbox, who has the key to the lock, can open and read the letters (decrypt with the private key).

**Advantages:**

- Solves the key distribution problem — the public key can be sent openly.
- Enables digital signatures and certificates.

**Disadvantages:**

- Significantly slower than symmetric cryptography.
- The size of data that can be encrypted is limited by the key size.

The most widely used asymmetric algorithm is **RSA** (detailed in section 5).

### 2.3 Direct Comparison

| Characteristic | Symmetric | Asymmetric |
|---|---|---|
| Number of keys | 1 (shared) | 2 (public + private) |
| Speed | Fast | Slow |
| Data size | Unlimited | Limited by key size |
| Key distribution | Problematic (requires secure channel) | Simplified (public key is open) |
| Typical use | Bulk data encryption | Key exchange, digital signatures |
| Algorithm example | AES | RSA |

### 2.4 Hybrid Cryptography

In practice, both types are used **together** in a model called **hybrid cryptography**. This is the model used by virtually all modern security protocols (TLS/HTTPS, PGP, S/MIME).

How it works:

1. A **random symmetric key** (called a session key) is generated.
2. The **data is encrypted** with this symmetric key (fast, no size limit).
3. The **symmetric key is encrypted** with the recipient's RSA public key (solves distribution).
4. The recipient uses their **RSA private key** to decrypt the symmetric key.
5. With the recovered symmetric key, the recipient **decrypts the data**.

This way, you get the best of both worlds: the speed of symmetric cryptography and the secure key exchange of asymmetric cryptography.

---

## 3. Hash Functions

Hash functions are frequently used alongside encryption algorithms (for example, in RSA's OAEP padding and in AES GCM authentication). Therefore, it's important to understand them before diving into AES and RSA details.

### 3.1 What is a Hash Function

A **cryptographic hash function** is a mathematical function that takes an input of any size and produces a fixed-size output, called a **digest** or **hash**. The operation is **one-way**: it is computationally infeasible to recover the original input from the hash.

Analogy: think of a fingerprint. Each person has a unique fingerprint that identifies them, but by looking at the fingerprint, you cannot reconstruct the entire person. Similarly, the hash is a "fingerprint" of the data.

### 3.2 Essential Properties

A good cryptographic hash function must have:

- **Determinism**: the same input always produces the same hash.
- **Avalanche effect**: a minimal change in the input (even a single bit) generates a completely different hash.
- **Pre-image resistance**: given a hash, it is infeasible to find an input that produces that hash.
- **Second pre-image resistance**: given an input, it is infeasible to find another different input that produces the same hash.
- **Collision resistance**: it is infeasible to find two distinct inputs that produce the same hash.

### 3.3 Hash Algorithms

#### SHA-1 (Secure Hash Algorithm 1)

| Property | Value |
|---|---|
| Output size | 160 bits (20 bytes) |
| Internal block size | 512 bits |
| Status | **DEPRECATED** |

SHA-1 was widely used for decades, but in 2017, researchers from Google and CWI Amsterdam demonstrated the first practical collision (SHAttered attack), proving that two different inputs could produce the same SHA-1 hash. Since then, SHA-1 is considered **insecure** and should not be used in new systems. It is still found in legacy systems for compatibility reasons.

#### SHA-2 (Family)

The SHA-2 family, standardized by NIST in FIPS 180-4, is the current standard and widely used:

| Variant | Output Size | Internal Block Size | Common Use |
|---|---|---|---|
| SHA-224 | 224 bits (28 bytes) | 512 bits | Rarely used, compatibility |
| SHA-256 | 256 bits (32 bytes) | 512 bits | **Recommended standard** for general use |
| SHA-384 | 384 bits (48 bytes) | 1024 bits | High security |
| SHA-512 | 512 bits (64 bytes) | 1024 bits | High security, efficient on 64-bit |

**SHA-256** is the most common and recommended choice for most scenarios, offering a good balance between security and performance.

#### SHA-3 (Family)

SHA-3 was standardized by NIST in 2015 (FIPS 202) and is based on the **Keccak** algorithm, which uses a completely different internal construction from SHA-2 (called *sponge construction*). It is **not a replacement** for SHA-2 (which remains secure), but rather an **alternative** with a distinct architecture, offering cryptographic diversity.

| Variant | Output Size | Internal Block Size (rate) |
|---|---|---|
| SHA3-256 | 256 bits (32 bytes) | 1088 bits |
| SHA3-512 | 512 bits (64 bytes) | 576 bits |

### 3.4 Applications of Hash Functions

- **Integrity verification**: checking if a file was corrupted or tampered with during download.
- **Password storage**: the hash of the password is stored, not the password itself. (In practice, specialized functions like Argon2, bcrypt, or PBKDF2 are used, which add *salt* and are deliberately slow.)
- **Digital signatures**: the document is first hashed and then the hash is signed with the private key (*hash-then-sign*).
- **HMAC**: *Hash-based Message Authentication Code* — combines a secret key with the hash to verify authenticity and integrity simultaneously.
- **OAEP padding**: the RSA OAEP padding scheme uses hash functions internally (detailed in section 5.4).

---

## 4. AES (Advanced Encryption Standard)

AES is the most widely used symmetric encryption algorithm in the world. It is a United States government standard and is adopted globally in virtually all modern security protocols and systems.

### 4.1 History

In the 1990s, **DES** (*Data Encryption Standard*), which had been the standard since 1977, was clearly aging. With a key of only 56 bits, it could already be broken by brute force — in 1999, a dedicated machine broke DES in less than 24 hours.

In **January 1997**, NIST (*National Institute of Standards and Technology*) launched an open international call for proposals for a new encryption standard. The process was open and transparent:

- **15 algorithms** were submitted by teams from around the world.
- **5 finalists** were selected: Rijndael, Serpent, Twofish, RC6, and MARS.
- In **October 2000**, NIST announced the winner: **Rijndael**.

Rijndael was developed by two Belgian cryptographers, **Joan Daemen** and **Vincent Rijmen**, from the ESAT/COSIC laboratory at KU Leuven University in Belgium. The choice surprised many observers, who did not expect the American government to adopt a standard created by non-Americans — which demonstrated the seriousness and impartiality of the selection process.

On **November 26, 2001**, AES was officially published as **FIPS 197** by NIST.

### 4.2 How It Works

AES is a **block cipher**: it operates on fixed-size data blocks of **128 bits (16 bytes)**. If the data to be encrypted is larger than 128 bits, a **mode of operation** (section 4.4) is needed to process multiple blocks.

Internally, AES uses a **substitution-permutation network** (SPN). Data passes through multiple **rounds** of transformation, where each round applies four operations:

1. **SubBytes** — Each byte of the block is replaced by another using a substitution table (S-box). This step introduces **non-linearity**, essential for security.

2. **ShiftRows** — The rows of the state matrix (4×4 bytes) are cyclically shifted. The first row doesn't change, the second is shifted by 1 position, the third by 2 positions, and the fourth by 3 positions. This ensures **diffusion** across columns.

3. **MixColumns** — Each column of the matrix is transformed by matrix multiplication in the GF(2⁸) field. This provides additional **diffusion**, making each output byte depend on all bytes of the input column. (This step is omitted in the last round.)

4. **AddRoundKey** — The block is combined (XOR) with a subkey derived from the main key. Without this step, the previous operations would be just a fixed substitution that could be pre-computed.

### 4.3 Key Sizes

AES supports three key sizes. The main difference is the number of transformation rounds:

| Key Size | Number of Rounds | Security Level |
|---|---|---|
| 128 bits (16 bytes) | 10 | Secure for general use |
| 192 bits (24 bytes) | 12 | Additional security margin |
| 256 bits (32 bytes) | 14 | Maximum — required for classified data by the US government |

All three sizes are considered secure today. **AES-128** is sufficient for the vast majority of use cases. **AES-256** is recommended when extra security margin is desired against possible future advances (including quantum computing, where Grover's algorithm would effectively reduce AES-256's security to ~128 symmetric bits).

### 4.4 Modes of Operation

Since AES operates on 128-bit blocks, a **mode of operation** is needed to encrypt data larger than a single block. Each mode defines how blocks are processed and chained, and each has distinct security and performance properties.

#### 4.4.1 ECB (Electronic Codebook)

**Reference**: NIST SP 800-38A

Each block is encrypted **independently** with the same key. No IV (*Initialization Vector*) is used.

```
Block 1 → AES(key) → Encrypted block 1
Block 2 → AES(key) → Encrypted block 2
Block 3 → AES(key) → Encrypted block 3
```

**INSECURE for most uses.** The main problem is that identical plaintext blocks produce identical ciphertext blocks, which leaks patterns from the original data. The classic example is the "ECB penguin": when encrypting an image with ECB, the silhouette of the original image remains clearly visible in the encrypted result.

ECB is only acceptable in very specific scenarios, such as encrypting a single block of data (for example, a single AES key).

#### 4.4.2 CBC (Cipher Block Chaining)

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

#### 4.4.3 CTR (Counter)

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

#### 4.4.4 GCM (Galois/Counter Mode)

**Reference**: NIST SP 800-38D (2007)

GCM combines **CTR** mode (for confidentiality) with **GHASH** authentication (based on multiplication in the Galois field). It is an **AEAD** (*Authenticated Encryption with Associated Data*) mode, meaning it provides **confidentiality and authenticity** simultaneously.

**Characteristics:**

- Produces an **authentication tag** (typically 128 bits) that allows verification of whether data has been tampered with.
- Supports **AAD** (*Additional Authenticated Data*): data that is authenticated but not encrypted (such as protocol headers).
- The recommended nonce/IV is **96 bits (12 bytes)** — different lengths are supported but reduce security.
- Fully **parallelizable**.
- The **nonce must never be reused** with the same key. Nonce reuse in GCM is catastrophic: it allows recovery of the authentication key and message forgery.

GCM is the **recommended mode for most modern applications**. It is used in TLS 1.3, SSH, IPsec, and many other protocols.

#### 4.4.5 CFB (Cipher Feedback)

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

#### 4.4.6 OFB (Output Feedback)

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

#### 4.4.7 CCM (Counter with CBC-MAC)

**Reference**: NIST SP 800-38C, RFC 3610

CCM combines **CTR** mode (for confidentiality) with **CBC-MAC** (for authentication). Like GCM, it is an **AEAD** mode.

**Characteristics:**

- Requires **two passes** over the data (one for the MAC, another for encryption), unlike GCM which does it in a single pass.
- The nonce size is between **7 and 13 bytes** (default: 11 bytes). There is an inverse relationship: L + N = 15, where L is the field defining the maximum message size and N is the nonce size.
- Supports AAD.
- Widely used in **IEEE 802.11i (Wi-Fi WPA2)** and **Bluetooth**.
- Less efficient than GCM, but may be preferred in hardware-constrained environments.

### 4.5 Modes of Operation Comparison

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

### 4.6 Padding

Padding is only necessary for **block modes** (ECB and CBC), where the plaintext must be an exact multiple of 16 bytes (128 bits). Stream modes (CTR, CFB, OFB) and authenticated modes (GCM, CCM) do not require padding.

#### 4.6.1 PKCS#7

**Reference**: RFC 5652

The most widely used and recommended padding scheme. Pads with N bytes, each with the value N (where N is the number of bytes needed to complete the block).

```
Data:     [0x48 0x65 0x6C 0x6C 0x6F]              (5 bytes — "Hello")
Padding:  [0x48 0x65 0x6C 0x6C 0x6F 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B]
                                                    (11 bytes of padding, each = 0x0B)
```

If the data is already a multiple of 16, a **full padding block is added** (16 bytes with value 0x10). This ensures that padding is always **unambiguously reversible**.

#### 4.6.2 ISO 7816-4

**Reference**: ISO/IEC 7816-4

Also called *bit padding*. Pads with byte `0x80` followed by `0x00` bytes until the block is complete.

```
Data:     [0x48 0x65 0x6C 0x6C 0x6F]
Padding:  [0x48 0x65 0x6C 0x6C 0x6F 0x80 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
```

Originally used in **smart card** applications. Also unambiguously reversible, since the `0x80` marker indicates where padding begins.

#### 4.6.3 Zero Padding

Pads with `0x00` bytes until the block is complete.

```
Data:     [0x48 0x65 0x6C 0x6C 0x6F]
Padding:  [0x48 0x65 0x6C 0x6C 0x6F 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
```

**Problem**: if the plaintext ends with `0x00` bytes, it's impossible to distinguish the real bytes from the padding bytes. This makes zero padding **ambiguous for binary data** and not recommended for general use. It may be acceptable when data is known to be exclusively text.

#### 4.6.4 No Padding

No padding is added. The plaintext **must** be an exact multiple of 16 bytes. Otherwise, the operation will fail.

Used with stream modes (CTR, CFB, OFB) and authenticated modes (GCM, CCM), which operate at byte level and do not require block alignment.

#### Padding Schemes Comparison

| Scheme | Unambiguously Reversible | When to Use |
|---|---|---|
| PKCS#7 | Yes | **Recommended** for ECB and CBC |
| ISO 7816-4 | Yes | Smart cards or when required by standard |
| Zero Padding | No (binary data) | Text only — legacy use |
| No Padding | N/A | CTR, GCM, CFB, OFB, CCM |

### 4.7 Security Considerations

- **Never reuse a nonce/IV with the same key.** In CTR and GCM, reuse is catastrophic. In CBC, it compromises the confidentiality of initial blocks.
- **Always prefer authenticated modes** (GCM or CCM). Without authentication, an attacker can alter ciphertext in ways that produce predictable changes in the plaintext.
- **Never use ECB** for data larger than one block, as it leaks patterns.
- **Key derivation**: never use a password directly as an AES key. Use key derivation functions like PBKDF2, HKDF, or Argon2 to transform a password into a proper cryptographic key.
- **IV/nonce generation**: always use a cryptographically secure random number generator (CSPRNG).

---

## 5. RSA (Rivest-Shamir-Adleman)

RSA is the most well-known and widely used asymmetric encryption algorithm. It can be used for both **encryption** and **digital signatures**.

### 5.1 History

In **1977**, three MIT researchers — **Ron Rivest**, **Adi Shamir**, and **Leonard Adleman** — published the first practical public-key cryptosystem. Rivest and Shamir, both computer scientists, proposed candidate functions, while Adleman, a mathematician, tried to break them. After 42 failed attempts, in April 1977, Rivest formalized the idea that would become RSA.

The algorithm was published in **Scientific American** magazine in 1977 and quickly became the standard for public-key cryptography. The US patent for RSA expired in **September 2000**, making it free to use worldwide.

The name "RSA" comes from the initials of the three creators' surnames: **R**ivest, **S**hamir, and **A**dleman.

### 5.2 How It Works

RSA's security is based on a mathematical problem: the **difficulty of factoring the product of two very large prime numbers**. Multiplying two primes is fast, but given only the result, finding the original factors is computationally infeasible for sufficiently large numbers.

#### Key Generation

1. Choose two large prime numbers **p** and **q** (each with hundreds of digits).
2. Compute **n = p × q** (the modulus). This value is public.
3. Compute **φ(n) = (p − 1) × (q − 1)** (Euler's totient function).
4. Choose a public exponent **e**, coprime to φ(n). The most commonly used value is **e = 65537** (0x10001), chosen because it is prime and has few active bits (efficient for exponentiation).
5. Compute the private exponent **d = e⁻¹ mod φ(n)** (the modular inverse of e).

- **Public key**: (n, e)
- **Private key**: (n, d)

#### Encryption and Decryption

- **Encrypt**: c = m^e mod n (where m is the numeric message and c is the ciphertext)
- **Decrypt**: m = c^d mod n

Security relies on the fact that, without knowing p and q (which compose d), it is computationally infeasible to calculate d from only (n, e).

### 5.3 Key Sizes

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

The key size also limits the **maximum data size** that can be directly encrypted (detailed in section 5.4).

### 5.4 Padding Schemes

In RSA, the plaintext message needs to be transformed into a number between 0 and n−1 before encryption. **Padding** (or encoding scheme) is the process that performs this transformation securely. Encrypting without padding (called "textbook RSA") is extremely insecure.

#### 5.4.1 PKCS#1 v1.5

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

#### 5.4.2 OAEP (Optimal Asymmetric Encryption Padding)

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

#### OAEP Versions

| Version | Reference | Details |
|---|---|---|
| OAEP v1 | Bellare-Rogaway (1994) | Original proposal with SHA-1 |
| OAEP v2.0 | PKCS#1 v2.0 (RFC 2437) | Incorporation into PKCS#1 standard with MGF1 |
| OAEP v2.1 | PKCS#1 v2.1 (RFC 3447) / v2.2 (RFC 8017) | **Recommended** — configurable hash, MGF1, label support |

> **Recommendation**: always use **OAEP v2.1** (or later) with **SHA-256** or higher. As per RFC 8017: *"RSAES-OAEP is required to be supported for new applications"*.

### 5.5 Hash Algorithms Used with RSA

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

### 5.6 Key Formats

RSA keys can be stored and transmitted in different standardized formats. Each format has a specific purpose.

#### 5.6.1 PKCS#1

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

#### 5.6.2 PKCS#8 (PrivateKeyInfo)

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

#### 5.6.3 X.509 (SubjectPublicKeyInfo)

**Reference**: RFC 5280

**Generic** format for public keys, widely used in digital certificates. Encapsulates the public key with an algorithm identifier.

```
-----BEGIN PUBLIC KEY-----
(Base64-encoded data)
-----END PUBLIC KEY-----
```

#### Format Comparison

| Format | Key Type | RSA-Specific? | PEM Header |
|---|---|---|---|
| PKCS#1 | Public and Private | Yes | `BEGIN RSA PUBLIC KEY` / `BEGIN RSA PRIVATE KEY` |
| PKCS#8 | Private only | No (generic) | `BEGIN PRIVATE KEY` |
| X.509 | Public only | No (generic) | `BEGIN PUBLIC KEY` |

### 5.7 Security Considerations

- **Minimum key size**: use at least **2048 bits**. 1024-bit keys are considered obsolete.
- **Always use OAEP**: avoid PKCS#1 v1.5 for encryption in new projects due to the Bleichenbacher vulnerability.
- **Do not encrypt large data directly**: RSA is limited by key size. For larger data, use hybrid cryptography (section 2.4).
- **Prime generation**: the quality of the random number generator is critical. Predictable primes completely compromise security.
- **Quantum threat**: **Shor's algorithm** allows a sufficiently large quantum computer to factor integers in polynomial time, which would break RSA. Although quantum computers of this capability do not yet exist, sensitive organizations are already planning migration to post-quantum algorithms (such as those selected by NIST: CRYSTALS-Kyber for encryption and CRYSTALS-Dilithium for signatures).

---

## 6. When to Use AES vs RSA

### 6.1 Scenarios for AES

- **File and database encryption**: large volumes of data where speed is essential.
- **Network traffic**: after key negotiation (TLS), all traffic is encrypted with AES.
- **Disk encryption**: solutions like BitLocker, FileVault, and LUKS use AES.
- **When both parties already share a key**: no need for key exchange.

### 6.2 Scenarios for RSA

- **Key exchange**: securely sending an AES key to another party.
- **Digital signatures**: signing documents, code, or certificates.
- **Certificate-based authentication**: TLS, SSH, X.509 certificates.
- **When parties have no shared secret**: the public key can be distributed openly.

### 6.3 Decision Table

| Need | Recommended Algorithm |
|---|---|
| Encrypt large volumes of data | AES (preferably GCM) |
| Exchange keys securely | RSA-OAEP |
| Digitally sign data | RSA + SHA-256 (or higher) |
| Encrypt and authenticate simultaneously | AES-GCM or AES-CCM |
| Encrypt data and send to unknown parties | Hybrid cryptography (RSA + AES) |
| Store passwords | Do not use AES or RSA — use Argon2, bcrypt, or PBKDF2 |

---

## 7. References

### NIST Standards (FIPS)

- [**FIPS 197**](https://csrc.nist.gov/pubs/fips/197/final) — Advanced Encryption Standard (AES). NIST, 2001 (updated 2023).
- [**FIPS 180-4**](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) — Secure Hash Standard (SHS): SHA-1, SHA-224, SHA-256, SHA-384, SHA-512. NIST, 2015.
- [**FIPS 202**](https://csrc.nist.gov/pubs/fips/202/final) — SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions. NIST, 2015.

### NIST Special Publications (SP)

- [**NIST SP 800-38A**](https://csrc.nist.gov/pubs/sp/800/38/a/final) — Recommendation for Block Cipher Modes of Operation: Methods and Techniques (ECB, CBC, CFB, OFB, CTR). NIST, 2001.
- [**NIST SP 800-38C**](https://csrc.nist.gov/pubs/sp/800/38/c/upd1/final) — Recommendation for Block Cipher Modes of Operation: The CCM Mode for Authentication and Confidentiality. NIST, 2004.
- [**NIST SP 800-38D**](https://csrc.nist.gov/pubs/sp/800/38/d/final) — Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC. NIST, 2007.
- [**NIST SP 800-57 Part 1 Rev. 5**](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) — Recommendation for Key Management: Part 1 – General. NIST, 2020.

### RFCs (IETF)

- [**RFC 8017**](https://datatracker.ietf.org/doc/html/rfc8017) — PKCS #1: RSA Cryptography Specifications Version 2.2. IETF, 2016.
- [**RFC 3447**](https://datatracker.ietf.org/doc/html/rfc3447) — Public-Key Cryptography Standards (PKCS) #1: RSA Cryptography Specifications Version 2.1. IETF, 2003.
- [**RFC 2437**](https://datatracker.ietf.org/doc/html/rfc2437) — PKCS #1: RSA Cryptography Specifications Version 2.0. IETF, 1998.
- [**RFC 5652**](https://datatracker.ietf.org/doc/html/rfc5652) — Cryptographic Message Syntax (CMS). IETF, 2009.
- [**RFC 5958**](https://datatracker.ietf.org/doc/html/rfc5958) — Asymmetric Key Packages (PKCS#8). IETF, 2010.
- [**RFC 5280**](https://datatracker.ietf.org/doc/html/rfc5280) — Internet X.509 Public Key Infrastructure Certificate and CRL Profile. IETF, 2008.
- [**RFC 3610**](https://datatracker.ietf.org/doc/html/rfc3610) — Counter with CBC-MAC (CCM). IETF, 2003.
