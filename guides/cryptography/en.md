# Cryptography

A comprehensive guide on cryptography, covering fundamental concepts and the principles behind the main cryptographic techniques.

## Table of Contents

- [1. What is Cryptography?](#1-what-is-cryptography)
- [2. Symmetric vs Asymmetric Cryptography](#2-symmetric-vs-asymmetric-cryptography)
- [3. Hash Functions](#3-hash-functions)
- [4. Cryptography Use Cases](#4-cryptography-use-cases)
- [5. When to Use Which Type](#5-when-to-use-which-type)
- [6. References](#6-references)

---

## 1. What is Cryptography?

### 1.1 Definition

The word **cryptography** comes from the Greek: *kryptos* (hidden, secret) and *graphein* (writing). In simple terms, cryptography is the science of transforming readable information into something incomprehensible, so that only those who possess the correct "key" can reverse the process and read the original information.

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

The most widely used symmetric algorithm today is **AES**.

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

The most widely used asymmetric algorithm is **RSA**.

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
3. The **symmetric key is encrypted** with the recipient's public key (solves distribution).
4. The recipient uses their **private key** to decrypt the symmetric key.
5. With the recovered symmetric key, the recipient **decrypts the data**.

This way, you get the best of both worlds: the speed of symmetric cryptography and the secure key exchange of asymmetric cryptography.

---

## 3. Hash Functions

Hash functions are frequently used alongside encryption algorithms and play a critical role in many cryptographic protocols. Therefore, it's important to understand them as part of any cryptography foundation.

### 3.1 What is a Hash Function?

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

---

## 4. Cryptography Use Cases

Cryptography is the backbone of modern digital security. Below are the most common real-world scenarios where cryptographic techniques are applied.

### 4.1 HTTPS/TLS (Web Traffic Protection)

Every time you see the padlock icon in your browser, TLS (Transport Layer Security) is at work. It uses a combination of asymmetric cryptography (for the initial handshake and key exchange) and symmetric cryptography (for encrypting the actual data stream). This protects everything from login credentials to online purchases against eavesdropping and tampering.

### 4.2 End-to-End Encryption (WhatsApp, Signal)

Messaging apps like WhatsApp and Signal implement end-to-end encryption, meaning that only the sender and the recipient can read the messages. Not even the service provider has access to the content. This is achieved through a combination of key agreement protocols and symmetric encryption, ensuring that messages remain private throughout their entire journey.

### 4.3 Password Vaults

Password managers like 1Password, Bitwarden, and KeePass use strong symmetric encryption to protect your stored credentials. A single master password derives an encryption key (typically via PBKDF2 or Argon2), which then encrypts the entire vault. Without the master password, the stored data is computationally inaccessible.

### 4.4 Digital Signatures

Digital signatures use asymmetric cryptography to guarantee authorship and integrity of documents, software, and certificates. The signer uses their private key to sign a hash of the data, and anyone with the corresponding public key can verify the signature. This is the foundation of code signing, PDF document signatures, and the X.509 certificate infrastructure that powers the internet.

### 4.5 Disk/Storage Encryption

Full-disk encryption solutions like BitLocker (Windows), FileVault (macOS), and LUKS (Linux) use symmetric encryption to protect all data on a storage device. If the device is lost or stolen, the data remains unreadable without the correct credentials. This is critical for laptops, external drives, and any device that might leave a secure environment.

### 4.6 VPN (WireGuard, IPsec)

Virtual Private Networks create an encrypted tunnel between your device and a remote server, protecting all network traffic from interception. Modern VPN protocols like WireGuard use state-of-the-art key agreement and symmetric encryption to ensure both performance and security. IPsec, another widely deployed protocol, uses a combination of key exchange and symmetric algorithms to secure network communications at the IP layer.

---

## 5. When to Use Which Type

Choosing the right cryptographic approach depends on your specific scenario. Here is a practical guide to help decide between symmetric, asymmetric, hybrid, and key agreement approaches.

### 5.1 Symmetric Cryptography

Use symmetric algorithms (such as AES or ChaCha20) when:

- **Encrypting large volumes of data**: files, databases, disk encryption, or network streams.
- **Both parties already share a secret key**: no key exchange is needed.
- **Performance is critical**: symmetric encryption is orders of magnitude faster than asymmetric encryption.

### 5.2 Asymmetric Cryptography

Use asymmetric algorithms (such as RSA or ECDSA) when:

- **Signing data digitally**: documents, code, certificates — proving authorship and integrity.
- **Certificate-based authentication**: TLS, SSH, X.509 certificate validation.
- **Parties have no pre-shared secret**: the public key can be distributed openly.

### 5.3 Hybrid Cryptography

Use hybrid approaches when:

- **Sending encrypted data to another party without a shared secret**: generate a random symmetric key, encrypt the data with it, and encrypt the symmetric key with the recipient's public key.
- **Implementing secure communication protocols**: TLS, PGP, and S/MIME all follow this model.

### 5.4 Key Agreement

Use key agreement protocols (such as ECDH or X25519) when:

- **Establishing a shared secret over an insecure channel**: both parties contribute to the creation of a shared key without it ever being transmitted.
- **Forward secrecy is required**: ephemeral key agreement ensures that compromising a long-term key does not compromise past sessions.
- **Modern protocol design**: WireGuard and TLS 1.3, for example, prefer ECDH-based key exchange over RSA key transport.

### 5.5 Decision Table

| Need | Recommended Approach |
|---|---|
| Encrypt large volumes of data | Symmetric encryption (e.g., AES-GCM, ChaCha20-Poly1305) |
| Exchange keys securely | Key agreement (e.g., ECDH, X25519) or asymmetric encryption (e.g., RSA-OAEP) |
| Digitally sign data | Asymmetric signatures (e.g., RSA + SHA-256, ECDSA, Ed25519) |
| Encrypt and authenticate simultaneously | Authenticated symmetric encryption (e.g., AES-GCM, ChaCha20-Poly1305) |
| Encrypt data and send to unknown parties | Hybrid cryptography (key agreement or asymmetric + symmetric) |
| Achieve forward secrecy | Ephemeral key agreement (e.g., ECDHE) |
| Store passwords | Do not use encryption — use Argon2, bcrypt, or PBKDF2 |

---

## 6. References

### NIST Standards (FIPS)

- [**FIPS 180-4**](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) — Secure Hash Standard (SHS): SHA-1, SHA-224, SHA-256, SHA-384, SHA-512. NIST, 2015.
- [**FIPS 202**](https://csrc.nist.gov/pubs/fips/202/final) — SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions. NIST, 2015.

### NIST Special Publications (SP)

- [**NIST SP 800-57 Part 1 Rev. 5**](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) — Recommendation for Key Management: Part 1 – General. NIST, 2020.
