import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:pointycastle/asymmetric/rsa.dart';

import '../../exceptions/fortis_encryption_exception.dart';

/// Encrypts [message] using OAEP v2.1 (RFC 3447 / RFC 8017) with the given
/// [key], [digest], and optional [label].
///
/// OAEP v2.1 differs from v2.0 in that the encoded message (EM) includes a
/// leading 0x00 byte before the masked seed and masked DB, making EM exactly
/// [k] bytes where [k] is the key size in bytes.
Uint8List oaepV21Encrypt({
  required RSAPublicKey key,
  required Uint8List message,
  required Digest digest,
  required Uint8List label,
  required Random rng,
}) {
  final k = _keyBytes(key.modulus!);
  final hLen = digest.digestSize;

  if (message.length > k - 2 * hLen - 2) {
    throw FortisEncryptionException(
      'Message is too long for the given RSA key size and hash combination. '
      'Maximum message length: ${k - 2 * hLen - 2} bytes.',
    );
  }

  // 1. lHash = Hash(label)
  final lHash = _hash(digest, label);

  // 2. DB = lHash || PS || 0x01 || M
  final dbLen = k - hLen - 1;
  final db = Uint8List(dbLen);
  db.setAll(0, lHash);
  // PS (zero bytes) is already initialised
  final separatorIdx = dbLen - message.length - 1;
  db[separatorIdx] = 0x01;
  db.setAll(separatorIdx + 1, message);

  // 3. seed — random hLen bytes
  final seed = Uint8List.fromList(List.generate(hLen, (_) => rng.nextInt(256)));

  // 4. maskedDB = DB XOR MGF1(seed, dbLen)
  final maskedDb = _xor(db, _mgf1(seed, dbLen, digest));

  // 5. maskedSeed = seed XOR MGF1(maskedDB, hLen)
  final maskedSeed = _xor(seed, _mgf1(maskedDb, hLen, digest));

  // 6. EM = 0x00 || maskedSeed || maskedDB
  final em = Uint8List(k);
  em[0] = 0x00;
  em.setAll(1, maskedSeed);
  em.setAll(1 + hLen, maskedDb);

  // 7. RSA encryption — RSAEngine accepts up to inputBlockSize+1 = k bytes
  final engine = RSAEngine()..init(true, PublicKeyParameter<RSAPublicKey>(key));
  final out = Uint8List(engine.outputBlockSize);
  engine.processBlock(em, 0, em.length, out, 0);
  return out;
}

/// Decrypts [ciphertext] using OAEP v2.1 (RFC 3447 / RFC 8017) with the given
/// [key], [digest], and optional [label].
Uint8List oaepV21Decrypt({
  required RSAPrivateKey key,
  required Uint8List ciphertext,
  required Digest digest,
  required Uint8List label,
}) {
  final k = _keyBytes(key.modulus!);
  final hLen = digest.digestSize;

  if (ciphertext.length != k) {
    throw FortisEncryptionException(
      'Ciphertext length (${ciphertext.length}) does not match RSA key size '
      '($k bytes).',
    );
  }

  // lHash = Hash(label)
  final lHash = _hash(digest, label);

  // RSA decryption — manual to preserve the leading 0x00 in EM
  final em = _rsaDecryptRaw(key, ciphertext);

  // EM = 0x00 || maskedSeed || maskedDB
  // Use constant-time checks to avoid timing oracles
  var error = (em[0] != 0x00) ? 1 : 0;

  final maskedSeed = em.sublist(1, 1 + hLen);
  final maskedDb = em.sublist(1 + hLen);

  // seed = maskedSeed XOR MGF1(maskedDB, hLen)
  final seed = _xor(maskedSeed, _mgf1(maskedDb, hLen, digest));

  // DB = maskedDB XOR MGF1(seed, k - hLen - 1)
  final db = _xor(maskedDb, _mgf1(seed, k - hLen - 1, digest));

  // Verify lHash' == lHash (constant-time)
  for (var i = 0; i < hLen; i++) {
    error |= db[i] ^ lHash[i];
  }

  // Locate the 0x01 separator after PS (constant-time search — no early exit)
  var start = -1;
  for (var i = hLen; i < db.length; i++) {
    if (start == -1) {
      if (db[i] == 0x01) {
        start = i + 1;
      } else if (db[i] != 0x00) {
        error = 1; // invalid byte in PS
      }
    }
  }

  if (error != 0 || start == -1) {
    throw FortisEncryptionException('Decryption error.');
  }

  return db.sublist(start);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

int _keyBytes(BigInt modulus) => (modulus.bitLength + 7) ~/ 8;

Uint8List _hash(Digest digest, Uint8List data) {
  digest.reset();
  digest.update(data, 0, data.length);
  final out = Uint8List(digest.digestSize);
  digest.doFinal(out, 0);
  return out;
}

Uint8List _xor(Uint8List a, Uint8List b) {
  final out = Uint8List(a.length);
  for (var i = 0; i < a.length; i++) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}

Uint8List _mgf1(Uint8List seed, int length, Digest digest) {
  final output = BytesBuilder();
  var counter = 0;
  while (output.length < length) {
    final c = Uint8List(4)
      ..[0] = (counter >> 24) & 0xff
      ..[1] = (counter >> 16) & 0xff
      ..[2] = (counter >> 8) & 0xff
      ..[3] = counter & 0xff;
    digest.reset();
    digest.update(seed, 0, seed.length);
    digest.update(c, 0, 4);
    final hashOut = Uint8List(digest.digestSize);
    digest.doFinal(hashOut, 0);
    output.add(hashOut);
    counter++;
  }
  return Uint8List.fromList(output.toBytes().sublist(0, length));
}

/// RSA decryption primitive using CRT, returning exactly [k] bytes.
///
/// Unlike [RSAEngine], this preserves any leading 0x00 bytes needed by the
/// OAEP v2.1 EM structure.
Uint8List _rsaDecryptRaw(RSAPrivateKey key, Uint8List ciphertext) {
  final k = _keyBytes(key.modulus!);
  final c = _bytesToBigInt(ciphertext);

  final p = key.p!;
  final q = key.q!;
  final d = key.privateExponent!;
  final dp = d.remainder(p - BigInt.one);
  final dq = d.remainder(q - BigInt.one);
  final qInv = q.modInverse(p);

  final mP = c.remainder(p).modPow(dp, p);
  final mQ = c.remainder(q).modPow(dq, q);
  var h = (mP - mQ) * qInv % p;
  if (h.isNegative) h += p;
  final m = h * q + mQ;

  return _bigIntToBytes(m, k);
}

BigInt _bytesToBigInt(Uint8List bytes) {
  var result = BigInt.zero;
  for (final b in bytes) {
    result = (result << 8) | BigInt.from(b);
  }
  return result;
}

Uint8List _bigIntToBytes(BigInt value, int length) {
  final result = Uint8List(length);
  var temp = value;
  for (var i = length - 1; i >= 0; i--) {
    result[i] = (temp & BigInt.from(0xff)).toInt();
    temp = temp >> 8;
  }
  return result;
}
