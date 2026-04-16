import 'dart:typed_data';

import 'package:fortis/fortis.dart';
import 'package:test/test.dart';

void main() {
  late FortisRsaKeyPair pair;

  setUpAll(() async {
    pair = await Fortis.rsa().keySize(2048).generateKeyPair();
  });

  group('keySize validation in generateKeyPair', () {
    test('keySize(0) throws FortisConfigException', () async {
      await expectLater(
        Fortis.rsa().keySize(0).generateKeyPair(),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('keySize(-2048) throws FortisConfigException', () async {
      await expectLater(
        Fortis.rsa().keySize(-2048).generateKeyPair(),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('keySize(2047) throws FortisConfigException', () async {
      await expectLater(
        Fortis.rsa().keySize(2047).generateKeyPair(),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('keySize(2049) throws (not a power of 2)', () async {
      await expectLater(
        Fortis.rsa().keySize(2049).generateKeyPair(),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('keySize(512) throws (below minimum)', () async {
      await expectLater(
        Fortis.rsa().keySize(512).generateKeyPair(),
        throwsA(isA<FortisConfigException>()),
      );
    });
  });

  group('label validation', () {
    test('label with pkcs1_v1_5 padding throws FortisConfigException', () {
      expect(
        () => Fortis.rsa()
            .padding(RsaPadding.pkcs1_v1_5)
            .hash(RsaHash.sha256)
            .encrypter(pair.publicKey, label: 'x'),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('label with oaep_v1 padding throws FortisConfigException', () {
      expect(
        () => Fortis.rsa()
            .padding(RsaPadding.oaep_v1)
            .hash(RsaHash.sha1)
            .encrypter(pair.publicKey, label: 'x'),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('label with oaep_v2 padding throws FortisConfigException', () {
      expect(
        () => Fortis.rsa()
            .padding(RsaPadding.oaep_v2)
            .hash(RsaHash.sha256)
            .encrypter(pair.publicKey, label: 'x'),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('int label with oaep_v2_1 throws FortisConfigException', () {
      expect(
        () => Fortis.rsa()
            .padding(RsaPadding.oaep_v2_1)
            .hash(RsaHash.sha256)
            .encrypter(pair.publicKey, label: 42),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('double label with oaep_v2_1 throws FortisConfigException', () {
      expect(
        () => Fortis.rsa()
            .padding(RsaPadding.oaep_v2_1)
            .hash(RsaHash.sha256)
            .decrypter(pair.privateKey, label: 3.14),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test(
      'List<int> label with oaep_v2_1 throws (must be String or Uint8List)',
      () {
        expect(
          () => Fortis.rsa()
              .padding(RsaPadding.oaep_v2_1)
              .hash(RsaHash.sha256)
              .encrypter(pair.publicKey, label: [1, 2, 3]),
          throwsA(isA<FortisConfigException>()),
        );
      },
    );

    test('empty String label round-trips', () {
      final enc = Fortis.rsa()
          .padding(RsaPadding.oaep_v2_1)
          .hash(RsaHash.sha256)
          .encrypter(pair.publicKey, label: '');
      final dec = Fortis.rsa()
          .padding(RsaPadding.oaep_v2_1)
          .hash(RsaHash.sha256)
          .decrypter(pair.privateKey, label: '');
      final ct = enc.encrypt('hi');
      expect(dec.decryptToString(ct), equals('hi'));
    });
  });

  group('plaintext size limits (OAEP v2 + SHA-256 on RSA-2048)', () {
    // Max OAEP payload for RSA-2048 + SHA-256: 256 - 2*32 - 2 = 190 bytes.
    RsaEncrypter enc() => Fortis.rsa()
        .padding(RsaPadding.oaep_v2)
        .hash(RsaHash.sha256)
        .encrypter(pair.publicKey);

    test('190-byte plaintext encrypts successfully', () {
      final data = Uint8List(190);
      expect(() => enc().encrypt(data), returnsNormally);
    });

    test('191-byte plaintext throws FortisEncryptionException', () {
      final data = Uint8List(191);
      expect(
        () => enc().encrypt(data),
        throwsA(isA<FortisEncryptionException>()),
      );
    });

    test('1000-byte plaintext throws FortisEncryptionException', () {
      final data = Uint8List(1000);
      expect(
        () => enc().encrypt(data),
        throwsA(isA<FortisEncryptionException>()),
      );
    });
  });

  group('ciphertext corruption detection', () {
    RsaEncrypter encrypter() => Fortis.rsa()
        .padding(RsaPadding.oaep_v2)
        .hash(RsaHash.sha256)
        .encrypter(pair.publicKey);

    RsaDecrypter decrypter() => Fortis.rsa()
        .padding(RsaPadding.oaep_v2)
        .hash(RsaHash.sha256)
        .decrypter(pair.privateKey);

    test('flipping a single byte throws FortisEncryptionException', () {
      final ct = encrypter().encrypt('hello');
      final tampered = Uint8List.fromList(ct);
      tampered[ct.length ~/ 2] ^= 0xFF;
      expect(
        () => decrypter().decrypt(tampered),
        throwsA(isA<FortisEncryptionException>()),
      );
    });

    test('truncated ciphertext throws FortisEncryptionException', () {
      final ct = encrypter().encrypt('hello');
      final truncated = ct.sublist(0, ct.length - 10);
      expect(
        () => decrypter().decrypt(truncated),
        throwsA(isA<FortisEncryptionException>()),
      );
    });

    test('empty ciphertext throws FortisEncryptionException', () {
      expect(
        () => decrypter().decrypt(Uint8List(0)),
        throwsA(isA<FortisEncryptionException>()),
      );
    });

    test('random garbage bytes throw FortisEncryptionException', () {
      final garbage = Uint8List.fromList(List.generate(256, (i) => i));
      expect(
        () => decrypter().decrypt(garbage),
        throwsA(isA<FortisEncryptionException>()),
      );
    });
  });

  group('padding/hash mismatch between encrypt and decrypt', () {
    test('encrypt OAEP v2, decrypt PKCS1 v1.5 fails', () {
      final ct = Fortis.rsa()
          .padding(RsaPadding.oaep_v2)
          .hash(RsaHash.sha256)
          .encrypter(pair.publicKey)
          .encrypt('hello');

      expect(
        () => Fortis.rsa()
            .padding(RsaPadding.pkcs1_v1_5)
            .hash(RsaHash.sha256)
            .decrypter(pair.privateKey)
            .decrypt(ct),
        throwsA(isA<FortisEncryptionException>()),
      );
    });

    test('encrypt OAEP v2 + SHA-256, decrypt OAEP v2 + SHA-512 fails', () {
      final ct = Fortis.rsa()
          .padding(RsaPadding.oaep_v2)
          .hash(RsaHash.sha256)
          .encrypter(pair.publicKey)
          .encrypt('hello');

      expect(
        () => Fortis.rsa()
            .padding(RsaPadding.oaep_v2)
            .hash(RsaHash.sha512)
            .decrypter(pair.privateKey)
            .decrypt(ct),
        throwsA(isA<FortisEncryptionException>()),
      );
    });

    test('encrypt OAEP v2.1 with label, decrypt OAEP v2 fails', () {
      final ct = Fortis.rsa()
          .padding(RsaPadding.oaep_v2_1)
          .hash(RsaHash.sha256)
          .encrypter(pair.publicKey, label: 'ctx')
          .encrypt('hello');

      // OAEP v2 has no label concept — decrypting a label-bound ciphertext
      // without the label must fail.
      expect(
        () => Fortis.rsa()
            .padding(RsaPadding.oaep_v2)
            .hash(RsaHash.sha256)
            .decrypter(pair.privateKey)
            .decrypt(ct),
        throwsA(isA<FortisEncryptionException>()),
      );
    });

    test('encrypt OAEP v1 (SHA-1), decrypt OAEP v2 (SHA-256) fails', () {
      final ct = Fortis.rsa()
          .padding(RsaPadding.oaep_v1)
          .hash(RsaHash.sha1)
          .encrypter(pair.publicKey)
          .encrypt('hello');

      expect(
        () => Fortis.rsa()
            .padding(RsaPadding.oaep_v2)
            .hash(RsaHash.sha256)
            .decrypter(pair.privateKey)
            .decrypt(ct),
        throwsA(isA<FortisEncryptionException>()),
      );
    });
  });

  group('RSA key serialization — PEM/DER cross-format', () {
    test('public key PEM (X.509) round-trip preserves key', () {
      final pem = pair.publicKey.toPem();
      final restored = FortisRsaPublicKey.fromPem(pem);
      expect(restored.toDerBase64(), equals(pair.publicKey.toDerBase64()));
    });

    test('public key PEM (PKCS#1) round-trip preserves key', () {
      final pem = pair.publicKey.toPem(format: RsaPublicKeyFormat.pkcs1);
      final restored = FortisRsaPublicKey.fromPem(
        pem,
        format: RsaPublicKeyFormat.pkcs1,
      );
      expect(
        restored.toDerBase64(format: RsaPublicKeyFormat.pkcs1),
        equals(pair.publicKey.toDerBase64(format: RsaPublicKeyFormat.pkcs1)),
      );
    });

    test('private key PEM (PKCS#8) round-trip preserves key', () {
      final pem = pair.privateKey.toPem();
      final restored = FortisRsaPrivateKey.fromPem(pem);
      expect(restored.toDerBase64(), equals(pair.privateKey.toDerBase64()));
    });

    test('private key PEM (PKCS#1) round-trip preserves key', () {
      final pem = pair.privateKey.toPem(format: RsaPrivateKeyFormat.pkcs1);
      final restored = FortisRsaPrivateKey.fromPem(
        pem,
        format: RsaPrivateKeyFormat.pkcs1,
      );
      final restoredB64 = restored.toDerBase64(
        format: RsaPrivateKeyFormat.pkcs1,
      );
      final originalB64 = pair.privateKey.toDerBase64(
        format: RsaPrivateKeyFormat.pkcs1,
      );
      expect(restoredB64, equals(originalB64));
    });

    test('reading X.509 PEM as PKCS#1 format throws FortisKeyException', () {
      final pem = pair.publicKey.toPem(); // X.509
      expect(
        () => FortisRsaPublicKey.fromPem(pem, format: RsaPublicKeyFormat.pkcs1),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('reading PKCS#1 DER as X.509 throws FortisKeyException', () {
      final der = pair.publicKey.toDer(format: RsaPublicKeyFormat.pkcs1);
      expect(
        () => FortisRsaPublicKey.fromDer(der, format: RsaPublicKeyFormat.x509),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('reading PKCS#8 DER as PKCS#1 throws FortisKeyException', () {
      final der = pair.privateKey.toDer(); // PKCS#8
      expect(
        () =>
            FortisRsaPrivateKey.fromDer(der, format: RsaPrivateKeyFormat.pkcs1),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('garbage PEM body throws FortisKeyException', () {
      const badPem =
          '-----BEGIN PUBLIC KEY-----\n'
          'not-really-base64!!\n'
          '-----END PUBLIC KEY-----';
      expect(
        () => FortisRsaPublicKey.fromPem(badPem),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('empty PEM throws FortisKeyException', () {
      expect(
        () => FortisRsaPublicKey.fromPem(''),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('garbage DER bytes throw FortisKeyException', () {
      expect(
        () =>
            FortisRsaPublicKey.fromDer(Uint8List.fromList([0x01, 0x02, 0x03])),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('empty DER throws FortisKeyException', () {
      expect(
        () => FortisRsaPublicKey.fromDer(Uint8List(0)),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('garbage private-key PEM throws FortisKeyException', () {
      expect(
        () => FortisRsaPrivateKey.fromPem('nothing-useful'),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('empty Base64 for DER throws FortisKeyException', () {
      // Empty base64 decodes to empty bytes → invalid DER.
      expect(
        () => FortisRsaPublicKey.fromDerBase64(''),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('cross-key: decrypter with other private key fails', () async {
      final other = await Fortis.rsa().keySize(2048).generateKeyPair();

      final ct = Fortis.rsa()
          .padding(RsaPadding.oaep_v2)
          .hash(RsaHash.sha256)
          .encrypter(pair.publicKey)
          .encrypt('hello');

      expect(
        () => Fortis.rsa()
            .padding(RsaPadding.oaep_v2)
            .hash(RsaHash.sha256)
            .decrypter(other.privateKey)
            .decrypt(ct),
        throwsA(isA<FortisEncryptionException>()),
      );
    });
  });

  group('decrypter — invalid input types', () {
    RsaDecrypter dec() => Fortis.rsa()
        .padding(RsaPadding.oaep_v2)
        .hash(RsaHash.sha256)
        .decrypter(pair.privateKey);

    test('int input throws FortisConfigException', () {
      expect(() => dec().decrypt(42), throwsA(isA<FortisConfigException>()));
    });

    test('bool input throws FortisConfigException', () {
      expect(() => dec().decrypt(true), throwsA(isA<FortisConfigException>()));
    });

    test('List<int> input throws FortisConfigException', () {
      expect(
        () => dec().decrypt([1, 2, 3]),
        throwsA(isA<FortisConfigException>()),
      );
    });
  });

  group('encrypter — invalid input types', () {
    RsaEncrypter enc() => Fortis.rsa()
        .padding(RsaPadding.oaep_v2)
        .hash(RsaHash.sha256)
        .encrypter(pair.publicKey);

    test('int plaintext throws FortisConfigException', () {
      expect(() => enc().encrypt(42), throwsA(isA<FortisConfigException>()));
    });

    test('List<int> plaintext throws FortisConfigException', () {
      expect(
        () => enc().encrypt([1, 2, 3]),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('Map plaintext throws FortisConfigException', () {
      expect(
        () => enc().encrypt(<String, String>{'a': 'b'}),
        throwsA(isA<FortisConfigException>()),
      );
    });
  });

  group('OAEP v2.1 — size validation', () {
    // For 2048-bit RSA + SHA-256, OAEP v2.1 max message = 256 - 2*32 - 2 = 190
    // bytes. Anything bigger must be rejected at encryption time.
    test('encrypt with message longer than max throws', () {
      final encrypter = Fortis.rsa()
          .padding(RsaPadding.oaep_v2_1)
          .hash(RsaHash.sha256)
          .encrypter(pair.publicKey);
      final tooLong = Uint8List(200); // 200 > 190
      expect(
        () => encrypter.encrypt(tooLong),
        throwsA(isA<FortisEncryptionException>()),
      );
    });

    test('decrypt with ciphertext shorter than key size throws', () {
      final decrypter = Fortis.rsa()
          .padding(RsaPadding.oaep_v2_1)
          .hash(RsaHash.sha256)
          .decrypter(pair.privateKey);
      final shortCt = Uint8List(100); // 2048-bit RSA key = 256-byte ciphertext
      expect(
        () => decrypter.decrypt(shortCt),
        throwsA(isA<FortisEncryptionException>()),
      );
    });

    test('decrypt with ciphertext longer than key size throws', () {
      final decrypter = Fortis.rsa()
          .padding(RsaPadding.oaep_v2_1)
          .hash(RsaHash.sha256)
          .decrypter(pair.privateKey);
      final longCt = Uint8List(512);
      expect(
        () => decrypter.decrypt(longCt),
        throwsA(isA<FortisEncryptionException>()),
      );
    });
  });
}
