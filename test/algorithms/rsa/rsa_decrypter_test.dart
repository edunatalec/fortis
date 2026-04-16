import 'dart:typed_data';

import 'package:fortis/fortis.dart';
import 'package:test/test.dart';

void main() {
  late FortisRsaKeyPair pair;
  late FortisRsaKeyPair otherPair;

  setUpAll(() async {
    pair = await Fortis.rsa().keySize(2048).generateKeyPair();
    otherPair = await Fortis.rsa().keySize(2048).generateKeyPair();
  });

  RsaEncrypter makeEncrypter(
    FortisRsaKeyPair kp, {
    RsaPadding padding = RsaPadding.oaep_v2,
    RsaHash hash = RsaHash.sha256,
  }) => Fortis.rsa().padding(padding).hash(hash).encrypter(kp.publicKey);

  RsaDecrypter makeDecrypter(
    FortisRsaKeyPair kp, {
    RsaPadding padding = RsaPadding.oaep_v2,
    RsaHash hash = RsaHash.sha256,
  }) => Fortis.rsa().padding(padding).hash(hash).decrypter(kp.privateKey);

  final plaintext = Uint8List.fromList('hello fortis'.codeUnits);

  group('decrypt(Object input) — Uint8List input', () {
    test('recovers original plaintext from raw Uint8List', () {
      final ciphertext = makeEncrypter(pair).encrypt(plaintext);
      final recovered = makeDecrypter(pair).decrypt(ciphertext);
      expect(recovered, equals(plaintext));
    });

    test(
      'end-to-end: encrypt(Uint8List) → decrypt(Uint8List) → equals original',
      () {
        final ciphertext = makeEncrypter(pair).encrypt(plaintext);
        expect(makeDecrypter(pair).decrypt(ciphertext), equals(plaintext));
      },
    );
  });

  group('decrypt(Object input) — String (Base64) input', () {
    test('recovers original plaintext from Base64 string', () {
      final b64 = makeEncrypter(pair).encryptToString(plaintext);
      final recovered = makeDecrypter(pair).decrypt(b64);
      expect(recovered, equals(plaintext));
    });

    test(
      'end-to-end: encryptToString(String) → decrypt(String) → equals original bytes',
      () {
        final b64 = makeEncrypter(pair).encryptToString('hello fortis');
        final recovered = makeDecrypter(pair).decrypt(b64);
        expect(recovered, equals(Uint8List.fromList('hello fortis'.codeUnits)));
      },
    );
  });

  group('decrypt(Object input) — unsupported type', () {
    test('throws FortisConfigException with descriptive message', () {
      expect(
        () => makeDecrypter(pair).decrypt(42),
        throwsA(isA<FortisConfigException>()),
      );
    });
  });

  group('decryptToString(Object input)', () {
    test('recovers original UTF-8 string from Uint8List input', () {
      const original = 'hello fortis';
      final ciphertext = makeEncrypter(pair).encrypt(original);
      expect(makeDecrypter(pair).decryptToString(ciphertext), equals(original));
    });

    test('recovers original UTF-8 string from Base64 String input', () {
      const original = 'hello fortis';
      final b64 = makeEncrypter(pair).encryptToString(original);
      expect(makeDecrypter(pair).decryptToString(b64), equals(original));
    });

    test(
      'end-to-end: encrypt(String) → decryptToString(Uint8List) → equals original',
      () {
        const original = 'hello fortis';
        final ciphertext = makeEncrypter(pair).encrypt(original);
        expect(
          makeDecrypter(pair).decryptToString(ciphertext),
          equals(original),
        );
      },
    );

    test(
      'end-to-end: encryptToString(String) → decryptToString(String) → equals original',
      () {
        const original = 'Fortis é uma biblioteca de criptografia!';
        final b64 = makeEncrypter(pair).encryptToString(original);
        expect(makeDecrypter(pair).decryptToString(b64), equals(original));
      },
    );

    test('unsupported input type throws FortisConfigException', () {
      expect(
        () => makeDecrypter(pair).decryptToString(42),
        throwsA(isA<FortisConfigException>()),
      );
    });
  });

  group('wrong key', () {
    test('decrypt with wrong key throws FortisEncryptionException', () {
      final ciphertext = makeEncrypter(pair).encrypt(plaintext);
      expect(
        () => makeDecrypter(otherPair).decrypt(ciphertext),
        throwsA(isA<FortisEncryptionException>()),
      );
    });

    test('decryptToString with wrong key throws FortisEncryptionException', () {
      final ciphertext = makeEncrypter(pair).encrypt(plaintext);
      expect(
        () => makeDecrypter(otherPair).decryptToString(ciphertext),
        throwsA(isA<FortisEncryptionException>()),
      );
    });
  });

  group('padding × hash matrix', () {
    final matrixPlaintext = Uint8List.fromList('matrix test'.codeUnits);

    const hashes = [
      RsaHash.sha1,
      RsaHash.sha224,
      RsaHash.sha256,
      RsaHash.sha384,
      RsaHash.sha512,
      RsaHash.sha3_256,
      RsaHash.sha3_512,
    ];

    test('round-trip: RsaPadding.pkcs1_v1_5', () {
      final ciphertext = Fortis.rsa()
          .padding(RsaPadding.pkcs1_v1_5)
          .hash(RsaHash.sha256)
          .encrypter(pair.publicKey)
          .encrypt(matrixPlaintext);

      final recovered = Fortis.rsa()
          .padding(RsaPadding.pkcs1_v1_5)
          .hash(RsaHash.sha256)
          .decrypter(pair.privateKey)
          .decrypt(ciphertext);

      expect(recovered, equals(matrixPlaintext));
    });

    test('round-trip: RsaPadding.oaep_v1 + RsaHash.sha1', () {
      final ciphertext = Fortis.rsa()
          .padding(RsaPadding.oaep_v1)
          .hash(RsaHash.sha1)
          .encrypter(pair.publicKey)
          .encrypt(matrixPlaintext);

      final recovered = Fortis.rsa()
          .padding(RsaPadding.oaep_v1)
          .hash(RsaHash.sha1)
          .decrypter(pair.privateKey)
          .decrypt(ciphertext);

      expect(recovered, equals(matrixPlaintext));
    });

    for (final hash in hashes) {
      test('round-trip: RsaPadding.oaep_v2 + $hash', () {
        final ciphertext = Fortis.rsa()
            .padding(RsaPadding.oaep_v2)
            .hash(hash)
            .encrypter(pair.publicKey)
            .encrypt(matrixPlaintext);

        final recovered = Fortis.rsa()
            .padding(RsaPadding.oaep_v2)
            .hash(hash)
            .decrypter(pair.privateKey)
            .decrypt(ciphertext);

        expect(recovered, equals(matrixPlaintext));
      });
    }

    for (final hash in hashes) {
      test('round-trip: RsaPadding.oaep_v2_1 + $hash', () {
        final ciphertext = Fortis.rsa()
            .padding(RsaPadding.oaep_v2_1)
            .hash(hash)
            .encrypter(pair.publicKey)
            .encrypt(matrixPlaintext);

        final recovered = Fortis.rsa()
            .padding(RsaPadding.oaep_v2_1)
            .hash(hash)
            .decrypter(pair.privateKey)
            .decrypt(ciphertext);

        expect(recovered, equals(matrixPlaintext));
      });
    }

    // oaep_v2_1 label sub-group
    group('RsaPadding.oaep_v2_1 label', () {
      test('matching label succeeds', () {
        final ciphertext = Fortis.rsa()
            .padding(RsaPadding.oaep_v2_1)
            .hash(RsaHash.sha256)
            .encrypter(pair.publicKey, label: 'fortis-label')
            .encrypt(matrixPlaintext);

        final recovered = Fortis.rsa()
            .padding(RsaPadding.oaep_v2_1)
            .hash(RsaHash.sha256)
            .decrypter(pair.privateKey, label: 'fortis-label')
            .decrypt(ciphertext);

        expect(recovered, equals(matrixPlaintext));
      });

      test('different label throws FortisEncryptionException', () {
        final ciphertext = Fortis.rsa()
            .padding(RsaPadding.oaep_v2_1)
            .hash(RsaHash.sha256)
            .encrypter(pair.publicKey, label: 'fortis-label')
            .encrypt(matrixPlaintext);

        expect(
          () => Fortis.rsa()
              .padding(RsaPadding.oaep_v2_1)
              .hash(RsaHash.sha256)
              .decrypter(pair.privateKey, label: 'other-label')
              .decrypt(ciphertext),
          throwsA(isA<FortisEncryptionException>()),
        );
      });

      test('decrypt without label throws FortisEncryptionException', () {
        final ciphertext = Fortis.rsa()
            .padding(RsaPadding.oaep_v2_1)
            .hash(RsaHash.sha256)
            .encrypter(pair.publicKey, label: 'fortis-label')
            .encrypt(matrixPlaintext);

        expect(
          () => Fortis.rsa()
              .padding(RsaPadding.oaep_v2_1)
              .hash(RsaHash.sha256)
              .decrypter(pair.privateKey)
              .decrypt(ciphertext),
          throwsA(isA<FortisEncryptionException>()),
        );
      });
    });
  });
}
