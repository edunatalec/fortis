import 'dart:convert';
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

  group('RsaDecrypter', () {
    final plaintext = Uint8List.fromList('hello fortis'.codeUnits);

    RsaEncrypter makeEncrypter(FortisRsaKeyPair kp) => Fortis.rsa()
        .padding(RsaPadding.oaep_v2)
        .hash(RsaHash.sha256)
        .encrypter(kp.publicKey);

    RsaDecrypter makeDecrypter(FortisRsaKeyPair kp) => Fortis.rsa()
        .padding(RsaPadding.oaep_v2)
        .hash(RsaHash.sha256)
        .decrypter(kp.privateKey);

    test('decrypt recovers original plaintext', () {
      final ciphertext = makeEncrypter(pair).encrypt(plaintext);
      final recovered = makeDecrypter(pair).decrypt(ciphertext);
      expect(recovered, equals(plaintext));
    });

    test(
      'end-to-end round-trip: generate → encrypt → decrypt → equal',
      () async {
        final newPair = await Fortis.rsa().keySize(2048).generateKeyPair();
        final ciphertext = makeEncrypter(newPair).encrypt(plaintext);
        final recovered = makeDecrypter(newPair).decrypt(ciphertext);
        expect(recovered, equals(plaintext));
      },
    );

    test('wrong key throws FortisEncryptionException', () {
      final ciphertext = makeEncrypter(pair).encrypt(plaintext);
      expect(
        () => makeDecrypter(otherPair).decrypt(ciphertext),
        throwsA(isA<FortisEncryptionException>()),
      );
    });

    test('decryptToString recovers original UTF-8 string', () {
      const original = 'hello fortis';
      final encrypter = makeEncrypter(pair);
      final decrypter = makeDecrypter(pair);
      final ciphertext = encrypter.encryptString(original);
      expect(decrypter.decryptToString(ciphertext), equals(original));
    });

    test(
      'decryptFromBase64 recovers original bytes from Base64 ciphertext',
      () {
        final encrypter = makeEncrypter(pair);
        final decrypter = makeDecrypter(pair);
        final b64Ciphertext = base64Encode(encrypter.encrypt(plaintext));
        expect(decrypter.decryptFromBase64(b64Ciphertext), equals(plaintext));
      },
    );

    test(
      'decryptFromBase64ToString recovers original UTF-8 string from Base64 ciphertext',
      () {
        const original = 'hello fortis';
        final encrypter = makeEncrypter(pair);
        final decrypter = makeDecrypter(pair);
        final b64Ciphertext = encrypter.encryptStringToBase64(original);
        expect(
          decrypter.decryptFromBase64ToString(b64Ciphertext),
          equals(original),
        );
      },
    );

    test(
      'end-to-end: encryptStringToBase64 → decryptFromBase64ToString equals original',
      () {
        const original = 'Fortis é uma biblioteca de criptografia!';
        final encrypter = makeEncrypter(pair);
        final decrypter = makeDecrypter(pair);
        final b64Ciphertext = encrypter.encryptStringToBase64(original);
        expect(
          decrypter.decryptFromBase64ToString(b64Ciphertext),
          equals(original),
        );
      },
    );
  });

  group('padding × hash matrix', () {
    final plaintext = Uint8List.fromList('matrix test'.codeUnits);

    const hashes = [
      RsaHash.sha1,
      RsaHash.sha224,
      RsaHash.sha256,
      RsaHash.sha384,
      RsaHash.sha512,
      RsaHash.sha3_256,
      RsaHash.sha3_512,
    ];

    // pkcs1_v1_5 — does not use a hash; tested once with a placeholder hash
    test('round-trip: RsaPadding.pkcs1_v1_5', () {
      final ciphertext = Fortis.rsa()
          .padding(RsaPadding.pkcs1_v1_5)
          .hash(RsaHash.sha256)
          .encrypter(pair.publicKey)
          .encrypt(plaintext);

      final recovered = Fortis.rsa()
          .padding(RsaPadding.pkcs1_v1_5)
          .hash(RsaHash.sha256)
          .decrypter(pair.privateKey)
          .decrypt(ciphertext);

      expect(recovered, equals(plaintext));
    });

    // oaep_v1 — SHA-1 based by definition
    test('round-trip: RsaPadding.oaep_v1 + RsaHash.sha1', () {
      final ciphertext = Fortis.rsa()
          .padding(RsaPadding.oaep_v1)
          .hash(RsaHash.sha1)
          .encrypter(pair.publicKey)
          .encrypt(plaintext);

      final recovered = Fortis.rsa()
          .padding(RsaPadding.oaep_v1)
          .hash(RsaHash.sha1)
          .decrypter(pair.privateKey)
          .decrypt(ciphertext);

      expect(recovered, equals(plaintext));
    });

    // oaep_v2 — all hashes
    for (final hash in hashes) {
      test('round-trip: RsaPadding.oaep_v2 + $hash', () {
        final ciphertext = Fortis.rsa()
            .padding(RsaPadding.oaep_v2)
            .hash(hash)
            .encrypter(pair.publicKey)
            .encrypt(plaintext);

        final recovered = Fortis.rsa()
            .padding(RsaPadding.oaep_v2)
            .hash(hash)
            .decrypter(pair.privateKey)
            .decrypt(ciphertext);

        expect(recovered, equals(plaintext));
      });
    }

    // oaep_v2_1 — all hashes
    for (final hash in hashes) {
      test('round-trip: RsaPadding.oaep_v2_1 + $hash', () {
        final ciphertext = Fortis.rsa()
            .padding(RsaPadding.oaep_v2_1)
            .hash(hash)
            .encrypter(pair.publicKey)
            .encrypt(plaintext);

        final recovered = Fortis.rsa()
            .padding(RsaPadding.oaep_v2_1)
            .hash(hash)
            .decrypter(pair.privateKey)
            .decrypt(ciphertext);

        expect(recovered, equals(plaintext));
      });
    }

    // oaep_v2_1 label sub-group (sha256 as representative hash)
    group('RsaPadding.oaep_v2_1 label', () {
      test('matching label succeeds', () {
        final ciphertext = Fortis.rsa()
            .padding(RsaPadding.oaep_v2_1)
            .hash(RsaHash.sha256)
            .encrypter(pair.publicKey, label: 'fortis-label')
            .encrypt(plaintext);

        final recovered = Fortis.rsa()
            .padding(RsaPadding.oaep_v2_1)
            .hash(RsaHash.sha256)
            .decrypter(pair.privateKey, label: 'fortis-label')
            .decrypt(ciphertext);

        expect(recovered, equals(plaintext));
      });

      test('different label throws FortisEncryptionException', () {
        final ciphertext = Fortis.rsa()
            .padding(RsaPadding.oaep_v2_1)
            .hash(RsaHash.sha256)
            .encrypter(pair.publicKey, label: 'fortis-label')
            .encrypt(plaintext);

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
            .encrypt(plaintext);

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
