import 'dart:typed_data';

import 'package:fortis/fortis.dart';
import 'package:test/test.dart';

void main() {
  late FortisRsaKeyPair pair;

  setUpAll(() async {
    pair = await Fortis.rsa().keySize(2048).generateKeyPair();
  });

  final plaintext = Uint8List.fromList('round-trip test'.codeUnits);

  // ---------------------------------------------------------------------------
  // Padding round-trips
  // ---------------------------------------------------------------------------

  group('Padding round-trips', () {
    for (final padding in [
      RsaPadding.pkcs1_v1_5,
      RsaPadding.oaep_v1,
      RsaPadding.oaep_v2,
    ]) {
      test('$padding with sha256 — encrypt → decrypt → equal', () {
        final encrypter = Fortis.rsa()
            .padding(padding)
            .hash(RsaHash.sha256)
            .encrypter(pair.publicKey);
        final decrypter = Fortis.rsa()
            .padding(padding)
            .hash(RsaHash.sha256)
            .decrypter(pair.privateKey);

        final ciphertext = encrypter.encrypt(plaintext);
        final recovered = decrypter.decrypt(ciphertext);
        expect(recovered, equals(plaintext));
      });
    }

    test('oaep_v2_1 without label — encrypt → decrypt → equal', () {
      final encrypter = Fortis.rsa()
          .padding(RsaPadding.oaep_v2_1)
          .hash(RsaHash.sha256)
          .encrypter(pair.publicKey);
      final decrypter = Fortis.rsa()
          .padding(RsaPadding.oaep_v2_1)
          .hash(RsaHash.sha256)
          .decrypter(pair.privateKey);

      final ciphertext = encrypter.encrypt(plaintext);
      final recovered = decrypter.decrypt(ciphertext);
      expect(recovered, equals(plaintext));
    });
  });

  // ---------------------------------------------------------------------------
  // Hash round-trips (OAEP v2)
  // ---------------------------------------------------------------------------

  group('Hash round-trips with oaep_v2', () {
    for (final hash in RsaHash.values) {
      test('oaep_v2 + $hash — encrypt → decrypt → equal', () {
        final encrypter = Fortis.rsa()
            .padding(RsaPadding.oaep_v2)
            .hash(hash)
            .encrypter(pair.publicKey);
        final decrypter = Fortis.rsa()
            .padding(RsaPadding.oaep_v2)
            .hash(hash)
            .decrypter(pair.privateKey);

        final ciphertext = encrypter.encrypt(plaintext);
        final recovered = decrypter.decrypt(ciphertext);
        expect(recovered, equals(plaintext));
      });
    }
  });

  // ---------------------------------------------------------------------------
  // OAEP v2.1 label support
  // ---------------------------------------------------------------------------

  group('OAEP v2.1 — label support', () {
    test('String label — encrypt → decrypt → equal', () {
      const labelStr = 'my-label';
      final encrypter = Fortis.rsa()
          .padding(RsaPadding.oaep_v2_1)
          .hash(RsaHash.sha256)
          .encrypter(pair.publicKey, label: labelStr);
      final decrypter = Fortis.rsa()
          .padding(RsaPadding.oaep_v2_1)
          .hash(RsaHash.sha256)
          .decrypter(pair.privateKey, label: labelStr);

      final ciphertext = encrypter.encrypt(plaintext);
      final recovered = decrypter.decrypt(ciphertext);
      expect(recovered, equals(plaintext));
    });

    test('Uint8List label — encrypt → decrypt → equal', () {
      final labelBytes = Uint8List.fromList('binary-label'.codeUnits);
      final encrypter = Fortis.rsa()
          .padding(RsaPadding.oaep_v2_1)
          .hash(RsaHash.sha256)
          .encrypter(pair.publicKey, label: labelBytes);
      final decrypter = Fortis.rsa()
          .padding(RsaPadding.oaep_v2_1)
          .hash(RsaHash.sha256)
          .decrypter(pair.privateKey, label: labelBytes);

      final ciphertext = encrypter.encrypt(plaintext);
      final recovered = decrypter.decrypt(ciphertext);
      expect(recovered, equals(plaintext));
    });

    test('wrong label causes FortisEncryptionException on decrypt', () {
      final encrypter = Fortis.rsa()
          .padding(RsaPadding.oaep_v2_1)
          .hash(RsaHash.sha256)
          .encrypter(pair.publicKey, label: 'correct-label');
      final decrypter = Fortis.rsa()
          .padding(RsaPadding.oaep_v2_1)
          .hash(RsaHash.sha256)
          .decrypter(pair.privateKey, label: 'wrong-label');

      final ciphertext = encrypter.encrypt(plaintext);
      expect(
        () => decrypter.decrypt(ciphertext),
        throwsA(isA<FortisEncryptionException>()),
      );
    });

    test('label with non-v2.1 padding throws FortisConfigException', () {
      expect(
        () => Fortis.rsa()
            .padding(RsaPadding.oaep_v2)
            .hash(RsaHash.sha256)
            .encrypter(pair.publicKey, label: 'label'),
        throwsA(isA<FortisConfigException>()),
      );
    });
  });
}
