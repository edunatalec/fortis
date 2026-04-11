import 'dart:convert';
import 'dart:typed_data';

import 'package:fortis/fortis.dart';
import 'package:test/test.dart';

void main() {
  test('teste', () async {
    final pair = await Fortis.rsa().keySize(2048).generateKeyPair();

    final encrypter = Fortis.rsa()
        .padding(RsaPadding.oaep_v2_1)
        .hash(RsaHash.sha256)
        .encrypter(pair.publicKey);

    final ciphertext = encrypter.encrypt(
      Uint8List.fromList('Hello World'.codeUnits),
    );

    print(base64.encode(ciphertext));

    final dencrypter = Fortis.rsa()
        .padding(RsaPadding.oaep_v2_1)
        .hash(RsaHash.sha256)
        .decrypter(pair.privateKey);

    final decrypted = dencrypter.decrypt(ciphertext);

    print(String.fromCharCodes(decrypted));
  });

  group('RsaBuilder — key generation', () {
    test('generates RSA-2048 key pair successfully', () async {
      final pair = await Fortis.rsa().keySize(2048).generateKeyPair();

      expect(pair, isNotNull);
    });

    test(
      'generates RSA-4096 key pair successfully',
      () async {
        final pair = await Fortis.rsa().keySize(4096).generateKeyPair();
        expect(pair, isNotNull);
      },
      timeout: const Timeout(Duration(minutes: 3)),
    );

    test('rejects keySize < 2048 with FortisConfigException', () async {
      await expectLater(
        () => Fortis.rsa().keySize(1024).generateKeyPair(),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test(
      'rejects keySize that is not a power of 2 with FortisConfigException',
      () async {
        await expectLater(
          () => Fortis.rsa().keySize(3000).generateKeyPair(),
          throwsA(isA<FortisConfigException>()),
        );
      },
    );

    test(
      'generated key pair contains non-null public and private keys',
      () async {
        final pair = await Fortis.rsa().keySize(2048).generateKeyPair();
        expect(pair.publicKey, isNotNull);
        expect(pair.privateKey, isNotNull);
        expect(pair.publicKey.key, isNotNull);
        expect(pair.privateKey.key, isNotNull);
      },
    );

    test('generates different key pairs on each call', () async {
      final pair1 = await Fortis.rsa().keySize(2048).generateKeyPair();
      final pair2 = await Fortis.rsa().keySize(2048).generateKeyPair();

      expect(
        pair1.publicKey.key.modulus,
        isNot(equals(pair2.publicKey.key.modulus)),
      );
    });
  });
}
