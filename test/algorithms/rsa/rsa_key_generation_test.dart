import 'dart:convert';

import 'package:fortis/fortis.dart';
import 'package:test/test.dart';

void main() {
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

  group('FortisRsaPublicKey — Base64 serialization', () {
    late FortisRsaKeyPair pair;

    setUpAll(() async {
      pair = await Fortis.rsa().keySize(2048).generateKeyPair();
    });

    test('toDerBase64 returns a non-empty Base64 string', () {
      final b64 = pair.publicKey.toDerBase64();
      expect(b64, isNotEmpty);
      // A valid Base64 string decodes without error
      expect(() => base64Decode(b64), returnsNormally);
    });

    test(
      'round-trip: toDerBase64 → fromDerBase64 → toDerBase64 equals original',
      () {
        final original = pair.publicKey.toDerBase64();
        final restored = FortisRsaPublicKey.fromDerBase64(original);
        expect(restored.toDerBase64(), equals(original));
      },
    );

    test(
      'fromDerBase64 with invalid Base64 string throws FortisKeyException',
      () {
        expect(
          () => FortisRsaPublicKey.fromDerBase64('not-valid-base64!!!'),
          throwsA(isA<FortisKeyException>()),
        );
      },
    );
  });

  group('FortisRsaPrivateKey — Base64 serialization', () {
    late FortisRsaKeyPair pair;

    setUpAll(() async {
      pair = await Fortis.rsa().keySize(2048).generateKeyPair();
    });

    test('toDerBase64 returns a non-empty Base64 string', () {
      final b64 = pair.privateKey.toDerBase64();
      expect(b64, isNotEmpty);
      expect(() => base64Decode(b64), returnsNormally);
    });

    test(
      'round-trip: toDerBase64 → fromDerBase64 → toDerBase64 equals original',
      () {
        final original = pair.privateKey.toDerBase64();
        final restored = FortisRsaPrivateKey.fromDerBase64(original);
        expect(restored.toDerBase64(), equals(original));
      },
    );

    test(
      'fromDerBase64 with invalid Base64 string throws FortisKeyException',
      () {
        expect(
          () => FortisRsaPrivateKey.fromDerBase64('not-valid-base64!!!'),
          throwsA(isA<FortisKeyException>()),
        );
      },
    );
  });
}
