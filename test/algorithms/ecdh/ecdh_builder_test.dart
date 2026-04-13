import 'package:fortis/fortis.dart';
import 'package:test/test.dart';

void main() {
  group('generateKeyPair()', () {
    test('generates a key pair with P-256 by default', () async {
      final pair = await Fortis.ecdh().generateKeyPair();
      expect(pair.publicKey.curve, EcdhCurve.p256);
      expect(pair.privateKey.curve, EcdhCurve.p256);
    });

    for (final curve in EcdhCurve.values) {
      test('generates a key pair with ${curve.name}', () async {
        final pair = await Fortis.ecdh().curve(curve).generateKeyPair();
        expect(pair.publicKey.curve, curve);
        expect(pair.privateKey.curve, curve);
      });
    }

    test('two generated key pairs are different', () async {
      final pair1 = await Fortis.ecdh().generateKeyPair();
      final pair2 = await Fortis.ecdh().generateKeyPair();
      expect(
        pair1.publicKey.toDerBase64(),
        isNot(equals(pair2.publicKey.toDerBase64())),
      );
    });
  });

  group('keyDerivation()', () {
    test('throws FortisConfigException for invalid AES key size', () async {
      final pair = await Fortis.ecdh().generateKeyPair();
      expect(
        () => Fortis.ecdh().aesKeySize(512).keyDerivation(pair.privateKey),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('accepts valid AES key sizes (128, 192, 256)', () async {
      final pair = await Fortis.ecdh().generateKeyPair();
      for (final size in [128, 192, 256]) {
        expect(
          () => Fortis.ecdh().aesKeySize(size).keyDerivation(pair.privateKey),
          returnsNormally,
        );
      }
    });
  });

  group('builder immutability', () {
    test('curve() returns a new builder instance', () {
      final b1 = Fortis.ecdh();
      final b2 = b1.curve(EcdhCurve.p384);
      expect(identical(b1, b2), isFalse);
    });

    test('aesKeySize() returns a new builder instance', () {
      final b1 = Fortis.ecdh();
      final b2 = b1.aesKeySize(128);
      expect(identical(b1, b2), isFalse);
    });
  });
}
