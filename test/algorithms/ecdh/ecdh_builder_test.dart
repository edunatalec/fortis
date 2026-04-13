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
    test('throws FortisConfigException for invalid key size', () async {
      final pair = await Fortis.ecdh().generateKeyPair();
      expect(
        () => Fortis.ecdh().keySize(0).keyDerivation(pair.privateKey),
        throwsA(isA<FortisConfigException>()),
      );
      expect(
        () => Fortis.ecdh().keySize(7).keyDerivation(pair.privateKey),
        throwsA(isA<FortisConfigException>()),
      );
      expect(
        () => Fortis.ecdh().keySize(-8).keyDerivation(pair.privateKey),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('accepts valid key sizes', () async {
      final pair = await Fortis.ecdh().generateKeyPair();
      for (final size in [8, 128, 192, 256, 512]) {
        expect(
          () => Fortis.ecdh().keySize(size).keyDerivation(pair.privateKey),
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

    test('keySize() returns a new builder instance', () {
      final b1 = Fortis.ecdh();
      final b2 = b1.keySize(128);
      expect(identical(b1, b2), isFalse);
    });
  });
}
