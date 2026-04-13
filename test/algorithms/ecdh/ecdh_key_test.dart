import 'package:fortis/fortis.dart';
import 'package:test/test.dart';

void main() {
  late Map<EcdhCurve, FortisEcdhKeyPair> pairs;

  setUpAll(() async {
    pairs = {};
    for (final curve in EcdhCurve.values) {
      pairs[curve] = await Fortis.ecdh().curve(curve).generateKeyPair();
    }
  });

  group('FortisEcdhPublicKey', () {
    group('X.509 format', () {
      for (final curve in EcdhCurve.values) {
        test('PEM round-trip with ${curve.name}', () {
          final key = pairs[curve]!.publicKey;
          final pem = key.toPem();
          final restored = FortisEcdhPublicKey.fromPem(pem);
          expect(restored.toDerBase64(), equals(key.toDerBase64()));
          expect(restored.curve, curve);
        });

        test('DER round-trip with ${curve.name}', () {
          final key = pairs[curve]!.publicKey;
          final der = key.toDer();
          final restored = FortisEcdhPublicKey.fromDer(der);
          expect(restored.toDerBase64(), equals(key.toDerBase64()));
        });

        test('DerBase64 round-trip with ${curve.name}', () {
          final key = pairs[curve]!.publicKey;
          final b64 = key.toDerBase64();
          final restored = FortisEcdhPublicKey.fromDerBase64(b64);
          expect(restored.toDerBase64(), equals(b64));
        });
      }
    });

    group('uncompressed point format', () {
      for (final curve in EcdhCurve.values) {
        test('DER round-trip with ${curve.name}', () {
          final key = pairs[curve]!.publicKey;
          final raw = key.toDer(format: EcdhPublicKeyFormat.uncompressedPoint);
          final restored = FortisEcdhPublicKey.fromDer(
            raw,
            format: EcdhPublicKeyFormat.uncompressedPoint,
            curve: curve,
          );
          expect(restored.toDerBase64(), equals(key.toDerBase64()));
        });

        test('DerBase64 round-trip with ${curve.name}', () {
          final key = pairs[curve]!.publicKey;
          final b64 = key.toDerBase64(
            format: EcdhPublicKeyFormat.uncompressedPoint,
          );
          final restored = FortisEcdhPublicKey.fromDerBase64(
            b64,
            format: EcdhPublicKeyFormat.uncompressedPoint,
            curve: curve,
          );
          expect(restored.toDerBase64(), equals(key.toDerBase64()));
        });
      }

      test('throws without curve parameter', () {
        final key = pairs[EcdhCurve.p256]!.publicKey;
        final raw = key.toDer(format: EcdhPublicKeyFormat.uncompressedPoint);
        expect(
          () => FortisEcdhPublicKey.fromDer(
            raw,
            format: EcdhPublicKeyFormat.uncompressedPoint,
          ),
          throwsA(isA<FortisKeyException>()),
        );
      });

      test('throws on toPem()', () {
        final key = pairs[EcdhCurve.p256]!.publicKey;
        expect(
          () => key.toPem(format: EcdhPublicKeyFormat.uncompressedPoint),
          throwsA(isA<FortisKeyException>()),
        );
      });
    });

    test('invalid PEM throws FortisKeyException', () {
      expect(
        () => FortisEcdhPublicKey.fromPem('not a valid pem'),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('invalid Base64 throws FortisKeyException', () {
      expect(
        () => FortisEcdhPublicKey.fromDerBase64('!!!invalid!!!'),
        throwsA(isA<FortisKeyException>()),
      );
    });
  });

  group('FortisEcdhPrivateKey', () {
    group('PKCS#8 format', () {
      for (final curve in EcdhCurve.values) {
        test('PEM round-trip with ${curve.name}', () {
          final key = pairs[curve]!.privateKey;
          final pem = key.toPem();
          final restored = FortisEcdhPrivateKey.fromPem(pem);
          expect(restored.toDerBase64(), equals(key.toDerBase64()));
          expect(restored.curve, curve);
        });

        test('DER round-trip with ${curve.name}', () {
          final key = pairs[curve]!.privateKey;
          final der = key.toDer();
          final restored = FortisEcdhPrivateKey.fromDer(der);
          expect(restored.toDerBase64(), equals(key.toDerBase64()));
        });

        test('DerBase64 round-trip with ${curve.name}', () {
          final key = pairs[curve]!.privateKey;
          final b64 = key.toDerBase64();
          final restored = FortisEcdhPrivateKey.fromDerBase64(b64);
          expect(restored.toDerBase64(), equals(b64));
        });
      }
    });

    group('SEC1 format', () {
      for (final curve in EcdhCurve.values) {
        test('PEM round-trip with ${curve.name}', () {
          final key = pairs[curve]!.privateKey;
          final pem = key.toPem(format: EcdhPrivateKeyFormat.sec1);
          final restored = FortisEcdhPrivateKey.fromPem(
            pem,
            format: EcdhPrivateKeyFormat.sec1,
          );
          expect(restored.toDerBase64(), equals(key.toDerBase64()));
        });

        test('DER round-trip with ${curve.name}', () {
          final key = pairs[curve]!.privateKey;
          final der = key.toDer(format: EcdhPrivateKeyFormat.sec1);
          final restored = FortisEcdhPrivateKey.fromDer(
            der,
            format: EcdhPrivateKeyFormat.sec1,
          );
          expect(restored.toDerBase64(), equals(key.toDerBase64()));
        });

        test('DerBase64 round-trip with ${curve.name}', () {
          final key = pairs[curve]!.privateKey;
          final b64 = key.toDerBase64(format: EcdhPrivateKeyFormat.sec1);
          final restored = FortisEcdhPrivateKey.fromDerBase64(
            b64,
            format: EcdhPrivateKeyFormat.sec1,
          );
          expect(restored.toDerBase64(), equals(key.toDerBase64()));
        });
      }
    });

    test('invalid PEM throws FortisKeyException', () {
      expect(
        () => FortisEcdhPrivateKey.fromPem('not a valid pem'),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('invalid Base64 throws FortisKeyException', () {
      expect(
        () => FortisEcdhPrivateKey.fromDerBase64('!!!invalid!!!'),
        throwsA(isA<FortisKeyException>()),
      );
    });
  });
}
