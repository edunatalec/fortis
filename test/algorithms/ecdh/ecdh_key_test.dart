import 'package:fortis/fortis.dart';
import 'package:pointycastle/ecc/api.dart';
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

  group('constructor — key↔curve mismatch', () {
    test('FortisEcdhPublicKey: P-256 key declared as P-384 throws', () {
      final p256Key = pairs[EcdhCurve.p256]!.publicKey.key;
      expect(
        () => FortisEcdhPublicKey(p256Key, EcdhCurve.p384),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('FortisEcdhPublicKey: P-521 key declared as P-256 throws', () {
      final p521Key = pairs[EcdhCurve.p521]!.publicKey.key;
      expect(
        () => FortisEcdhPublicKey(p521Key, EcdhCurve.p256),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('FortisEcdhPublicKey: matching key+curve constructs normally', () {
      for (final curve in EcdhCurve.values) {
        final k = pairs[curve]!.publicKey.key;
        expect(
          () => FortisEcdhPublicKey(k, curve),
          returnsNormally,
          reason: 'curve=$curve',
        );
      }
    });

    test('FortisEcdhPrivateKey: P-256 key declared as P-384 throws', () {
      final p256Key = pairs[EcdhCurve.p256]!.privateKey.key;
      expect(
        () => FortisEcdhPrivateKey(p256Key, EcdhCurve.p384),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('FortisEcdhPrivateKey: P-384 key declared as P-521 throws', () {
      final p384Key = pairs[EcdhCurve.p384]!.privateKey.key;
      expect(
        () => FortisEcdhPrivateKey(p384Key, EcdhCurve.p521),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('FortisEcdhPrivateKey: matching key+curve constructs normally', () {
      for (final curve in EcdhCurve.values) {
        final k = pairs[curve]!.privateKey.key;
        expect(
          () => FortisEcdhPrivateKey(k, curve),
          returnsNormally,
          reason: 'curve=$curve',
        );
      }
    });

    test('ECPrivateKey with null parameters throws FortisKeyException', () {
      // PointyCastle allows a bare ECPrivateKey(d) with no domain params.
      final keyWithoutParams = ECPrivateKey(BigInt.one, null);
      expect(
        () => FortisEcdhPrivateKey(keyWithoutParams, EcdhCurve.p256),
        throwsA(isA<FortisKeyException>()),
      );
    });
  });
}
