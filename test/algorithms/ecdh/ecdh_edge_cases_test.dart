import 'dart:typed_data';

import 'package:fortis/fortis.dart';
import 'package:test/test.dart';

void main() {
  late FortisEcdhKeyPair p256Pair;
  late FortisEcdhKeyPair p384Pair;
  late FortisEcdhKeyPair p521Pair;

  setUpAll(() async {
    p256Pair = await Fortis.ecdh().curve(EcdhCurve.p256).generateKeyPair();
    p384Pair = await Fortis.ecdh().curve(EcdhCurve.p384).generateKeyPair();
    p521Pair = await Fortis.ecdh().curve(EcdhCurve.p521).generateKeyPair();
  });

  group('keySize boundaries', () {
    test(
      'keySize(1) throws FortisConfigException (not a multiple of 8)',
      () async {
        final pair = await Fortis.ecdh().generateKeyPair();
        expect(
          () => Fortis.ecdh().keySize(1).keyDerivation(pair.privateKey),
          throwsA(isA<FortisConfigException>()),
        );
      },
    );

    test('keySize(9) throws FortisConfigException', () async {
      final pair = await Fortis.ecdh().generateKeyPair();
      expect(
        () => Fortis.ecdh().keySize(9).keyDerivation(pair.privateKey),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('keySize(-256) throws FortisConfigException', () async {
      final pair = await Fortis.ecdh().generateKeyPair();
      expect(
        () => Fortis.ecdh().keySize(-256).keyDerivation(pair.privateKey),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('keySize(8) is the minimum valid size', () async {
      final pair = await Fortis.ecdh().generateKeyPair();
      expect(
        () => Fortis.ecdh().keySize(8).keyDerivation(pair.privateKey),
        returnsNormally,
      );
    });
  });

  group('cross-curve rejection', () {
    test('deriveSharedSecret: P-256 private + P-384 public throws', () {
      final d = Fortis.ecdh().keyDerivation(p256Pair.privateKey);
      expect(
        () => d.deriveSharedSecret(p384Pair.publicKey),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('deriveKey: P-256 private + P-521 public throws', () {
      final d = Fortis.ecdh().keyDerivation(p256Pair.privateKey);
      expect(
        () => d.deriveKey(p521Pair.publicKey),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('deriveAesKey: P-384 private + P-256 public throws', () {
      final d = Fortis.ecdh().keyDerivation(p384Pair.privateKey);
      expect(
        () => d.deriveAesKey(p256Pair.publicKey),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('deriveAesKey: P-521 private + P-384 public throws', () {
      final d = Fortis.ecdh().keyDerivation(p521Pair.privateKey);
      expect(
        () => d.deriveAesKey(p384Pair.publicKey),
        throwsA(isA<FortisKeyException>()),
      );
    });
  });

  group('deriveAesKey — key size validation', () {
    test('keySize(64) throws (not a valid AES size)', () {
      final d = Fortis.ecdh().keySize(64).keyDerivation(p256Pair.privateKey);
      expect(
        () => d.deriveAesKey(p256Pair.publicKey),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('keySize(384) throws (not a valid AES size)', () {
      final d = Fortis.ecdh().keySize(384).keyDerivation(p256Pair.privateKey);
      expect(
        () => d.deriveAesKey(p256Pair.publicKey),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('keySize(1024) throws (too large for AES)', () {
      final d = Fortis.ecdh().keySize(1024).keyDerivation(p256Pair.privateKey);
      expect(
        () => d.deriveAesKey(p256Pair.publicKey),
        throwsA(isA<FortisConfigException>()),
      );
    });
  });

  group('HKDF static — invalid key sizes', () {
    final secret = Uint8List.fromList(List.filled(32, 0x01));

    test('hkdf(keySize: 0) throws', () {
      expect(
        () => EcdhKeyDerivation.hkdf(secret, keySize: 0),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('hkdf(keySize: -128) throws', () {
      expect(
        () => EcdhKeyDerivation.hkdf(secret, keySize: -128),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('hkdf(keySize: 13) throws (not multiple of 8)', () {
      expect(
        () => EcdhKeyDerivation.hkdf(secret, keySize: 13),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('hkdfDeriveAesKey(keySize: 512) throws (not AES size)', () {
      expect(
        () => EcdhKeyDerivation.hkdfDeriveAesKey(secret, keySize: 512),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('hkdfDeriveAesKey(keySize: 100) throws', () {
      expect(
        () => EcdhKeyDerivation.hkdfDeriveAesKey(secret, keySize: 100),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('hkdf with empty secret returns a key (not an error)', () {
      // HKDF accepts any IKM length, including zero.
      final out = EcdhKeyDerivation.hkdf(Uint8List(0));
      expect(out.length, 32);
    });

    test('hkdf with null salt and info uses defaults (deterministic)', () {
      final a = EcdhKeyDerivation.hkdf(secret);
      final b = EcdhKeyDerivation.hkdf(secret);
      expect(a, equals(b));
    });

    test('hkdf with empty salt vs no salt produces same output', () {
      final a = EcdhKeyDerivation.hkdf(secret);
      final b = EcdhKeyDerivation.hkdf(secret, salt: Uint8List(0));
      expect(a, equals(b));
    });
  });

  group('public key format — cross-format rejection', () {
    test('uncompressedPoint import without curve throws', () {
      final raw = p256Pair.publicKey.toDer(
        format: EcdhPublicKeyFormat.uncompressedPoint,
      );
      expect(
        () => FortisEcdhPublicKey.fromDer(
          raw,
          format: EcdhPublicKeyFormat.uncompressedPoint,
        ),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('uncompressedPoint toPem throws FortisKeyException', () {
      expect(
        () => p256Pair.publicKey.toPem(
          format: EcdhPublicKeyFormat.uncompressedPoint,
        ),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('X.509 DER imported as uncompressedPoint throws', () {
      final der = p256Pair.publicKey.toDer(); // X.509
      expect(
        () => FortisEcdhPublicKey.fromDer(
          der,
          format: EcdhPublicKeyFormat.uncompressedPoint,
          curve: EcdhCurve.p256,
        ),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('uncompressedPoint imported with wrong curve throws', () {
      final raw = p256Pair.publicKey.toDer(
        format: EcdhPublicKeyFormat.uncompressedPoint,
      );
      // Point belongs to p256 but we tell it it's p521 — the byte layout
      // doesn't line up.
      expect(
        () => FortisEcdhPublicKey.fromDer(
          raw,
          format: EcdhPublicKeyFormat.uncompressedPoint,
          curve: EcdhCurve.p521,
        ),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('empty PEM throws FortisKeyException', () {
      expect(
        () => FortisEcdhPublicKey.fromPem(''),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('empty DER throws FortisKeyException', () {
      expect(
        () => FortisEcdhPublicKey.fromDer(Uint8List(0)),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('garbage PEM body throws FortisKeyException', () {
      const badPem =
          '-----BEGIN PUBLIC KEY-----\n'
          'not-real-base64!!!\n'
          '-----END PUBLIC KEY-----';
      expect(
        () => FortisEcdhPublicKey.fromPem(badPem),
        throwsA(isA<FortisKeyException>()),
      );
    });
  });

  group('private key format — cross-format rejection', () {
    test('PKCS#8 PEM imported as SEC1 throws', () {
      final pem = p256Pair.privateKey.toPem(); // PKCS#8
      expect(
        () => FortisEcdhPrivateKey.fromPem(
          pem,
          format: EcdhPrivateKeyFormat.sec1,
        ),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('SEC1 PEM imported as PKCS#8 throws', () {
      final pem = p256Pair.privateKey.toPem(format: EcdhPrivateKeyFormat.sec1);
      expect(
        () => FortisEcdhPrivateKey.fromPem(pem),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('garbage PEM body throws FortisKeyException', () {
      expect(
        () => FortisEcdhPrivateKey.fromPem('nonsense'),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('empty DER throws FortisKeyException', () {
      expect(
        () => FortisEcdhPrivateKey.fromDer(Uint8List(0)),
        throwsA(isA<FortisKeyException>()),
      );
    });
  });

  group('FortisEcdhKeyPair integrity', () {
    test('publicKey and privateKey use the same curve', () async {
      for (final curve in EcdhCurve.values) {
        final pair = await Fortis.ecdh().curve(curve).generateKeyPair();
        expect(pair.publicKey.curve, equals(curve));
        expect(pair.privateKey.curve, equals(curve));
      }
    });

    test(
      'two pairs have different public keys (overwhelmingly likely)',
      () async {
        final a = await Fortis.ecdh().generateKeyPair();
        final b = await Fortis.ecdh().generateKeyPair();
        expect(
          a.publicKey.toDerBase64(),
          isNot(equals(b.publicKey.toDerBase64())),
        );
      },
    );
  });

  group('EcdhCurve.fromOid — unknown OIDs', () {
    test('returns null for empty string', () {
      expect(EcdhCurve.fromOid(''), isNull);
    });

    test('returns null for unknown OID', () {
      expect(EcdhCurve.fromOid('1.2.3.4.5'), isNull);
    });

    test('returns p256 for known OID', () {
      expect(EcdhCurve.fromOid('1.2.840.10045.3.1.7'), equals(EcdhCurve.p256));
    });

    test('returns p384 for known OID', () {
      expect(EcdhCurve.fromOid('1.3.132.0.34'), equals(EcdhCurve.p384));
    });

    test('returns p521 for known OID', () {
      expect(EcdhCurve.fromOid('1.3.132.0.35'), equals(EcdhCurve.p521));
    });
  });
}
