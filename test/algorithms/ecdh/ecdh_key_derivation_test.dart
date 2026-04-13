import 'dart:typed_data';

import 'package:fortis/fortis.dart';
import 'package:test/test.dart';

void main() {
  late FortisEcdhKeyPair alice;
  late FortisEcdhKeyPair bob;

  setUpAll(() async {
    alice = await Fortis.ecdh().curve(EcdhCurve.p256).generateKeyPair();
    bob = await Fortis.ecdh().curve(EcdhCurve.p256).generateKeyPair();
  });

  group('deriveSharedSecret()', () {
    test('both sides derive the same shared secret', () {
      final aliceDerivation = Fortis.ecdh().keyDerivation(alice.privateKey);
      final bobDerivation = Fortis.ecdh().keyDerivation(bob.privateKey);

      final aliceSecret = aliceDerivation.deriveSharedSecret(bob.publicKey);
      final bobSecret = bobDerivation.deriveSharedSecret(alice.publicKey);

      expect(aliceSecret, equals(bobSecret));
    });

    test('shared secret has correct length for P-256', () {
      final derivation = Fortis.ecdh().keyDerivation(alice.privateKey);
      final secret = derivation.deriveSharedSecret(bob.publicKey);
      expect(secret.length, EcdhCurve.p256.fieldSizeBytes);
    });

    for (final curve in EcdhCurve.values) {
      test('works with ${curve.name}', () async {
        final a = await Fortis.ecdh().curve(curve).generateKeyPair();
        final b = await Fortis.ecdh().curve(curve).generateKeyPair();

        final secretA = Fortis.ecdh()
            .keyDerivation(a.privateKey)
            .deriveSharedSecret(b.publicKey);
        final secretB = Fortis.ecdh()
            .keyDerivation(b.privateKey)
            .deriveSharedSecret(a.publicKey);

        expect(secretA, equals(secretB));
        expect(secretA.length, curve.fieldSizeBytes);
      });
    }

    test('different key pairs produce different shared secrets', () async {
      final charlie = await Fortis.ecdh()
          .curve(EcdhCurve.p256)
          .generateKeyPair();

      final secretWithBob = Fortis.ecdh()
          .keyDerivation(alice.privateKey)
          .deriveSharedSecret(bob.publicKey);
      final secretWithCharlie = Fortis.ecdh()
          .keyDerivation(alice.privateKey)
          .deriveSharedSecret(charlie.publicKey);

      expect(secretWithBob, isNot(equals(secretWithCharlie)));
    });

    test('throws FortisKeyException for mismatched curves', () async {
      final p384Pair = await Fortis.ecdh()
          .curve(EcdhCurve.p384)
          .generateKeyPair();

      final derivation = Fortis.ecdh().keyDerivation(alice.privateKey);
      expect(
        () => derivation.deriveSharedSecret(p384Pair.publicKey),
        throwsA(isA<FortisKeyException>()),
      );
    });
  });

  group('deriveKey()', () {
    test('returns a valid FortisAesKey with default size (256)', () {
      final derivation = Fortis.ecdh().keyDerivation(alice.privateKey);
      final aesKey = derivation.deriveKey(bob.publicKey);
      expect(aesKey.keySize, 256);
    });

    for (final size in [128, 192, 256]) {
      test('returns AES-$size key', () {
        final derivation = Fortis.ecdh()
            .aesKeySize(size)
            .keyDerivation(alice.privateKey);
        final aesKey = derivation.deriveKey(bob.publicKey);
        expect(aesKey.keySize, size);
      });
    }

    test('both sides derive the same AES key', () {
      final aliceKey = Fortis.ecdh()
          .keyDerivation(alice.privateKey)
          .deriveKey(bob.publicKey);
      final bobKey = Fortis.ecdh()
          .keyDerivation(bob.privateKey)
          .deriveKey(alice.publicKey);

      expect(aliceKey.toBase64(), equals(bobKey.toBase64()));
    });

    test('different salt produces different keys', () {
      final derivation = Fortis.ecdh().keyDerivation(alice.privateKey);
      final key1 = derivation.deriveKey(
        bob.publicKey,
        salt: Uint8List.fromList([1, 2, 3]),
      );
      final key2 = derivation.deriveKey(
        bob.publicKey,
        salt: Uint8List.fromList([4, 5, 6]),
      );
      expect(key1.toBase64(), isNot(equals(key2.toBase64())));
    });

    test('different info produces different keys', () {
      final derivation = Fortis.ecdh().keyDerivation(alice.privateKey);
      final key1 = derivation.deriveKey(
        bob.publicKey,
        info: Uint8List.fromList('context-a'.codeUnits),
      );
      final key2 = derivation.deriveKey(
        bob.publicKey,
        info: Uint8List.fromList('context-b'.codeUnits),
      );
      expect(key1.toBase64(), isNot(equals(key2.toBase64())));
    });
  });

  group('hkdfDeriveKey()', () {
    test('same input produces same output (deterministic)', () {
      final secret = Uint8List.fromList(List.filled(32, 0xAB));
      final key1 = EcdhKeyDerivation.hkdfDeriveKey(secret);
      final key2 = EcdhKeyDerivation.hkdfDeriveKey(secret);
      expect(key1.toBase64(), equals(key2.toBase64()));
    });

    test('different shared secrets produce different keys', () {
      final secret1 = Uint8List.fromList(List.filled(32, 0xAB));
      final secret2 = Uint8List.fromList(List.filled(32, 0xCD));
      final key1 = EcdhKeyDerivation.hkdfDeriveKey(secret1);
      final key2 = EcdhKeyDerivation.hkdfDeriveKey(secret2);
      expect(key1.toBase64(), isNot(equals(key2.toBase64())));
    });

    test('throws FortisConfigException for invalid AES key size', () {
      final secret = Uint8List.fromList(List.filled(32, 0xAB));
      expect(
        () => EcdhKeyDerivation.hkdfDeriveKey(secret, aesKeySize: 64),
        throwsA(isA<FortisConfigException>()),
      );
    });

    for (final size in [128, 192, 256]) {
      test('produces AES-$size key', () {
        final secret = Uint8List.fromList(List.filled(32, 0xAB));
        final key = EcdhKeyDerivation.hkdfDeriveKey(secret, aesKeySize: size);
        expect(key.keySize, size);
      });
    }
  });

  group('end-to-end: ECDH + AES', () {
    test('Alice encrypts with AES, Bob decrypts', () {
      final aliceAesKey = Fortis.ecdh()
          .keyDerivation(alice.privateKey)
          .deriveKey(bob.publicKey);
      final bobAesKey = Fortis.ecdh()
          .keyDerivation(bob.privateKey)
          .deriveKey(alice.publicKey);

      final cipher = Fortis.aes().mode(AesMode.gcm).cipher(aliceAesKey);
      final plaintext = 'my-secret-password-123';
      final encrypted = cipher.encryptToString(plaintext);

      final decryptCipher = Fortis.aes().mode(AesMode.gcm).cipher(bobAesKey);
      final decrypted = decryptCipher.decryptToString(encrypted);

      expect(decrypted, equals(plaintext));
    });
  });
}
