import 'dart:typed_data';

import 'package:fortis/fortis.dart';
import 'package:fortis/src/core/fortis_log.dart';
import 'package:test/test.dart';

void main() {
  late FortisAesKey key;

  setUpAll(() async {
    key = await Fortis.aes().keySize(256).generateKey();
  });

  // ── FortisLog ─────────────────────────────────────────────────────────────

  group('FortisLog', () {
    test('info() does not throw', () {
      expect(() => FortisLog.info('test info message'), returnsNormally);
    });

    test('warn() does not throw', () {
      expect(() => FortisLog.warn('test warning message'), returnsNormally);
    });
  });

  // ── nonceSize() — GCM validation ─────────────────────────────────────────

  group('nonceSize() — GCM validation', () {
    AesAuthModeBuilder gcm() =>
        Fortis.aes().mode(AesMode.gcm) as AesAuthModeBuilder;

    test('nonceSize(12) is valid (default)', () {
      expect(() => gcm().nonceSize(12), returnsNormally);
    });

    test('nonceSize(1) is valid (minimum)', () {
      expect(() => gcm().nonceSize(1), returnsNormally);
    });

    test('nonceSize(16) is valid (no exception)', () {
      expect(() => gcm().nonceSize(16), returnsNormally);
    });

    test('nonceSize(17) is valid but logs a FortisLog.warn', () {
      // Warning is sent to dart:developer; no exception is thrown.
      expect(() => gcm().nonceSize(17), returnsNormally);
    });

    test('nonceSize(0) throws FortisConfigException', () {
      expect(() => gcm().nonceSize(0), throwsA(isA<FortisConfigException>()));
    });

    test('nonceSize(-1) throws FortisConfigException', () {
      expect(() => gcm().nonceSize(-1), throwsA(isA<FortisConfigException>()));
    });
  });

  // ── nonceSize() — CCM validation ─────────────────────────────────────────

  group('nonceSize() — CCM validation', () {
    AesAuthModeBuilder ccm() =>
        Fortis.aes().mode(AesMode.ccm) as AesAuthModeBuilder;

    test('nonceSize(7) is valid (minimum)', () {
      expect(() => ccm().nonceSize(7), returnsNormally);
    });

    test('nonceSize(11) is valid (default)', () {
      expect(() => ccm().nonceSize(11), returnsNormally);
    });

    test('nonceSize(13) is valid (maximum)', () {
      expect(() => ccm().nonceSize(13), returnsNormally);
    });

    test('nonceSize(6) throws FortisConfigException', () {
      expect(() => ccm().nonceSize(6), throwsA(isA<FortisConfigException>()));
    });

    test('nonceSize(14) throws FortisConfigException', () {
      expect(() => ccm().nonceSize(14), throwsA(isA<FortisConfigException>()));
    });
  });

  // Compile-time safety:
  // The lines below would NOT compile because AesBlockModeBuilder and
  // AesStreamModeBuilder do not define nonceSize():
  //
  //   (Fortis.aes().mode(AesMode.cbc) as AesBlockModeBuilder).nonceSize(12);
  //   (Fortis.aes().mode(AesMode.ctr) as AesStreamModeBuilder).nonceSize(12);

  // ── nonceSize() — GCM round-trip ─────────────────────────────────────────

  group('nonceSize() — GCM round-trip', () {
    AesEncrypter encGcm(int size) =>
        (Fortis.aes().mode(AesMode.gcm) as AesAuthModeBuilder)
            .nonceSize(size)
            .encrypter(key);

    AesDecrypter decGcm(int size) =>
        (Fortis.aes().mode(AesMode.gcm) as AesAuthModeBuilder)
            .nonceSize(size)
            .decrypter(key);

    test('nonceSize(12) encrypt → decrypt recovers plaintext', () {
      final cipher = encGcm(12).encrypt('hello fortis');
      expect(decGcm(12).decryptToString(cipher), equals('hello fortis'));
    });

    test('explicit 12-byte iv → decrypt recovers plaintext', () {
      final iv = Uint8List(12);
      final cipher = encGcm(12).encrypt('hello fortis', iv: iv);
      expect(decGcm(12).decryptToString(cipher), equals('hello fortis'));
    });

    test('nonceSize(8) encrypt → nonceSize(8) decrypt recovers plaintext', () {
      final cipher = encGcm(8).encrypt('hello fortis');
      expect(decGcm(8).decryptToString(cipher), equals('hello fortis'));
    });

    test('nonceSize(8) + iv of wrong size throws FortisConfigException', () {
      expect(
        () => encGcm(8).encrypt('hello', iv: Uint8List(12)),
        throwsA(isA<FortisConfigException>()),
      );
    });
  });

  // ── nonceSize() — CCM round-trip ─────────────────────────────────────────

  group('nonceSize() — CCM round-trip', () {
    for (final size in [7, 11, 13]) {
      test('nonceSize($size) encrypt → decrypt recovers plaintext', () {
        final encrypter = (Fortis.aes().mode(AesMode.ccm) as AesAuthModeBuilder)
            .nonceSize(size)
            .encrypter(key);
        final decrypter = (Fortis.aes().mode(AesMode.ccm) as AesAuthModeBuilder)
            .nonceSize(size)
            .decrypter(key);
        final cipher = encrypter.encrypt('hello fortis');
        expect(decrypter.decryptToString(cipher), equals('hello fortis'));
      });
    }
  });
}
