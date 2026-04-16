import 'dart:typed_data';

import 'package:fortis/fortis.dart';
import 'package:fortis/src/core/fortis_log.dart';
import 'package:test/test.dart';

void main() {
  late FortisAesKey key;

  setUpAll(() async {
    key = await Fortis.aes().keySize(256).generateKey();
  });

  group('FortisLog', () {
    test('info() does not throw', () {
      expect(() => FortisLog.info('test info message'), returnsNormally);
    });

    test('warn() does not throw', () {
      expect(() => FortisLog.warn('test warning message'), returnsNormally);
    });
  });

  group('ivSize() — GCM validation', () {
    AesGcmModeBuilder gcm() =>
        Fortis.aes().mode(AesMode.gcm) as AesGcmModeBuilder;

    test('ivSize(12) is valid (default)', () {
      expect(() => gcm().ivSize(12), returnsNormally);
    });

    test('ivSize(1) is valid (minimum)', () {
      expect(() => gcm().ivSize(1), returnsNormally);
    });

    test('ivSize(16) is valid (no exception)', () {
      expect(() => gcm().ivSize(16), returnsNormally);
    });

    test('ivSize(17) is valid but logs a FortisLog.warn', () {
      // Warning is sent to dart:developer; no exception is thrown.
      expect(() => gcm().ivSize(17), returnsNormally);
    });

    test('ivSize(0) throws FortisConfigException', () {
      expect(() => gcm().ivSize(0), throwsA(isA<FortisConfigException>()));
    });

    test('ivSize(-1) throws FortisConfigException', () {
      expect(() => gcm().ivSize(-1), throwsA(isA<FortisConfigException>()));
    });
  });

  group('ivSize() — CCM validation', () {
    AesCcmModeBuilder ccm() =>
        Fortis.aes().mode(AesMode.ccm) as AesCcmModeBuilder;

    test('ivSize(7) is valid (minimum)', () {
      expect(() => ccm().ivSize(7), returnsNormally);
    });

    test('ivSize(11) is valid (default)', () {
      expect(() => ccm().ivSize(11), returnsNormally);
    });

    test('ivSize(13) is valid (maximum)', () {
      expect(() => ccm().ivSize(13), returnsNormally);
    });

    test('ivSize(6) throws FortisConfigException', () {
      expect(() => ccm().ivSize(6), throwsA(isA<FortisConfigException>()));
    });

    test('ivSize(14) throws FortisConfigException', () {
      expect(() => ccm().ivSize(14), throwsA(isA<FortisConfigException>()));
    });
  });

  // Compile-time safety (these would fail to compile):
  //   Fortis.aes().cbc().ivSize(12);      // ivSize not on CBC/stream builders
  //   Fortis.aes().gcm().tagSize(96);     // tagSize not on GCM (fixed at 128)

  group('ivSize() — GCM round-trip', () {
    AesCipher gcmCipher(int size) =>
        (Fortis.aes().mode(AesMode.gcm) as AesGcmModeBuilder)
            .ivSize(size)
            .cipher(key);

    test('ivSize(12) encrypt → decrypt recovers plaintext', () {
      final c = gcmCipher(12);
      final ciphertext = c.encrypt('hello fortis');
      expect(c.decryptToString(ciphertext), equals('hello fortis'));
    });

    test('explicit 12-byte iv → decrypt recovers plaintext', () {
      final c = gcmCipher(12);
      final iv = Uint8List(12);
      final ciphertext = c.encrypt('hello fortis', iv: iv);
      expect(c.decryptToString(ciphertext), equals('hello fortis'));
    });

    test('ivSize(8) encrypt → ivSize(8) decrypt recovers plaintext', () {
      final c = gcmCipher(8);
      final ciphertext = c.encrypt('hello fortis');
      expect(c.decryptToString(ciphertext), equals('hello fortis'));
    });

    test('ivSize(8) + iv of wrong size throws FortisConfigException', () {
      expect(
        () => gcmCipher(8).encrypt('hello', iv: Uint8List(12)),
        throwsA(isA<FortisConfigException>()),
      );
    });
  });

  group('ivSize() — CCM round-trip', () {
    for (final size in [7, 11, 13]) {
      test('ivSize($size) encrypt → decrypt recovers plaintext', () {
        final c = (Fortis.aes().mode(AesMode.ccm) as AesCcmModeBuilder)
            .ivSize(size)
            .cipher(key);
        final ciphertext = c.encrypt('hello fortis');
        expect(c.decryptToString(ciphertext), equals('hello fortis'));
      });
    }
  });

  group('tagSize() — CCM', () {
    test('tagSize(96) round-trip', () {
      final c = Fortis.aes().ccm().tagSize(96).cipher(key);
      final ct = c.encrypt('hello fortis');
      expect(c.decryptToString(ct), equals('hello fortis'));
    });

    test('tagSize(64) round-trip', () {
      final c = Fortis.aes().ccm().tagSize(64).cipher(key);
      final ct = c.encrypt('hello fortis');
      expect(c.decryptToString(ct), equals('hello fortis'));
    });

    test('all NIST-valid sizes round-trip', () {
      for (final bits in [32, 48, 64, 80, 96, 112, 128]) {
        final c = Fortis.aes().ccm().tagSize(bits).cipher(key);
        final ct = c.encrypt('hello fortis');
        expect(
          c.decryptToString(ct),
          equals('hello fortis'),
          reason: 'tagSize=$bits',
        );
      }
    });

    test('tagSize(65) throws FortisConfigException', () {
      expect(
        () => Fortis.aes().ccm().tagSize(65),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('tagSize(0) throws FortisConfigException', () {
      expect(
        () => Fortis.aes().ccm().tagSize(0),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('tagSize(-1) throws FortisConfigException', () {
      expect(
        () => Fortis.aes().ccm().tagSize(-1),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('tagSize(256) throws FortisConfigException', () {
      expect(
        () => Fortis.aes().ccm().tagSize(256),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('tagSize + aad + ivSize chained round-trip', () {
      final aad = Uint8List.fromList([1, 2, 3, 4]);
      final c = Fortis.aes().ccm().tagSize(96).aad(aad).ivSize(11).cipher(key);
      final ct = c.encrypt('hello fortis');
      expect(c.decryptToString(ct), equals('hello fortis'));
    });
  });
}
