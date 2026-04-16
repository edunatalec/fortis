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
    AesAuthModeBuilder gcm() =>
        Fortis.aes().mode(AesMode.gcm) as AesAuthModeBuilder;

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
    AesAuthModeBuilder ccm() =>
        Fortis.aes().mode(AesMode.ccm) as AesAuthModeBuilder;

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

  // Compile-time safety:
  // The lines below would NOT compile because AesCbcModeBuilder and
  // AesStreamModeBuilder do not define ivSize():
  //
  //   (Fortis.aes().mode(AesMode.cbc) as AesCbcModeBuilder).ivSize(12);
  //   (Fortis.aes().mode(AesMode.ctr) as AesStreamModeBuilder).ivSize(12);

  group('ivSize() — GCM round-trip', () {
    AesCipher gcmCipher(int size) =>
        (Fortis.aes().mode(AesMode.gcm) as AesAuthModeBuilder)
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
        final c = (Fortis.aes().mode(AesMode.ccm) as AesAuthModeBuilder)
            .ivSize(size)
            .cipher(key);
        final ciphertext = c.encrypt('hello fortis');
        expect(c.decryptToString(ciphertext), equals('hello fortis'));
      });
    }
  });

  group('tagSize()', () {
    test('tagSize(128) GCM round-trip (default)', () {
      final c = Fortis.aes().gcm().tagSize(128).cipher(key);
      final ct = c.encrypt('hello fortis');
      expect(c.decryptToString(ct), equals('hello fortis'));
    });

    test('tagSize(96) CCM round-trip', () {
      final c = Fortis.aes().ccm().tagSize(96).cipher(key);
      final ct = c.encrypt('hello fortis');
      expect(c.decryptToString(ct), equals('hello fortis'));
    });

    test('tagSize(64) CCM round-trip', () {
      final c = Fortis.aes().ccm().tagSize(64).cipher(key);
      final ct = c.encrypt('hello fortis');
      expect(c.decryptToString(ct), equals('hello fortis'));
    });

    test('tagSize + aad + ivSize chained round-trip (CCM)', () {
      final aad = Uint8List.fromList([1, 2, 3, 4]);
      final c = Fortis.aes().ccm().tagSize(96).aad(aad).ivSize(11).cipher(key);
      final ct = c.encrypt('hello fortis');
      expect(c.decryptToString(ct), equals('hello fortis'));
    });
  });
}
