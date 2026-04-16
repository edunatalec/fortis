import 'package:fortis/fortis.dart';
import 'package:test/test.dart';

// These tests ensure `encryptToPayload` returns a *statically* typed
// `AesPayload` / `AesAuthPayload` — no `as` cast required at call sites.
// The assertions using `runtimeType` are a belt-and-braces check;
// the real coverage is compile-time: this file would fail to compile if
// the return types regressed to `Object`.
void main() {
  late FortisAesKey key;

  setUpAll(() async {
    key = await Fortis.aes().generateKey();
  });

  group('AesAuthCipher — typed encryptToPayload', () {
    test(
      '.gcm().cipher() returns AesAuthCipher with AesAuthPayload result',
      () {
        final cipher = Fortis.aes().gcm().cipher(key);
        expect(cipher, isA<AesAuthCipher>());

        // Statically typed — no cast.
        final AesAuthPayload payload = cipher.encryptToPayload('hello');
        expect(payload.iv, isNotEmpty);
        expect(payload.data, isNotEmpty);
        expect(payload.tag, isNotEmpty);
      },
    );

    test(
      '.ccm().cipher() returns AesAuthCipher with AesAuthPayload result',
      () {
        final cipher = Fortis.aes().ccm().cipher(key);
        expect(cipher, isA<AesAuthCipher>());

        final AesAuthPayload payload = cipher.encryptToPayload('hello');
        expect(payload.tag, isNotEmpty);
      },
    );
  });

  group('AesStandardCipher — typed encryptToPayload', () {
    for (final buildCipher in <(String, AesStandardCipher Function())>[
      ('cbc', () => Fortis.aes().cbc().cipher(key)),
      ('ctr', () => Fortis.aes().ctr().cipher(key)),
      ('cfb', () => Fortis.aes().cfb().cipher(key)),
      ('ofb', () => Fortis.aes().ofb().cipher(key)),
    ]) {
      test('.${buildCipher.$1}().cipher() returns AesStandardCipher', () {
        final cipher = buildCipher.$2();
        expect(cipher, isA<AesStandardCipher>());

        // Statically typed — no cast.
        final AesPayload payload = cipher.encryptToPayload('hello');
        expect(payload.iv, isNotEmpty);
        expect(payload.data, isNotEmpty);
      });
    }
  });

  group('AesEcbCipher — no encryptToPayload', () {
    test(
      '.ecb().cipher() returns AesEcbCipher (no encryptToPayload exposed)',
      () {
        final cipher = Fortis.aes().ecb().cipher(key);
        expect(cipher, isA<AesEcbCipher>());

        // Compile-time invariant: AesEcbCipher does not declare
        // `encryptToPayload`. Uncommenting the line below must not compile:
        //
        //   cipher.encryptToPayload('x');
      },
    );
  });

  group('impossible casts between sealed subtypes throw TypeError', () {
    test('AesAuthCipher cannot be cast to AesStandardCipher', () {
      final AesCipher cipher = Fortis.aes().gcm().cipher(key);
      expect(() => cipher as AesStandardCipher, throwsA(isA<TypeError>()));
    });

    test('AesAuthCipher cannot be cast to AesEcbCipher', () {
      final AesCipher cipher = Fortis.aes().gcm().cipher(key);
      expect(() => cipher as AesEcbCipher, throwsA(isA<TypeError>()));
    });

    test('AesStandardCipher cannot be cast to AesAuthCipher', () {
      final AesCipher cipher = Fortis.aes().cbc().cipher(key);
      expect(() => cipher as AesAuthCipher, throwsA(isA<TypeError>()));
    });

    test('AesStandardCipher cannot be cast to AesEcbCipher', () {
      final AesCipher cipher = Fortis.aes().ctr().cipher(key);
      expect(() => cipher as AesEcbCipher, throwsA(isA<TypeError>()));
    });

    test('AesEcbCipher cannot be cast to AesAuthCipher', () {
      final AesCipher cipher = Fortis.aes().ecb().cipher(key);
      expect(() => cipher as AesAuthCipher, throwsA(isA<TypeError>()));
    });

    test('AesEcbCipher cannot be cast to AesStandardCipher', () {
      final AesCipher cipher = Fortis.aes().ecb().cipher(key);
      expect(() => cipher as AesStandardCipher, throwsA(isA<TypeError>()));
    });

    test('dynamic mode(AesMode.gcm).cipher() is AesAuthCipher at runtime', () {
      final AesCipher cipher = Fortis.aes().mode(AesMode.gcm).cipher(key);
      expect(cipher, isA<AesAuthCipher>());
      expect(cipher, isNot(isA<AesStandardCipher>()));
      expect(cipher, isNot(isA<AesEcbCipher>()));
    });

    test('dynamic mode(AesMode.cbc).cipher() is AesStandardCipher', () {
      final AesCipher cipher = Fortis.aes().mode(AesMode.cbc).cipher(key);
      expect(cipher, isA<AesStandardCipher>());
      expect(cipher, isNot(isA<AesAuthCipher>()));
      expect(cipher, isNot(isA<AesEcbCipher>()));
    });

    test('dynamic mode(AesMode.ecb).cipher() is AesEcbCipher', () {
      final AesCipher cipher = Fortis.aes().mode(AesMode.ecb).cipher(key);
      expect(cipher, isA<AesEcbCipher>());
      expect(cipher, isNot(isA<AesAuthCipher>()));
      expect(cipher, isNot(isA<AesStandardCipher>()));
    });

    test('sealed pattern matching covers all three subtypes exhaustively', () {
      String describe(AesCipher c) => switch (c) {
        AesEcbCipher() => 'ecb',
        AesStandardCipher() => 'standard',
        AesAuthCipher() => 'auth',
      };

      expect(describe(Fortis.aes().ecb().cipher(key)), equals('ecb'));
      expect(describe(Fortis.aes().cbc().cipher(key)), equals('standard'));
      expect(describe(Fortis.aes().ctr().cipher(key)), equals('standard'));
      expect(describe(Fortis.aes().gcm().cipher(key)), equals('auth'));
      expect(describe(Fortis.aes().ccm().cipher(key)), equals('auth'));
    });
  });

  group('mode-builder cast safety', () {
    test('ecb builder cannot be cast to AesAuthModeBuilder', () {
      final AesModeBuilder builder = Fortis.aes().mode(AesMode.ecb);
      expect(() => builder as AesAuthModeBuilder, throwsA(isA<TypeError>()));
    });

    test('gcm builder cannot be cast to AesCbcModeBuilder', () {
      final AesModeBuilder builder = Fortis.aes().mode(AesMode.gcm);
      expect(() => builder as AesCbcModeBuilder, throwsA(isA<TypeError>()));
    });

    test('stream builder cannot be cast to AesAuthModeBuilder', () {
      final AesModeBuilder builder = Fortis.aes().mode(AesMode.ctr);
      expect(() => builder as AesAuthModeBuilder, throwsA(isA<TypeError>()));
    });
  });

  group('round-trip: typed payloads via specific ciphers', () {
    test('GCM: encryptToPayload → decrypt → plaintext', () {
      final cipher = Fortis.aes().gcm().cipher(key);
      final payload = cipher.encryptToPayload('hello fortis');
      expect(cipher.decryptToString(payload), equals('hello fortis'));
    });

    test('CBC: encryptToPayload → decrypt → plaintext', () {
      final cipher = Fortis.aes().cbc().cipher(key);
      final payload = cipher.encryptToPayload('hello fortis');
      expect(cipher.decryptToString(payload), equals('hello fortis'));
    });
  });
}
