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
