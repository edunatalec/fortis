import 'dart:convert';
import 'dart:typed_data';

import 'package:fortis/fortis.dart';
import 'package:test/test.dart';

void main() {
  late FortisAesKey key;

  setUpAll(() async {
    key = await Fortis.aes().keySize(256).generateKey();
  });

  // ── helpers ──────────────────────────────────────────────────────────────

  AesEncrypter enc(AesMode mode) => Fortis.aes().mode(mode).encrypter(key);
  AesDecrypter dec(AesMode mode) => Fortis.aes().mode(mode).decrypter(key);

  AesEncrypter encWithAad(AesMode mode, Uint8List aad) =>
      (Fortis.aes().mode(mode) as AesAuthModeBuilder).aad(aad).encrypter(key);
  AesDecrypter decWithAad(AesMode mode, Uint8List aad) =>
      (Fortis.aes().mode(mode) as AesAuthModeBuilder).aad(aad).decrypter(key);

  const plaintext = 'hello fortis';
  final plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

  // ── decrypt(Uint8List) ───────────────────────────────────────────────────

  group('decrypt — Uint8List input', () {
    test('recovers original plaintext from combined Uint8List', () {
      final cipher = enc(AesMode.gcm).encrypt(plaintextBytes);
      expect(dec(AesMode.gcm).decrypt(cipher), equals(plaintextBytes));
    });

    test('end-to-end: encrypt → decrypt → equals original', () {
      final cipher = enc(AesMode.gcm).encrypt(plaintext);
      expect(dec(AesMode.gcm).decrypt(cipher), equals(plaintextBytes));
    });
  });

  // ── decrypt(String) ──────────────────────────────────────────────────────

  group('decrypt — String input (Base64)', () {
    test('recovers original plaintext from Base64 string', () {
      final cipher = enc(AesMode.gcm).encryptToString(plaintext);
      expect(dec(AesMode.gcm).decrypt(cipher), equals(plaintextBytes));
    });

    test('end-to-end: encryptToString → decrypt → equals original', () {
      final cipher = enc(AesMode.cbc).encryptToString(plaintext);
      expect(dec(AesMode.cbc).decrypt(cipher), equals(plaintextBytes));
    });
  });

  // ── decrypt(Map<String, String>) ─────────────────────────────────────────

  group('decrypt — Map input', () {
    test("recovers plaintext with key 'iv'", () {
      final payload =
          enc(AesMode.cbc).encryptToPayload(plaintext) as AesPayload;
      expect(dec(AesMode.cbc).decrypt(payload.toMap()), equals(plaintextBytes));
    });

    test("recovers plaintext with key 'nonce'", () {
      final payload =
          enc(AesMode.gcm).encryptToPayload(plaintext) as AesAuthPayload;
      expect(
        dec(AesMode.gcm).decrypt(payload.toMap(ivKey: 'nonce')),
        equals(plaintextBytes),
      );
    });

    test("throws FortisConfigException when both 'iv' and 'nonce' present", () {
      expect(
        () => dec(AesMode.gcm)
            .decrypt({'iv': 'a', 'nonce': 'b', 'data': 'c', 'tag': 'd'}),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test(
      "throws FortisConfigException when neither 'iv' nor 'nonce' present",
      () {
        expect(
          () => dec(AesMode.gcm).decrypt({'data': 'c', 'tag': 'd'}),
          throwsA(isA<FortisConfigException>()),
        );
      },
    );

    test("throws FortisConfigException when 'data' missing", () {
      expect(
        () => dec(AesMode.gcm).decrypt({'iv': 'a', 'tag': 'd'}),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test("throws FortisConfigException when 'tag' missing for GCM", () {
      expect(
        () => dec(AesMode.gcm).decrypt({'iv': 'a', 'data': 'c'}),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test("throws FortisConfigException when 'tag' missing for CCM", () {
      expect(
        () => dec(AesMode.ccm).decrypt({'iv': 'a', 'data': 'c'}),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test(
      "end-to-end: encryptToPayload → toMap() → decrypt → equals original",
      () {
        final payload =
            enc(AesMode.gcm).encryptToPayload(plaintext) as AesAuthPayload;
        expect(
          dec(AesMode.gcm).decrypt(payload.toMap()),
          equals(plaintextBytes),
        );
      },
    );

    test(
      "end-to-end: encryptToPayload → toMap(ivKey: 'nonce') → decrypt → equals original",
      () {
        final payload =
            enc(AesMode.gcm).encryptToPayload(plaintext) as AesAuthPayload;
        expect(
          dec(AesMode.gcm).decrypt(payload.toMap(ivKey: 'nonce')),
          equals(plaintextBytes),
        );
      },
    );
  });

  // ── decrypt(AesAuthPayload) ───────────────────────────────────────────────

  group('decrypt — AesAuthPayload input', () {
    test('recovers plaintext from AesAuthPayload in GCM mode', () {
      final payload =
          enc(AesMode.gcm).encryptToPayload(plaintext) as AesAuthPayload;
      expect(dec(AesMode.gcm).decrypt(payload), equals(plaintextBytes));
    });

    test('recovers plaintext from AesAuthPayload in CCM mode', () {
      final payload =
          enc(AesMode.ccm).encryptToPayload(plaintext) as AesAuthPayload;
      expect(dec(AesMode.ccm).decrypt(payload), equals(plaintextBytes));
    });

    test('throws FortisConfigException when used with CBC mode', () {
      final payload = AesAuthPayload(iv: 'a', data: 'b', tag: 'c');
      expect(
        () => dec(AesMode.cbc).decrypt(payload),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('throws FortisConfigException when used with CTR mode', () {
      final payload = AesAuthPayload(iv: 'a', data: 'b', tag: 'c');
      expect(
        () => dec(AesMode.ctr).decrypt(payload),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test(
      'end-to-end: encryptToPayload → decrypt(AesAuthPayload) → equals original',
      () {
        final payload =
            enc(AesMode.gcm).encryptToPayload(plaintext) as AesAuthPayload;
        expect(dec(AesMode.gcm).decrypt(payload), equals(plaintextBytes));
      },
    );
  });

  // ── decrypt(AesPayload) ──────────────────────────────────────────────────

  group('decrypt — AesPayload input', () {
    for (final mode in [AesMode.cbc, AesMode.ctr, AesMode.cfb, AesMode.ofb]) {
      test(
        'recovers plaintext from AesPayload in ${mode.name.toUpperCase()} mode',
        () {
          final payload = enc(mode).encryptToPayload(plaintext) as AesPayload;
          expect(dec(mode).decrypt(payload), equals(plaintextBytes));
        },
      );
    }

    test('throws FortisConfigException when used with GCM mode', () {
      final payload = AesPayload(iv: 'a', data: 'b');
      expect(
        () => dec(AesMode.gcm).decrypt(payload),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('throws FortisConfigException when used with CCM mode', () {
      final payload = AesPayload(iv: 'a', data: 'b');
      expect(
        () => dec(AesMode.ccm).decrypt(payload),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test(
      'end-to-end: encryptToPayload → decrypt(AesPayload) → equals original',
      () {
        final payload =
            enc(AesMode.cbc).encryptToPayload(plaintext) as AesPayload;
        expect(dec(AesMode.cbc).decrypt(payload), equals(plaintextBytes));
      },
    );
  });

  // ── decrypt — unsupported type ────────────────────────────────────────────

  group('decrypt — unsupported type', () {
    test('throws FortisConfigException for unsupported input type (int)', () {
      expect(
        () => dec(AesMode.gcm).decrypt(42),
        throwsA(isA<FortisConfigException>()),
      );
    });
  });

  // ── decryptToString ──────────────────────────────────────────────────────

  group('decryptToString', () {
    test('recovers original UTF-8 string from Uint8List', () {
      expect(
        dec(AesMode.gcm).decryptToString(enc(AesMode.gcm).encrypt(plaintext)),
        equals(plaintext),
      );
    });

    test('recovers original UTF-8 string from Base64 String', () {
      expect(
        dec(AesMode.gcm)
            .decryptToString(enc(AesMode.gcm).encryptToString(plaintext)),
        equals(plaintext),
      );
    });

    test('recovers original UTF-8 string from Map<String, String>', () {
      final payload =
          enc(AesMode.gcm).encryptToPayload(plaintext) as AesAuthPayload;
      expect(
        dec(AesMode.gcm).decryptToString(payload.toMap()),
        equals(plaintext),
      );
    });

    test('recovers original UTF-8 string from AesAuthPayload', () {
      final payload =
          enc(AesMode.gcm).encryptToPayload(plaintext) as AesAuthPayload;
      expect(dec(AesMode.gcm).decryptToString(payload), equals(plaintext));
    });

    test('recovers original UTF-8 string from AesPayload', () {
      final payload =
          enc(AesMode.cbc).encryptToPayload(plaintext) as AesPayload;
      expect(dec(AesMode.cbc).decryptToString(payload), equals(plaintext));
    });

    test(
      "end-to-end: encryptToPayload → toMap() → decryptToString → equals original string",
      () {
        final payload =
            enc(AesMode.gcm).encryptToPayload(plaintext) as AesAuthPayload;
        expect(
          dec(AesMode.gcm).decryptToString(payload.toMap()),
          equals(plaintext),
        );
      },
    );
  });

  // ── Mode × key size matrix ───────────────────────────────────────────────

  group('round-trip: mode × key size matrix', () {
    final modes = [
      AesMode.cbc,
      AesMode.ctr,
      AesMode.gcm,
      AesMode.cfb,
      AesMode.ofb,
      AesMode.ccm,
      AesMode.ecb,
    ];
    final keySizes = [128, 192, 256];

    for (final mode in modes) {
      for (final size in keySizes) {
        test('round-trip: ${mode.name.toUpperCase()} + $size-bit key', () async {
          final k = await Fortis.aes().keySize(size).generateKey();
          final encrypter = Fortis.aes().mode(mode).encrypter(k);
          final decrypter = Fortis.aes().mode(mode).decrypter(k);
          final cipher = encrypter.encrypt(plaintext);
          expect(decrypter.decryptToString(cipher), equals(plaintext));
        });
      }
    }
  });

  // ── GCM/CCM authentication tests ─────────────────────────────────────────

  group('GCM/CCM authentication', () {
    final aad = Uint8List.fromList(utf8.encode('additional-data'));

    for (final mode in [AesMode.gcm, AesMode.ccm]) {
      test(
        '${mode.name.toUpperCase()} AAD matching: encrypt with AAD → decrypt with same AAD → succeeds',
        () {
          final cipher = encWithAad(mode, aad).encrypt(plaintext);
          expect(
            decWithAad(mode, aad).decryptToString(cipher),
            equals(plaintext),
          );
        },
      );

      test(
        '${mode.name.toUpperCase()} AAD mismatch → throws FortisEncryptionException',
        () {
          final cipher = encWithAad(mode, aad).encrypt(plaintext);
          final wrongAad = Uint8List.fromList(utf8.encode('wrong-aad'));
          expect(
            () => decWithAad(mode, wrongAad).decrypt(cipher),
            throwsA(isA<FortisEncryptionException>()),
          );
        },
      );

      test(
        '${mode.name.toUpperCase()} auth tag tampering → throws FortisEncryptionException',
        () {
          final cipher = enc(mode).encrypt(plaintext);
          final tampered = Uint8List.fromList(cipher);
          tampered[tampered.length - 1] ^= 0xFF;
          expect(
            () => dec(mode).decrypt(tampered),
            throwsA(isA<FortisEncryptionException>()),
          );
        },
      );
    }
  });

  // ── Interoperability test ─────────────────────────────────────────────────

  group('interoperability', () {
    test('interop: decrypt(Map) recovers .NET-style separated fields', () {
      final ciphertext = enc(AesMode.gcm).encrypt(plaintext);
      final iv = base64Encode(ciphertext.sublist(0, 12));
      final tag = base64Encode(ciphertext.sublist(ciphertext.length - 16));
      final data =
          base64Encode(ciphertext.sublist(12, ciphertext.length - 16));

      expect(
        dec(AesMode.gcm)
            .decryptToString({'nonce': iv, 'data': data, 'tag': tag}),
        equals(plaintext),
      );
    });
  });
}
