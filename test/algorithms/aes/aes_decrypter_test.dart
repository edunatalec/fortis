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

  AesCipher cipher(AesMode mode) => Fortis.aes().mode(mode).cipher(key);

  AesCipher cipherWithAad(AesMode mode, Uint8List aad) =>
      (Fortis.aes().mode(mode) as AesAuthModeBuilder).aad(aad).cipher(key);

  const plaintext = 'hello fortis';
  final plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

  // ── decrypt(Uint8List) ───────────────────────────────────────────────────

  group('decrypt — Uint8List input', () {
    test('recovers original plaintext from combined Uint8List', () {
      final c = cipher(AesMode.gcm);
      final ciphertext = c.encrypt(plaintextBytes);
      expect(c.decrypt(ciphertext), equals(plaintextBytes));
    });

    test('end-to-end: encrypt → decrypt → equals original', () {
      final c = cipher(AesMode.gcm);
      final ciphertext = c.encrypt(plaintext);
      expect(c.decrypt(ciphertext), equals(plaintextBytes));
    });
  });

  // ── decrypt(String) ──────────────────────────────────────────────────────

  group('decrypt — String input (Base64)', () {
    test('recovers original plaintext from Base64 string', () {
      final c = cipher(AesMode.gcm);
      final ciphertext = c.encryptToString(plaintext);
      expect(c.decrypt(ciphertext), equals(plaintextBytes));
    });

    test('end-to-end: encryptToString → decrypt → equals original', () {
      final c = cipher(AesMode.cbc);
      final ciphertext = c.encryptToString(plaintext);
      expect(c.decrypt(ciphertext), equals(plaintextBytes));
    });
  });

  // ── decrypt(Map<String, String>) ─────────────────────────────────────────

  group('decrypt — Map input', () {
    test("recovers plaintext with key 'iv'", () {
      final c = cipher(AesMode.cbc);
      final payload = c.encryptToPayload(plaintext) as AesPayload;
      expect(c.decrypt(payload.toMap()), equals(plaintextBytes));
    });

    test("recovers plaintext with key 'nonce'", () {
      final c = cipher(AesMode.gcm);
      final payload = c.encryptToPayload(plaintext) as AesAuthPayload;
      expect(
        c.decrypt(payload.toMap(ivKey: 'nonce')),
        equals(plaintextBytes),
      );
    });

    test("throws FortisConfigException when both 'iv' and 'nonce' present", () {
      expect(
        () => cipher(
          AesMode.gcm,
        ).decrypt({'iv': 'a', 'nonce': 'b', 'data': 'c', 'tag': 'd'}),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test(
      "throws FortisConfigException when neither 'iv' nor 'nonce' present",
      () {
        expect(
          () => cipher(AesMode.gcm).decrypt({'data': 'c', 'tag': 'd'}),
          throwsA(isA<FortisConfigException>()),
        );
      },
    );

    test("throws FortisConfigException when 'data' missing", () {
      expect(
        () => cipher(AesMode.gcm).decrypt({'iv': 'a', 'tag': 'd'}),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test("throws FortisConfigException when 'tag' missing for GCM", () {
      expect(
        () => cipher(AesMode.gcm).decrypt({'iv': 'a', 'data': 'c'}),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test("throws FortisConfigException when 'tag' missing for CCM", () {
      expect(
        () => cipher(AesMode.ccm).decrypt({'iv': 'a', 'data': 'c'}),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test(
      "end-to-end: encryptToPayload → toMap() → decrypt → equals original",
      () {
        final c = cipher(AesMode.gcm);
        final payload = c.encryptToPayload(plaintext) as AesAuthPayload;
        expect(
          c.decrypt(payload.toMap()),
          equals(plaintextBytes),
        );
      },
    );

    test(
      "end-to-end: encryptToPayload → toMap(ivKey: 'nonce') → decrypt → equals original",
      () {
        final c = cipher(AesMode.gcm);
        final payload = c.encryptToPayload(plaintext) as AesAuthPayload;
        expect(
          c.decrypt(payload.toMap(ivKey: 'nonce')),
          equals(plaintextBytes),
        );
      },
    );
  });

  // ── decrypt(AesAuthPayload) ───────────────────────────────────────────────

  group('decrypt — AesAuthPayload input', () {
    test('recovers plaintext from AesAuthPayload in GCM mode', () {
      final c = cipher(AesMode.gcm);
      final payload = c.encryptToPayload(plaintext) as AesAuthPayload;
      expect(c.decrypt(payload), equals(plaintextBytes));
    });

    test('recovers plaintext from AesAuthPayload in CCM mode', () {
      final c = cipher(AesMode.ccm);
      final payload = c.encryptToPayload(plaintext) as AesAuthPayload;
      expect(c.decrypt(payload), equals(plaintextBytes));
    });

    test('throws FortisConfigException when used with CBC mode', () {
      final payload = AesAuthPayload(iv: 'a', data: 'b', tag: 'c');
      expect(
        () => cipher(AesMode.cbc).decrypt(payload),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('throws FortisConfigException when used with CTR mode', () {
      final payload = AesAuthPayload(iv: 'a', data: 'b', tag: 'c');
      expect(
        () => cipher(AesMode.ctr).decrypt(payload),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test(
      'end-to-end: encryptToPayload → decrypt(AesAuthPayload) → equals original',
      () {
        final c = cipher(AesMode.gcm);
        final payload = c.encryptToPayload(plaintext) as AesAuthPayload;
        expect(c.decrypt(payload), equals(plaintextBytes));
      },
    );
  });

  // ── decrypt(AesPayload) ──────────────────────────────────────────────────

  group('decrypt — AesPayload input', () {
    for (final mode in [AesMode.cbc, AesMode.ctr, AesMode.cfb, AesMode.ofb]) {
      test(
        'recovers plaintext from AesPayload in ${mode.name.toUpperCase()} mode',
        () {
          final c = cipher(mode);
          final payload = c.encryptToPayload(plaintext) as AesPayload;
          expect(c.decrypt(payload), equals(plaintextBytes));
        },
      );
    }

    test('throws FortisConfigException when used with GCM mode', () {
      final payload = AesPayload(iv: 'a', data: 'b');
      expect(
        () => cipher(AesMode.gcm).decrypt(payload),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('throws FortisConfigException when used with CCM mode', () {
      final payload = AesPayload(iv: 'a', data: 'b');
      expect(
        () => cipher(AesMode.ccm).decrypt(payload),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test(
      'end-to-end: encryptToPayload → decrypt(AesPayload) → equals original',
      () {
        final c = cipher(AesMode.cbc);
        final payload = c.encryptToPayload(plaintext) as AesPayload;
        expect(c.decrypt(payload), equals(plaintextBytes));
      },
    );
  });

  // ── decrypt — unsupported type ────────────────────────────────────────────

  group('decrypt — unsupported type', () {
    test('throws FortisConfigException for unsupported input type (int)', () {
      expect(
        () => cipher(AesMode.gcm).decrypt(42),
        throwsA(isA<FortisConfigException>()),
      );
    });
  });

  // ── decryptToString ──────────────────────────────────────────────────────

  group('decryptToString', () {
    test('recovers original UTF-8 string from Uint8List', () {
      final c = cipher(AesMode.gcm);
      expect(
        c.decryptToString(c.encrypt(plaintext)),
        equals(plaintext),
      );
    });

    test('recovers original UTF-8 string from Base64 String', () {
      final c = cipher(AesMode.gcm);
      expect(
        c.decryptToString(c.encryptToString(plaintext)),
        equals(plaintext),
      );
    });

    test('recovers original UTF-8 string from Map<String, String>', () {
      final c = cipher(AesMode.gcm);
      final payload = c.encryptToPayload(plaintext) as AesAuthPayload;
      expect(
        c.decryptToString(payload.toMap()),
        equals(plaintext),
      );
    });

    test('recovers original UTF-8 string from AesAuthPayload', () {
      final c = cipher(AesMode.gcm);
      final payload = c.encryptToPayload(plaintext) as AesAuthPayload;
      expect(c.decryptToString(payload), equals(plaintext));
    });

    test('recovers original UTF-8 string from AesPayload', () {
      final c = cipher(AesMode.cbc);
      final payload = c.encryptToPayload(plaintext) as AesPayload;
      expect(c.decryptToString(payload), equals(plaintext));
    });

    test(
      "end-to-end: encryptToPayload → toMap() → decryptToString → equals original string",
      () {
        final c = cipher(AesMode.gcm);
        final payload = c.encryptToPayload(plaintext) as AesAuthPayload;
        expect(
          c.decryptToString(payload.toMap()),
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
        test(
          'round-trip: ${mode.name.toUpperCase()} + $size-bit key',
          () async {
            final k = await Fortis.aes().keySize(size).generateKey();
            final c = Fortis.aes().mode(mode).cipher(k);
            final ciphertext = c.encrypt(plaintext);
            expect(c.decryptToString(ciphertext), equals(plaintext));
          },
        );
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
          final c = cipherWithAad(mode, aad);
          final ciphertext = c.encrypt(plaintext);
          expect(
            c.decryptToString(ciphertext),
            equals(plaintext),
          );
        },
      );

      test(
        '${mode.name.toUpperCase()} AAD mismatch → throws FortisEncryptionException',
        () {
          final c = cipherWithAad(mode, aad);
          final ciphertext = c.encrypt(plaintext);
          final wrongAad = Uint8List.fromList(utf8.encode('wrong-aad'));
          expect(
            () => cipherWithAad(mode, wrongAad).decrypt(ciphertext),
            throwsA(isA<FortisEncryptionException>()),
          );
        },
      );

      test(
        '${mode.name.toUpperCase()} auth tag tampering → throws FortisEncryptionException',
        () {
          final c = cipher(mode);
          final ciphertext = c.encrypt(plaintext);
          final tampered = Uint8List.fromList(ciphertext);
          tampered[tampered.length - 1] ^= 0xFF;
          expect(
            () => c.decrypt(tampered),
            throwsA(isA<FortisEncryptionException>()),
          );
        },
      );
    }
  });

  // ── Interoperability test ─────────────────────────────────────────────────

  group('interoperability', () {
    test('interop: decrypt(Map) recovers .NET-style separated fields', () {
      final c = cipher(AesMode.gcm);
      final ciphertext = c.encrypt(plaintext);
      final iv = base64Encode(ciphertext.sublist(0, 12));
      final tag = base64Encode(ciphertext.sublist(ciphertext.length - 16));
      final data = base64Encode(
        ciphertext.sublist(12, ciphertext.length - 16),
      );

      expect(
        c.decryptToString({'nonce': iv, 'data': data, 'tag': tag}),
        equals(plaintext),
      );
    });
  });

  // ── Same instance and cross-cipher tests ──────────────────────────────────

  group('AesCipher — symmetric usage', () {
    test('same instance encrypts and decrypts', () {
      final c = Fortis.aes().mode(AesMode.gcm).cipher(key);
      final ciphertext = c.encrypt('hello fortis');
      expect(c.decryptToString(ciphertext), equals('hello fortis'));
    });

    test('two ciphers with same key produce compatible output', () {
      final cipher1 = Fortis.aes().mode(AesMode.gcm).cipher(key);
      final cipher2 = Fortis.aes().mode(AesMode.gcm).cipher(key);
      final ciphertext = cipher1.encrypt('hello fortis');
      expect(cipher2.decryptToString(ciphertext), equals('hello fortis'));
    });
  });
}
