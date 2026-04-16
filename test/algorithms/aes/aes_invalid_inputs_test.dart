import 'dart:convert';
import 'dart:typed_data';

import 'package:fortis/fortis.dart';
import 'package:test/test.dart';

void main() {
  late FortisAesKey key;

  setUpAll(() async {
    key = await Fortis.aes().generateKey();
  });

  group('FortisAesKey.fromBytes — invalid sizes', () {
    test('empty bytes (0 bits) throws FortisKeyException', () {
      expect(
        () => FortisAesKey.fromBytes(Uint8List(0)),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('1-byte key (8 bits) throws FortisKeyException', () {
      expect(
        () => FortisAesKey.fromBytes(Uint8List(1)),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('15-byte key (off-by-one from 128) throws FortisKeyException', () {
      expect(
        () => FortisAesKey.fromBytes(Uint8List(15)),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('17-byte key (off-by-one from 128) throws FortisKeyException', () {
      expect(
        () => FortisAesKey.fromBytes(Uint8List(17)),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('empty Base64 throws FortisKeyException', () {
      expect(
        () => FortisAesKey.fromBase64(''),
        throwsA(isA<FortisKeyException>()),
      );
    });
  });

  group('encrypt() — invalid plaintext types', () {
    test('int plaintext throws FortisConfigException', () {
      final cipher = Fortis.aes().gcm().cipher(key);
      expect(() => cipher.encrypt(42), throwsA(isA<FortisConfigException>()));
    });

    test('double plaintext throws FortisConfigException', () {
      final cipher = Fortis.aes().gcm().cipher(key);
      expect(() => cipher.encrypt(3.14), throwsA(isA<FortisConfigException>()));
    });

    test('List<int> plaintext throws FortisConfigException', () {
      final cipher = Fortis.aes().gcm().cipher(key);
      expect(
        () => cipher.encrypt([1, 2, 3]),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('bool plaintext throws FortisConfigException', () {
      final cipher = Fortis.aes().gcm().cipher(key);
      expect(() => cipher.encrypt(true), throwsA(isA<FortisConfigException>()));
    });

    test('Map plaintext throws FortisConfigException', () {
      final cipher = Fortis.aes().gcm().cipher(key);
      expect(
        () => cipher.encrypt({'a': 'b'}),
        throwsA(isA<FortisConfigException>()),
      );
    });
  });

  group('encrypt() — IV size validation per mode', () {
    test('CBC with 12-byte IV throws FortisConfigException', () {
      final cipher = Fortis.aes().cbc().cipher(key);
      expect(
        () => cipher.encrypt('hi', iv: Uint8List(12)),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('CTR with 8-byte IV throws FortisConfigException', () {
      final cipher = Fortis.aes().ctr().cipher(key);
      expect(
        () => cipher.encrypt('hi', iv: Uint8List(8)),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('CFB with 32-byte IV throws FortisConfigException', () {
      final cipher = Fortis.aes().cfb().cipher(key);
      expect(
        () => cipher.encrypt('hi', iv: Uint8List(32)),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('OFB with 0-byte IV throws FortisConfigException', () {
      final cipher = Fortis.aes().ofb().cipher(key);
      expect(
        () => cipher.encrypt('hi', iv: Uint8List(0)),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('GCM with wrong IV size (16 vs 12 default) throws', () {
      final cipher = Fortis.aes().gcm().cipher(key);
      expect(
        () => cipher.encrypt('hi', iv: Uint8List(16)),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('CCM with wrong IV size (8 vs 11 default) throws', () {
      final cipher = Fortis.aes().ccm().cipher(key);
      expect(
        () => cipher.encrypt('hi', iv: Uint8List(8)),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('ECB with any IV throws FortisConfigException', () {
      final cipher = Fortis.aes().ecb().cipher(key);
      expect(
        () => cipher.encrypt('hi', iv: Uint8List(16)),
        throwsA(isA<FortisConfigException>()),
      );
    });
  });

  group('encrypt() — noPadding alignment', () {
    test('CBC + noPadding with 15-byte plaintext throws', () {
      final cipher = Fortis.aes()
          .cbc()
          .padding(AesPadding.noPadding)
          .cipher(key);
      expect(
        () => cipher.encrypt(Uint8List(15)),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('CBC + noPadding with 1-byte plaintext throws', () {
      final cipher = Fortis.aes()
          .cbc()
          .padding(AesPadding.noPadding)
          .cipher(key);
      expect(
        () => cipher.encrypt(Uint8List(1)),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('ECB + noPadding with 17-byte plaintext throws', () {
      final cipher = Fortis.aes()
          .ecb()
          .padding(AesPadding.noPadding)
          .cipher(key);
      expect(
        () => cipher.encrypt(Uint8List(17)),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('CBC + noPadding with aligned data encrypts without throwing', () {
      final cipher = Fortis.aes()
          .cbc()
          .padding(AesPadding.noPadding)
          .cipher(key);
      expect(() => cipher.encrypt(Uint8List(32)), returnsNormally);
    });
  });

  group('decrypt() — invalid input types', () {
    test('int input throws FortisConfigException', () {
      final cipher = Fortis.aes().gcm().cipher(key);
      expect(() => cipher.decrypt(42), throwsA(isA<FortisConfigException>()));
    });

    test('double input throws FortisConfigException', () {
      final cipher = Fortis.aes().gcm().cipher(key);
      expect(() => cipher.decrypt(1.5), throwsA(isA<FortisConfigException>()));
    });

    test('bool input throws FortisConfigException', () {
      final cipher = Fortis.aes().gcm().cipher(key);
      expect(
        () => cipher.decrypt(false),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('List<int> input throws FortisConfigException', () {
      final cipher = Fortis.aes().gcm().cipher(key);
      expect(
        () => cipher.decrypt([1, 2, 3]),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('Map<String, int> input throws FortisConfigException', () {
      final cipher = Fortis.aes().gcm().cipher(key);
      expect(
        () => cipher.decrypt(<String, int>{'iv': 1, 'data': 2, 'tag': 3}),
        throwsA(isA<FortisConfigException>()),
      );
    });
  });

  group('decrypt() — truncated ciphertext', () {
    test('CBC with <16 bytes throws FortisEncryptionException', () {
      final cipher = Fortis.aes().cbc().cipher(key);
      expect(
        () => cipher.decrypt(Uint8List(10)),
        throwsA(isA<FortisEncryptionException>()),
      );
    });

    test('CTR with <16 bytes throws FortisEncryptionException', () {
      final cipher = Fortis.aes().ctr().cipher(key);
      expect(
        () => cipher.decrypt(Uint8List(5)),
        throwsA(isA<FortisEncryptionException>()),
      );
    });

    test('CFB with empty bytes throws FortisEncryptionException', () {
      final cipher = Fortis.aes().cfb().cipher(key);
      expect(
        () => cipher.decrypt(Uint8List(0)),
        throwsA(isA<FortisEncryptionException>()),
      );
    });

    test('OFB with 15 bytes throws FortisEncryptionException', () {
      final cipher = Fortis.aes().ofb().cipher(key);
      expect(
        () => cipher.decrypt(Uint8List(15)),
        throwsA(isA<FortisEncryptionException>()),
      );
    });

    test('GCM with <12 bytes throws FortisEncryptionException', () {
      final cipher = Fortis.aes().gcm().cipher(key);
      expect(
        () => cipher.decrypt(Uint8List(5)),
        throwsA(isA<FortisEncryptionException>()),
      );
    });

    test('GCM with exactly IV size and no data throws', () {
      final cipher = Fortis.aes().gcm().cipher(key);
      // 12 bytes of IV but no ciphertext/tag — auth will fail
      expect(
        () => cipher.decrypt(Uint8List(12)),
        throwsA(isA<FortisEncryptionException>()),
      );
    });
  });

  group('decrypt() — Map input validation', () {
    test('empty Map throws FortisConfigException', () {
      final cipher = Fortis.aes().gcm().cipher(key);
      expect(
        () => cipher.decrypt(<String, String>{}),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('Map with only iv throws (missing data)', () {
      final cipher = Fortis.aes().gcm().cipher(key);
      expect(
        () =>
            cipher.decrypt(<String, String>{'iv': base64Encode(Uint8List(12))}),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('Map with iv and data but no tag throws for GCM', () {
      final cipher = Fortis.aes().gcm().cipher(key);
      expect(
        () => cipher.decrypt(<String, String>{
          'iv': base64Encode(Uint8List(12)),
          'data': base64Encode(Uint8List(16)),
        }),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('Map with both iv and nonce throws', () {
      final cipher = Fortis.aes().gcm().cipher(key);
      expect(
        () => cipher.decrypt(<String, String>{
          'iv': 'AAAAAAAAAAAAAA==',
          'nonce': 'AAAAAAAAAAAAAA==',
          'data': 'AAAA',
          'tag': 'AAAAAAAAAAAAAAAAAAAAAA==',
        }),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('Map for CBC with tag field still decodes (tag is ignored)', () {
      final cipher = Fortis.aes().cbc().cipher(key);
      // CBC doesn't require tag. Producing a valid payload and passing an
      // extra 'tag' key should be allowed — the library just reads iv+data.
      final payload = cipher.encryptToPayload('hello');
      final map = payload.toMap();
      map['tag'] = base64Encode(Uint8List(16)); // extra, ignored
      expect(cipher.decryptToString(map), equals('hello'));
    });
  });

  group('decrypt() — cross-payload type rejection', () {
    test('AesAuthPayload into CBC cipher throws FortisConfigException', () {
      final cipher = Fortis.aes().cbc().cipher(key);
      const payload = AesAuthPayload(iv: 'a', data: 'b', tag: 'c');
      expect(
        () => cipher.decrypt(payload),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('AesAuthPayload into CTR cipher throws FortisConfigException', () {
      final cipher = Fortis.aes().ctr().cipher(key);
      const payload = AesAuthPayload(iv: 'a', data: 'b', tag: 'c');
      expect(
        () => cipher.decrypt(payload),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('AesPayload into GCM cipher throws FortisConfigException', () {
      final cipher = Fortis.aes().gcm().cipher(key);
      const payload = AesPayload(iv: 'a', data: 'b');
      expect(
        () => cipher.decrypt(payload),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('AesPayload into CCM cipher throws FortisConfigException', () {
      final cipher = Fortis.aes().ccm().cipher(key);
      const payload = AesPayload(iv: 'a', data: 'b');
      expect(
        () => cipher.decrypt(payload),
        throwsA(isA<FortisConfigException>()),
      );
    });
  });

  group('decrypt() — tampering detection on authenticated modes', () {
    test('GCM: flipping a byte in ciphertext triggers auth failure', () {
      final cipher = Fortis.aes().gcm().cipher(key);
      final ct = cipher.encrypt('hello fortis');
      // Tamper a byte in the middle (inside ciphertext region).
      final tampered = Uint8List.fromList(ct);
      tampered[ct.length ~/ 2] ^= 0xFF;
      expect(
        () => cipher.decrypt(tampered),
        throwsA(isA<FortisEncryptionException>()),
      );
    });

    test('GCM: flipping a byte in IV triggers auth failure', () {
      final cipher = Fortis.aes().gcm().cipher(key);
      final ct = cipher.encrypt('hello fortis');
      final tampered = Uint8List.fromList(ct);
      tampered[0] ^= 0x01;
      expect(
        () => cipher.decrypt(tampered),
        throwsA(isA<FortisEncryptionException>()),
      );
    });

    test('CCM: flipping a tag byte triggers auth failure', () {
      final cipher = Fortis.aes().ccm().cipher(key);
      final ct = cipher.encrypt('hello fortis');
      final tampered = Uint8List.fromList(ct);
      tampered[ct.length - 1] ^= 0xFF;
      expect(
        () => cipher.decrypt(tampered),
        throwsA(isA<FortisEncryptionException>()),
      );
    });
  });

  group('AesAuthModeBuilder.ivSize — boundary validation', () {
    test('GCM.ivSize(0) throws FortisConfigException', () {
      expect(
        () => Fortis.aes().gcm().ivSize(0),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('GCM.ivSize(-5) throws FortisConfigException', () {
      expect(
        () => Fortis.aes().gcm().ivSize(-5),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('CCM.ivSize(6) throws FortisConfigException', () {
      expect(
        () => Fortis.aes().ccm().ivSize(6),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('CCM.ivSize(14) throws FortisConfigException', () {
      expect(
        () => Fortis.aes().ccm().ivSize(14),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('CCM.ivSize(100) throws FortisConfigException', () {
      expect(
        () => Fortis.aes().ccm().ivSize(100),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('GCM ivSize round-trip with non-default size', () {
      final cipher = Fortis.aes().gcm().ivSize(8).cipher(key);
      final ct = cipher.encrypt('hello');
      expect(cipher.decryptToString(ct), equals('hello'));
    });

    test('CCM ivSize(7) boundary round-trip', () {
      final cipher = Fortis.aes().ccm().ivSize(7).cipher(key);
      final ct = cipher.encrypt('hello');
      expect(cipher.decryptToString(ct), equals('hello'));
    });

    test('CCM ivSize(13) boundary round-trip', () {
      final cipher = Fortis.aes().ccm().ivSize(13).cipher(key);
      final ct = cipher.encrypt('hello');
      expect(cipher.decryptToString(ct), equals('hello'));
    });
  });

  group('AAD mismatch detection', () {
    final aadA = Uint8List.fromList(utf8.encode('context-A'));
    final aadB = Uint8List.fromList(utf8.encode('context-B'));

    test('GCM: encrypt with AAD-A, decrypt with AAD-B throws', () {
      final encCipher = Fortis.aes().gcm().aad(aadA).cipher(key);
      final decCipher = Fortis.aes().gcm().aad(aadB).cipher(key);
      final ct = encCipher.encrypt('hello');
      expect(
        () => decCipher.decrypt(ct),
        throwsA(isA<FortisEncryptionException>()),
      );
    });

    test('GCM: encrypt with AAD, decrypt without AAD throws', () {
      final encCipher = Fortis.aes().gcm().aad(aadA).cipher(key);
      final decCipher = Fortis.aes().gcm().cipher(key); // no AAD
      final ct = encCipher.encrypt('hello');
      expect(
        () => decCipher.decrypt(ct),
        throwsA(isA<FortisEncryptionException>()),
      );
    });

    test('CCM: encrypt without AAD, decrypt with AAD throws', () {
      final encCipher = Fortis.aes().ccm().cipher(key);
      final decCipher = Fortis.aes().ccm().aad(aadA).cipher(key);
      final ct = encCipher.encrypt('hello');
      expect(
        () => decCipher.decrypt(ct),
        throwsA(isA<FortisEncryptionException>()),
      );
    });
  });

  group('wrong key detection', () {
    test('GCM with wrong key throws FortisEncryptionException', () async {
      final otherKey = await Fortis.aes().generateKey();
      final encCipher = Fortis.aes().gcm().cipher(key);
      final decCipher = Fortis.aes().gcm().cipher(otherKey);
      final ct = encCipher.encrypt('hello');
      expect(
        () => decCipher.decrypt(ct),
        throwsA(isA<FortisEncryptionException>()),
      );
    });

    test(
      'CBC with wrong key yields garbage (no auth) but does not throw',
      () async {
        final otherKey = await Fortis.aes().generateKey();
        final encCipher = Fortis.aes().cbc().cipher(key);
        final decCipher = Fortis.aes().cbc().cipher(otherKey);
        final ct = encCipher.encrypt('hello fortis, many bytes here please');
        // CBC has no authentication — decryption with wrong key either
        // throws on padding, or returns garbage. Either way the plaintext
        // should not match.
        try {
          final got = decCipher.decrypt(ct);
          expect(
            got,
            isNot(
              equals(
                Uint8List.fromList(
                  'hello fortis, many bytes here please'.codeUnits,
                ),
              ),
            ),
          );
        } on FortisException {
          // Also acceptable: padding check failed.
        }
      },
    );

    test('different keySize between encrypt and decrypt fails', () async {
      final key128 = await Fortis.aes().keySize(128).generateKey();
      final key256 = await Fortis.aes().keySize(256).generateKey();
      final encCipher = Fortis.aes().gcm().cipher(key128);
      final decCipher = Fortis.aes().gcm().cipher(key256);
      final ct = encCipher.encrypt('hello');
      expect(
        () => decCipher.decrypt(ct),
        throwsA(isA<FortisEncryptionException>()),
      );
    });
  });
}
