import 'dart:convert';
import 'dart:typed_data';

import 'package:fortis/fortis.dart';
import 'package:test/test.dart';

void main() {
  late FortisAesKey key;

  setUpAll(() async {
    key = await Fortis.aes().keySize(256).generateKey();
  });

  AesCipher cipher(AesMode mode) => Fortis.aes().mode(mode).cipher(key);
  AesAuthCipher authCipher(AesMode mode) =>
      Fortis.aes().mode(mode).cipher(key) as AesAuthCipher;
  AesStandardCipher stdCipher(AesMode mode) =>
      Fortis.aes().mode(mode).cipher(key) as AesStandardCipher;

  group('encrypt — Uint8List plaintext', () {
    test('accepts Uint8List and returns non-empty Uint8List', () {
      final result = cipher(AesMode.gcm).encrypt(Uint8List.fromList([1, 2, 3]));
      expect(result, isA<Uint8List>());
      expect(result, isNotEmpty);
    });
  });

  group('encrypt — String plaintext', () {
    test('accepts String and returns non-empty Uint8List', () {
      final result = cipher(AesMode.gcm).encrypt('hello fortis');
      expect(result, isA<Uint8List>());
      expect(result, isNotEmpty);
    });
  });

  group('encrypt — randomness', () {
    test('different calls produce different output (random IV)', () {
      final c = cipher(AesMode.gcm);
      final r1 = c.encrypt('hello');
      final r2 = c.encrypt('hello');
      expect(r1, isNot(equals(r2)));
    });
  });

  group('encrypt — explicit iv', () {
    test('explicit iv produces deterministic output', () {
      final c = cipher(AesMode.gcm);
      final iv = Uint8List(12);
      final r1 = c.encrypt('hello', iv: iv);
      final r2 = c.encrypt('hello', iv: iv);
      expect(r1, equals(r2));
    });

    test('wrong iv size throws FortisConfigException', () {
      expect(
        () => cipher(AesMode.gcm).encrypt('hello', iv: Uint8List(8)),
        throwsA(isA<FortisConfigException>()),
      );
    });
  });

  group('encrypt — unsupported type', () {
    test('unsupported plaintext type throws FortisConfigException', () {
      expect(
        () => cipher(AesMode.gcm).encrypt(42),
        throwsA(isA<FortisConfigException>()),
      );
    });
  });

  group('encryptToString', () {
    test('accepts Uint8List and returns valid Base64 string', () {
      final result = cipher(
        AesMode.gcm,
      ).encryptToString(Uint8List.fromList([1, 2, 3]));
      expect(result, isA<String>());
      expect(() => base64Decode(result), returnsNormally);
    });

    test('accepts String and returns valid Base64 string', () {
      final result = cipher(AesMode.gcm).encryptToString('hello fortis');
      expect(result, isA<String>());
      expect(() => base64Decode(result), returnsNormally);
    });
  });

  group('encryptToPayload — mode routing', () {
    test('GCM mode returns AesAuthPayload', () {
      expect(
        authCipher(AesMode.gcm).encryptToPayload('hello'),
        isA<AesAuthPayload>(),
      );
    });

    test('CCM mode returns AesAuthPayload', () {
      expect(
        authCipher(AesMode.ccm).encryptToPayload('hello'),
        isA<AesAuthPayload>(),
      );
    });

    test('CBC mode returns AesPayload', () {
      expect(
        stdCipher(AesMode.cbc).encryptToPayload('hello'),
        isA<AesPayload>(),
      );
    });

    test('CTR mode returns AesPayload', () {
      expect(
        stdCipher(AesMode.ctr).encryptToPayload('hello'),
        isA<AesPayload>(),
      );
    });

    test('CFB mode returns AesPayload', () {
      expect(
        stdCipher(AesMode.cfb).encryptToPayload('hello'),
        isA<AesPayload>(),
      );
    });

    test('OFB mode returns AesPayload', () {
      expect(
        stdCipher(AesMode.ofb).encryptToPayload('hello'),
        isA<AesPayload>(),
      );
    });

    test('ECB mode has no encryptToPayload (compile-time check)', () {
      // AesEcbCipher does not expose encryptToPayload at all — so there is
      // no runtime "throws" to test. This test documents that invariant.
      final ecbCipher = Fortis.aes().ecb().cipher(key);
      expect(ecbCipher, isA<AesEcbCipher>());
    });
  });

  group('encryptToPayload — AesAuthPayload fields', () {
    late AesAuthPayload payload;

    setUp(() {
      payload = authCipher(AesMode.gcm).encryptToPayload('hello');
    });

    test('has non-empty iv', () => expect(payload.iv, isNotEmpty));
    test('has non-empty data', () => expect(payload.data, isNotEmpty));
    test('has non-empty tag', () => expect(payload.tag, isNotEmpty));

    test("toMap() uses 'iv' key by default", () {
      final map = payload.toMap();
      expect(map.containsKey('iv'), isTrue);
      expect(map.containsKey('nonce'), isFalse);
      expect(map.containsKey('data'), isTrue);
      expect(map.containsKey('tag'), isTrue);
    });

    test("toMap(ivKey: 'nonce') uses 'nonce' key", () {
      final map = payload.toMap(ivKey: 'nonce');
      expect(map.containsKey('nonce'), isTrue);
      expect(map.containsKey('iv'), isFalse);
    });
  });

  group('encryptToPayload — AesPayload fields', () {
    late AesPayload payload;

    setUp(() {
      payload = stdCipher(AesMode.cbc).encryptToPayload('hello');
    });

    test('has non-empty iv', () => expect(payload.iv, isNotEmpty));
    test('has non-empty data', () => expect(payload.data, isNotEmpty));

    test("toMap() uses 'iv' key by default", () {
      final map = payload.toMap();
      expect(map.containsKey('iv'), isTrue);
      expect(map.containsKey('nonce'), isFalse);
      expect(map.containsKey('data'), isTrue);
    });

    test("toMap(ivKey: 'nonce') uses 'nonce' key", () {
      final map = payload.toMap(ivKey: 'nonce');
      expect(map.containsKey('nonce'), isTrue);
      expect(map.containsKey('iv'), isFalse);
    });
  });
}
