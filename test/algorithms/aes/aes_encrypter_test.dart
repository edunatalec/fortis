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

  // ── encrypt(Object plaintext, {Uint8List? iv}) ───────────────────────────

  group('encrypt — Uint8List plaintext', () {
    test('accepts Uint8List and returns non-empty Uint8List', () {
      final result = enc(AesMode.gcm).encrypt(Uint8List.fromList([1, 2, 3]));
      expect(result, isA<Uint8List>());
      expect(result, isNotEmpty);
    });
  });

  group('encrypt — String plaintext', () {
    test('accepts String and returns non-empty Uint8List', () {
      final result = enc(AesMode.gcm).encrypt('hello fortis');
      expect(result, isA<Uint8List>());
      expect(result, isNotEmpty);
    });
  });

  group('encrypt — randomness', () {
    test('different calls produce different output (random IV)', () {
      final encrypter = enc(AesMode.gcm);
      final r1 = encrypter.encrypt('hello');
      final r2 = encrypter.encrypt('hello');
      expect(r1, isNot(equals(r2)));
    });
  });

  group('encrypt — explicit iv', () {
    test('explicit iv produces deterministic output', () {
      final encrypter = enc(AesMode.gcm);
      final iv = Uint8List(12);
      final r1 = encrypter.encrypt('hello', iv: iv);
      final r2 = encrypter.encrypt('hello', iv: iv);
      expect(r1, equals(r2));
    });

    test('wrong iv size throws FortisConfigException', () {
      expect(
        () => enc(AesMode.gcm).encrypt('hello', iv: Uint8List(8)),
        throwsA(isA<FortisConfigException>()),
      );
    });
  });

  group('encrypt — unsupported type', () {
    test('unsupported plaintext type throws FortisConfigException', () {
      expect(
        () => enc(AesMode.gcm).encrypt(42),
        throwsA(isA<FortisConfigException>()),
      );
    });
  });

  // ── encryptToString(Object plaintext, {Uint8List? iv}) ───────────────────

  group('encryptToString', () {
    test('accepts Uint8List and returns valid Base64 string', () {
      final result =
          enc(AesMode.gcm).encryptToString(Uint8List.fromList([1, 2, 3]));
      expect(result, isA<String>());
      expect(() => base64Decode(result), returnsNormally);
    });

    test('accepts String and returns valid Base64 string', () {
      final result = enc(AesMode.gcm).encryptToString('hello fortis');
      expect(result, isA<String>());
      expect(() => base64Decode(result), returnsNormally);
    });
  });

  // ── encryptToPayload(Object plaintext, {Uint8List? iv}) ──────────────────

  group('encryptToPayload — mode routing', () {
    test('GCM mode returns AesAuthPayload', () {
      expect(enc(AesMode.gcm).encryptToPayload('hello'), isA<AesAuthPayload>());
    });

    test('CCM mode returns AesAuthPayload', () {
      expect(enc(AesMode.ccm).encryptToPayload('hello'), isA<AesAuthPayload>());
    });

    test('CBC mode returns AesPayload', () {
      expect(enc(AesMode.cbc).encryptToPayload('hello'), isA<AesPayload>());
    });

    test('CTR mode returns AesPayload', () {
      expect(enc(AesMode.ctr).encryptToPayload('hello'), isA<AesPayload>());
    });

    test('CFB mode returns AesPayload', () {
      expect(enc(AesMode.cfb).encryptToPayload('hello'), isA<AesPayload>());
    });

    test('OFB mode returns AesPayload', () {
      expect(enc(AesMode.ofb).encryptToPayload('hello'), isA<AesPayload>());
    });

    test('ECB mode throws FortisConfigException', () {
      expect(
        () => enc(AesMode.ecb).encryptToPayload('hello'),
        throwsA(isA<FortisConfigException>()),
      );
    });
  });

  group('encryptToPayload — AesAuthPayload fields', () {
    late AesAuthPayload payload;

    setUp(() {
      payload = enc(AesMode.gcm).encryptToPayload('hello') as AesAuthPayload;
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
      payload = enc(AesMode.cbc).encryptToPayload('hello') as AesPayload;
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
