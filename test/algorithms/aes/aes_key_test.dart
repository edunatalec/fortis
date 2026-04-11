import 'dart:convert';
import 'dart:typed_data';

import 'package:fortis/fortis.dart';
import 'package:test/test.dart';

void main() {
  group('FortisAesKey — fromBytes', () {
    test('accepts 128-bit key (16 bytes)', () {
      final key = FortisAesKey.fromBytes(Uint8List(16));
      expect(key.keySize, equals(128));
    });

    test('accepts 192-bit key (24 bytes)', () {
      final key = FortisAesKey.fromBytes(Uint8List(24));
      expect(key.keySize, equals(192));
    });

    test('accepts 256-bit key (32 bytes)', () {
      final key = FortisAesKey.fromBytes(Uint8List(32));
      expect(key.keySize, equals(256));
    });

    test('rejects 64-bit key with FortisKeyException', () {
      expect(
        () => FortisAesKey.fromBytes(Uint8List(8)),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('rejects 512-bit key with FortisKeyException', () {
      expect(
        () => FortisAesKey.fromBytes(Uint8List(64)),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('toBytes returns copy of key bytes with correct length', () {
      final bytes = Uint8List.fromList(List.generate(32, (i) => i));
      final key = FortisAesKey.fromBytes(bytes);
      expect(key.toBytes(), equals(bytes));
      expect(key.toBytes().length, equals(32));
    });
  });

  group('FortisAesKey — Base64 serialization', () {
    late FortisAesKey key;

    setUpAll(() async {
      key = await Fortis.aes().keySize(256).generateKey();
    });

    test('toBase64 returns non-empty Base64 string', () {
      final b64 = key.toBase64();
      expect(b64, isNotEmpty);
      expect(() => base64Decode(b64), returnsNormally);
    });

    test('fromBase64 round-trips correctly', () {
      final b64 = key.toBase64();
      final restored = FortisAesKey.fromBase64(b64);
      expect(restored.toBase64(), equals(b64));
    });

    test('fromBytes round-trips correctly', () {
      final bytes = key.toBytes();
      final restored = FortisAesKey.fromBytes(bytes);
      expect(restored.toBytes(), equals(bytes));
    });

    test('invalid Base64 throws FortisKeyException', () {
      expect(
        () => FortisAesKey.fromBase64('not-valid-base64!!!'),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('Base64 of wrong length throws FortisKeyException', () {
      // 10 bytes = invalid AES key size
      final bad = base64Encode(Uint8List(10));
      expect(
        () => FortisAesKey.fromBase64(bad),
        throwsA(isA<FortisKeyException>()),
      );
    });

    test('128-bit key has 16-byte toBytes', () async {
      final k128 = await Fortis.aes().keySize(128).generateKey();
      expect(k128.toBytes().length, equals(16));
      expect(k128.keySize, equals(128));
    });

    test('256-bit key has 32-byte toBytes', () async {
      final k256 = await Fortis.aes().keySize(256).generateKey();
      expect(k256.toBytes().length, equals(32));
      expect(k256.keySize, equals(256));
    });
  });

  group('FortisAesKey — key generation', () {
    test('generates AES-128 key successfully', () async {
      final k = await Fortis.aes().keySize(128).generateKey();
      expect(k.keySize, equals(128));
    });

    test('generates AES-192 key successfully', () async {
      final k = await Fortis.aes().keySize(192).generateKey();
      expect(k.keySize, equals(192));
    });

    test('generates AES-256 key successfully', () async {
      final k = await Fortis.aes().keySize(256).generateKey();
      expect(k.keySize, equals(256));
    });

    test('rejects invalid key size 64 with FortisConfigException', () async {
      expect(
        () => Fortis.aes().keySize(64).generateKey(),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('rejects invalid key size 512 with FortisConfigException', () async {
      expect(
        () => Fortis.aes().keySize(512).generateKey(),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('two generated keys are different', () async {
      final k1 = await Fortis.aes().keySize(256).generateKey();
      final k2 = await Fortis.aes().keySize(256).generateKey();
      expect(k1.toBytes(), isNot(equals(k2.toBytes())));
    });
  });
}
