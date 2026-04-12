import 'dart:convert';
import 'dart:typed_data';

import 'package:fortis/fortis.dart';
import 'package:test/test.dart';

void main() {
  late FortisRsaKeyPair pair;

  setUpAll(() async {
    pair = await Fortis.rsa().keySize(2048).generateKeyPair();
  });

  RsaEncrypter makeEncrypter({
    RsaPadding padding = RsaPadding.oaep_v2,
    RsaHash hash = RsaHash.sha256,
  }) =>
      Fortis.rsa().padding(padding).hash(hash).encrypter(pair.publicKey);

  group('encrypt(Object plaintext)', () {
    test('accepts Uint8List plaintext → returns non-empty Uint8List', () {
      final result =
          makeEncrypter().encrypt(Uint8List.fromList([1, 2, 3, 4, 5]));
      expect(result, isA<Uint8List>());
      expect(result, isNotEmpty);
    });

    test('accepts String plaintext → returns non-empty Uint8List', () {
      final result = makeEncrypter().encrypt('hello fortis');
      expect(result, isA<Uint8List>());
      expect(result, isNotEmpty);
    });

    test('encrypted output differs from plaintext', () {
      final plaintext = Uint8List.fromList('hello fortis'.codeUnits);
      final result = makeEncrypter().encrypt(plaintext);
      expect(result, isNot(equals(plaintext)));
    });

    test(
      'OAEP is probabilistic — same plaintext produces different ciphertexts',
      () {
        final encrypter = makeEncrypter();
        final c1 = encrypter.encrypt('hello fortis');
        final c2 = encrypter.encrypt('hello fortis');
        expect(c1, isNot(equals(c2)));
      },
    );

    test('unsupported plaintext type throws FortisConfigException', () {
      expect(
        () => makeEncrypter().encrypt(42),
        throwsA(isA<FortisConfigException>()),
      );
    });
  });

  group('encryptToString(Object plaintext)', () {
    test('accepts Uint8List plaintext → returns valid Base64 string', () {
      final result =
          makeEncrypter().encryptToString(Uint8List.fromList([1, 2, 3]));
      expect(result, isA<String>());
      expect(result, isNotEmpty);
      expect(() => base64Decode(result), returnsNormally);
    });

    test('accepts String plaintext → returns valid Base64 string', () {
      final result = makeEncrypter().encryptToString('hello fortis');
      expect(result, isA<String>());
      expect(result, isNotEmpty);
      expect(() => base64Decode(result), returnsNormally);
    });

    test('result is non-empty and decodable Base64', () {
      final result = makeEncrypter().encryptToString('fortis');
      expect(result, isNotEmpty);
      final decoded = base64Decode(result);
      expect(decoded, isNotEmpty);
    });
  });
}
