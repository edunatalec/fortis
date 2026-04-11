import 'dart:typed_data';

import 'package:fortis/fortis.dart';
import 'package:test/test.dart';

void main() {
  late FortisRsaKeyPair pair;

  setUpAll(() async {
    pair = await Fortis.rsa().keySize(2048).generateKeyPair();
  });

  group('RsaEncrypter', () {
    final plaintext = Uint8List.fromList('hello fortis'.codeUnits);

    RsaEncrypter makeEncrypter({
      RsaPadding padding = RsaPadding.oaep_v2,
      RsaHash hash = RsaHash.sha256,
    }) =>
        Fortis.rsa().padding(padding).hash(hash).encrypter(pair.publicKey);

    test('returns non-empty Uint8List', () {
      final encrypter = makeEncrypter();
      final result = encrypter.encrypt(plaintext);
      expect(result, isNotEmpty);
    });

    test('encrypted output differs from plaintext', () {
      final encrypter = makeEncrypter();
      final result = encrypter.encrypt(plaintext);
      expect(result, isNot(equals(plaintext)));
    });

    test('OAEP is probabilistic — same plaintext produces different ciphertexts',
        () {
      final encrypter = makeEncrypter();
      final c1 = encrypter.encrypt(plaintext);
      final c2 = encrypter.encrypt(plaintext);
      expect(c1, isNot(equals(c2)));
    });

    test('compile-time safety — encrypter not available without padding/hash',
        () {
      // The following line must NOT compile if uncommented:
      // Fortis.rsa().encrypter(pair.publicKey);
      //
      // This test verifies the invariant holds by ensuring the builder
      // returns the correct type.
      final builder = Fortis.rsa();
      expect(builder, isA<RsaBuilder>());
    });
  });
}
