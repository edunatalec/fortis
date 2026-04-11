import 'dart:typed_data';

import 'package:fortis/fortis.dart';
import 'package:test/test.dart';

void main() {
  late FortisRsaKeyPair pair;
  late FortisRsaKeyPair otherPair;

  setUpAll(() async {
    pair = await Fortis.rsa().keySize(2048).generateKeyPair();
    otherPair = await Fortis.rsa().keySize(2048).generateKeyPair();
  });

  group('RsaDecrypter', () {
    final plaintext = Uint8List.fromList('hello fortis'.codeUnits);

    RsaEncrypter makeEncrypter(FortisRsaKeyPair kp) => Fortis.rsa()
        .padding(RsaPadding.oaep_v2)
        .hash(RsaHash.sha256)
        .encrypter(kp.publicKey);

    RsaDecrypter makeDecrypter(FortisRsaKeyPair kp) => Fortis.rsa()
        .padding(RsaPadding.oaep_v2)
        .hash(RsaHash.sha256)
        .decrypter(kp.privateKey);

    test('decrypt recovers original plaintext', () {
      final ciphertext = makeEncrypter(pair).encrypt(plaintext);
      final recovered = makeDecrypter(pair).decrypt(ciphertext);
      expect(recovered, equals(plaintext));
    });

    test('end-to-end round-trip: generate → encrypt → decrypt → equal',
        () async {
      final newPair = await Fortis.rsa().keySize(2048).generateKeyPair();
      final ciphertext = makeEncrypter(newPair).encrypt(plaintext);
      final recovered = makeDecrypter(newPair).decrypt(ciphertext);
      expect(recovered, equals(plaintext));
    });

    test('wrong key throws FortisEncryptionException', () {
      final ciphertext = makeEncrypter(pair).encrypt(plaintext);
      expect(
        () => makeDecrypter(otherPair).decrypt(ciphertext),
        throwsA(isA<FortisEncryptionException>()),
      );
    });
  });
}
