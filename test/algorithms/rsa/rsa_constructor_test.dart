import 'dart:typed_data';

import 'package:fortis/fortis.dart';
import 'package:test/test.dart';

void main() {
  late FortisRsaKeyPair pair;
  final label = Uint8List.fromList([1, 2, 3]);

  setUpAll(() async {
    pair = await Fortis.rsa().keySize(2048).generateKeyPair();
  });

  group('RsaEncrypter constructor — label validation', () {
    test('pkcs1_v1_5 + label throws FortisConfigException', () {
      expect(
        () => RsaEncrypter(
          key: pair.publicKey,
          padding: RsaPadding.pkcs1_v1_5,
          hash: RsaHash.sha256,
          label: label,
        ),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('oaep_v1 + label throws FortisConfigException', () {
      expect(
        () => RsaEncrypter(
          key: pair.publicKey,
          padding: RsaPadding.oaep_v1,
          hash: RsaHash.sha1,
          label: label,
        ),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('oaep_v2 + label throws FortisConfigException', () {
      expect(
        () => RsaEncrypter(
          key: pair.publicKey,
          padding: RsaPadding.oaep_v2,
          hash: RsaHash.sha256,
          label: label,
        ),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('oaep_v2_1 + label constructs normally', () {
      expect(
        () => RsaEncrypter(
          key: pair.publicKey,
          padding: RsaPadding.oaep_v2_1,
          hash: RsaHash.sha256,
          label: label,
        ),
        returnsNormally,
      );
    });

    test('any padding without label constructs normally', () {
      for (final p in RsaPadding.values) {
        expect(
          () => RsaEncrypter(
            key: pair.publicKey,
            padding: p,
            hash: RsaHash.sha256,
          ),
          returnsNormally,
          reason: 'padding=$p',
        );
      }
    });
  });

  group('RsaDecrypter constructor — label validation', () {
    test('pkcs1_v1_5 + label throws FortisConfigException', () {
      expect(
        () => RsaDecrypter(
          key: pair.privateKey,
          padding: RsaPadding.pkcs1_v1_5,
          hash: RsaHash.sha256,
          label: label,
        ),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('oaep_v2 + label throws FortisConfigException', () {
      expect(
        () => RsaDecrypter(
          key: pair.privateKey,
          padding: RsaPadding.oaep_v2,
          hash: RsaHash.sha256,
          label: label,
        ),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('oaep_v2_1 + label constructs normally', () {
      expect(
        () => RsaDecrypter(
          key: pair.privateKey,
          padding: RsaPadding.oaep_v2_1,
          hash: RsaHash.sha256,
          label: label,
        ),
        returnsNormally,
      );
    });
  });
}
