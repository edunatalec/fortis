import 'dart:typed_data';

import 'package:fortis/fortis.dart';
import 'package:test/test.dart';

void main() {
  late FortisAesKey key;

  setUpAll(() async {
    key = await Fortis.aes().keySize(256).generateKey();
  });

  group('AesPadding — round-trip coverage', () {
    test('CBC + zeroPadding recovers short plaintext', () {
      final cipher = Fortis.aes()
          .cbc()
          .padding(AesPadding.zeroPadding)
          .cipher(key);
      final ct = cipher.encrypt('hello');
      // zeroPadding is ambiguous — expect at least the original bytes back.
      final decoded = cipher.decryptToString(ct);
      expect(decoded, startsWith('hello'));
    });

    test('CBC + zeroPadding with 15-byte plaintext round-trip', () {
      final cipher = Fortis.aes()
          .cbc()
          .padding(AesPadding.zeroPadding)
          .cipher(key);
      final ct = cipher.encrypt('abcdefghijklmno'); // 15 bytes
      final decoded = cipher.decryptToString(ct);
      expect(decoded, startsWith('abcdefghijklmno'));
    });

    test('CBC + noPadding accepts 16-byte-aligned input', () {
      final cipher = Fortis.aes()
          .cbc()
          .padding(AesPadding.noPadding)
          .cipher(key);
      final aligned = Uint8List.fromList(List.generate(32, (i) => i));
      final ct = cipher.encrypt(aligned);
      // Decrypting exercises _NoPadding.padCount.
      expect(() => cipher.decrypt(ct), returnsNormally);
    });

    test('CBC + noPadding with misaligned data throws', () {
      final cipher = Fortis.aes()
          .cbc()
          .padding(AesPadding.noPadding)
          .cipher(key);
      expect(
        () => cipher.encrypt('not aligned'),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('CBC + iso7816 padding round-trip', () {
      final cipher = Fortis.aes().cbc().padding(AesPadding.iso7816).cipher(key);
      final ct = cipher.encrypt('hello fortis');
      expect(cipher.decryptToString(ct), equals('hello fortis'));
    });

    test('ECB + zeroPadding round-trip', () {
      final cipher = Fortis.aes()
          .ecb()
          .padding(AesPadding.zeroPadding)
          .cipher(key);
      final ct = cipher.encrypt('hi');
      final decoded = cipher.decryptToString(ct);
      expect(decoded, startsWith('hi'));
    });

    test('ECB + noPadding accepts 16-byte-aligned input', () {
      final cipher = Fortis.aes()
          .ecb()
          .padding(AesPadding.noPadding)
          .cipher(key);
      final aligned = Uint8List.fromList(List.generate(16, (i) => i));
      final ct = cipher.encrypt(aligned);
      expect(() => cipher.decrypt(ct), returnsNormally);
    });

    test('ECB + noPadding with misaligned data throws', () {
      final cipher = Fortis.aes()
          .ecb()
          .padding(AesPadding.noPadding)
          .cipher(key);
      expect(
        () => cipher.encrypt(Uint8List(15)),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('ECB + iso7816 padding round-trip', () {
      final cipher = Fortis.aes().ecb().padding(AesPadding.iso7816).cipher(key);
      final ct = cipher.encrypt('hello fortis');
      expect(cipher.decryptToString(ct), equals('hello fortis'));
    });
  });

  group('stream cipher block loop (CFB/OFB)', () {
    // Long inputs exercise the `while (offset + blockSize <= input.length)`
    // loop in _processStreamBlockCipher.

    test('CFB with 32-byte aligned input round-trip', () {
      final cipher = Fortis.aes().cfb().cipher(key);
      final input = Uint8List.fromList(List.generate(32, (i) => i & 0xff));
      final ct = cipher.encrypt(input);
      expect(cipher.decrypt(ct), equals(input));
    });

    test('CFB with 48-byte aligned input round-trip', () {
      final cipher = Fortis.aes().cfb().cipher(key);
      final input = Uint8List.fromList(List.generate(48, (i) => i & 0xff));
      final ct = cipher.encrypt(input);
      expect(cipher.decrypt(ct), equals(input));
    });

    test('CFB with 20-byte unaligned input round-trip', () {
      final cipher = Fortis.aes().cfb().cipher(key);
      final input = Uint8List.fromList(List.generate(20, (i) => i & 0xff));
      final ct = cipher.encrypt(input);
      expect(cipher.decrypt(ct), equals(input));
    });

    test('OFB with 48-byte aligned input round-trip', () {
      final cipher = Fortis.aes().ofb().cipher(key);
      final input = Uint8List.fromList(List.generate(48, (i) => i & 0xff));
      final ct = cipher.encrypt(input);
      expect(cipher.decrypt(ct), equals(input));
    });

    test('OFB with 33-byte unaligned input round-trip', () {
      final cipher = Fortis.aes().ofb().cipher(key);
      final input = Uint8List.fromList(List.generate(33, (i) => i & 0xff));
      final ct = cipher.encrypt(input);
      expect(cipher.decrypt(ct), equals(input));
    });
  });
}
