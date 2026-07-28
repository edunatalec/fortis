import 'package:fortis/fortis.dart';
import 'package:test/test.dart';

void main() {
  group('FortisException.toString()', () {
    test('FortisConfigException formats as "runtimeType: message"', () {
      const e = FortisConfigException('boom');
      expect(e.toString(), equals('FortisConfigException: boom'));
      expect(e.message, equals('boom'));
    });

    test('FortisKeyException formats as "runtimeType: message"', () {
      const e = FortisKeyException('bad key');
      expect(e.toString(), equals('FortisKeyException: bad key'));
    });

    test('FortisEncryptionException formats as "runtimeType: message"', () {
      const e = FortisEncryptionException('decryption failed');
      expect(
        e.toString(),
        equals('FortisEncryptionException: decryption failed'),
      );
    });

    test('all concrete exceptions are instances of FortisException', () {
      expect(const FortisConfigException('x'), isA<FortisException>());
      expect(const FortisKeyException('x'), isA<FortisException>());
      expect(const FortisEncryptionException('x'), isA<FortisException>());
    });
  });
}
