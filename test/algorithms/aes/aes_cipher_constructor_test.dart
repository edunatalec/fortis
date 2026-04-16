import 'package:fortis/fortis.dart';
import 'package:test/test.dart';

void main() {
  late FortisAesKey key;

  setUpAll(() async {
    key = await Fortis.aes().generateKey();
  });

  group('AesAuthCipher constructor — tagSizeBits validation', () {
    test('GCM + tagSizeBits=128 constructs normally', () {
      expect(
        () => AesAuthCipher(mode: AesMode.gcm, key: key, tagSizeBits: 128),
        returnsNormally,
      );
    });

    test('GCM + tagSizeBits=96 throws FortisConfigException', () {
      // PointyCastle only accepts 128 for GCM. The constructor must reject
      // anything else up front, not silently fail later at encrypt time.
      expect(
        () => AesAuthCipher(mode: AesMode.gcm, key: key, tagSizeBits: 96),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('GCM + tagSizeBits=0 throws FortisConfigException', () {
      expect(
        () => AesAuthCipher(mode: AesMode.gcm, key: key, tagSizeBits: 0),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('CCM + tagSizeBits=96 constructs normally (valid per NIST)', () {
      expect(
        () => AesAuthCipher(mode: AesMode.ccm, key: key, tagSizeBits: 96),
        returnsNormally,
      );
    });

    test('CCM + tagSizeBits=65 throws FortisConfigException', () {
      // 65 is not in the NIST SP 800-38C set {32,48,64,80,96,112,128}.
      expect(
        () => AesAuthCipher(mode: AesMode.ccm, key: key, tagSizeBits: 65),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('CCM + tagSizeBits=0 throws FortisConfigException', () {
      expect(
        () => AesAuthCipher(mode: AesMode.ccm, key: key, tagSizeBits: 0),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('CCM + tagSizeBits=256 throws FortisConfigException', () {
      expect(
        () => AesAuthCipher(mode: AesMode.ccm, key: key, tagSizeBits: 256),
        throwsA(isA<FortisConfigException>()),
      );
    });
  });

  group('AesStandardCipher constructor — padding consistency', () {
    test('CBC + padding=null throws FortisConfigException', () {
      // CBC requires a padding scheme; null leads to a runtime NPE deep in
      // the encrypt path. Must be rejected at construction time.
      expect(
        () => AesStandardCipher(mode: AesMode.cbc, key: key),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('CBC + padding=pkcs7 constructs normally', () {
      expect(
        () => AesStandardCipher(
          mode: AesMode.cbc,
          key: key,
          padding: AesPadding.pkcs7,
        ),
        returnsNormally,
      );
    });

    test('CTR + padding=pkcs7 throws FortisConfigException', () {
      // Stream modes don't use padding. Passing one suggests a misuse —
      // reject rather than silently ignoring.
      expect(
        () => AesStandardCipher(
          mode: AesMode.ctr,
          key: key,
          padding: AesPadding.pkcs7,
        ),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('CFB + padding=pkcs7 throws FortisConfigException', () {
      expect(
        () => AesStandardCipher(
          mode: AesMode.cfb,
          key: key,
          padding: AesPadding.pkcs7,
        ),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('OFB + padding=pkcs7 throws FortisConfigException', () {
      expect(
        () => AesStandardCipher(
          mode: AesMode.ofb,
          key: key,
          padding: AesPadding.pkcs7,
        ),
        throwsA(isA<FortisConfigException>()),
      );
    });

    test('CTR + padding=null constructs normally', () {
      expect(
        () => AesStandardCipher(mode: AesMode.ctr, key: key),
        returnsNormally,
      );
    });
  });
}
