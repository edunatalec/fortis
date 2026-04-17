import 'package:pointycastle/ecc/api.dart';

import '../../exceptions/fortis_key_exception.dart';
import 'ecdh_curve.dart';

/// Verifies that the PointyCastle EC key parameters match the declared curve.
///
/// Called by both `FortisEcdhPublicKey` and `FortisEcdhPrivateKey` constructors
/// to reject forged combinations like a P-256 key announced as P-384.
void validateKeyCurveMatch(ECDomainParameters? params, EcdhCurve curve) {
  final actual = params?.domainName;
  if (actual == null) {
    throw FortisKeyException(
      'EC key has no domain parameters; cannot verify curve.',
    );
  }
  if (actual != curve.domainName) {
    throw FortisKeyException(
      'EC key curve mismatch: key is $actual but was declared as '
      '${curve.domainName} (${curve.name}).',
    );
  }
}
