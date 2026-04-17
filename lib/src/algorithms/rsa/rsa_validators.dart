import 'dart:typed_data';

import '../../exceptions/fortis_config_exception.dart';
import 'rsa_padding.dart';

/// Shared label/padding validation for `RsaEncrypter` and `RsaDecrypter`.
///
/// Only OAEP v2.1 consumes the label; other paddings would silently ignore
/// it, so the combination is rejected at construction time.
void validateLabelPadding(Uint8List? label, RsaPadding padding) {
  if (label != null && padding != RsaPadding.oaep_v2_1) {
    throw FortisConfigException(
      'label is only supported with RsaPadding.oaep_v2_1, '
      'but padding is $padding.',
    );
  }
}
