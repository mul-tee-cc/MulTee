use common::error::MulTeeErrCode;
use common::error::MulTeeError;

pub(crate) fn map_known_err(err: MulTeeError) -> MulTeeError {
  match err {
    MulTeeError {
      tag: MulTeeErrCode::CRYPTO_MBED,
      sub: -18,
      message,
    } => MulTeeError {
      tag: MulTeeErrCode::CRYPTO_AUTH_TAG_VERIFY_FAILED,
      sub: 0,
      message,
    },
    MulTeeError {
      tag: MulTeeErrCode::CRYPTO_INVALID_KEY_INDEX | MulTeeErrCode::KEY_IMPORT,
      ..
    } => {
      MulTeeErrCode::CRYPTO_INVALID_KEY_NAME.msg(format!("Key wasn't loaded successfully: {}", err))
    }
    // MulTeeError { tag: MulTeeErrCode::KEY_IMPORT, ..} => MulTeeErrCode::CRYPTO_INVALID_KEY_NAME.msg("Key wasn't loaded successfully"),
    x => x,
  }
}
