/**
 * Error codes for OSCORE (Object Security for Constrained RESTful Environments) operations.
 * General errors: 0-99, OSCORE-specific errors: 200+
 */
export enum OscoreError {
  /* Operation completed successfully */
  OK = 0,
  /* Buffer too small to contain result */
  BUFFER_TOO_SMALL = 1,
  /* HKDF operation failed */
  HKDF_FAILED = 2,
  /* Unexpected result from external library */
  UNEXPECTED_RESULT_FROM_EXT_LIB = 3,
  /* Invalid parameter provided */
  WRONG_PARAMETER = 4,
  /* Cryptographic operation not implemented */
  CRYPTO_OPERATION_NOT_IMPLEMENTED = 5,
  /* Feature not supported */
  NOT_SUPPORTED_FEATURE = 6,

  /* Not an OSCORE packet */
  NOT_OSCORE_PKT = 200,
  /* First request after device reboot */
  FIRST_REQUEST_AFTER_REBOOT = 201,
  /* Echo option validation failed */
  ECHO_VALIDATION_FAILED = 202,
  /* Unknown HKDF algorithm */
  OSCORE_UNKNOWN_HKDF = 203,
  /* Token mismatch */
  TOKEN_MISMATCH = 204,
  /* Invalid AEAD algorithm */
  OSCORE_INVALID_ALGORITHM_AEAD = 205,
  /* Invalid HKDF algorithm */
  OSCORE_INVALID_ALGORITHM_HKDF = 206,
  /* KID and Recipient ID mismatch */
  OSCORE_KID_RECIPIENT_ID_MISMATCH = 207,
  /* Too many options in message */
  TOO_MANY_OPTIONS = 208,
  /* Option value length too long */
  OSCORE_VALUELEN_TOO_LONG_ERROR = 209,
  /* Invalid token length */
  OSCORE_INPKT_INVALID_TKL = 210,
  /* Invalid option delta */
  OSCORE_INPKT_INVALID_OPTION_DELTA = 211,
  /* Invalid option length */
  OSCORE_INPKT_INVALID_OPTIONLEN = 212,
  /* Invalid PIV */
  OSCORE_INPKT_INVALID_PIV = 213,
  /* Invalid input packet */
  NOT_VALID_INPUT_PACKET = 214,
  /* Replay window protection error */
  OSCORE_REPLAY_WINDOW_PROTECTION_ERROR = 215,
  /* Replay notification protection error */
  OSCORE_REPLAY_NOTIFICATION_PROTECTION_ERROR = 216,
  /* Missing Echo option */
  NO_ECHO_OPTION = 217,
  /* Echo value mismatch */
  ECHO_VAL_MISMATCH = 218,
  /* SSN overflow */
  OSCORE_SSN_OVERFLOW = 219,
  /* Maximum interactions reached */
  OSCORE_MAX_INTERACTIONS = 220,
  /* Duplicate token in interaction */
  OSCORE_INTERACTION_DUPLICATED_TOKEN = 221,
  /* Interaction not found */
  OSCORE_INTERACTION_NOT_FOUND = 222,
  /* Wrong URI path */
  OSCORE_WRONG_URI_PATH = 223,
  /* No response received */
  OSCORE_NO_RESPONSE = 224,
}

export class OscoreProtocolError extends Error {
  public readonly status: OscoreError;
  constructor(code: OscoreError, message?: string) {
    super(message ?? `OSCORE error ${code}`);
    this.status = code;
    Object.setPrototypeOf(this, OscoreProtocolError.prototype);
  }
}

export class OscoreRebootRecoveryError extends OscoreProtocolError {
  public readonly decrypted: Buffer;
  constructor(decrypted: Buffer) {
    super(OscoreError.FIRST_REQUEST_AFTER_REBOOT, 'First request after reboot – Echo challenge required');
    this.decrypted = decrypted;
    Object.setPrototypeOf(this, OscoreRebootRecoveryError.prototype);
  }
}
