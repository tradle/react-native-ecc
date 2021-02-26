export const ErrorCode = Object.freeze({
  Canceled: 'canceled',
  BiometryNotAvailable: 'biometry-not-available',
  LockoutTemporarily: 'lockout-temporarily',
  LockoutPermanent: 'lockout-permanent',
  Generic: 'generic',
});

/**
 * Check: https://developer.android.com/reference/androidx/biometric/BiometricPrompt
 */
export const AndroidErrorCode = Object.freeze({
  1: ErrorCode.BiometryNotAvailable,    // ERROR_HW_UNAVAILABLE
  2: ErrorCode.Generic,                 // ERROR_UNABLE_TO_PROCESS
  3: ErrorCode.Generic,                 // ERROR_TIMEOUT
  4: ErrorCode.Generic,                 // ERROR_NO_SPACE
  5: ErrorCode.Canceled,                // ERROR_CANCELED
  7: ErrorCode.LockoutTemporarily,      // ERROR_LOCKOUT
  8: ErrorCode.Generic,                 // ERROR_VENDOR
  9: ErrorCode.LockoutPermanent,        // ERROR_LOCKOUT_PERMANENT
  10: ErrorCode.Canceled,               // ERROR_USER_CANCELED
  11: ErrorCode.BiometryNotAvailable,   // ERROR_NO_BIOMETRICS
  12: ErrorCode.BiometryNotAvailable,   // ERROR_HW_NOT_PRESENT
  13: ErrorCode.Canceled,               // ERROR_NEGATIVE_BUTTON
  14: ErrorCode.BiometryNotAvailable,   // ERROR_NO_DEVICE_CREDENTIAL
  15: ErrorCode.Generic,                // ERROR_SECURITY_UPDATE_REQUIRED
  1000: ErrorCode.Generic,              // ERROR_INVALID_PROMPT_PARAMETERS (custom error)
  1001: ErrorCode.BiometryNotAvailable, // ERROR_INVALID_SIGNATURE (custom error)
});

/**
 * Check: https://developer.apple.com/documentation/security/1542001-security_framework_result_codes
 */
export const IOSErrorCode = Object.freeze({
  '-128': ErrorCode.Canceled,               // errSecUserCanceled: User canceled the operation.
  '-25291': ErrorCode.BiometryNotAvailable, // errSecNotAvailable: No keychain is available. You may need to restart your computer.
  '-25292': ErrorCode.Generic,              // errSecReadOnly: This keychain cannot be modified.
  '-25293': ErrorCode.LockoutTemporarily,   // errSecAuthFailed: The user name or passphrase you entered is not correct.
  '-25294': ErrorCode.BiometryNotAvailable, // errSecNoSuchKeychain: The specified keychain could not be found.
  '-25295': ErrorCode.BiometryNotAvailable, // errSecInvalidKeychain: The specified keychain is not a valid keychain file.
  '-25296': ErrorCode.BiometryNotAvailable, // errSecDuplicateKeychain: A keychain with the same name already exists.
  '-25297': ErrorCode.Generic,              // errSecDuplicateCallback: The specified callback function is already installed.
  '-25298': ErrorCode.Generic,              // errSecInvalidCallback: The specified callback function is not valid.
  '-25299': ErrorCode.BiometryNotAvailable, // errSecDuplicateItem: The specified item already exists in the keychain.
  '-25300': ErrorCode.BiometryNotAvailable, // errSecItemNotFound: The specified item could not be found in the keychain.
  '-25301': ErrorCode.Generic,              // errSecBufferTooSmall: There is not enough memory available to use the specified item.
  '-25302': ErrorCode.Generic,              // errSecDataTooLarge: This item contains information which is too large or in a format that cannot be displayed.
  '-25303': ErrorCode.Generic,              // errSecNoSuchAttr: The specified attribute does not exist.
  '-25304': ErrorCode.BiometryNotAvailable, // errSecInvalidItemRef: The specified item is no longer valid. It may have been deleted from the keychain.
  '-25305': ErrorCode.BiometryNotAvailable, // errSecInvalidSearchRef: Unable to search the current keychain.
  '-25306': ErrorCode.BiometryNotAvailable, // errSecNoSuchClass: The specified item does not appear to be a valid keychain item.
  '-25307': ErrorCode.BiometryNotAvailable, // errSecNoDefaultKeychain: A default keychain could not be found.
  '-25308': ErrorCode.Generic,              // errSecInteractionNotAllowed: User interaction is not allowed.
  '-25309': ErrorCode.Generic,              // errSecReadOnlyAttr: The specified attribute could not be modified.
  '-25310': ErrorCode.BiometryNotAvailable, // errSecWrongSecVersion: This keychain was created by a different version of the system software and cannot be opened.
  '-25311': ErrorCode.BiometryNotAvailable, // errSecKeySizeNotAllowed: This item specifies a key size which is too large or too small.
  '-25312': ErrorCode.Generic,              // errSecNoStorageModule: A required component (data storage module) could not be loaded. You may need to restart your computer.
  '-25313': ErrorCode.Generic,              // errSecNoCertificateModule: A required component (certificate module) could not be loaded. You may need to restart your computer.
  '-25314': ErrorCode.Generic,              // errSecNoPolicyModule: A required component (policy module) could not be loaded. You may need to restart your computer.
  '-25315': ErrorCode.Generic,              // errSecInteractionRequired: User interaction is required, but is currently not allowed.
  '-25316': ErrorCode.Generic,              // errSecDataNotAvailable: The contents of this item cannot be retrieved.
  '-25317': ErrorCode.Generic,              // errSecDataNotModifiable: The contents of this item cannot be modified.
  '-25318': ErrorCode.Generic,              // errSecCreateChainFailed: One or more certificates required to validate this certificate cannot be found.
  '-25319': ErrorCode.Generic,              // errSecInvalidPrefsDomain: The specified preferences domain is not valid.
});

export default class ECCError extends Error {
  constructor(errorCode, nativeErrorCode) {
    super('ECCError');

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, ECCError);
    }

    this.name = 'ECCError';

    this.code = errorCode;
    this.nativeCode = nativeErrorCode;
  }
}
