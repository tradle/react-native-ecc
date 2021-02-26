declare module 'react-native-ecc' {
  type PublicKey = string;

  interface SignArgs {
    publicKey: PublicKey;
    data: string;
    promptTitle: string;
    promptMessage: string;
    promptCancel: string;
  }

  interface PublicKeyPoints {
    x: string;
    y: string;
  }

  export enum ErrorCode {
    Canceled = 'canceled',
    BiometryNotAvailable = 'biometry-not-available',
    LockoutTemporarily = 'lockout-temporarily',
    LockoutPermanent = 'lockout-permanent',
    Generic = 'generic',
  }

  export class ECCError extends Error {
    errorCode: ErrorCode;
    nativeCode: string;

    constructor(errorCode: ErrorCode, nativeCode: string);
  }

  function setServiceID(): void;
  function generateKeys(): Promise<PublicKey>;
  function sign(args: SignArgs): Promise<string>;
  function cancelSigning(): Promise<void>;
  function computeCoordinates(publicKey: PublicKey): PublicKeyPoints;
}
