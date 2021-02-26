package com.rn.ecc;

import androidx.biometric.BiometricPrompt;

import com.facebook.react.bridge.Callback;

import java.security.Signature;

public class ECCAuthenticationCallback extends BiometricPrompt.AuthenticationCallback {
    private final KeyManager keyManager;
    private final String data;
    private final Callback callback;

    public ECCAuthenticationCallback(KeyManager keyManager, String data, Callback callback) {
        this.keyManager = keyManager;
        this.data = data;
        this.callback = callback;
    }

    @Override
    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult authenticationResult) {
        super.onAuthenticationSucceeded(authenticationResult);
        try {
            BiometricPrompt.CryptoObject cryptoObject = authenticationResult.getCryptoObject();
            Signature signature = cryptoObject.getSignature();
            String signedData = keyManager.sign(data, signature);
            callback.invoke(null, signedData);
        } catch (Exception ex) {
            callback.invoke(ECCModule.ERROR_INVALID_SIGNATURE, null);
        }
    }

    @Override
    public void onAuthenticationError(int errorCode, CharSequence errorCharSequence) {
        super.onAuthenticationError(errorCode, errorCharSequence);
        callback.invoke(errorCode, null);
    }
}
