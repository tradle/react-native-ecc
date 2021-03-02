package com.rn.ecc;

import android.content.Context;
import android.os.Build;

import androidx.biometric.BiometricPrompt;
import androidx.biometric.BiometricPrompt.PromptInfo;
import androidx.fragment.app.FragmentActivity;

import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.UiThreadUtil;

import java.security.Signature;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;


public class ECCModule extends ReactContextBaseJavaModule {
    private static final String KEY_TO_ALIAS_MAPPER = "key.to.alias.mapper";
    private final KeyManager keyManager;
    private BiometricPrompt biometricPrompt;

    // Triggered when invalid parameters have been given to the biometric prompt
    // (e.g., no prompt title).
    public static final int ERROR_INVALID_PROMPT_PARAMETERS = 1000;
    // Triggered when trying to sign and the biometric set changed.
    public static final int ERROR_INVALID_SIGNATURE = 1001;
    // Triggered by some OnePlus devices (that implement the biometric prompt
    // wrong) on soft failures (e.g., wrong fingerprint).
    public static final int ERROR_NON_COMPLIANT_PROMPT = 1002;

    public ECCModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.keyManager = new KeyManager(reactContext.getSharedPreferences(KEY_TO_ALIAS_MAPPER, Context.MODE_PRIVATE));
    }

    @Override
    public String getName() {
        return "RNECC";
    }

    @Override
    public Map<String, Object> getConstants() {
        final Map<String, Object> constants = new HashMap<>();
        constants.put("preHash", true);
        return constants;
    }

    @ReactMethod
    public void generateECPair(ReadableMap map, Callback function) {
        try {
            String publicKey = keyManager.generateKeys();
            function.invoke(null, publicKey);
        } catch (Exception ex) {
            function.invoke(ex.toString(), null);
        }
    }

    @ReactMethod
    public void hasKey(final ReadableMap map, Callback function) {
        final String publicKey = map.getString("pub");
        function.invoke(null, keyManager.hasStoredKeysInKeystore(publicKey));
    }

    @ReactMethod
    public void sign(final ReadableMap map, final Callback function) {
        final String data = map.getString("hash");
        final String publicKey = map.getString("pub");
        final String message = map.getString("promptMessage");
        final String title = map.getString("promptTitle");
        final String cancel = map.getString("promptCancel");

        UiThreadUtil.runOnUiThread(
            new Runnable() {
                @Override
                public void run() {
                    try {
                        biometricPrompt = new BiometricPrompt(
                            (FragmentActivity) getCurrentActivity(),
                            Executors.newSingleThreadExecutor(),
                            new ECCAuthenticationCallback(keyManager, data, function)
                        );

                        PromptInfo promptInfo = new PromptInfo.Builder()
                            .setTitle(title)
                            .setDescription(message)
                            .setNegativeButtonText(cancel)
                            .build();

                        Signature signature = keyManager.getSigningSignature(publicKey);
                        BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(signature);

                        biometricPrompt.authenticate(promptInfo, cryptoObject);
                    } catch (IllegalArgumentException ex) {
                        function.invoke(ERROR_INVALID_PROMPT_PARAMETERS, null);
                    } catch (Exception ex) {
                        function.invoke(ERROR_INVALID_SIGNATURE, null);
                    }
                }
            });
    }

    @ReactMethod
    public void verify(ReadableMap map, Callback function) {
        try {
            String data = map.getString("hash");
            String publicKey = map.getString("pub");
            String expected = map.getString("sig");

            Signature signature = keyManager.getVerifyingSignature(publicKey);
            function.invoke(null, keyManager.verify(data, expected, signature));
        } catch (Exception ex) {
            function.invoke(ex.toString(), null);
        }
    }

    @ReactMethod
    public void cancelSigning(ReadableMap map, Callback function) {
        cancelAuthentication();
    }

    private void cancelAuthentication() {
        try {
            if (biometricPrompt != null) {
                biometricPrompt.cancelAuthentication();
            }
        } catch (Exception ex) {
            // Do nothing.
        } finally {
            biometricPrompt = null;
        }
    }

    public class ECCAuthenticationCallback extends BiometricPrompt.AuthenticationCallback {
        // See: https://forums.oneplus.com/threads/oneplus-7-pro-fingerprint-biometricprompt-does-not-show.1035821/
        private final String[] ONEPLUS_MODELS_WITHOUT_BIOMETRIC_BUG = {
            "A0001", // OnePlus One
            "ONE A2001", "ONE A2003", "ONE A2005", // OnePlus 2
            "ONE E1001", "ONE E1003", "ONE E1005", // OnePlus X
            "ONEPLUS A3000", "ONEPLUS SM-A3000", "ONEPLUS A3003", // OnePlus 3
            "ONEPLUS A3010", // OnePlus 3T
            "ONEPLUS A5000", // OnePlus 5
            "ONEPLUS A5010", // OnePlus 5T
            "ONEPLUS A6000", "ONEPLUS A6003" // OnePlus 6
        };

        public boolean hasOnePlusBiometricBug() {
            return Build.BRAND.equalsIgnoreCase("oneplus") &&
                !Arrays.asList(ONEPLUS_MODELS_WITHOUT_BIOMETRIC_BUG).contains(Build.MODEL);
        }

        private final KeyManager keyManager;
        private final String data;
        private final Callback callback;
        private boolean onePlusWithBiometricBugFailure;

        public ECCAuthenticationCallback(KeyManager keyManager, String data, Callback callback) {
            this.keyManager = keyManager;
            this.data = data;
            this.callback = callback;
            this.onePlusWithBiometricBugFailure = false;
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
            } finally {
                biometricPrompt = null;
                onePlusWithBiometricBugFailure = false;
            }
        }

        @Override
        public void onAuthenticationError(int errorCode, CharSequence errorCharSequence) {
            super.onAuthenticationError(errorCode, errorCharSequence);
            if (this.onePlusWithBiometricBugFailure) {
                biometricPrompt = null;
                onePlusWithBiometricBugFailure = false;
                callback.invoke(ERROR_NON_COMPLIANT_PROMPT, null);
            } else {
                callback.invoke(errorCode, null);
            }
        }

        @Override
        public void onAuthenticationFailed() {
            super.onAuthenticationFailed();

            if (biometricPrompt != null && hasOnePlusBiometricBug()) {
                onePlusWithBiometricBugFailure = true;
                cancelAuthentication();
            }
        }
    }
}
