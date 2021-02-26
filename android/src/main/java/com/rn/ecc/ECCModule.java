package com.rn.ecc;

import android.content.Context;

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
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;


/**
 * Created by Jacob Gins on 6/2/2016.
 */
public class ECCModule extends ReactContextBaseJavaModule {
    private static final String KEY_TO_ALIAS_MAPPER = "key.to.alias.mapper";
    private final KeyManager keyManager;
    private BiometricPrompt biometricPrompt;

    public static final int ERROR_INVALID_PROMPT_PARAMETERS = 1000;
    public static final int ERROR_INVALID_SIGNATURE = 1001;

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
        if (biometricPrompt != null) {
            biometricPrompt.cancelAuthentication();
            biometricPrompt = null;
        }
        function.invoke(null, null);
    }
}
