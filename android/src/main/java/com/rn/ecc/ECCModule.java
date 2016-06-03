package com.rn.ecc;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * Created by boris on 6/2/2016.
 */
public class ECCModule extends ReactContextBaseJavaModule {

    public ECCModule(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return "ECC";
    }

    @ReactMethod
    public void sign(String keyAlias, String data, Callback function) {
        String signature = "";
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            boolean isKey = ks.containsAlias(keyAlias);
            if (!isKey) {
                /*
                 * Generate a new EC key pair entry in the Android Keystore by
                * using the KeyPairGenerator API. The private key can only be
                * used for signing or verification and only with SHA-256,
                        * SHA-512 or none as the message digest.
                */
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
                kpg.initialize(new KeyGenParameterSpec.Builder(
                        keyAlias,
                        KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                        .setDigests(KeyProperties.DIGEST_SHA256,
                                    KeyProperties.DIGEST_SHA512,
                                    KeyProperties.DIGEST_NONE)
                        .build());
                KeyPair kp = kpg.genKeyPair();
            }

            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);

            KeyStore.Entry entry = ks.getEntry(keyAlias, null);
            if (!(entry instanceof KeyStore.PrivateKeyEntry))
                Log.e("SIG", "Not an instance of a PrivateKeyEntry");
            else {
                Signature s = Signature.getInstance("NONEwithECDSA");
                PrivateKey key = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
                s.initSign(key);
                s.update(data.getBytes("UTF-8"));
                byte[] signatureBytes = s.sign();
                signature = byteArrayToHex(signatureBytes);
                Log.i("SIG", signature);
            }
        } catch (Exception ex) {
            Log.e("SIGN", "ERR", ex);
        }

        function.invoke(null, signature);
    }

    @ReactMethod
    public void verify(String keyAlias, String data, String signature, Callback function) {
        boolean verified = false;
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            KeyStore.Entry entry = ks.getEntry(keyAlias, null);
            if (entry instanceof KeyStore.PrivateKeyEntry) {
                PublicKey publicKey = ((KeyStore.PrivateKeyEntry) entry).getCertificate().getPublicKey();
                Signature sig = Signature.getInstance("NONEwithECDSA");
                sig.initVerify(publicKey);
                sig.update(data.getBytes("UTF-8"));
                verified = sig.verify(hexStringToByteArray(signature));
            }
        } catch (Exception ex) {
            Log.e("VERI", "ERR", ex);
        }
        function.invoke(null, verified);
    }

    private String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for(byte b: a)
            sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

}
