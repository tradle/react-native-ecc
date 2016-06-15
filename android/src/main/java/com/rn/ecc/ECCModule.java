package com.rn.ecc;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
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
import java.util.UUID;

/**
 * Created by boris on 6/2/2016.
 */
public class ECCModule extends ReactContextBaseJavaModule {
    private static final String KEY_TO_ALIAS_MAPPER = "key.to.alias.mapper";

    private SharedPreferences pref;

    public ECCModule(ReactApplicationContext reactContext) {
        super(reactContext);
        pref = reactContext.getSharedPreferences(KEY_TO_ALIAS_MAPPER, Context.MODE_PRIVATE);
    }

    @Override
    public String getName() {
        return "ECC";
    }

    @ReactMethod
    public void generateECPair(int sizeInBits, Callback function) {
        String keyAlias = UUID.randomUUID().toString();
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);

            /*
             * Generate a new EC key pair entry in the Android Keystore by
             * using the KeyPairGenerator API. The private key can only be
             * used for signing or verification and only with SHA-256,
             * SHA-512 or NONE as the message digest.
            */
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            kpg.initialize(new KeyGenParameterSpec.Builder(
                    keyAlias,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256,
                                KeyProperties.DIGEST_SHA512,
                                KeyProperties.DIGEST_NONE)
                    .setKeySize(sizeInBits)
                    .build());
            KeyPair kp = kpg.genKeyPair();
            PublicKey publicKey = kp.getPublic();
            byte[] publicKeyBytes = publicKey.getEncoded();
            String publicKeyString = Base64.encodeToString(publicKeyBytes, Base64.DEFAULT);

            SharedPreferences.Editor editor = pref.edit();
            editor.putString(publicKeyString, keyAlias);
            editor.commit();

            function.invoke(null, publicKeyString);

        } catch (Exception ex) {
            Log.e("generateECPair", "ERR", ex);
            function.invoke(ex.toString(), null);
        }
    }

    @ReactMethod
    public void hasKey(String publicKeyString, Callback function) {
        boolean found;
        try {
            String keyAlias = pref.getString(publicKeyString, null);
            if (keyAlias == null) {
                function.invoke("Unknown public key", null);
                return;
            }
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            KeyStore.Entry entry = ks.getEntry(keyAlias, null);
            found = (entry instanceof KeyStore.PrivateKeyEntry)? true : false;
        } catch (Exception ex) {
            Log.e("hasKey", "ERR", ex);
            function.invoke(ex.toString(), null);
            return;
        }
        function.invoke(null, found);
    }

    @ReactMethod
    public void sign(String publicKeyString, String data, Callback function) {
        String keyAlias = pref.getString(publicKeyString, null);
        if (keyAlias == null) {
            function.invoke("Unknown PublicKey", null);
            return;
        }
        String signature = "";
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);

            KeyStore.Entry entry = ks.getEntry(keyAlias, null);
            if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
                function.invoke("Not an instance of a PrivateKeyEntry", null);
                return;
            }
            else {
                Signature s = Signature.getInstance("NONEwithECDSA");
                PrivateKey key = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
                s.initSign(key);
                s.update(data.getBytes("UTF-8"));
                byte[] signatureBytes = s.sign();
                signature = Base64.encodeToString(signatureBytes, Base64.DEFAULT);
            }
        } catch (Exception ex) {
            Log.e("sign", "ERR", ex);
            function.invoke(ex.toString(), null);
            return;
        }

        function.invoke(null, signature);
    }

    @ReactMethod
    public void verify(String publicKeyString, String data, String signature, Callback function) {
        String keyAlias = pref.getString(publicKeyString, null);
        if (keyAlias == null) {
            function.invoke("Unknown public key", null);
            return;
        }
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
                byte[] signatureBytes = Base64.decode(signature, Base64.DEFAULT);
                verified = sig.verify(signatureBytes);
            }
            else {
                function.invoke("Not an instance of a PrivateKeyEntry", null);
                return;
            }
        } catch (Exception ex) {
            Log.e("verify", "ERR", ex);
            function.invoke(ex.toString(), null);
            return;
        }
        function.invoke(null, verified);
    }
}
