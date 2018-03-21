package com.rn.ecc;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.security.auth.x500.X500Principal;

/**
 * Created by Jacob Gins on 6/2/2016.
 */
public class ECCModule extends ReactContextBaseJavaModule {
    private static final String KEYSTORE_PROVIDER_ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String KEY_TO_ALIAS_MAPPER = "key.to.alias.mapper";
    private static final Map<Integer, String> sizeToName = new HashMap<Integer, String>();
    private static final Map<Integer, byte[]> sizeToHead = new HashMap<Integer, byte[]>();
    private SharedPreferences pref;
    private final boolean isModern = android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M;

    static {
        sizeToName.put(192, "secp192r1");
        sizeToName.put(224, "secp224r1");
        sizeToName.put(256, "secp256r1");
        sizeToName.put(384, "secp384r1");
        // sizeToName.put(521, "secp521r1");
    }

    public ECCModule(ReactApplicationContext reactContext) {
        super(reactContext);
        pref = reactContext.getSharedPreferences(KEY_TO_ALIAS_MAPPER, Context.MODE_PRIVATE);
    }

    @Override
    public String getName() {
        return "RNECC";
    }

    private KeyPairGenerator getKeyPairGenerator(int sizeInBits, String keyAlias) throws
            NoSuchAlgorithmException,
            InvalidAlgorithmParameterException,
            NoSuchProviderException {
        return isModern ? getNewKeyPairGenerator(sizeInBits, keyAlias) : getOldKeyPairGenerator(sizeInBits, keyAlias);
    }

    @TargetApi(Build.VERSION_CODES.M)
    private KeyPairGenerator getNewKeyPairGenerator(int sizeInBits, String keyAlias) throws
            NoSuchAlgorithmException,
            InvalidAlgorithmParameterException,
            NoSuchProviderException {
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

        return kpg;
    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    private KeyPairGenerator getOldKeyPairGenerator(int sizeInBits, String keyAlias) throws
            NoSuchAlgorithmException,
            InvalidAlgorithmParameterException,
            NoSuchProviderException {
        Calendar start = new GregorianCalendar();
        Calendar end = new GregorianCalendar();
        end.add(Calendar.YEAR, 10);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE_PROVIDER_ANDROID_KEYSTORE);
        Context context = getReactApplicationContext().getApplicationContext();
        kpg.initialize(new KeyPairGeneratorSpec.Builder(context)
                .setAlias(keyAlias)
                //                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                //                    .setDigests(KeyProperties.DIGEST_SHA256,
                //                                KeyProperties.DIGEST_SHA512,
                //                                KeyProperties.DIGEST_NONE)
                .setKeyType(KeyProperties.KEY_ALGORITHM_EC)
                .setKeySize(sizeInBits)
                .setStartDate(start.getTime())
                .setEndDate(end.getTime())
                .setSubject(new X500Principal("CN=" + keyAlias))
                .setSerialNumber(BigInteger.valueOf(Math.abs(keyAlias.hashCode())))
                .build());
        return kpg;
    }

    @ReactMethod
    public void generateECPair(ReadableMap map, Callback function) {
        int sizeInBits = map.getInt("bits");
        String keyAlias = UUID.randomUUID().toString();
        try {
            KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID_KEYSTORE);
            ks.load(null);

            /*
             * Generate a new EC key pair entry in the Android Keystore by
             * using the KeyPairGenerator API. The private key can only be
             * used for signing or verification and only with SHA-256,
             * SHA-512 or NONE as the message digest.
            */
            KeyPairGenerator kpg = getKeyPairGenerator(sizeInBits, keyAlias);
            KeyPair kp = kpg.genKeyPair();
            ECPublicKey publicKey = (ECPublicKey)kp.getPublic();
            byte[] publicKeyBytes = encodeECPublicKey(publicKey);
            String publicKeyString = toBase64(publicKeyBytes);
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
        try {
            KeyStore.Entry entry = getEntry(publicKeyString);
            function.invoke(null, entry instanceof KeyStore.PrivateKeyEntry);
        } catch (Exception ex) {
            Log.e("hasKey", "ERR", ex);
            function.invoke(ex.toString(), null);
            return;
        }
        function.invoke(null, false);
    }

    public KeyStore.Entry getEntry (String publicKeyString) throws GeneralSecurityException, IOException {
        String keyAlias = pref.getString(publicKeyString, null);
        if (keyAlias == null) {
            return null;
        }

        KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID_KEYSTORE);
        ks.load(null);
        return ks.getEntry(keyAlias, null);
    }

    @Override
    public Map<String, Object> getConstants() {
        final Map<String, Object> constants = new HashMap<>();
        constants.put("preHash", this.isModern);
        return constants;
    }

    @ReactMethod
    public void sign(ReadableMap map, Callback function) {
        String publicKeyString = map.getString("pub");
        String algorithm = getAlgorithm(map);
        String signature = "";
        try {
            byte[] data = getDataProp(map);
            KeyStore.Entry entry = getEntry(publicKeyString);
            Signature s = Signature.getInstance(algorithm);
            PrivateKey key = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
            s.initSign(key);
            s.update(data);
            byte[] signatureBytes = s.sign();
            signature = toBase64(signatureBytes);
//            WritableMap toVerify = new WritableNativeMap();
//            toVerify.putString("sig", signature);
//            toVerify.putString("pub", publicKeyString);
//            toVerify.putString("data", map.getString("data"));
//            toVerify.putString("algorithm", map.getString("algorithm"));
//            boolean good = verify(toVerify);
//            if (!good) {
//                Log.e("sign", "ERR");
//            }
        } catch (Exception ex) {
            Log.e("sign", "ERR", ex);
            function.invoke(ex.toString(), null);
            return;
        }

        function.invoke(null, signature);
    }

    @ReactMethod
    public void verify(ReadableMap map, Callback function) {
        try {
            boolean verified = verify(map);
            function.invoke(null, verified);
        } catch (Exception ex) {
            Log.e("RNECC", "verify error", ex);
            function.invoke(ex.toString(), null);
            return;
        }
    }

    private boolean verify (ReadableMap map) throws GeneralSecurityException {
        byte[] data = getDataProp(map);
        byte[] sigBytes = getSigProp(map);
        byte[] pubKeyBytes = getPubProp(map);
        String algorithm = getAlgorithm(map);
        ECPublicKey publicKey = decodeECPublicKey(pubKeyBytes);
        Signature sig = Signature.getInstance(algorithm);
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(sigBytes);
    }

    private static byte[] encodeECPublicKey(ECPublicKey pubKey) throws InvalidKeyException {
        int keyLengthBytes = pubKey.getParams().getOrder().bitLength() / 8;

        ECPoint w = pubKey.getW();
        BigInteger x = w.getAffineX();
        BigInteger y = w.getAffineY();
        byte[] b = combine(x, y, keyLengthBytes * 2);
        byte[] publicKeyEncoded = new byte[1 + 2 * keyLengthBytes];
        publicKeyEncoded[0] = 0x04;
        for (int i = 0; i < b.length; i++) {
            publicKeyEncoded[i + 1] = b[i];
        }

        return publicKeyEncoded;
    }

    private static String toBase64(byte[] bytes) {
        return Base64.encodeToString(bytes, Base64.NO_WRAP);
    }

    private static byte[] fromBase64(String str) {
        return Base64.decode(str, Base64.NO_WRAP);
    }

    // courtesy of:
    // http://stackoverflow.com/questions/30445997/loading-raw-64-byte-long-ecdsa-public-key-in-java
    private static byte[] createHeadForNamedCurve(int size)
            throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        String name = sizeToName.get(size);
        ECGenParameterSpec m = new ECGenParameterSpec(name);
        kpg.initialize(m);
        KeyPair kp = kpg.generateKeyPair();
        byte[] encoded = kp.getPublic().getEncoded();
        return Arrays.copyOf(encoded, encoded.length - 2 * (size / Byte.SIZE));
    }

    public static ECPublicKey decodeECPublicKey(byte[] pubKeyBytes)
            throws InvalidKeySpecException,
            InvalidKeyException,
            NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        // uncompressed keys only
        if (pubKeyBytes[0] != 0x04) {
            throw new InvalidKeyException("only uncompressed keys supported");
        }

        byte[] w = Arrays.copyOfRange(pubKeyBytes, 1, pubKeyBytes.length);
        int size = w.length / 2 * Byte.SIZE;
        byte[] head = sizeToHead.get(size);
        if (head == null) {
            head = createHeadForNamedCurve(size);
            sizeToHead.put(size, head);
        }

        byte[] encodedKey = new byte[head.length + w.length];
        System.arraycopy(head, 0, encodedKey, 0, head.length);
        System.arraycopy(w, 0, encodedKey, head.length, w.length);
        KeyFactory eckf;
        try {
            eckf = KeyFactory.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("EC key factory not present in runtime");
        }

        X509EncodedKeySpec ecpks = new X509EncodedKeySpec(encodedKey);
        try {
            return (ECPublicKey) eckf.generatePublic(ecpks);
        } catch (Exception e) {
            Log.e("RNECC", "failed to decode EC pubKey", e);
            throw e;
        }
    }

    // https://github.com/i2p/i2p.i2p/blob/master/core/java/src/net/i2p/crypto/SigUtil.java

    /**
     *  @param bi non-negative
     *  @return array of exactly len bytes
     */
    public static byte[] rectify(BigInteger bi, int len)
            throws InvalidKeyException {
        byte[] b = bi.toByteArray();
        if (b.length == len) {
            // just right
            return b;
        }
        if (b.length > len + 1)
            throw new InvalidKeyException("key too big (" + b.length + ") max is " + (len + 1));
        byte[] rv = new byte[len];
        if (b.length == 0)
            return rv;
        if ((b[0] & 0x80) != 0)
            throw new InvalidKeyException("negative");
        if (b.length > len) {
            // leading 0 byte
            if (b[0] != 0)
                throw new InvalidKeyException("key too big (" + b.length + ") max is " + len);
            System.arraycopy(b, 1, rv, 0, len);
        } else {
            // smaller
            System.arraycopy(b, 0, rv, len - b.length, b.length);
        }
        return rv;
    }

    /**
     *  Combine two BigIntegers of nominal length = len / 2
     *  @return array of exactly len bytes
     */
    private static byte[] combine(BigInteger x, BigInteger y, int len)
            throws InvalidKeyException {
        int sublen = len / 2;
        byte[] b = new byte[len];
        byte[] bx = rectify(x, sublen);
        byte[] by = rectify(y, sublen);
        System.arraycopy(bx, 0, b, 0, sublen);
        System.arraycopy(by, 0, b, sublen, sublen);
        return b;
    }

    private static byte[] getDataProp(ReadableMap map) {
        if (map.hasKey("data")) {
            return getBinaryProp(map, "data");
        }

        return getBinaryProp(map, "hash");
    }

    private static byte[] getSigProp (ReadableMap map) {
        return getBinaryProp(map, "sig");
    }

    private static byte[] getPubProp (ReadableMap map) {
        return getBinaryProp(map, "pub");
    }

    private static byte[] getBinaryProp (ReadableMap map, String propName) {
        return fromBase64(map.getString(propName));
    }

    private static String getAlgorithm (ReadableMap map) {
        String alg = map.hasKey("algorithm") ?  map.getString("algorithm") : "NONE";
        return alg.toUpperCase() + "withECDSA";
    }
}
