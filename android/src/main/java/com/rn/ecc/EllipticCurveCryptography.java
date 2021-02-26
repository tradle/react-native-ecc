package com.rn.ecc;

import android.util.Base64;
import android.util.Log;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;


public class EllipticCurveCryptography {
    private static final int SIZE = 256;
    private static final String CURVE = "secp256r1";

    public static String getPublicKey(ECPublicKey ecPublicKey) throws InvalidKeyException {
        byte[] publicKeyBytes = encodeECPublicKey(ecPublicKey);
        return toBase64(publicKeyBytes);
    }

    private static byte[] encodeECPublicKey(ECPublicKey ecPublicKey) throws InvalidKeyException {
        int keyLengthBytes = ecPublicKey.getParams().getOrder().bitLength() / 8;

        ECPoint w = ecPublicKey.getW();
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
        byte[] head = createHeadForNamedCurve();

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

    private static byte[] combine(BigInteger x, BigInteger y, int len) throws InvalidKeyException {
        int halfLength = len / 2;
        byte[] b = new byte[len];
        byte[] bx = rectify(x, halfLength);
        byte[] by = rectify(y, halfLength);
        System.arraycopy(bx, 0, b, 0, halfLength);
        System.arraycopy(by, 0, b, halfLength, halfLength);
        return b;
    }

    private static byte[] rectify(BigInteger bi, int len)
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

    private static String toBase64(byte[] bytes) {
        return Base64.encodeToString(bytes, Base64.NO_WRAP);
    }

    private static byte[] createHeadForNamedCurve()
        throws NoSuchAlgorithmException,
        InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec m = new ECGenParameterSpec(CURVE);
        kpg.initialize(m);
        KeyPair kp = kpg.generateKeyPair();
        byte[] encoded = kp.getPublic().getEncoded();
        return Arrays.copyOf(encoded, encoded.length - 2 * (SIZE / Byte.SIZE));
    }
}
