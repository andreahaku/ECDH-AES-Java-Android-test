package com.example.android2mm;

import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ECDH {
    static {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    public static KeyPair generateECDH() {
        try {
            ECGenParameterSpec ecParamSpec = new ECGenParameterSpec("secp256k1");
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "SC");
            keyPairGenerator.initialize(ecParamSpec);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            return keyPair;
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException
                | NoSuchProviderException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String getPublicKey(KeyPair keyPair) {
        return Base64.encodeToString(keyPair.getPublic().getEncoded(), Base64.DEFAULT).replaceAll("\n", "");
    }

    public static PublicKey stringToPublicKey(String key) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        byte[] keyBytes = Base64.decode(key.getBytes("utf-8"), Base64.DEFAULT);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("ECDH", "SC");
        PublicKey publicKey = keyFactory.generatePublic(spec);
        return publicKey;
    }

    public static SecretKey computeECDHSecret(PrivateKey privateKey, String publicKey) {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "SC");
            keyAgreement.init(privateKey);

            keyAgreement.doPhase(stringToPublicKey(publicKey), true);
            SecretKey key = keyAgreement.generateSecret("AES");
            return key;
        } catch (InvalidKeyException | NoSuchAlgorithmException
                | NoSuchProviderException | UnsupportedEncodingException
                | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String encryptAuthIV(SecretKey key, String plainText) {
        try {
            byte[] iv = new SecureRandom().generateSeed(16);

            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "SC");
            byte[] plainTextBytes = plainText.getBytes("UTF-8");
            byte[] cipherText;

            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            cipherText = new byte[cipher.getOutputSize(plainTextBytes.length)];


            int encryptLength = cipher.update(plainTextBytes, 0,
                    plainTextBytes.length, cipherText, 0);
            encryptLength += cipher.doFinal(cipherText, encryptLength);

            byte[] concatenatedBytes = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, concatenatedBytes, 0, iv.length);
            System.arraycopy(cipherText, 0, concatenatedBytes, iv.length, cipherText.length);

            return Base64.encodeToString(concatenatedBytes, Base64.DEFAULT).replaceAll("\n", "");
        } catch (NoSuchAlgorithmException | NoSuchProviderException
                | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException
                | UnsupportedEncodingException | ShortBufferException
                | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String decryptAuthIV(SecretKey key, String cipherText) {
        try {
            Key decryptionKey = new SecretKeySpec(key.getEncoded(), key.getAlgorithm());

            byte[] iv = new byte[16];
            byte[] cipherBytes = Base64.decode(cipherText.getBytes("utf-8"), Base64.DEFAULT);
            System.arraycopy(cipherBytes, 0, iv, 0, iv.length);

            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "SC");

            byte[] plainText;
            byte[] cipherTextBytes = new byte[cipherBytes.length - iv.length];

            System.arraycopy(cipherBytes, iv.length, cipherTextBytes, 0, cipherBytes.length - iv.length);

            cipher.init(Cipher.DECRYPT_MODE, decryptionKey, ivSpec);
            plainText = new byte[cipher.getOutputSize(cipherTextBytes.length)];
            int decryptLength = cipher.update(cipherTextBytes, 0,
                    cipherTextBytes.length, plainText, 0);
            decryptLength += cipher.doFinal(plainText, decryptLength);

            return new String(plainText, "UTF-8");
        } catch (NoSuchAlgorithmException | NoSuchProviderException
                | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException
                | IllegalBlockSizeException | BadPaddingException
                | ShortBufferException | UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String bytesToHex(byte[] data, int length) {
        String digits = "0123456789ABCDEF";
        StringBuffer buffer = new StringBuffer();

        for (int i = 0; i != length; i++) {
            int v = data[i] & 0xff;

            buffer.append(digits.charAt(v >> 4));
            buffer.append(digits.charAt(v & 0xf));
        }

        return buffer.toString();
    }

    public static String bytesToHex(byte[] data) {
        return bytesToHex(data, data.length);
    }

    public static byte[] hexToBytes(String string) {
        int length = string.length();
        byte[] data = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            data[i / 2] = (byte) ((Character.digit(string.charAt(i), 16) << 4) + Character
                    .digit(string.charAt(i + 1), 16));
        }
        return data;
    }
}
