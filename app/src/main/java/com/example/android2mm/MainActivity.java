package com.example.android2mm;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;

import java.security.KeyPair;
import javax.crypto.SecretKey;

public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        main(null);
    }

    public static void main(String[] args) {
        String plainText = "This is a message!";
        String plainText2 = "This is another message!";

        // Initialize two key pairs
        KeyPair keyPairA = ECDH.generateECDH();
        KeyPair keyPairB = ECDH.generateECDH();

        // Gets the two public keys to be exchanged
        String PublicKeyA = ECDH.getPublicKey(keyPairA);
        String PublicKeyB = ECDH.getPublicKey(keyPairB);
        System.out.println("ECDH - Alice Public key: " + PublicKeyA);
        System.out.println("ECDH - Bob Public key: " + PublicKeyB);

        // Computes the AES secret keys to encrypt/decrypt the message
        SecretKey secretKeyA = ECDH.computeECDHSecret(keyPairA.getPrivate(),
                PublicKeyB);
        SecretKey secretKeyB = ECDH.computeECDHSecret(keyPairB.getPrivate(),
                PublicKeyA);

        System.out.println("ECDH - Alice Calculated shared key: " + ECDH.bytesToHex(secretKeyA.getEncoded()));
        System.out.println("ECDH - Bob Calculated Shared key: " + ECDH.bytesToHex(secretKeyB.getEncoded()));

        // Encrypt the message using 'secretKeyA'
        String cipherText = ECDH.encryptAuthIV(secretKeyA, plainText);
        System.out.println("ECDH - Alice Encrypted cipher text: " + cipherText);

        // Decrypt the message using 'secretKeyB'
        String decryptedPlainText = ECDH.decryptAuthIV(secretKeyB, cipherText);
        System.out.println("ECDH - Bob Decrypted cipher text: " + decryptedPlainText);

        // Encrypt the message using 'secretKeyB'
        String cipherText2 = ECDH.encryptAuthIV(secretKeyB, plainText2);
        System.out.println("ECDH - Bob Encrypted cipher text: " + cipherText2);

        // Decrypt the message using 'secretKeyA'
        String decryptedPlainText2 = ECDH.decryptAuthIV(secretKeyA, cipherText2);
        System.out.println("ECDH - Alice Decrypted cipher text: " + decryptedPlainText2);
    }
}