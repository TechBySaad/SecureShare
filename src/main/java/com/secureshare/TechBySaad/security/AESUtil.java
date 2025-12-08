package com.secureshare.TechBySaad.security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * AES Utility using modern AES-GCM encryption.
 * GCM provides confidentiality + integrity.
 * This version keeps the project simple, but secure.
 */
public class AESUtil {

    private static final String ALGO = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    // 16-byte fixed key (AES-128)
    // OK for learning, but do NOT use like this in real systems.
    private static final String FIXED_KEY = "MySecretKey12345";

    // GCM standard tag length = 128 bits (16 bytes)
    private static final int TAG_LENGTH_BITS = 128;

    // IV must be 12 bytes for GCM
    private static final int IV_LENGTH = 12;

    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * Returns the fixed AES key used by the app.
     * (Later we will replace this with per-file keys.)
     */
    public static SecretKey getAppKey() {
        return new SecretKeySpec(FIXED_KEY.getBytes(StandardCharsets.UTF_8), ALGO);
    }

    /**
     * Generates a random 12-byte IV for AES-GCM.
     */
    private static byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        secureRandom.nextBytes(iv);
        return iv;
    }

    /**
     * Encrypts data using AES-GCM.
     *
     * Output format = IV + Ciphertext
     * This makes it easy to store everything in one byte[].
     */
    public static byte[] encrypt(byte[] data, SecretKey key) throws Exception {
        byte[] iv = generateIV();

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));

        byte[] ciphertext = cipher.doFinal(data);

        // Combine IV + ciphertext into one array
        byte[] output = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, output, 0, iv.length);
        System.arraycopy(ciphertext, 0, output, iv.length, ciphertext.length);
        return output;
    }

    /**
     * Decrypts AES-GCM data.
     * Expects input in the format: [IV(12 bytes)] + [ciphertext]
     */
    public static byte[] decrypt(byte[] encryptedData, SecretKey key) throws Exception {

        // Extract IV (first 12 bytes)
        byte[] iv = new byte[IV_LENGTH];
        System.arraycopy(encryptedData, 0, iv, 0, IV_LENGTH);

        // Extract ciphertext (remaining bytes)
        byte[] ciphertext = new byte[encryptedData.length - IV_LENGTH];
        System.arraycopy(encryptedData, IV_LENGTH, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));

        return cipher.doFinal(ciphertext);
    }
}
