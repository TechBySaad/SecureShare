package com.secureshare.TechBySaad.security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Utility class for handling X25519 operations + HKDF key derivation.
 * This keeps FileService clean and readable.
 */
public class X25519Util {

    static {
        // Ensure BouncyCastle is registered
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Generates a fresh ephemeral X25519 keypair.
     */
    public static KeyPair generateEphemeralKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519", "BC");
        return kpg.generateKeyPair();
    }

    /**
     * Calculates ECDH shared secret:
     * shared = X25519( privateKey_sender , publicKey_receiver )
     */
    /**
     * Calculates ECDH shared secret using X25519.
     * This version works across JDK 17+ and BC without errors.
     */
    public static byte[] computeSharedSecret(PrivateKey myPrivateKey, byte[] peerPublicKeyBytes) throws Exception {

        // Create PublicKey object from raw/base64 bytes
        KeyFactory keyFactory = KeyFactory.getInstance("X25519", "BC");
        PublicKey peerPublicKey = keyFactory.generatePublic(
                new X509EncodedKeySpec(peerPublicKeyBytes)
        );

        // Perform X25519 key agreement
        javax.crypto.KeyAgreement ka = javax.crypto.KeyAgreement.getInstance("X25519", "BC");
        ka.init(myPrivateKey);
        ka.doPhase(peerPublicKey, true);

        return ka.generateSecret();
    }


    /**
     * Derives a strong AES-256 key using HKDF-SHA256.
     * Input: shared secret from X25519.
     */
    public static byte[] deriveAesKey(byte[] sharedSecret) throws Exception {

        // HKDF: extract + expand
        byte[] salt = new byte[32]; // can stay zeroed; optional for HKDF
        Mac mac = Mac.getInstance("HmacSHA256");

        // EXTRACT
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(sharedSecret);

        // EXPAND (need 32 bytes for AES-256)
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update("SecureShareKeyWrap".getBytes()); // context string
        mac.update((byte) 1); // HKDF counter

        return Arrays.copyOf(mac.doFinal(), 32);
    }
}
