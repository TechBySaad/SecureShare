package com.secureshare.TechBySaad.services;

import com.secureshare.TechBySaad.models.User;
import com.secureshare.TechBySaad.repositories.UserRepository;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Base64;

/// This service handles user registration and now also generates asymmetric keys
@Service
public class UserService {

    /// Repository for accessing the users table in the database
    private final UserRepository userRepository;

    /// Password encoder used to hash passwords securely
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    /// This method runs automatically when Spring starts the application
    /// It registers BouncyCastle so that X25519 becomes available
    @PostConstruct
    public void setupProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /// Constructor used by Spring for injecting dependencies
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /// Checks if a username already exists (used in registration validation)
    public boolean usernameExists(String username) {
        return userRepository.existsByUsername(username);
    }

    /// Handles new user registration
    /// Steps:
    /// 1) Hash password
    /// 2) Generate X25519 key pair
    /// 3) Encrypt private key
    /// 4) Save user to database
    public User register(User user) {

        try {
            /// Store raw password temporarily for private key encryption
            String rawPassword = user.getPassword();

            /// Hash password before saving (never store plain text)
            user.setPassword(passwordEncoder.encode(rawPassword));

            /// Generate X25519 asymmetric key pair using BouncyCastle
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("X25519", "BC");
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            /// Convert keys into Base64 text for storage
            String publicKeyEncoded = Base64.getEncoder()
                    .encodeToString(keyPair.getPublic().getEncoded());

            String privateKeyEncoded = Base64.getEncoder()
                    .encodeToString(keyPair.getPrivate().getEncoded());

            /// Encrypt the private key using the *raw password*
            String encryptedPrivateKey = encryptPrivateKey(privateKeyEncoded, rawPassword);

            /// Store keys in the user record
            user.setPublicKey(publicKeyEncoded);
            user.setPrivateKey(encryptedPrivateKey);

        } catch (Exception e) {
            e.printStackTrace();
        }

        /// Save user data into database
        return userRepository.save(user);
    }

    /// Finds a user by username (used during login)
    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    /// ------------------------------------------------------------
    /// SECURE PRIVATE KEY ENCRYPTION USING PBKDF2 + AES-GCM
    /// ------------------------------------------------------------

    private String encryptPrivateKey(String privateKey, String password) throws Exception {

        // 1) Generate random salt for PBKDF2
        byte[] salt = new byte[16];
        new java.security.SecureRandom().nextBytes(salt);

        // 2) Derive AES key from password using PBKDF2
        javax.crypto.SecretKeyFactory factory =
                javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

        javax.crypto.spec.PBEKeySpec spec =
                new javax.crypto.spec.PBEKeySpec(password.toCharArray(), salt, 65536, 256);

        SecretKey derivedKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

        // 3) Generate random IV for AES-GCM
        byte[] iv = new byte[12];
        new java.security.SecureRandom().nextBytes(iv);

        // 4) AES-GCM encryption
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, derivedKey, new javax.crypto.spec.GCMParameterSpec(128, iv));

        byte[] encryptedBytes = cipher.doFinal(privateKey.getBytes());

        // 5) Store salt + iv + ciphertext together (Base64)
        byte[] output = new byte[salt.length + iv.length + encryptedBytes.length];
        System.arraycopy(salt, 0, output, 0, salt.length);
        System.arraycopy(iv, 0, output, salt.length, iv.length);
        System.arraycopy(encryptedBytes, 0, output, salt.length + iv.length, encryptedBytes.length);

        return Base64.getEncoder().encodeToString(output);
    }

    /// ------------------------------------------------------------
    /// DECRYPT PRIVATE KEY USING PBKDF2 + AES-GCM
    /// ------------------------------------------------------------
    public String decryptPrivateKey(String encryptedPrivateKey, String password) throws Exception {

        byte[] allBytes = Base64.getDecoder().decode(encryptedPrivateKey);

        // read salt (16 bytes)
        byte[] salt = java.util.Arrays.copyOfRange(allBytes, 0, 16);

        // read iv (12 bytes)
        byte[] iv = java.util.Arrays.copyOfRange(allBytes, 16, 28);

        // remaining = ciphertext
        byte[] ciphertext = java.util.Arrays.copyOfRange(allBytes, 28, allBytes.length);

        // rebuild PBKDF2 key
        javax.crypto.SecretKeyFactory factory =
                javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

        javax.crypto.spec.PBEKeySpec spec =
                new javax.crypto.spec.PBEKeySpec(password.toCharArray(), salt, 65536, 256);

        SecretKey derivedKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

        // AES-GCM decryption
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, derivedKey, new javax.crypto.spec.GCMParameterSpec(128, iv));

        byte[] decryptedBytes = cipher.doFinal(ciphertext);

        return new String(decryptedBytes);
    }


}
