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

    /// Encrypts the private key using AES
    /// NOTE: This is temporary — we will replace with stronger PBKDF2
    private String encryptPrivateKey(String privateKey, String password) throws Exception {

        /// Create a 16-byte AES key from the password (simple version)
        byte[] aesKeyBytes = password
                .repeat(2)                 // ensure length
                .substring(0, 16)          // trim to AES-128 size
                .getBytes();

        SecretKey secretKey = new SecretKeySpec(aesKeyBytes, "AES");

        /// Encrypt using AES in default ECB mode (we will upgrade this later)
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] encrypted = cipher.doFinal(privateKey.getBytes());

        /// Return encrypted value as Base64 string
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /// Decrypts the private key using AES and the user's raw password
    /// This will be called later when performing asymmetric decryption
    public String decryptPrivateKey(String encryptedPrivateKey, String password) throws Exception {

        /// Rebuild the same AES key used during encryption
        byte[] aesKeyBytes = password
                .repeat(2)                 // ensure length
                .substring(0, 16)          // trim to 16 bytes
                .getBytes();

        SecretKey secretKey = new SecretKeySpec(aesKeyBytes, "AES");

        /// Decode the stored Base64 encrypted key
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedPrivateKey);

        /// Decrypt using AES
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] decrypted = cipher.doFinal(encryptedBytes);

        /// Return the original private key as Base64 text
        return new String(decrypted);
    }

}
