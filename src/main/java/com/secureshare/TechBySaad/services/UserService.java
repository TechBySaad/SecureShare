package com.secureshare.TechBySaad.services;

import com.secureshare.TechBySaad.models.User;
import com.secureshare.TechBySaad.repositories.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.util.Base64;

/// This service handles all user-related operations such as registration and lookup
/// It acts as the middle layer between controllers and the database
@Service
public class UserService {

    /// Repository that communicates with the database for User records
    private final UserRepository userRepository;

    /// BCrypt safely hashes passwords before saving — never store plain text passwords
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    /// Constructor-based dependency injection — Spring provides the UserRepository instance
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /// Checks if a username already exists — prevents duplicate accounts during registration
    public boolean usernameExists(String username) {
        return userRepository.existsByUsername(username);
    }

    /// Registers a new user by hashing their password and generating encryption keys
    public User register(User user) {

        /// 1️⃣ SECURE PASSWORD HASHING
        /// Converts plain text password into a strong salted hash
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        /// 2️⃣ GENERATE X25519 KEYPAIR FOR ENCRYPTION
        /// This creates a private & public key per user — used later for secure sharing
        generateKeyPairForUser(user);

        /// 3️⃣ SAVE USER IN DATABASE
        return userRepository.save(user);
    }

    /// Retrieves a user by username — used during login authentication
    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    /// --------------------------------------------------------------
    /// PRIVATE METHOD — CREATES X25519 PUBLIC & PRIVATE KEYS
    /// --------------------------------------------------------------
    private void generateKeyPairForUser(User user) {
        try {
            /// Create a key pair generator for X25519 (modern elliptic-curve algorithm)
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("X25519");

            /// Initialize generator (no specific key size needed for X25519)
            keyPairGenerator.initialize(256);

            /// Generate the key pair (public + private key)
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            /// Encode keys to Base64 so they can be stored as text in the database
            String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            String privateKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

            /// Store keys inside the user entity
            user.setPublicKey(publicKeyBase64);
            user.setPrivateKey(privateKeyBase64);

        } catch (Exception e) {
            /// If something goes wrong, print the error — but do NOT stop registration
            e.printStackTrace();
        }
    }
}
