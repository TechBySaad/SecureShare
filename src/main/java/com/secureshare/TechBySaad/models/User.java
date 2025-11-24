package com.secureshare.TechBySaad.models;

import jakarta.persistence.*;

/// This class represents a user in the system and maps to the "users" table.
/// It stores login credentials and now also supports asymmetric encryption keys.
@Entity
@Table(name = "users")
public class User {

    /// Primary key that uniquely identifies each user.
    /// AUTO_INCREMENT (IDENTITY) ensures the database generates the ID automatically.
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /// The username used for login.
    /// `unique = true` ensures no two users can register with the same username.
    /// `nullable = false` means this field is required.
    @Column(nullable = false, unique = true)
    private String username;

    /// Stores the **hashed password** (never plain text).
    /// Password hashing is handled in the service layer before saving.
    @Column(nullable = false)
    private String password;

    /// ------------------------------
    /// NEW FIELDS FOR ASYMMETRIC KEYS
    /// ------------------------------

    /// Stores the user's **public key** (X25519).
    /// This will be shared with other users for secure key exchange.
    /// Stored as TEXT because keys may exceed normal VARCHAR length.
    @Column(columnDefinition = "TEXT")
    private String publicKey;

    /// Stores the user's **private key** (X25519).
    /// IMPORTANT:
    /// - This is sensitive information
    /// - Currently stored as plain text temporarily
    /// - In the next step, we will encrypt it before saving
    @Column(columnDefinition = "TEXT")
    private String privateKey;

    /// Default constructor required by JPA.
    /// Used internally when loading user objects from the database.
    public User() {}

    // -----------------
    // GETTERS & SETTERS
    // -----------------

    /// Returns the internal user ID.
    public Long getId() {
        return id;
    }

    /// Sets the user ID — typically only done by JPA.
    public void setId(Long id) {
        this.id = id;
    }

    /// Returns the username for this user.
    public String getUsername() {
        return username;
    }

    /// Sets the username — used during registration.
    public void setUsername(String username) {
        this.username = username;
    }

    /// Returns the hashed password.
    public String getPassword() {
        return password;
    }

    /// Sets the password — must already be hashed before saving.
    public void setPassword(String password) {
        this.password = password;
    }

    /// Returns the user's public key.
    public String getPublicKey() {
        return publicKey;
    }

    /// Sets the user's public key — will be generated automatically on registration.
    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    /// Returns the user's private key.
    public String getPrivateKey() {
        return privateKey;
    }

    /// Sets the private key — later we will encrypt this before saving.
    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }
}
