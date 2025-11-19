package com.secureshare.TechBySaad.models;

import jakarta.persistence.*;

/// This class represents a user in the system and maps to a database table
/// It's a JPA entity that stores user authentication information
@Entity
@Table(name = "users")
public class User {

    /// Primary key that auto-generates when a new user is registered
    /// The database automatically assigns sequential IDs as new users sign up
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /// Stores the unique username for login purposes
    /// The 'unique = true' constraint prevents duplicate usernames in the system
    /// 'nullable = false' means every user must have a username
    @Column(nullable = false, unique = true)
    private String username;

    /// Stores the encrypted password for security
    /// In a real application, this should always be hashed/encrypted, never stored in plain text
    /// 'nullable = false' ensures every user account has a password
    @Column(nullable = false)
    private String password;

    /// Default constructor required by JPA/Hibernate
    /// Spring uses this when creating user instances from database results
    public User() {}

    /// GETTERS & SETTERS

    /// These methods allow controlled access to the user's private data

    /// Returns the unique numeric identifier for this user
    public Long getId() {
        return id;
    }

    /// Sets the user ID - typically only used by JPA when loading from database
    public void setId(Long id) {
        this.id = id;
    }

    /// Returns the username that this user logs in with
    public String getUsername() {
        return username;
    }

    /// Sets the username - used during user registration
    public void setUsername(String username) {
        this.username = username;
    }

    /// Returns the encrypted password (should never return plain text)
    public String getPassword() {
        return password;
    }

    /// Sets the password - should always receive an already-encrypted password
    /// The encryption/hashing should happen in the service layer before calling this
    public void setPassword(String password) {
        this.password = password;
    }
}