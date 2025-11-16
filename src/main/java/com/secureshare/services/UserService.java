package com.secureshare.services;

import com.secureshare.models.User;
import com.secureshare.repositories.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

/// This service handles all user-related business logic like registration and authentication
/// It acts as a middle layer between controllers and the database repository
@Service
public class UserService {

    /// Repository that handles database operations for User entities
    /// Spring automatically injects this dependency through the constructor
    private final UserRepository userRepository;

    /// Password encoder used to securely hash passwords before storing them
    /// BCrypt is a strong hashing algorithm that includes salt automatically
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    /// Constructor that Spring uses to inject the UserRepository dependency
    /// This is called dependency injection - Spring provides the actual repository instance
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /// Checks if a username is already taken in the system
    /// Used during registration to prevent duplicate usernames
    public boolean usernameExists(String username) {
        return userRepository.existsByUsername(username);
    }

    /// Handles new user registration with proper security measures
    /// Takes a user object, hashes the password, and saves to database
    public User register(User user) {
        // Hash the password before saving to database
        /// This converts the plain text password into a secure irreversible hash
        /// The same password will produce different hashes each time due to built-in salt
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        /// Save the user with the hashed password to the database
        return userRepository.save(user);
    }

    /// Finds a user by their username
    /// Used during login to verify user credentials
    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }
}