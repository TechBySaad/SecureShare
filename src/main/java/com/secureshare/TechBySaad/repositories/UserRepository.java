package com.secureshare.TechBySaad.repositories;

import com.secureshare.TechBySaad.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /// Fetches a user based on username — used during login
    User findByUsername(String username);

    /// Checks if a username already exists — used during registration
    boolean existsByUsername(String username);

    /// NEW (Optional helper for later)
    /// We will use this when generating keys only once
    boolean existsByPublicKeyNotNull();
}

