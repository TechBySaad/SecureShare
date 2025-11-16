package com.secureshare.services;

import com.secureshare.models.User;
import com.secureshare.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;

/// This service acts as the bridge between our custom user database and Spring Security
/// It's responsible for loading user information during the login process
@Service
public class CustomUserDetailsService implements UserDetailsService {

    /// We automatically connect to the UserRepository to access our user data
    /// This lets us search for users in our database
    @Autowired
    private UserRepository userRepository;

    /// This is the heart of the authentication process - Spring Security calls this method
    /// every time someone tries to log in to find out if the user exists and get their details
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        /// First, we try to find the user in our database using the provided username
        /// This queries our 'users' table to see if we have a matching user
        User user = userRepository.findByUsername(username);

        /// If we didn't find any user with that username, we need to tell Spring Security
        /// that this user doesn't exist so it can show an appropriate error message
        if (user == null) {
            throw new UsernameNotFoundException("User not found!");
        }

        /// If we found the user, we need to convert our custom User object into
        /// something that Spring Security understands - a UserDetails object
        /// We're using Spring Security's built-in User builder for this
        return org.springframework.security.core.userdetails.User
                .withUsername(user.getUsername())  /// The login username
                .password(user.getPassword())      /// The encrypted password from our database
                .roles()  /// <-- We're not assigning any specific roles to users
                /// Empty roles means all users have the same basic permissions
                .build(); /// This creates the final UserDetails object for Spring Security
    }
}