package com.secureshare.TechBySaad.controllers;

import com.secureshare.TechBySaad.models.User;
import com.secureshare.TechBySaad.services.UserService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

/// This controller handles authentication-related pages such as registration and login
/// It connects the front-end forms to the UserService which performs the actual logic
@Controller
public class AuthController {

    /// Service that contains business logic for registering and validating users
    private final UserService userService;

    /// Constructor-based dependency injection — Spring automatically provides UserService
    public AuthController(UserService userService) {
        this.userService = userService;
    }

    /// ------------------------------------------------------------
    /// DISPLAY REGISTRATION PAGE
    /// ------------------------------------------------------------
    /// Handles GET requests to "/register"
    /// Shows an empty registration form to the user
    @GetMapping("/register")
    public String showRegisterForm(Model model) {

        /// Create an empty User object for form binding
        model.addAttribute("user", new User());

        /// Return the register.html page
        return "register";
    }

    /// ------------------------------------------------------------
    /// PROCESS USER REGISTRATION
    /// ------------------------------------------------------------
    /// Handles POST requests submitted from the registration form
    @PostMapping("/register")
    public String registerUser(@ModelAttribute User user, Model model) {

        /// Check if username already exists — prevents duplicate accounts
        if (userService.usernameExists(user.getUsername())) {

            /// Send error back to the form without losing user input
            model.addAttribute("error", "Username already taken!");
            return "register";
        }

        /// Register the user — this also:
        /// ✅ hashes the password
        /// ✅ generates X25519 keypair (public + private keys)
        userService.register(user);

        /// Show success message and redirect to login
        model.addAttribute("success", "Account created successfully! Please login.");

        return "login";
    }

    /// ------------------------------------------------------------
    /// DISPLAY LOGIN PAGE
    /// ------------------------------------------------------------
    /// Handles GET requests to "/login"
    /// Simply returns the login view — Spring Security handles authentication
    @GetMapping("/login")
    public String showLoginPage() {
        return "login";
    }
}
