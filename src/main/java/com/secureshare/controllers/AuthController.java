package com.secureshare.controllers;

import com.secureshare.models.User;
import com.secureshare.services.UserService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class AuthController {

    private final UserService userService;

    /// This is the constructor that Spring uses to inject the UserService dependency
    /// When creating an AuthController, Spring automatically provides the UserService instance
    public AuthController(UserService userService) {
        this.userService = userService;
    }

    /// Handles GET requests to the /register URL - shows the registration form to users
    /// We create a new empty User object and pass it to the view so the form can bind to it
    @GetMapping("/register")
    public String showRegisterForm(Model model) {
        model.addAttribute("user", new User());
        return "register";
    }

    /// Handles POST requests to the /register URL - processes the form submission
    /// The @ModelAttribute automatically populates the User object with form data
    @PostMapping("/register")
    public String registerUser(@ModelAttribute User user, Model model) {

        /// First check if the username is already taken in our system
        /// This prevents duplicate usernames and maintains data integrity
        if (userService.usernameExists(user.getUsername())) {
            /// If username exists, show an error message and return to registration form
            model.addAttribute("error", "Username already taken!");
            return "register";
        }

        /// If username is available, save the new user to the database
        userService.register(user);

        /// Show success message and redirect to login page
        /// The user now needs to log in with their newly created credentials
        model.addAttribute("success", "Account created successfully! Please login.");
        return "login";
    }

    /// Handles GET requests to the /login URL - simply displays the login page
    /// This is a straightforward page display without any complex logic
    @GetMapping("/login")
    public String showLoginPage() {
        return "login";
    }
}