package com.secureshare.controllers;

import com.secureshare.services.FileService;
import com.secureshare.services.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DashboardController {

    private final FileService fileService;
    private final UserService userService;

    /// Constructor that Spring uses to inject both FileService and UserService dependencies
    /// These services handle file operations and user-related business logic respectively
    public DashboardController(FileService fileService, UserService userService) {
        this.fileService = fileService;
        this.userService = userService;
    }

    /// Handles GET requests to the /dashboard URL - the main user dashboard after login
    /// Spring Security automatically provides the Authentication object for the logged-in user
    @GetMapping("/dashboard")
    public String dashboard(Authentication auth, Model model) {

        /// Extract the username from the authentication object
        /// This gives us the currently logged-in user's identifier
        String username = auth.getName();

        /// Add the username to the model so it can be displayed in the dashboard view
        /// This personalizes the dashboard for each user
        model.addAttribute("username", username);

        /// Fetch all files belonging to the current user and add them to the model
        /// This populates the file list that users see on their dashboard
        model.addAttribute("files", fileService.getFilesByUser(username));

        /// Return the dashboard view template name
        /// Spring MVC will look for a template called "dashboard.html" (or similar)
        return "dashboard";
    }
}