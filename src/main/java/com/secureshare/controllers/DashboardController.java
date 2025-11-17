package com.secureshare.controllers;

import com.secureshare.models.FileEntity;
import com.secureshare.services.FileService;
import com.secureshare.services.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.List;

/// This controller handles the main dashboard page that users see after logging in
/// It's the central hub where users can view their files and storage information
@Controller
public class DashboardController {

    private final FileService fileService;
    private final UserService userService;

    /// Constructor that Spring uses to inject both service dependencies
    /// FileService handles file operations, UserService handles user data
    public DashboardController(FileService fileService, UserService userService) {
        this.fileService = fileService;
        this.userService = userService;
    }

    /// Handles the main dashboard page request - this is what users see after logging in
    /// Spring Security automatically provides the Authentication object for the logged-in user
    @GetMapping("/dashboard")
    public String dashboard(Authentication auth, Model model) {

        /// Get the username of the currently logged-in user from Spring Security
        /// This ensures each user only sees their own files and data
        String username = auth.getName();

        // Add username to the model so it can be displayed in the dashboard
        /// This personalizes the dashboard by showing who is currently logged in
        model.addAttribute("username", username);

        // Add list of files belonging to this user
        /// Fetch all files that this specific user has uploaded
        /// The files are typically displayed in a table or list on the dashboard
        List<FileEntity> files = fileService.getFilesByUser(username);
        model.addAttribute("files", files);

        // Add total storage used (formatted in MB for easy reading)
        /// Calculate how much storage space the user has consumed
        /// This helps users manage their storage limits and see their usage
        String totalStorageFormattedMB = fileService.getTotalStorageFormatted(username);
        model.addAttribute("totalStorageFormattedMB", totalStorageFormattedMB);

        /// Return the dashboard view template
        /// Spring will look for a template called "dashboard.html" to render
        return "dashboard";
    }
}