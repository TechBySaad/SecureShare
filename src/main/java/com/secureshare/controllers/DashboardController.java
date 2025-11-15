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

    public DashboardController(FileService fileService, UserService userService) {
        this.fileService = fileService;
        this.userService = userService;
    }

    @GetMapping("/dashboard")
    public String dashboard(Authentication auth, Model model) {

        String username = auth.getName();

        // Add logged in username
        model.addAttribute("username", username);

        // FIXED: use the correct method from FileService
        model.addAttribute("files", fileService.getFilesByUser(username));

        return "dashboard";
    }
}
