package com.secureshare.TechBySaad.controllers;

import com.secureshare.TechBySaad.models.FileEntity;
import com.secureshare.TechBySaad.services.FileService;
import com.secureshare.TechBySaad.services.UserService;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.List;

/**
 * ---------------------------------------------------------------
 * DASHBOARD CONTROLLER
 * ---------------------------------------------------------------
 * This controller handles the main Dashboard page.
 * After the user logs in, Spring Security redirects them to "/dashboard".
 *
 * Responsibilities:
 *  - Show logged-in user's files
 *  - Show total number of files
 *  - Show total storage used by the user
 *  - Pass all information to dashboard.html (Thymeleaf template)
 * ---------------------------------------------------------------
 */
@Controller
public class DashboardController {

    private final FileService fileService;
    private final UserService userService;

    /**
     * Constructor injection (recommended by Spring)
     * ---------------------------------------------------------------
     * Spring automatically gives us:
     *  - FileService: for file operations (upload, delete, list...)
     *  - UserService: for user-related operations (optional here)
     * ---------------------------------------------------------------
     */
    public DashboardController(FileService fileService, UserService userService) {
        this.fileService = fileService;
        this.userService = userService;
    }

    /**
     * MAIN DASHBOARD PAGE CONTROLLER
     * ---------------------------------------------------------------
     * @GetMapping("/dashboard")
     * This method is called when the user goes to:
     *     http://localhost:8081/dashboard
     *
     * Spring Security automatically injects:
     *  - Authentication auth → contains logged-in user's username
     *
     * What this method does:
     *  1. Find logged-in username
     *  2. Get all files uploaded by this user
     *  3. Calculate total storage used
     *  4. Pass everything to dashboard.html
     * ---------------------------------------------------------------
     */
    @GetMapping("/dashboard")
    public String dashboard(Authentication auth, Model model) {

        // 1. Get logged-in username
        //    This ensures we always fetch the correct user's files.
        String username = auth.getName();

        // 2. Add username to the HTML model
        //    Used inside dashboard.html: <span th:text="${username}">
        model.addAttribute("username", username);

        // 3. Fetch all files uploaded by this user
        //    dashboard.html shows these in the table.
        List<FileEntity> files = fileService.getFilesByUser(username);
        model.addAttribute("files", files);

        // 4. Get total storage (converted into MB)
        //    Shown in “TOTAL STORAGE” card.
        String totalStorageFormattedMB = fileService.getTotalStorageFormatted(username);
        model.addAttribute("totalStorageFormattedMB", totalStorageFormattedMB);

        // 5. Render the template: src/main/resources/templates/dashboard.html
        return "dashboard";
    }
}
