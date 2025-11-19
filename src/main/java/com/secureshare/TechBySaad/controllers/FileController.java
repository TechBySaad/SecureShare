package com.secureshare.TechBySaad.controllers;

import com.secureshare.TechBySaad.models.FileEntity;
import com.secureshare.TechBySaad.services.FileService;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.http.ResponseEntity;

@Controller
public class FileController {

    private final FileService fileService;

    /// Constructor that Spring uses to inject the FileService dependency
    /// This service handles all the file operations like upload, download, and sharing
    public FileController(FileService fileService) {
        this.fileService = fileService;
    }


    /// UPLOAD FILE (AES ENCRYPTION HAPPENS IN SERVICE)

    /// Handles file uploads from the dashboard form
    /// The uploaded file is automatically encrypted using AES encryption in the service layer
    @PostMapping("/upload")
    public String uploadFile(@RequestParam("file") MultipartFile file,
                             Authentication auth,
                             Model model) {

        /// Get the currently logged-in user's username to associate the file with them
        String username = auth.getName();  // Logged-in user

        try {
            /// Save the file to storage (encryption happens inside this method)
            fileService.saveFile(file, username);
            /// Show success message to the user
            model.addAttribute("success", "File uploaded successfully!");
        } catch (Exception e) {
            /// If something goes wrong, log the error and show error message
            e.printStackTrace();
            model.addAttribute("error", "Failed to upload file.");
        }

        /// Refresh the file list to show the newly uploaded file
        model.addAttribute("files", fileService.getFilesByUser(username));
        /// Return to the dashboard page
        return "dashboard";
    }

    /// DELETE FILE

    /// Handles file deletion when user clicks delete link
    /// The file ID comes from the URL path
    @GetMapping("/delete/{id}")
    public String deleteFile(@PathVariable Long id, Authentication auth) {
        /// Call the service to remove the file from storage and database
        fileService.deleteFile(id);
        /// Redirect back to dashboard to see updated file list
        return "redirect:/dashboard";
    }


    /// DOWNLOAD FILE (DECRYPTED)


    /// Handles file downloads - automatically decrypts the file before sending to user
    /// Returns raw file data as a download response rather than a HTML page
    @GetMapping("/download/{id}")
    public ResponseEntity<byte[]> downloadFile(@PathVariable Long id) {

        /// Get the file from service (decryption happens inside this method)
        FileEntity file = fileService.getFile(id); // decrypted file

        /// If file doesn't exist, return 404 Not Found
        if (file == null) {
            return ResponseEntity.notFound().build();
        }

        /// Return the file as a downloadable attachment with proper headers
        return ResponseEntity.ok()
                /// Tell browser to download as attachment with original filename
                .header("Content-Disposition", "attachment; filename=\"" + file.getFileName() + "\"")
                /// Set the correct content type (like image/jpeg, application/pdf, etc.)
                .header("Content-Type", file.getFileType())
                /// Include the actual file data in the response body
                .body(file.getData());
    }


    ///  SHARE FILE WITH ANOTHER USER


    /// Allows users to share their files with other users in the system
    /// The target user gets access to view and download the shared file
    @PostMapping("/share/{id}")
    public String shareFile(@PathVariable("id") Long id,
                            @RequestParam("targetUser") String targetUser,
                            Authentication auth,
                            Model model) {

        /// Call service to create sharing relationship between file and target user
        fileService.shareFile(id, targetUser);

        /// Show success confirmation to the user
        model.addAttribute("success", "File shared with " + targetUser + " successfully!");
        /// Refresh the file list to show any sharing indicators
        model.addAttribute("files", fileService.getFilesByUser(auth.getName()));

        /// Return to dashboard with success message
        return "dashboard";
    }

}